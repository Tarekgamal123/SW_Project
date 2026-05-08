# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from datetime import datetime
import os

from config import config
from models import db, Log, Alert, Device, User
from forms import SubmitLogForm
from rules import apply_detection_rules
from utils import save_uploaded_file

# Import auth components
from auth import auth, login_manager, create_default_admin


def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)          # ← Now correctly imported

    # Register blueprints
    app.register_blueprint(auth, url_prefix='/auth')

    # ------------------- Database Upgrade -------------------
    def upgrade_database_safe():
        try:
            with app.app_context():
                conn = db.engine.connect()
                inspector = db.inspect(conn)
                columns = [col['name'] for col in inspector.get_columns('log')]
                
                new_columns = ['request_path', 'method', 'user_agent']
                for col in new_columns:
                    if col not in columns:
                        try:
                            db.engine.execute(f"ALTER TABLE log ADD COLUMN {col} VARCHAR(200)")
                            print(f"✅ Added column: {col}")
                        except:
                            pass
                conn.close()
        except Exception as e:
            print("Database upgrade error:", e)

    # Create tables and default admin
    with app.app_context():
        db.create_all()
        upgrade_database_safe()
        create_default_admin()

    # ------------------- Log Parsing Function -------------------
    def parse_log_line(line):
        entry = {
            'src_ip': None, 'username': None, 'timestamp': None,
            'event_type': 'unknown', 'status': None, 'details': line.strip(),
            'request_path': None, 'method': None, 'user_agent': None
        }

        import re
        # IP
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        if ip_match:
            entry['src_ip'] = ip_match.group()

        # Timestamp
        time_patterns = [
            (r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
            (r'(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})', '%d/%b/%Y:%H:%M:%S'),
        ]
        for pat, fmt in time_patterns:
            m = re.search(pat, line)
            if m:
                try:
                    entry['timestamp'] = datetime.strptime(m.group(1), fmt)
                    break
                except:
                    pass

        # Web Request
        web_match = re.search(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ([^"]+)"', line, re.I)
        if web_match:
            entry['method'] = web_match.group(1).upper()
            entry['request_path'] = web_match.group(2)
            entry['event_type'] = 'web_request'
            status_match = re.search(r'" (\d{3}) ', line)
            if status_match:
                code = int(status_match.group(1))
                entry['status'] = 'success' if 200 <= code < 300 else 'failed'

        # Login Events
        lower_line = line.lower()
        if 'failed password' in lower_line or 'authentication failure' in lower_line:
            entry['event_type'] = 'login'
            entry['status'] = 'failed'
        elif 'accepted password' in lower_line or 'session opened' in lower_line:
            entry['event_type'] = 'login'
            entry['status'] = 'success'

        return entry

    def process_log_line(line, source='upload'):
        parsed = parse_log_line(line)
        if not parsed.get('src_ip'):
            parsed['src_ip'] = 'unknown'

        log = Log(
            timestamp=parsed['timestamp'] or datetime.utcnow(),
            src_ip=parsed['src_ip'],
            username=parsed.get('username'),
            event_type=parsed['event_type'],
            status=parsed['status'],
            details=parsed['details'],
            request_path=parsed['request_path'],
            method=parsed['method'],
            user_agent=parsed.get('user_agent')
        )
        
        db.session.add(log)
        db.session.commit()

        # Update Device
        if parsed['src_ip'] != 'unknown':
            dev = Device.query.filter_by(ip=parsed['src_ip']).first()
            if dev:
                dev.last_seen = datetime.utcnow()
            else:
                dev = Device(ip=parsed['src_ip'], hostname=parsed['src_ip'])
                db.session.add(dev)
            db.session.commit()

        # Apply Detection Rules
        alerts = apply_detection_rules(log)
        for alert in alerts:
            db.session.add(alert)
        db.session.commit()

        return log

    # ====================== ROUTES ======================
    @app.route('/')
    @login_required
    def dashboard():
        total_logs = Log.query.count()
        total_alerts = Alert.query.count()
        success_logs = Log.query.filter_by(status='success').count()
        failed_logs = Log.query.filter_by(status='failed').count()
        devices_count = Device.query.count()

        recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
        
        from sqlalchemy import func
        top_attackers = db.session.query(
            Alert.src_ip, func.count(Alert.id)
        ).filter(Alert.src_ip.isnot(None))\
         .group_by(Alert.src_ip)\
         .order_by(func.count(Alert.id).desc()).limit(5).all()

        return render_template('index.html',
                               total_logs=total_logs,
                               total_alerts=total_alerts,
                               success_logs=success_logs,
                               failed_logs=failed_logs,
                               devices_count=devices_count,
                               recent_alerts=recent_alerts,
                               top_attackers=top_attackers)

    @app.route('/upload_logs', methods=['GET', 'POST'])
    @login_required
    def upload_logs():
        stats = None
        if request.method == 'POST':
            file = request.files.get('file')
            if file and file.filename:
                filepath = save_uploaded_file(file)
                if filepath:
                    success_count = failed_count = total_lines = 0
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if line.strip():
                                total_lines += 1
                                log = process_log_line(line)
                                if log.status == 'success':
                                    success_count += 1
                                elif log.status == 'failed':
                                    failed_count += 1
                    stats = {
                        'total_lines': total_lines,
                        'success': success_count,
                        'failed': failed_count,
                        'alerts': Alert.query.count(),
                        'filename': file.filename
                    }
                    flash('تم رفع وتحليل الملف بنجاح ✅', 'success')
                else:
                    flash('نوع الملف غير مدعوم', 'danger')
        return render_template('upload.html', stats=stats)

    @app.route('/submit_log', methods=['GET', 'POST'])
    @login_required
    def submit_log():
        form = SubmitLogForm()
        if form.validate_on_submit():
            log = Log(
                src_ip=form.src_ip.data,
                username=form.username.data,
                event_type=form.event_type.data,
                status=form.status.data,
                details=form.details.data,
                request_path=form.request_path.data,
                method=form.method.data,
                timestamp=datetime.utcnow()
            )
            db.session.add(log)
            db.session.commit()

            # تطبيق قواعد الكشف
            alerts = apply_detection_rules(log)
            for a in alerts:
                db.session.add(a)
            db.session.commit()

            flash('تم إضافة السجل بنجاح ✅', 'success')
            return redirect(url_for('dashboard'))
        
        return render_template('submit_log.html', form=form)

    @app.route('/logs')
    @login_required
    def view_logs():
        page = request.args.get('page', 1, type=int)
        
        # قراءة الفلاتر
        src_ip = request.args.get('src_ip', '').strip()
        status = request.args.get('status', '').strip()
        from_date = request.args.get('from_date')
        to_date = request.args.get('to_date')
        
        # بناء الاستعلام
        query = Log.query.order_by(Log.timestamp.desc())
        
        if src_ip:
            query = query.filter(Log.src_ip.like(f'%{src_ip}%'))
        
        if status:
            query = query.filter(Log.status == status)
        
        # فلتر التاريخ
        if from_date:
            try:
                from_dt = datetime.strptime(from_date, '%Y-%m-%d')
                query = query.filter(Log.timestamp >= from_dt)
            except:
                pass
        
        if to_date:
            try:
                to_dt = datetime.strptime(to_date, '%Y-%m-%d')
                to_dt = to_dt.replace(hour=23, minute=59, second=59)  # نهاية اليوم
                query = query.filter(Log.timestamp <= to_dt)
            except:
                pass
        
        logs = query.paginate(page=page, per_page=20, error_out=False)
        
        return render_template('logs.html', 
                            logs=logs,
                            src_ip=src_ip,
                            selected_status=status,
                            from_date=from_date,
                            to_date=to_date)

    @app.route('/alerts')
    @login_required
    def view_alerts():
        page = request.args.get('page', 1, type=int)
        alerts = Alert.query.order_by(Alert.timestamp.desc()).paginate(page=page, per_page=15, error_out=False)
        return render_template('alerts.html', alerts=alerts)

    @app.route('/device/<ip>')
    @login_required
    def device_details(ip):
        logs = Log.query.filter_by(src_ip=ip).order_by(Log.timestamp.desc()).limit(200).all()
        alerts = Alert.query.filter_by(src_ip=ip).order_by(Alert.timestamp.desc()).all()
        device = Device.query.filter_by(ip=ip).first()
        return render_template('device_details.html', ip=ip, device=device, logs=logs, alerts=alerts)

    @app.route('/devices')
    @login_required
    def devices():
        all_devices = Device.query.order_by(Device.last_seen.desc()).all()
        dev_list = []
        for dev in all_devices:
            success_cnt = Log.query.filter_by(src_ip=dev.ip, status='success').count()
            failed_cnt = Log.query.filter_by(src_ip=dev.ip, status='failed').count()
            last_log = Log.query.filter_by(src_ip=dev.ip).order_by(Log.timestamp.desc()).first()
            
            dev_list.append({
                'ip': dev.ip,
                'hostname': dev.hostname,
                'first_seen': dev.first_seen,
                'last_seen': dev.last_seen,
                'success_count': success_cnt,
                'failed_count': failed_cnt,
                'last_activity': last_log.timestamp if last_log else None
            })
        return render_template('devices.html', devices=dev_list)

    return app

    


# Run the application
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
