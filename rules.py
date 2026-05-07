# rules.py
from collections import defaultdict
from datetime import datetime, timedelta
from models import db, Alert
from threat_intel import BLACKLIST_IPS

# Global in-memory storage for tracking failed attempts (per IP)
# Note: This resets when server restarts. Later we can move it to database.
failed_attempts = defaultdict(list)


def apply_detection_rules(log_obj):
    """
    تطبق قواعد الكشف على سجل واحد وتعيد قائمة بالتنبيهات الجديدة.
    """
    alerts = []

    # ====================== RULE 1: Brute Force Detection ======================
    if log_obj.event_type == 'login' and log_obj.status == 'failed':
        ip = log_obj.src_ip
        now = datetime.utcnow()

        # Add current attempt
        failed_attempts[ip].append(now)

        # Remove attempts older than 60 seconds
        failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < timedelta(seconds=60)]

        # If 5 or more failed attempts in last 60 seconds
        if len(failed_attempts[ip]) >= 5:
            alert = Alert(
                severity='High',
                rule_name='Brute Force Detection',
                description=f'أكثر من 5 محاولات تسجيل دخول فاشلة من {ip} خلال 60 ثانية',
                src_ip=ip,
                log_ids=str(log_obj.id)
            )
            alerts.append(alert)

    # ====================== RULE 2: Blacklisted IP ======================
    if log_obj.src_ip and log_obj.src_ip in BLACKLIST_IPS:
        alert = Alert(
            severity='Critical',
            rule_name='Blacklisted IP',
            description=f'نشاط من عنوان IP مدرج في القائمة السوداء: {log_obj.src_ip}',
            src_ip=log_obj.src_ip,
            log_ids=str(log_obj.id)
        )
        alerts.append(alert)

    # ====================== RULE 3: New - Multiple Failed Attempts (Long Term) ======================
    if log_obj.event_type == 'login' and log_obj.status == 'failed':
        ip = log_obj.src_ip
        # Count total failed attempts from this IP (in last 24 hours)
        # This is a simple version - can be improved with database query later
        if len(failed_attempts[ip]) >= 10:  # 10+ failed attempts overall in memory
            alert = Alert(
                severity='Medium',
                rule_name='Suspicious Login Activity',
                description=f'عدد كبير من المحاولات الفاشلة من {ip} (أكثر من 10 محاولات)',
                src_ip=ip,
                log_ids=str(log_obj.id)
            )
            alerts.append(alert)

    # ====================== RULE 4: New - Successful Login After Many Failures ======================
    if log_obj.event_type == 'login' and log_obj.status == 'success':
        ip = log_obj.src_ip
        recent_failed = len([t for t in failed_attempts[ip] if datetime.utcnow() - t < timedelta(minutes=10)])
        
        if recent_failed >= 3:
            alert = Alert(
                severity='High',
                rule_name='Possible Brute Force Success',
                description=f'تسجيل دخول ناجح بعد {recent_failed} محاولات فاشلة من {ip}',
                src_ip=ip,
                log_ids=str(log_obj.id)
            )
            alerts.append(alert)

    # ====================== RULE 5: New - Web Scanning / Probing ======================
    if log_obj.event_type == 'web_request' and log_obj.status == 'failed':
        if log_obj.request_path and any(path in log_obj.request_path for path in ['/admin', '/wp-login', '/.env', '/config']):
            alert = Alert(
                severity='Medium',
                rule_name='Web Probing / Scanning',
                description=f'محاولة استكشاف غير مصرح بها للمسارات الحساسة: {log_obj.request_path} من {log_obj.src_ip}',
                src_ip=log_obj.src_ip,
                log_ids=str(log_obj.id)
            )
            alerts.append(alert)

    return alerts