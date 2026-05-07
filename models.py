# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    role = db.Column(db.String(20), default='analyst')  # admin, analyst

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    src_ip = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(100), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=True)
    details = db.Column(db.Text, nullable=True)
    request_path = db.Column(db.String(200), nullable=True)
    method = db.Column(db.String(10), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20), nullable=False)
    rule_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    src_ip = db.Column(db.String(45), nullable=True)
    log_ids = db.Column(db.String(200), nullable=True)
    is_resolved = db.Column(db.Boolean, default=False)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False)
    hostname = db.Column(db.String(100), nullable=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)