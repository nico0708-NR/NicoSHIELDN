"""
NicoShield — models.py
Modelos de base de datos (SQLAlchemy).
Desarrollado por Nicolás Rodríguez.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# ═══════════════════════════════════════════════════════════════
#  USUARIO
# ═══════════════════════════════════════════════════════════════
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(64), unique=True, nullable=False)
    email        = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin     = db.Column(db.Boolean, default=False)
    is_active    = db.Column(db.Boolean, default=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    last_login   = db.Column(db.DateTime, nullable=True)

    # Relaciones
    analyses = db.relationship("AnalysisLog", backref="user", lazy="dynamic")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


# ═══════════════════════════════════════════════════════════════
#  REGISTRO DE ANÁLISIS
# ═══════════════════════════════════════════════════════════════
class AnalysisLog(db.Model):
    __tablename__ = "analysis_logs"

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    tool         = db.Column(db.String(50), nullable=False)   # password, url, port, file
    input_data   = db.Column(db.Text, nullable=False)         # qué se analizó
    result       = db.Column(db.Text, nullable=False)         # resultado resumido
    risk_level   = db.Column(db.String(20), default="none")   # none, low, medium, high, critical
    details      = db.Column(db.Text, nullable=True)          # JSON con detalles completos
    ip_address   = db.Column(db.String(50), nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<AnalysisLog {self.tool} @ {self.created_at}>"


# ═══════════════════════════════════════════════════════════════
#  EVENTO DE SEGURIDAD (audit trail)
# ═══════════════════════════════════════════════════════════════
class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id          = db.Column(db.Integer, primary_key=True)
    event_type  = db.Column(db.String(50), nullable=False)   # login, logout, failed_login, etc.
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    description = db.Column(db.Text, nullable=False)
    ip_address  = db.Column(db.String(50), nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<SecurityEvent {self.event_type} @ {self.created_at}>"