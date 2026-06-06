"""
NicoShield — config.py
Configuración central de la aplicación.
Desarrollado por Nicolás Rodríguez.
"""

import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # ── Seguridad ────────────────────────────────────────────────
    SECRET_KEY = os.environ.get("SECRET_KEY", "nicoshield-dev-secret-key-2024")
    WTF_CSRF_ENABLED = True

    # ── Base de datos ────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "instance", "nicoshield.db"),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Sesiones ─────────────────────────────────────────────────
    PERMANENT_SESSION_LIFETIME = timedelta(hours=4)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # ── Subida de archivos ───────────────────────────────────────
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "instance", "uploads")

    # ── Escáner de puertos ───────────────────────────────────────
    PORT_SCAN_TIMEOUT = 1.0      # segundos por puerto
    PORT_SCAN_MAX_PORTS = 1000   # límite de seguridad

    # ── App info ─────────────────────────────────────────────────
    APP_NAME = "NicoShield"
    APP_VERSION = "1.0.0"
    APP_AUTHOR = "Nicolás Rodríguez"


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}