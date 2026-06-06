"""
NicoShield — auth.py
Blueprint de autenticación: login, logout, registro.
Desarrollado por Nicolás Rodríguez.
"""

from datetime import datetime
from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, session)
from flask_login import login_user, logout_user, login_required, current_user

from models import db, User, SecurityEvent

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _log_event(event_type: str, description: str, user_id=None):
    """Registra un evento de seguridad."""
    ip = request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr)
    event = SecurityEvent(
        event_type=event_type,
        user_id=user_id,
        description=description,
        ip_address=ip,
    )
    db.session.add(event)
    db.session.commit()


# ═══════════════════════════════════════════════════════════════
#  LOGIN
# ═══════════════════════════════════════════════════════════════
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(username=username).first()

        if user and user.is_active and user.check_password(password):
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()

            _log_event("login", f"Login exitoso: {username}", user_id=user.id)
            session.permanent = True

            next_page = request.args.get("next")
            flash(f"Bienvenido de nuevo, {user.username}! 👋", "success")
            return redirect(next_page or url_for("main.dashboard"))
        else:
            _log_event("failed_login", f"Intento fallido para: {username}")
            flash("Usuario o contraseña incorrectos.", "danger")

    return render_template("auth/login.html")


# ═══════════════════════════════════════════════════════════════
#  REGISTRO
# ═══════════════════════════════════════════════════════════════
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Validaciones
        errors = []
        if len(username) < 3:
            errors.append("El nombre de usuario debe tener al menos 3 caracteres.")
        if len(password) < 8:
            errors.append("La contraseña debe tener al menos 8 caracteres.")
        if password != confirm:
            errors.append("Las contraseñas no coinciden.")
        if User.query.filter_by(username=username).first():
            errors.append("Ese nombre de usuario ya está en uso.")
        if User.query.filter_by(email=email).first():
            errors.append("Ese email ya está registrado.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("auth/register.html",
                                   username=username, email=email)

        user = User(username=username, email=email)
        user.set_password(password)

        # Primer usuario → admin automáticamente
        if User.query.count() == 0:
            user.is_admin = True

        db.session.add(user)
        db.session.commit()

        _log_event("register", f"Nuevo usuario registrado: {username}", user_id=user.id)
        flash("Cuenta creada correctamente. Ya puedes iniciar sesión.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


# ═══════════════════════════════════════════════════════════════
#  LOGOUT
# ═══════════════════════════════════════════════════════════════
@auth_bp.route("/logout")
@login_required
def logout():
    _log_event("logout", f"Logout: {current_user.username}", user_id=current_user.id)
    logout_user()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("auth.login"))