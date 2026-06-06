"""
NicoShield — app.py
Aplicación principal Flask.
Plataforma de ciberseguridad defensiva/educativa.
Desarrollado por Nicolás Rodríguez.
"""

import os
import json
from datetime import datetime, timedelta

from flask import (Flask, render_template, redirect, url_for, flash,
                   request, jsonify, abort)
from flask_login import LoginManager, login_required, current_user

from config import config_map
from models import db, User, AnalysisLog, SecurityEvent
from auth import auth_bp
from tools import analyze_password, analyze_url, scan_ports, analyze_file


# ═══════════════════════════════════════════════════════════════
#  FACTORY
# ═══════════════════════════════════════════════════════════════
def create_app(env: str = "default") -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_map[env])

    # ── Crear carpetas necesarias ────────────────────────────────
    os.makedirs(app.config.get("UPLOAD_FOLDER",
                "instance/uploads"), exist_ok=True)
    os.makedirs("instance", exist_ok=True)

    # ── Extensiones ──────────────────────────────────────────────
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Inicia sesión para acceder a NicoShield."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── Blueprints ───────────────────────────────────────────────
    app.register_blueprint(auth_bp)

    # ── Crear tablas y admin por defecto ─────────────────────────
    with app.app_context():
        db.create_all()
        _seed_admin(app)

    # ── Contexto global para templates ───────────────────────────
    @app.context_processor
    def inject_globals():
        return {
            "app_name": app.config["APP_NAME"],
            "app_version": app.config["APP_VERSION"],
            "now": datetime.utcnow(),
        }

    # ── Registrar rutas ──────────────────────────────────────────
    register_routes(app)

    return app


def _seed_admin(app: Flask):
    """Crea usuario admin por defecto si no existe ninguno."""
    if User.query.count() == 0:
        admin = User(
            username="admin",
            email="admin@nicoshield.local",
            is_admin=True,
        )
        admin.set_password("NicoShield2024!")
        db.session.add(admin)
        db.session.commit()
        print("✅  Admin creado — usuario: admin | contraseña: NicoShield2024!")


# ═══════════════════════════════════════════════════════════════
#  RUTAS PRINCIPALES
# ═══════════════════════════════════════════════════════════════
def register_routes(app: Flask):

    # ── Inicio ────────────────────────────────────────────────────
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("auth.login"))

    # ── Dashboard ─────────────────────────────────────────────────
    @app.route("/dashboard")
    @login_required
    def dashboard():
        # Estadísticas generales
        total = AnalysisLog.query.filter_by(user_id=current_user.id).count()
        by_tool = db.session.query(
            AnalysisLog.tool, db.func.count(AnalysisLog.id)
        ).filter_by(user_id=current_user.id).group_by(AnalysisLog.tool).all()

        by_risk = db.session.query(
            AnalysisLog.risk_level, db.func.count(AnalysisLog.id)
        ).filter_by(user_id=current_user.id).group_by(AnalysisLog.risk_level).all()

        recent = (AnalysisLog.query
                  .filter_by(user_id=current_user.id)
                  .order_by(AnalysisLog.created_at.desc())
                  .limit(8).all())

        # Actividad últimos 7 días
        week_data = []
        for i in range(6, -1, -1):
            day = datetime.utcnow().date() - timedelta(days=i)
            count = AnalysisLog.query.filter(
                AnalysisLog.user_id == current_user.id,
                db.func.date(AnalysisLog.created_at) == day
            ).count()
            week_data.append({"day": day.strftime("%d/%m"), "count": count})

        stats = {
            "total": total,
            "by_tool": dict(by_tool),
            "by_risk": dict(by_risk),
            "week_data": week_data,
        }
        return render_template("dashboard.html", stats=stats, recent=recent)

    # ── TOOL: Contraseñas ─────────────────────────────────────────
    @app.route("/tools/password", methods=["GET", "POST"])
    @login_required
    def tool_password():
        result = None
        if request.method == "POST":
            password = request.form.get("password", "")
            if not password:
                flash("Ingresa una contraseña para analizar.", "warning")
            else:
                result = analyze_password(password)
                _save_log(
                    tool="password",
                    input_data="*" * len(password),  # no guardamos la contraseña real
                    result=f"{result['level']} ({result['score']}/100)",
                    risk_level=_score_to_risk(result["score"], invert=True),
                    details=json.dumps(result),
                )
        return render_template("tools/password.html", result=result)

    # ── TOOL: URLs / Phishing ─────────────────────────────────────
    @app.route("/tools/url", methods=["GET", "POST"])
    @login_required
    def tool_url():
        result = None
        if request.method == "POST":
            url = request.form.get("url", "").strip()
            if not url:
                flash("Ingresa una URL para analizar.", "warning")
            else:
                result = analyze_url(url)
                if "error" not in result:
                    _save_log(
                        tool="url",
                        input_data=url[:200],
                        result=f"{result['risk']} (score {result['score']})",
                        risk_level=result["risk_level"],
                        details=json.dumps(result),
                    )
        return render_template("tools/url.html", result=result)

    # ── TOOL: Escáner de puertos ──────────────────────────────────
    @app.route("/tools/ports", methods=["GET", "POST"])
    @login_required
    def tool_ports():
        result = None
        if request.method == "POST":
            target     = request.form.get("target", "").strip()
            port_range = request.form.get("port_range", "common")
            if not target:
                flash("Ingresa un host o IP para escanear.", "warning")
            else:
                result = scan_ports(target, port_range)
                if "error" not in result:
                    _save_log(
                        tool="port",
                        input_data=f"{target} ({port_range})",
                        result=f"{result['open_count']} puertos abiertos",
                        risk_level=result["overall_risk"],
                        details=json.dumps(result),
                    )
        return render_template("tools/ports.html", result=result)

    # ── TOOL: Análisis de archivos ────────────────────────────────
    @app.route("/tools/file", methods=["GET", "POST"])
    @login_required
    def tool_file():
        result = None
        if request.method == "POST":
            if "file" not in request.files:
                flash("No se recibió ningún archivo.", "warning")
            else:
                f = request.files["file"]
                if f.filename == "":
                    flash("Selecciona un archivo.", "warning")
                else:
                    file_data = f.read()
                    result = analyze_file(file_data, f.filename)
                    _save_log(
                        tool="file",
                        input_data=f.filename[:200],
                        result=f"MD5: {result['md5'][:16]}... | Riesgo: {result['risk_level']}",
                        risk_level=result["risk_level"],
                        details=json.dumps({k: v for k, v in result.items()
                                            if k != "indicators"} |
                                           {"indicators": result["indicators"]}),
                    )
        return render_template("tools/file.html", result=result)

    # ── Historial ─────────────────────────────────────────────────
    @app.route("/history")
    @login_required
    def history():
        page = request.args.get("page", 1, type=int)
        tool_filter = request.args.get("tool", "all")
        risk_filter = request.args.get("risk", "all")

        query = AnalysisLog.query.filter_by(user_id=current_user.id)
        if tool_filter != "all":
            query = query.filter_by(tool=tool_filter)
        if risk_filter != "all":
            query = query.filter_by(risk_level=risk_filter)

        logs = query.order_by(AnalysisLog.created_at.desc()).paginate(
            page=page, per_page=15, error_out=False
        )
        return render_template("history.html", logs=logs,
                               tool_filter=tool_filter, risk_filter=risk_filter)

    # ── Detalle de análisis ────────────────────────────────────────
    @app.route("/history/<int:log_id>")
    @login_required
    def history_detail(log_id):
        log = AnalysisLog.query.get_or_404(log_id)
        if log.user_id != current_user.id and not current_user.is_admin:
            abort(403)
        details = {}
        if log.details:
            try:
                details = json.loads(log.details)
            except Exception:
                pass
        return render_template("history_detail.html", log=log, details=details)

    # ── Admin panel ───────────────────────────────────────────────
    @app.route("/admin")
    @login_required
    def admin_panel():
        if not current_user.is_admin:
            abort(403)

        users   = User.query.order_by(User.created_at.desc()).all()
        events  = (SecurityEvent.query
                   .order_by(SecurityEvent.created_at.desc())
                   .limit(50).all())
        all_logs = AnalysisLog.query.order_by(AnalysisLog.created_at.desc()).limit(20).all()

        stats = {
            "total_users": User.query.count(),
            "total_analyses": AnalysisLog.query.count(),
            "total_events": SecurityEvent.query.count(),
            "analyses_today": AnalysisLog.query.filter(
                db.func.date(AnalysisLog.created_at) == datetime.utcnow().date()
            ).count(),
        }
        return render_template("admin.html", users=users, events=events,
                               all_logs=all_logs, stats=stats)

    # ── Admin: toggle usuario ──────────────────────────────────────
    @app.route("/admin/toggle_user/<int:user_id>", methods=["POST"])
    @login_required
    def toggle_user(user_id):
        if not current_user.is_admin:
            abort(403)
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            flash("No puedes desactivar tu propia cuenta.", "warning")
        else:
            user.is_active = not user.is_active
            db.session.commit()
            state = "activado" if user.is_active else "desactivado"
            flash(f"Usuario {user.username} {state}.", "success")
        return redirect(url_for("admin_panel"))

    # ── API: Análisis en tiempo real (AJAX) ───────────────────────
    @app.route("/api/analyze/password", methods=["POST"])
    @login_required
    def api_password():
        data = request.get_json(silent=True) or {}
        pwd  = data.get("password", "")
        if not pwd:
            return jsonify({"error": "Contraseña vacía"}), 400
        return jsonify(analyze_password(pwd))

    # ── Error handlers ─────────────────────────────────────────────
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("errors/500.html"), 500


# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════
def _save_log(tool, input_data, result, risk_level, details=None):
    ip = request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr)
    log = AnalysisLog(
        user_id=current_user.id,
        tool=tool,
        input_data=input_data,
        result=result,
        risk_level=risk_level,
        details=details,
        ip_address=ip,
    )
    db.session.add(log)
    db.session.commit()


def _score_to_risk(score: int, invert: bool = False) -> str:
    """Convierte score numérico a nivel de riesgo."""
    if invert:
        # Para contraseñas: score alto = menos riesgo
        if score >= 80: return "none"
        if score >= 60: return "low"
        if score >= 40: return "medium"
        if score >= 20: return "high"
        return "critical"
    else:
        if score <= 20: return "none"
        if score <= 40: return "low"
        if score <= 60: return "medium"
        if score <= 80: return "high"
        return "critical"


# ═══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════
app = create_app(os.environ.get("FLASK_ENV", "default"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"""
╔══════════════════════════════════════════════╗
║          NicoShield v1.0.0                   ║
║  Plataforma de Ciberseguridad Defensiva      ║
║  Desarrollado por Nicolás Rodríguez          ║
╠══════════════════════════════════════════════╣
║  URL:  http://127.0.0.1:{port}                  ║
║  User: admin                                 ║
║  Pass: NicoShield2024!                       ║
╚══════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=port, debug=True)