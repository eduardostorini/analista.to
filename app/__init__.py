"""App factory do Analista.to."""
from __future__ import annotations

from flask import Flask, render_template

from app.celery_app import celery_init_app
from app.config import get_config
from app.extensions import csrf, db, init_redis_clients, login_manager, migrate
from app.logging_config import configure_logging
from app.security.headers import apply_security_headers


def create_app(config_name: str | None = None, config_overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    config_cls = get_config(config_name)
    app.config.from_object(config_cls)
    if config_overrides:
        app.config.update(config_overrides)

    configure_logging(app.config["LOG_LEVEL"])

    db.init_app(app)
    with app.app_context():
        from app import models  # noqa: F401  (registra os modelos no metadata do SQLAlchemy)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "admin.login"
    from app.security import admin_auth  # noqa: F401  (registra o user_loader)

    if app.config["TRUST_PROXY_HEADERS"]:
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    init_redis_clients(app)
    celery_init_app(app)
    apply_security_headers(app)

    _register_blueprints(app)
    _register_cli(app)
    _register_error_handlers(app)
    _register_template_globals(app)

    return app


def _register_blueprints(app: Flask) -> None:
    from app.blueprints.admin import admin_bp
    from app.blueprints.health import health_bp
    from app.blueprints.live import live_bp
    from app.blueprints.main import main_bp
    from app.blueprints.public_pages import public_pages_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(live_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix=app.config["ADMIN_URL_PREFIX"])
    # Catch-all de páginas públicas de resultado — registrado por último para
    # não competir com os prefixos mais específicos acima.
    app.register_blueprint(public_pages_bp)


def _register_cli(app: Flask) -> None:
    from app.cli import register_cli_commands

    register_cli_commands(app)


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(_error):
        return render_template("errors/500.html"), 500

    @app.errorhandler(429)
    def rate_limited(_error):
        return render_template("errors/429.html"), 429


def _register_template_globals(app: Flask) -> None:
    @app.context_processor
    def inject_globals():
        return {
            "site_name": app.config["SITE_NAME"],
            "site_url": app.config["SITE_URL"],
        }
