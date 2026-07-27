"""Endpoint de health check, sem informações sensíveis, usado pelo Docker healthcheck."""
from __future__ import annotations

from flask import Blueprint, jsonify
from sqlalchemy import text

from app import extensions
from app.extensions import db

health_bp = Blueprint("health", __name__)


@health_bp.get("/healthz")
def healthz():
    checks = {"database": False, "redis": False}

    try:
        db.session.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        pass

    try:
        if extensions.redis_cache is not None:
            checks["redis"] = bool(extensions.redis_cache.ping())
    except Exception:
        pass

    healthy = all(checks.values())
    status_code = 200 if healthy else 503
    return jsonify(status="ok" if healthy else "degraded", checks=checks), status_code
