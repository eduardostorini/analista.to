"""Endpoints internos de suporte à interface: status de consulta em tempo
real (SSE, com fallback de polling) e o desafio do CAPTCHA matemático.

Não é uma API pública do produto — são chamadas que a própria página faz
para si mesma (barra de status, widget de CAPTCHA); por isso vivem fora de
qualquer namespace "api" e não são documentadas como uma API.
"""
from __future__ import annotations

import json
import time

from flask import Blueprint, Response, current_app, jsonify, request, stream_with_context
from werkzeug.exceptions import NotFound

from app import extensions
from app.extensions import db
from app.models import Search
from app.models.enums import TERMINAL_SEARCH_STATUSES
from app.security.captcha import MathCaptchaProvider
from app.services.job_service import JobService

live_bp = Blueprint("live", __name__)
_TERMINAL_VALUES = {status.value for status in TERMINAL_SEARCH_STATUSES}
# Precisa cobrir o pior caso realista de `run_search` (soft_time_limit=45s)
# mais a task subsequente de geração de página — ferramentas que fazem
# múltiplas tentativas de rede (Ping, HTTP 2/3 Checker, Brotli Checker,
# Subdomain Finder com fallback, screenshot do Website Hosting Checker)
# podem chegar perto desse limite. Um teto menor aqui fecha a conexão antes
# do evento "completed" ser publicado, deixando a barra de progresso
# parada até o fallback de polling assumir.
_SSE_MAX_DURATION_SECONDS = 60
_SSE_POLL_INTERVAL_SECONDS = 1


def _load_search(public_id: str) -> Search:
    search = db.session.query(Search).filter_by(public_id=public_id).one_or_none()
    if search is None:
        raise NotFound("Search not found.")
    return search


@live_bp.get("/jobs/<public_id>/status")
def job_status(public_id: str):
    search = _load_search(public_id)
    snapshot = JobService.get_status_dict(search)

    wants_stream = "text/event-stream" in request.headers.get("Accept", "")
    if not wants_stream:
        return jsonify(snapshot)

    return Response(
        stream_with_context(_sse_stream(public_id, snapshot)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def _format_sse(data: dict) -> str:
    return f"event: job_update\ndata: {json.dumps(data)}\n\n"


def _sse_stream(public_id: str, initial_snapshot: dict):
    yield _format_sse(initial_snapshot)

    if initial_snapshot.get("status") in _TERMINAL_VALUES or extensions.redis_pubsub is None:
        return

    pubsub = extensions.redis_pubsub.pubsub()
    pubsub.subscribe(f"job:{public_id}")
    started = time.monotonic()
    try:
        while time.monotonic() - started < _SSE_MAX_DURATION_SECONDS:
            message = pubsub.get_message(timeout=_SSE_POLL_INTERVAL_SECONDS, ignore_subscribe_messages=True)
            if message and message.get("type") == "message":
                payload = json.loads(message["data"])
                yield _format_sse(payload)
                if payload.get("status") in _TERMINAL_VALUES:
                    return
            else:
                yield ": keep-alive\n\n"
    finally:
        pubsub.close()


@live_bp.get("/api/altcha-challenge")
def altcha_challenge():
    from altcha import create_challenge

    cfg = current_app.config
    hmac_secret = cfg.get("ALTCHA_HMAC_SECRET")
    if not hmac_secret:
        return jsonify(error="ALTCHA is not configured."), 500

    hmac_key_secret = cfg.get("ALTCHA_HMAC_KEY_SECRET") or None
    challenge = create_challenge(
        algorithm="PBKDF2/SHA-256",
        cost=1000,
        hmac_secret=hmac_secret,
        hmac_key_secret=hmac_key_secret,
    )
    return jsonify(challenge.to_dict())


@live_bp.get("/captcha/math")
def math_captcha():
    if current_app.config["CAPTCHA_PROVIDER"] != "math":
        return jsonify(error="Math CAPTCHA is not active in this environment."), 404
    challenge = MathCaptchaProvider().generate()
    return jsonify(challenge)
