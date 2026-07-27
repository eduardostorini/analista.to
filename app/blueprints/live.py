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
_SSE_MAX_DURATION_SECONDS = 25
_SSE_POLL_INTERVAL_SECONDS = 1


def _load_search(public_id: str) -> Search:
    search = db.session.query(Search).filter_by(public_id=public_id).one_or_none()
    if search is None:
        raise NotFound("Consulta não encontrada.")
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


@live_bp.get("/captcha/math")
def math_captcha():
    if current_app.config["CAPTCHA_PROVIDER"] != "math":
        return jsonify(error="CAPTCHA matemático não está ativo neste ambiente."), 404
    challenge = MathCaptchaProvider().generate()
    return jsonify(challenge)
