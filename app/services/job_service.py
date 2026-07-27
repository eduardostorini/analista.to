"""Emite e distribui atualizações de status de uma consulta (seção 11).

Cada mudança de status grava uma linha em `job_events` (histórico
persistente) e publica no Redis (`job:<public_id>`) para os endpoints de
SSE/polling em tempo real, além de manter um snapshot com TTL para quem
conectar depois do evento já ter passado.
"""
from __future__ import annotations

import datetime as dt
import json
import logging

from app import extensions
from app.extensions import db
from app.models import JobEvent, Search
from app.models.enums import TERMINAL_SEARCH_STATUSES, SearchStatus

logger = logging.getLogger(__name__)

_SNAPSHOT_TTL_SECONDS = 3600


class JobService:
    @staticmethod
    def emit(search: Search, status: SearchStatus, progress: int, message: str = "") -> JobEvent:
        event = JobEvent(search_id=search.id, status=status, progress=progress, message=message)
        db.session.add(event)

        search.status = status
        now = dt.datetime.now(dt.timezone.utc)
        if status != SearchStatus.QUEUED and search.started_at is None:
            search.started_at = now
        if status in TERMINAL_SEARCH_STATUSES:
            search.completed_at = now

        db.session.commit()
        JobService._publish(search.public_id, status, progress, message)
        return event

    @staticmethod
    def _publish(public_id: str, status: SearchStatus, progress: int, message: str) -> None:
        payload = json.dumps({"status": status.value, "progress": progress, "message": message})
        if extensions.redis_pubsub is None:
            return
        try:
            extensions.redis_pubsub.publish(f"job:{public_id}", payload)
            extensions.redis_pubsub.set(f"job:{public_id}:snapshot", payload, ex=_SNAPSHOT_TTL_SECONDS)
        except Exception:  # pragma: no cover - Redis indisponível não pode derrubar a task
            logger.warning("Falha ao publicar atualização de job no Redis", exc_info=True)

    @staticmethod
    def get_snapshot(public_id: str) -> dict | None:
        if extensions.redis_pubsub is not None:
            try:
                raw = extensions.redis_pubsub.get(f"job:{public_id}:snapshot")
                if raw:
                    return json.loads(raw)
            except Exception:  # pragma: no cover
                logger.warning("Falha ao ler snapshot de job no Redis", exc_info=True)
        return None

    @staticmethod
    def get_status_dict(search: Search) -> dict:
        snapshot = JobService.get_snapshot(search.public_id)
        if snapshot:
            return snapshot

        last_event = (
            db.session.query(JobEvent)
            .filter_by(search_id=search.id)
            .order_by(JobEvent.created_at.desc())
            .first()
        )
        return {
            "status": search.status.value,
            "progress": last_event.progress if last_event else 0,
            "message": last_event.message if last_event else "",
        }
