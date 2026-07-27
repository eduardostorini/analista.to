"""Orquestra o ciclo de vida de uma consulta: validação, deduplicação,
criação do registro e enfileiramento da task Celery (seção 3 e 14).
"""
from __future__ import annotations

import datetime as dt
import logging
import secrets

from flask import current_app

from app import extensions
from app.extensions import db
from app.models import Search, Tool
from app.models.enums import SearchStatus, SearchVisibility
from app.security.hashing import compute_dedupe_key, compute_input_hash, hash_ip, hash_user_agent
from app.services.job_service import JobService
from app.tasks.task_names import RUN_SEARCH_TASK
from app.tools.base import BaseTool

logger = logging.getLogger(__name__)


class SearchService:
    @staticmethod
    def submit(
        *,
        tool: BaseTool,
        tool_row: Tool,
        raw_input: str,
        ip_address: str,
        user_agent: str,
    ) -> tuple[Search, bool]:
        """Valida, deduplica e cria (ou reaproveita) uma consulta.

        Retorna `(search, reused)`. Quando `reused=True`, `search` já está
        `completed` e nenhuma nova task foi enfileirada.
        """
        cleaned = tool.validate_input(raw_input)
        normalized = tool.normalize_input(cleaned)
        dedupe_key = compute_dedupe_key(tool.slug, normalized, tool.analyzer_version)
        input_hash = compute_input_hash(normalized)

        existing = SearchService._find_reusable(tool_row.id, dedupe_key, tool_row.result_ttl_seconds)
        if existing is not None:
            SearchService._record_reuse_metrics(existing)
            return existing, True

        search = Search(
            public_id=secrets.token_urlsafe(12),
            tool_id=tool_row.id,
            original_input=raw_input,
            normalized_input=normalized,
            input_hash=input_hash,
            dedupe_key=dedupe_key,
            input_type=tool.input_type,
            status=SearchStatus.QUEUED,
            visibility=SearchVisibility.PUBLIC,
            ip_hash=hash_ip(ip_address),
            user_agent_hash=hash_user_agent(user_agent) if user_agent else None,
        )
        db.session.add(search)
        db.session.commit()

        JobService.emit(search, SearchStatus.QUEUED, 0, "Consulta adicionada à fila")
        SearchService._enqueue(search)
        return search, False

    @staticmethod
    def _find_reusable(tool_id: int, dedupe_key: str, ttl_seconds: int) -> Search | None:
        if ttl_seconds <= 0:
            return None
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=ttl_seconds)
        return (
            db.session.query(Search)
            .filter(
                Search.tool_id == tool_id,
                Search.dedupe_key == dedupe_key,
                Search.status == SearchStatus.COMPLETED,
                Search.created_at >= cutoff,
            )
            .order_by(Search.created_at.desc())
            .first()
        )

    @staticmethod
    def _record_reuse_metrics(existing: Search) -> None:
        if existing.generated_page is not None:
            existing.generated_page.last_accessed_at = dt.datetime.now(dt.timezone.utc)
            db.session.commit()

        if extensions.redis_cache is None:
            return
        try:
            today = dt.date.today().isoformat()
            extensions.redis_cache.incr(f"metrics:tool:{existing.tool_id}:reuse:{today}")
        except Exception:  # pragma: no cover
            logger.warning("Falha ao registrar métrica de reaproveitamento", exc_info=True)

    @staticmethod
    def _enqueue(search: Search) -> None:
        celery_app = current_app.extensions["celery"]
        celery_app.send_task(RUN_SEARCH_TASK, args=[search.id])
