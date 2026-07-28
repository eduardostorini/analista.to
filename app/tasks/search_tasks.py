"""Task Celery que executa a lógica de uma ferramenta (seção 12).

Timeout, backoff exponencial e número máximo de tentativas são aplicados
apenas a falhas transitórias de rede (timeout, conexão recusada). Falhas
"definitivas" (bloqueio de SSRF, entrada inválida, resposta grande demais)
marcam a consulta como `failed` imediatamente, sem retry — e qualquer
exceção não prevista também é capturada, para que uma ferramenta com bug
nunca derrube o worker inteiro.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time

import dns.exception
import httpx
from celery.exceptions import MaxRetriesExceededError

from app.extensions import db
from app.models import AbuseEvent, Search, SearchResult
from app.models.enums import AbuseEventType, SearchStatus
from app.security.ssrf import ResponseTooLargeError, SSRFBlockedError
from app.services.job_service import JobService
from app.tasks.task_names import GENERATE_PAGE_TASK, RUN_SEARCH_TASK
from app.tools.exceptions import ToolExecutionError, ToolValidationError
from app.tools.registry import load_tools, registry
from make_celery import celery_app

logger = logging.getLogger(__name__)

_RETRYABLE_EXCEPTIONS = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.RemoteProtocolError,
    dns.exception.Timeout,
)
_NON_RETRYABLE_EXCEPTIONS = (
    SSRFBlockedError,
    ResponseTooLargeError,
    ToolExecutionError,
    ToolValidationError,
)

load_tools()


def _backoff_seconds(retry_count: int) -> int:
    return min(2**retry_count * 5, 60)


def _mark_failed(search: Search, *, error_code: str, error_message: str) -> None:
    existing = db.session.query(SearchResult).filter_by(search_id=search.id).one_or_none()
    if existing is None:
        existing = SearchResult(search_id=search.id)
        db.session.add(existing)
    existing.error_code = error_code
    existing.error_message = error_message
    db.session.commit()
    JobService.emit(search, SearchStatus.FAILED, 100, error_message)


def _save_result(search: Search, tool, result, duration_ms: int) -> None:
    result_hash = hashlib.sha256(
        json.dumps(result.data, sort_keys=True, default=str).encode()
    ).hexdigest()

    row = db.session.query(SearchResult).filter_by(search_id=search.id).one_or_none()
    if row is None:
        row = SearchResult(search_id=search.id)
        db.session.add(row)

    row.summary = tool.build_summary(result)
    row.normalized_result = result.data
    row.raw_result = result.raw
    row.result_hash = result_hash
    row.duration_ms = duration_ms
    row.error_code = result.error_code
    row.error_message = result.error_message
    db.session.commit()


@celery_app.task(
    bind=True,
    name=RUN_SEARCH_TASK,
    max_retries=3,
    acks_late=True,
    soft_time_limit=45,
    time_limit=60,
)
def run_search(self, search_id: int) -> None:
    load_tools()
    search = db.session.get(Search, search_id)
    if search is None:
        logger.warning("run_search: search_id=%s não encontrado", search_id)
        return

    tool = registry.get(search.tool.slug)
    if tool is None:
        _mark_failed(search, error_code="unknown_tool", error_message="Unrecognized tool.")
        return

    JobService.emit(search, SearchStatus.QUERYING, 25, "Querying services")
    started = time.monotonic()

    try:
        result = tool.execute(search.normalized_input)
    except _NON_RETRYABLE_EXCEPTIONS as exc:
        logger.info("run_search: falha definitiva em %s: %s", tool.slug, exc)
        if isinstance(exc, SSRFBlockedError):
            db.session.add(
                AbuseEvent(
                    ip_hash=search.ip_hash,
                    tool_id=search.tool_id,
                    event_type=AbuseEventType.SSRF_BLOCKED,
                    details={"reason": exc.reason, "input": search.normalized_input},
                )
            )
            db.session.commit()
        _mark_failed(search, error_code=type(exc).__name__, error_message=str(exc))
        return
    except _RETRYABLE_EXCEPTIONS as exc:
        try:
            raise self.retry(exc=exc, countdown=_backoff_seconds(self.request.retries))
        except MaxRetriesExceededError:
            _mark_failed(
                search,
                error_code="max_retries_exceeded",
                error_message="Could not complete the search after multiple attempts.",
            )
            return
    except Exception:  # pragma: no cover - rede de segurança final
        logger.exception("run_search: erro inesperado na ferramenta %s", tool.slug)
        _mark_failed(
            search, error_code="unexpected_error", error_message="Unexpected error while processing the search."
        )
        return

    duration_ms = int((time.monotonic() - started) * 1000)
    JobService.emit(search, SearchStatus.ANALYZING, 70, "Analyzing results")

    if not result.success:
        _mark_failed(
            search,
            error_code=result.error_code or "execution_failed",
            error_message=result.error_message or "The search did not return a valid result.",
        )
        return

    JobService.emit(search, SearchStatus.GENERATING_REPORT, 85, "Generating report")
    _save_result(search, tool, result, duration_ms)

    if tool.is_publicly_indexable:
        # A task de geração de página emite o status "completed" final,
        # depois de tentar publicar a página estática — mantém a linha do
        # tempo de eventos em ordem lógica (nunca "completed" seguido de
        # "generating_page").
        JobService.emit(search, SearchStatus.GENERATING_PAGE, 92, "Creating public page")
        self.app.send_task(GENERATE_PAGE_TASK, args=[search.id])
    else:
        JobService.emit(search, SearchStatus.COMPLETED, 100, "Completed")
