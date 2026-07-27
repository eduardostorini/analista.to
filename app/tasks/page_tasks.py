"""Task Celery que gera a página estática pública de um resultado (seção 15)."""
from __future__ import annotations

import logging

from app.extensions import db
from app.models import Search
from app.models.enums import SearchStatus
from app.services.job_service import JobService
from app.services.page_generation import PageGenerationService
from app.tasks.task_names import GENERATE_PAGE_TASK
from make_celery import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name=GENERATE_PAGE_TASK,
    max_retries=2,
    acks_late=True,
    soft_time_limit=30,
    time_limit=45,
)
def generate_page(self, search_id: int) -> None:
    search = db.session.get(Search, search_id)
    if search is None:
        logger.warning("generate_page: search_id=%s não encontrado", search_id)
        return

    # Marca como concluída ANTES de gerar a página: `PageIndexabilityService`
    # só indexa buscas com status terminal, então a página seria gravada
    # como "pending" para sempre se a avaliação rodasse antes desta linha.
    JobService.emit(search, SearchStatus.COMPLETED, 100, "Concluído")

    try:
        PageGenerationService.generate(search)
    except Exception:
        logger.exception("generate_page: falha ao gerar página para search=%s", search_id)
        # A geração de página é best-effort: uma falha aqui não deve reverter
        # o status "completed" já emitido acima.
