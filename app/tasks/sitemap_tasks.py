"""Task Celery periódica de regeneração dos sitemaps (seção 17)."""
from __future__ import annotations

import logging

from app.services.sitemap_service import SitemapService
from app.tasks.task_names import REGENERATE_SITEMAPS_TASK
from make_celery import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name=REGENERATE_SITEMAPS_TASK, soft_time_limit=120, time_limit=180)
def regenerate_sitemaps() -> None:
    files = SitemapService.regenerate_all()
    logger.info("regenerate_sitemaps: %d arquivo(s) escritos", len(files))
