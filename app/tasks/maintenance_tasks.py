"""Tarefas periódicas de manutenção (seção 17): expira páginas antigas,
remove arquivos órfãos no disco e atualiza os sitemaps em seguida.
"""
from __future__ import annotations

import datetime as dt
import logging
import shutil
from pathlib import Path

from flask import current_app

from app.extensions import db
from app.models import GeneratedPage
from app.models.enums import IndexStatus
from app.tasks.task_names import CLEANUP_EXPIRED_TASK, REGENERATE_SITEMAPS_TASK
from make_celery import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name=CLEANUP_EXPIRED_TASK, soft_time_limit=120, time_limit=180)
def cleanup_expired_searches() -> None:
    _expire_old_generated_pages()
    _remove_orphaned_page_directories()
    celery_app.send_task(REGENERATE_SITEMAPS_TASK)


def _expire_old_generated_pages() -> None:
    max_age_days = current_app.config["GENERATED_PAGE_MAX_AGE_DAYS"]
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=max_age_days)

    stale_pages = (
        db.session.query(GeneratedPage)
        .filter(
            GeneratedPage.generated_at < cutoff,
            GeneratedPage.index_status != IndexStatus.REMOVED,
        )
        .all()
    )

    for page in stale_pages:
        page.index_status = IndexStatus.REMOVED
        file_path = Path(page.file_path)
        if file_path.is_file():
            file_path.unlink(missing_ok=True)

    if stale_pages:
        db.session.commit()
        logger.info("cleanup_expired_searches: %d página(s) expirada(s)", len(stale_pages))


def _remove_orphaned_page_directories() -> None:
    """Remove diretórios em `GENERATED_PAGES_DIR/<tool>/<slug>/` que não
    correspondem a nenhum `GeneratedPage.file_path` conhecido no banco."""
    root = Path(current_app.config["GENERATED_PAGES_DIR"])
    if not root.is_dir():
        return

    known_paths = {Path(p) for (p,) in db.session.query(GeneratedPage.file_path).all()}
    removed = 0

    for tool_dir in root.iterdir():
        if not tool_dir.is_dir():
            continue
        for slug_dir in tool_dir.iterdir():
            if not slug_dir.is_dir():
                continue
            index_file = slug_dir / "index.html"
            if index_file not in known_paths:
                shutil.rmtree(slug_dir, ignore_errors=True)
                removed += 1

    if removed:
        logger.info("cleanup_expired_searches: %d diretório(s) órfão(s) removido(s)", removed)
