"""Entrypoint usado pelos containers `analisa_worker` e `analisa_scheduler`.

Uso:
    celery -A make_celery.celery_app worker --loglevel=info
    celery -A make_celery.celery_app beat --loglevel=info
"""
from app import create_app

flask_app = create_app()
celery_app = flask_app.extensions["celery"]

from app.tasks import search_tasks  # noqa: E402  registra as tasks no Celery
from app.tasks import page_tasks  # noqa: E402  registra as tasks no Celery
from app.tasks import sitemap_tasks  # noqa: E402  registra as tasks no Celery
from app.tasks import maintenance_tasks  # noqa: E402  registra as tasks no Celery
