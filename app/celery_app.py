"""Integração Celery <-> Flask (padrão recomendado para Flask 3 + Celery 5).

A task Celery roda dentro do contexto da aplicação Flask, permitindo usar
`db.session`, `current_app.config`, etc. normalmente dentro de `app/tasks/`.
"""
from __future__ import annotations

from celery import Celery, Task


def celery_init_app(app) -> Celery:
    class FlaskTask(Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery_app = Celery(app.import_name, task_cls=FlaskTask)
    celery_app.config_from_object(app.config["CELERY"])
    celery_app.set_default()
    app.extensions["celery"] = celery_app
    return celery_app
