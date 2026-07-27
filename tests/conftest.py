from __future__ import annotations

import os

os.environ.setdefault("FLASK_ENV", "testing")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault(
    "TEST_DATABASE_URL",
    "postgresql+psycopg://analisa:change-me-strong-password@localhost:15439/analisa_to_test",
)
os.environ.setdefault("IP_HASH_SALTS", "1:test-salt-one,2:test-salt-two")
os.environ.setdefault("IP_HASH_CURRENT_SALT_ID", "1")
os.environ.setdefault("REDIS_URL", "redis://:change-me-redis-password@localhost:16389/0")
os.environ.setdefault("CACHE_REDIS_URL", "redis://:change-me-redis-password@localhost:16389/5")
os.environ.setdefault("RATE_LIMIT_REDIS_URL", "redis://:change-me-redis-password@localhost:16389/6")
os.environ.setdefault("CELERY_BROKER_URL", "redis://:change-me-redis-password@localhost:16389/7")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://:change-me-redis-password@localhost:16389/8")
os.environ.setdefault("CAPTCHA_PROVIDER", "none")

import pytest

from app import create_app
from app import extensions as _extensions
from app.extensions import db as _db


@pytest.fixture(scope="session")
def app():
    application = create_app("testing")
    with application.app_context():
        _db.create_all()
    yield application
    with application.app_context():
        _db.drop_all()


@pytest.fixture(autouse=True)
def app_context(app):
    with app.app_context():
        yield


@pytest.fixture(autouse=True)
def _clean_redis(app_context):
    yield
    for client in (_extensions.redis_cache, _extensions.redis_rate_limit):
        if client is not None:
            client.flushdb()


@pytest.fixture(autouse=True)
def _clean_db(app_context):
    yield
    from app.models import AbuseEvent, GeneratedPage, JobEvent, Search, SearchResult, Tool, ToolCategory

    for model in (JobEvent, GeneratedPage, SearchResult, Search, AbuseEvent, Tool, ToolCategory):
        _db.session.query(model).delete()
    _db.session.commit()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app_context):
    return _db
