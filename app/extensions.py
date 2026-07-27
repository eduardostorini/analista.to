"""Instâncias de extensões, criadas fora da app factory para evitar import circular."""
from __future__ import annotations

import redis
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base declarativa SQLAlchemy 2.0 (estilo `Mapped`/`mapped_column`)."""


db = SQLAlchemy(model_class=Base)
migrate = Migrate()
csrf = CSRFProtect()
login_manager = LoginManager()

redis_cache: redis.Redis | None = None
redis_rate_limit: redis.Redis | None = None
redis_pubsub: redis.Redis | None = None


def init_redis_clients(app) -> None:
    global redis_cache, redis_rate_limit, redis_pubsub
    redis_cache = redis.Redis.from_url(app.config["CACHE_REDIS_URL"], decode_responses=True)
    redis_rate_limit = redis.Redis.from_url(app.config["RATE_LIMIT_REDIS_URL"], decode_responses=True)
    redis_pubsub = redis.Redis.from_url(app.config["REDIS_URL"], decode_responses=True)
