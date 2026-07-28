"""Verifica que as migrações Alembic aplicam/revertem sem erro contra um
banco totalmente vazio, criado e destruído só para este teste.
"""
from __future__ import annotations

import os
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config

_SCRATCH_DB = "analisa_to_migrations_scratch"
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _admin_dsn() -> str:
    test_url = os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql://analisa:Ww4NnlHBkAS1coYU9TSG4ePracEwZsPK@localhost:15439/analisa_to_test",
    )
    base = test_url.replace("postgresql+psycopg://", "postgresql://")
    return base.rsplit("/", 1)[0] + "/postgres"


@pytest.fixture
def scratch_database_url():
    admin_dsn = _admin_dsn()
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{_SCRATCH_DB}"')
        conn.execute(f'CREATE DATABASE "{_SCRATCH_DB}"')

    yield admin_dsn.rsplit("/", 1)[0] + f"/{_SCRATCH_DB}"

    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{_SCRATCH_DB}"')


def test_migrations_apply_and_revert_cleanly(scratch_database_url):
    alembic_cfg = Config(str(_PROJECT_ROOT / "migrations" / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(_PROJECT_ROOT / "migrations"))

    from app import create_app

    app = create_app(
        "testing",
        config_overrides={
            "SQLALCHEMY_DATABASE_URI": scratch_database_url.replace(
                "postgresql://", "postgresql+psycopg://"
            )
        },
    )

    with app.app_context():
        command.upgrade(alembic_cfg, "head")
        command.downgrade(alembic_cfg, "base")
        command.upgrade(alembic_cfg, "head")

        from app.extensions import db as _db

        _db.session.remove()
        _db.engine.dispose()

    with psycopg.connect(scratch_database_url, autocommit=True) as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
        ).fetchall()
    table_names = {r[0] for r in rows}
    expected = {
        "tool_categories",
        "tools",
        "searches",
        "search_results",
        "generated_pages",
        "job_events",
        "abuse_events",
        "alembic_version",
    }
    assert expected.issubset(table_names)
