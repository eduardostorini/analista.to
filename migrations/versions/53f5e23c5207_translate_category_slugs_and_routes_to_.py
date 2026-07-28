"""Translate category slugs and routes to English

Revision ID: 53f5e23c5207
Revises: 5ff5f88f1a67
Create Date: 2026-07-27 19:13:05.864633

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '53f5e23c5207'
down_revision = '5ff5f88f1a67'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "UPDATE tool_categories SET slug = 'domain-ip' WHERE slug = 'dominio-ip'"
        )
    )
    conn.execute(
        sa.text(
            "UPDATE tool_categories SET slug = 'http-server' WHERE slug = 'http-servidor'"
        )
    )
    conn.execute(
        sa.text(
            "UPDATE tool_categories SET slug = 'ssl-security' WHERE slug = 'ssl-seguranca'"
        )
    )


def downgrade():
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "UPDATE tool_categories SET slug = 'dominio-ip' WHERE slug = 'domain-ip'"
        )
    )
    conn.execute(
        sa.text(
            "UPDATE tool_categories SET slug = 'http-servidor' WHERE slug = 'http-server'"
        )
    )
    conn.execute(
        sa.text(
            "UPDATE tool_categories SET slug = 'ssl-seguranca' WHERE slug = 'ssl-security'"
        )
    )
