"""Painel administrativo (seção 23). O prefixo de URL é injetado em
`register_blueprint` a partir de `ADMIN_URL_PREFIX`, não fica hardcoded aqui,
para não expor a rota em um caminho óbvio por padrão.
"""
from flask import Blueprint

admin_bp = Blueprint("admin", __name__)

from app.blueprints.admin import routes  # noqa: E402,F401
