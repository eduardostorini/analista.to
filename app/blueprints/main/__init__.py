"""Blueprint principal: home, categorias e páginas de ferramenta."""
from flask import Blueprint

main_bp = Blueprint("main", __name__)

from app.blueprints.main import context  # noqa: E402,F401
from app.blueprints.main import routes  # noqa: E402,F401
