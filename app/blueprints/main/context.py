"""Contexto compartilhado pelas páginas de ferramenta e pela sidebar global."""
from __future__ import annotations

from flask import current_app, url_for

from app.blueprints.main import main_bp
from app.extensions import db
from app.models import Search, Tool, ToolCategory
from app.models.enums import SearchStatus, SearchVisibility


def build_tool_context(tool, tool_row: Tool) -> dict:
    related_tools = (
        db.session.query(Tool)
        .filter(Tool.category_id == tool_row.category_id, Tool.id != tool_row.id, Tool.is_active.is_(True))
        .order_by(Tool.sort_order)
        .limit(4)
        .all()
    )
    recent_searches = (
        db.session.query(Search)
        .filter(
            Search.tool_id == tool_row.id,
            Search.status == SearchStatus.COMPLETED,
            Search.visibility == SearchVisibility.PUBLIC,
        )
        .order_by(Search.created_at.desc())
        .limit(6)
        .all()
    )

    tool_url = url_for("main.category_or_tool_page", slug=tool_row.slug)

    return {
        "tool": tool,
        "tool_row": tool_row,
        "category": tool_row.category,
        "related_tools": related_tools,
        "recent_searches": recent_searches,
        "captcha_provider": current_app.config["CAPTCHA_PROVIDER"],
        "cap_public_url": current_app.config["CAP_PUBLIC_URL"],
        "cap_site_key": current_app.config["CAP_SITE_KEY"],
        "form_error": None,
        "tool_url": tool_url,
        "canonical_url": current_app.config["SITE_URL"] + tool_url,
        # Página do formulário (sem consulta associada) é conteúdo evergreen
        # e indexável; a página de resultado (`public_pages.public_result_page`)
        # sobrescreve `canonical_url`/`robots_index` para a URL canônica real.
        "robots_index": True,
    }


@main_bp.app_template_global()
def canonical_search_url(search: Search) -> str:
    """URL pública e legível (baseada no domínio/entrada, não no `public_id`)
    de uma consulta — usada em toda listagem de "consultas recentes"."""
    from app.tools.registry import registry

    tool = registry.get(search.tool.slug)
    if tool is None:
        return "#"
    slug = tool.public_slug(search.normalized_input)
    return url_for("public_pages.public_result_page", prefix=tool.public_url_prefix, slug=slug)


@main_bp.app_context_processor
def inject_sidebar_data():
    categories = (
        db.session.query(ToolCategory)
        .filter_by(is_active=True)
        .order_by(ToolCategory.sort_order)
        .all()
    )

    tools_index = [
        {
            "name": tool.name,
            "url": url_for("main.category_or_tool_page", slug=tool.slug),
            "category": tool.category.name,
            "keywords": tool.short_description,
        }
        for category in categories
        for tool in sorted(category.tools, key=lambda t: t.sort_order)
        if tool.is_active
    ]

    return {"sidebar_categories": categories, "tools_search_index": tools_index}
