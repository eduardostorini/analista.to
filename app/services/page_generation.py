"""Gera a página HTML estática de um resultado público (seção 15).

Reaproveita o mesmo template Jinja da ferramenta (`tool.template_name`),
renderizado em `mode="result"`, tanto para a página canônica pública quanto
para a view "consulta" — a diferença entre elas é só o `canonical_url` e a
diretiva de `robots_index` usada.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
from pathlib import Path

from flask import current_app, render_template

from app.blueprints.main.context import build_tool_context
from app.extensions import db
from app.models import GeneratedPage, Search
from app.models.enums import IndexStatus
from app.services.page_indexability import PageIndexabilityService
from app.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class PageGenerationService:
    @staticmethod
    def generate(search: Search) -> GeneratedPage | None:
        tool = _tool_for(search)
        if tool is None:
            logger.warning("PageGenerationService: ferramenta não encontrada para search=%s", search.id)
            return None

        result_row = search.result
        result = _to_tool_result(result_row) if result_row else None
        index_status = PageIndexabilityService.evaluate(tool=tool, search=search, result=result)

        slug = tool.public_slug(search.normalized_input)
        public_url = f"/{tool.public_url_prefix}/{slug}/"
        canonical_url = current_app.config["SITE_URL"] + public_url
        seo = tool.seo_metadata(search.normalized_input, result) if result else {
            "title": tool.name,
            "description": tool.short_description,
        }

        html = _render_result_html(tool, search, canonical_url, index_status == IndexStatus.INDEX)
        content_hash = hashlib.sha256(html.encode()).hexdigest()

        file_path = (
            Path(current_app.config["GENERATED_PAGES_DIR"]) / tool.slug / slug / "index.html"
        )
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(html, encoding="utf-8")

        page = db.session.query(GeneratedPage).filter_by(search_id=search.id).one_or_none()
        now = dt.datetime.now(dt.timezone.utc)
        if page is None:
            page = GeneratedPage(search_id=search.id)
            db.session.add(page)

        page.slug = slug
        page.public_url = public_url
        page.file_path = str(file_path)
        page.canonical_url = canonical_url
        page.seo_title = seo["title"]
        page.seo_description = seo["description"]
        page.index_status = index_status
        page.content_hash = content_hash
        page.updated_at = now
        if page.last_accessed_at is None:
            page.last_accessed_at = now

        db.session.commit()
        return page

    @staticmethod
    def regenerate_from_row(page: GeneratedPage) -> None:
        """Reescreve o arquivo estático a partir de uma linha já existente
        (usado por reprocessamento manual no admin e pela tarefa periódica)."""
        PageGenerationService.generate(page.search)


def _tool_for(search: Search) -> BaseTool | None:
    from app.tools.registry import registry

    return registry.get(search.tool.slug)


def _to_tool_result(result_row) -> ToolResult:
    return ToolResult(
        success=result_row.error_code is None,
        summary=result_row.summary or "",
        data=result_row.normalized_result or {},
        raw=result_row.raw_result or {},
        error_code=result_row.error_code,
        error_message=result_row.error_message,
    )


def _render_result_html(tool: BaseTool, search: Search, canonical_url: str, robots_index: bool) -> str:
    with current_app.test_request_context(f"/{tool.public_url_prefix}/{search.normalized_input}/"):
        context = build_tool_context(tool, search.tool)
        context.update(
            mode="result" if search.result and search.result.error_code is None else "failed",
            search=search,
            result=search.result,
            submitted_value=search.original_input,
            canonical_url=canonical_url,
            robots_index=robots_index,
        )
        return render_template(tool.template_name, **context)
