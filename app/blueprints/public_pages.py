"""Serve as páginas públicas de resultado, os sitemaps e o robots.txt.

Páginas de resultado tentam primeiro o arquivo estático já gerado
(`GENERATED_PAGES_DIR`); se ainda não existir, renderiza dinamicamente a
partir do banco (e reenfileira a geração), sem nunca criar uma consulta nova
a partir de um slug arbitrário — isso exigiria passar pelo formulário
protegido por CAPTCHA/rate limit.
"""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

from flask import Blueprint, Response, abort, current_app, render_template, send_file, url_for

from app.blueprints.main.context import build_tool_context
from app.extensions import db
from app.models import GeneratedPage, Search, Tool
from app.models.enums import TERMINAL_SEARCH_STATUSES, IndexStatus, SearchStatus
from app.tools.registry import load_tools, registry

public_pages_bp = Blueprint("public_pages", __name__)

# Mesmo charset produzido por `BaseTool.public_slug()` — usado para rejeitar
# qualquer tentativa de path traversal antes de tocar o filesystem.
_SLUG_RE = re.compile(r"[a-z0-9.\-]+")


@public_pages_bp.before_app_request
def _ensure_tools_loaded():
    load_tools()


@public_pages_bp.get("/robots.txt")
def robots_txt():
    admin_prefix = current_app.config["ADMIN_URL_PREFIX"]
    lines = [
        "User-agent: *",
        f"Disallow: {admin_prefix}",
        "",
        f"Sitemap: {current_app.config['SITE_URL']}/sitemap.xml",
        "",
    ]
    return Response("\n".join(lines), mimetype="text/plain")


@public_pages_bp.get("/sitemap.xml")
@public_pages_bp.get("/sitemap-<name>.xml")
def sitemap(name: str | None = None):
    filename = f"sitemap-{name}.xml" if name else "sitemap.xml"
    if ".." in filename or "/" in filename:
        abort(404)

    sitemaps_dir = Path(current_app.config["SITEMAPS_DIR"])
    file_path = sitemaps_dir / filename

    if not file_path.is_file():
        from app.services.sitemap_service import SitemapService

        SitemapService.regenerate_all()

    if not file_path.is_file():
        abort(404)

    return send_file(file_path, mimetype="application/xml")


@public_pages_bp.get("/screenshots/<tool_slug>/<slug>.png")
def screenshot(tool_slug: str, slug: str):
    if not _SLUG_RE.fullmatch(tool_slug) or not _SLUG_RE.fullmatch(slug):
        abort(404)

    screenshots_dir = Path(current_app.config["SCREENSHOTS_DIR"]).resolve()
    file_path = (screenshots_dir / tool_slug / f"{slug}.png").resolve()
    if screenshots_dir not in file_path.parents or not file_path.is_file():
        abort(404)

    response = send_file(file_path, mimetype="image/png")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


def _search_status_mode(status: SearchStatus) -> str:
    if status == SearchStatus.COMPLETED:
        return "result"
    if status in TERMINAL_SEARCH_STATUSES:
        return "failed"
    return "pending"


@public_pages_bp.get("/<path:prefix>/<slug>/")
def public_result_page(prefix: str, slug: str):
    """URL pública e canônica de um resultado — sempre baseada na entrada
    normalizada (ex.: `/dns/exemplo.com/`), nunca no `public_id` aleatório.

    Serve o HTML estático já gerado quando existe; caso contrário (consulta
    ainda em andamento, ou ferramenta não elegível para página pública),
    localiza a `Search` correspondente pelo mesmo slug e renderiza
    dinamicamente com o status atual — a mesma URL funciona do envio do
    formulário até o resultado final.
    """
    tool = next((t for t in registry.all() if t.public_url_prefix == prefix), None)
    if tool is None:
        abort(404)

    page = (
        db.session.query(GeneratedPage)
        .join(Search, GeneratedPage.search_id == Search.id)
        .filter(GeneratedPage.slug == slug, Search.tool.has(slug=tool.slug))
        .order_by(GeneratedPage.updated_at.desc())
        .first()
    )

    if page is not None:
        file_path = Path(page.file_path)
        if file_path.is_file() and page.index_status != IndexStatus.REMOVED:
            page.last_accessed_at = dt.datetime.now(dt.timezone.utc)
            db.session.commit()
            return send_file(file_path, mimetype="text/html")

        if page.index_status == IndexStatus.REMOVED:
            abort(404)

        search = page.search
        context = build_tool_context(tool, search.tool)
        context.update(
            mode=_search_status_mode(search.status),
            search=search,
            result=search.result,
            submitted_value=search.original_input,
            canonical_url=page.canonical_url,
            robots_index=page.index_status == IndexStatus.INDEX,
        )

        from app.tasks.task_names import GENERATE_PAGE_TASK

        current_app.extensions["celery"].send_task(GENERATE_PAGE_TASK, args=[search.id])

        return render_template(tool.template_name, **context)

    # Nenhuma página gerada ainda: pode ser uma consulta recém-enviada, ainda
    # em processamento, ou uma ferramenta não elegível para página pública.
    # Localiza a busca mais recente cujo slug (recomputado) bate com a URL —
    # nunca cria uma consulta nova a partir de um slug arbitrário.
    tool_row = db.session.query(Tool).filter_by(slug=tool.slug, is_active=True).one_or_none()
    if tool_row is None:
        abort(404)

    candidates = (
        db.session.query(Search)
        .filter(Search.tool_id == tool_row.id)
        .order_by(Search.created_at.desc())
        .limit(50)
        .all()
    )
    search = next((s for s in candidates if tool.public_slug(s.normalized_input) == slug), None)
    if search is None:
        abort(404)

    canonical_url = current_app.config["SITE_URL"] + url_for(
        "public_pages.public_result_page", prefix=tool.public_url_prefix, slug=slug
    )
    context = build_tool_context(tool, tool_row)
    context.update(
        mode=_search_status_mode(search.status),
        search=search,
        result=search.result,
        submitted_value=search.original_input,
        canonical_url=canonical_url,
        robots_index=False,
    )
    return render_template(tool.template_name, **context)
