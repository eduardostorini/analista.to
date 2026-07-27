"""Geração dos sitemaps XML (seção 17). Executado periodicamente pelo Celery
Beat e sob demanda pelo painel administrativo.

Um sitemap por tipo de conteúdo (institucional, categorias, ferramentas,
resultados públicos — este último paginado no limite configurado), mais um
sitemap index que referencia todos eles. Só entram páginas com
`index_status=INDEX`; nunca páginas com erro, pendentes ou expiradas.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from xml.sax.saxutils import escape

from flask import current_app, url_for

from app.extensions import db
from app.models import GeneratedPage, Tool, ToolCategory
from app.models.enums import IndexStatus

_XML_HEADER = '<?xml version="1.0" encoding="UTF-8"?>\n'
_URLSET_OPEN = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
_URLSET_CLOSE = "</urlset>\n"
_SITEMAPINDEX_OPEN = '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
_SITEMAPINDEX_CLOSE = "</sitemapindex>\n"


def _url_entry(loc: str, lastmod: dt.datetime | None = None) -> str:
    parts = [f"  <url>\n    <loc>{escape(loc)}</loc>\n"]
    if lastmod is not None:
        parts.append(f"    <lastmod>{lastmod.strftime('%Y-%m-%d')}</lastmod>\n")
    parts.append("  </url>\n")
    return "".join(parts)


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


class SitemapService:
    @staticmethod
    def regenerate_all() -> list[str]:
        sitemaps_dir = Path(current_app.config["SITEMAPS_DIR"])
        site_url = current_app.config["SITE_URL"]
        generated_files: list[str] = []

        generated_files.append(SitemapService._write_static_sitemap(sitemaps_dir, site_url))
        generated_files.append(SitemapService._write_categories_sitemap(sitemaps_dir, site_url))
        generated_files.append(SitemapService._write_tools_sitemap(sitemaps_dir, site_url))
        generated_files.extend(SitemapService._write_pages_sitemaps(sitemaps_dir, site_url))
        SitemapService._write_sitemap_index(sitemaps_dir, site_url, generated_files)

        return generated_files

    @staticmethod
    def _write_static_sitemap(sitemaps_dir: Path, site_url: str) -> str:
        with current_app.test_request_context():
            urls = [
                url_for("main.home"),
                url_for("main.roadmap"),
                url_for("main.docs"),
            ]
        body = _XML_HEADER + _URLSET_OPEN
        body += "".join(_url_entry(site_url + u) for u in urls)
        body += _URLSET_CLOSE
        _write(sitemaps_dir / "sitemap-static.xml", body)
        return "sitemap-static.xml"

    @staticmethod
    def _write_categories_sitemap(sitemaps_dir: Path, site_url: str) -> str:
        categories = db.session.query(ToolCategory).filter_by(is_active=True).all()
        with current_app.test_request_context():
            urls = [
                (url_for("main.category_or_tool_page", slug=c.slug), c.updated_at)
                for c in categories
            ]
        body = _XML_HEADER + _URLSET_OPEN
        body += "".join(_url_entry(site_url + u, lastmod) for u, lastmod in urls)
        body += _URLSET_CLOSE
        _write(sitemaps_dir / "sitemap-categories.xml", body)
        return "sitemap-categories.xml"

    @staticmethod
    def _write_tools_sitemap(sitemaps_dir: Path, site_url: str) -> str:
        tools = db.session.query(Tool).filter_by(is_active=True).all()
        with current_app.test_request_context():
            urls = [
                (url_for("main.category_or_tool_page", slug=t.slug), t.updated_at)
                for t in tools
            ]
        body = _XML_HEADER + _URLSET_OPEN
        body += "".join(_url_entry(site_url + u, lastmod) for u, lastmod in urls)
        body += _URLSET_CLOSE
        _write(sitemaps_dir / "sitemap-tools.xml", body)
        return "sitemap-tools.xml"

    @staticmethod
    def _write_pages_sitemaps(sitemaps_dir: Path, site_url: str) -> list[str]:
        limit = current_app.config["SITEMAP_MAX_URLS_PER_FILE"]
        pages = (
            db.session.query(GeneratedPage)
            .filter_by(index_status=IndexStatus.INDEX)
            .order_by(GeneratedPage.id)
            .all()
        )

        # Sitemaps antigos ficam órfãos se o número de páginas encolher;
        # limpamos todos antes de reescrever para não deixar arquivos obsoletos.
        for old_file in sitemaps_dir.glob("sitemap-pages-*.xml"):
            old_file.unlink()

        filenames: list[str] = []
        for index, chunk_start in enumerate(range(0, len(pages), limit), start=1):
            chunk = pages[chunk_start : chunk_start + limit]
            body = _XML_HEADER + _URLSET_OPEN
            body += "".join(_url_entry(site_url + p.public_url, p.updated_at) for p in chunk)
            body += _URLSET_CLOSE
            filename = f"sitemap-pages-{index}.xml"
            _write(sitemaps_dir / filename, body)
            filenames.append(filename)

        return filenames

    @staticmethod
    def _write_sitemap_index(sitemaps_dir: Path, site_url: str, filenames: list[str]) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        body = _XML_HEADER + _SITEMAPINDEX_OPEN
        for filename in filenames:
            body += (
                "  <sitemap>\n"
                f"    <loc>{escape(site_url)}/sitemaps/{escape(filename)}</loc>\n"
                f"    <lastmod>{now.strftime('%Y-%m-%d')}</lastmod>\n"
                "  </sitemap>\n"
            )
        body += _SITEMAPINDEX_CLOSE
        _write(sitemaps_dir / "sitemap.xml", body)
