"""Registro central de ferramentas — fonte da verdade da lógica de cada uma.

A tabela `tools` no banco espelha este registro (via `flask sync-tools`) e
guarda apenas os toggles administráveis (`is_active`, `is_featured`,
`sort_order`, `rate_limit`, `result_ttl_seconds`, `requires_captcha`,
`is_publicly_indexable`) — depois da primeira sincronização, esses campos
passam a ser "donos" do admin e não são mais sobrescritos automaticamente.
"""
from __future__ import annotations

import click
from flask import Flask

from app.tools.base import BaseTool
from app.tools.categories import CATEGORIES


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> BaseTool:
        if tool.slug in self._tools:
            return self._tools[tool.slug]
        self._tools[tool.slug] = tool
        return tool

    def get(self, slug: str) -> BaseTool | None:
        return self._tools.get(slug)

    def require(self, slug: str) -> BaseTool:
        tool = self.get(slug)
        if tool is None:
            raise KeyError(f"Ferramenta não encontrada: {slug!r}")
        return tool

    def all(self) -> list[BaseTool]:
        return list(self._tools.values())

    def by_category(self, category_slug: str) -> list[BaseTool]:
        return [t for t in self._tools.values() if t.category_slug == category_slug]


registry = ToolRegistry()
_loaded = False


def load_tools() -> ToolRegistry:
    """Importa e registra todas as ferramentas conhecidas. Idempotente."""
    global _loaded
    if _loaded:
        return registry

    # Lista explícita — adicionar uma ferramenta = 1 arquivo novo + 1 linha aqui.
    from app.tools.dns.dns_lookup import DnsLookupTool
    from app.tools.dns.mx_lookup import MxLookupTool
    from app.tools.dns.txt_lookup import TxtLookupTool
    from app.tools.domain.ip_lookup import IpLookupTool
    from app.tools.domain.open_ports_lookup import OpenPortsLookupTool
    from app.tools.domain.ping import PingTool
    from app.tools.domain.reverse_ip import ReverseIpLookupTool
    from app.tools.domain.subdomain_finder import SubdomainFinderTool
    from app.tools.domain.website_hosting import WebsiteHostingTool
    from app.tools.domain.whois_rdap import WhoisRdapTool
    from app.tools.email.blocklist_lookup import BlocklistLookupTool
    from app.tools.email.dmarc_checker import DmarcCheckerTool
    from app.tools.email.spf_checker import SpfCheckerTool
    from app.tools.http.brotli_checker import BrotliCheckerTool
    from app.tools.http.http_headers import HttpHeadersTool
    from app.tools.http.http_version_checker import HttpVersionCheckerTool
    from app.tools.http.redirect_checker import RedirectCheckerTool
    from app.tools.http.tech_detector import TechDetectorTool
    from app.tools.seo.meta_tags import MetaTagsTool
    from app.tools.seo.robots_checker import RobotsCheckerTool
    from app.tools.seo.sitemap_checker import SitemapCheckerTool
    from app.tools.ssl.security_headers import SecurityHeadersTool
    from app.tools.ssl.ssl_certificate import SslCertificateTool
    from app.tools.utils.qr_code_generator import QrCodeGeneratorTool

    for tool_cls in (
        DnsLookupTool,
        MxLookupTool,
        TxtLookupTool,
        WhoisRdapTool,
        IpLookupTool,
        OpenPortsLookupTool,
        PingTool,
        ReverseIpLookupTool,
        SubdomainFinderTool,
        WebsiteHostingTool,
        MetaTagsTool,
        RobotsCheckerTool,
        SitemapCheckerTool,
        HttpHeadersTool,
        HttpVersionCheckerTool,
        BrotliCheckerTool,
        RedirectCheckerTool,
        TechDetectorTool,
        SslCertificateTool,
        SecurityHeadersTool,
        SpfCheckerTool,
        DmarcCheckerTool,
        BlocklistLookupTool,
        QrCodeGeneratorTool,
    ):
        registry.register(tool_cls())

    _loaded = True
    return registry


def register_sync_tools_command(app: Flask) -> None:
    @app.cli.command("sync-tools")
    def sync_tools() -> None:
        """Synchronize `tool_categories`/`tools` from the code registry."""
        from app.extensions import db
        from app.models import Tool, ToolCategory

        load_tools()

        category_ids: dict[str, int] = {}
        for definition in CATEGORIES:
            category = db.session.query(ToolCategory).filter_by(slug=definition.slug).one_or_none()
            if category is None:
                category = ToolCategory(
                    slug=definition.slug,
                    name=definition.name,
                    description=definition.description,
                    icon=definition.icon,
                    sort_order=definition.sort_order,
                )
                db.session.add(category)
                db.session.flush()
                click.echo(f"+ category created: {definition.slug}")
            else:
                category.name = definition.name
                category.description = definition.description
                category.icon = definition.icon
                category.sort_order = definition.sort_order
            category_ids[definition.slug] = category.id

        known_slugs = set()
        for order, tool in enumerate(registry.all()):
            known_slugs.add(tool.slug)
            row = db.session.query(Tool).filter_by(handler=tool.handler_id).one_or_none()
            if row is None:
                row = db.session.query(Tool).filter_by(slug=tool.slug).one_or_none()

            if row is None:
                row = Tool(
                    slug=tool.slug,
                    handler=tool.handler_id,
                    category_id=category_ids[tool.category_slug],
                    name=tool.name,
                    short_description=tool.short_description,
                    description=tool.description,
                    icon=tool.icon,
                    input_type=tool.input_type,
                    is_active=True,
                    is_featured=False,
                    is_publicly_indexable=tool.is_publicly_indexable,
                    requires_captcha=tool.requires_captcha,
                    rate_limit=tool.rate_limit_per_minute,
                    result_ttl_seconds=tool.ttl_seconds,
                    sort_order=order * 10,
                )
                db.session.add(row)
                click.echo(f"+ tool created: {tool.slug}")
            else:
                # Campos derivados do código: sempre sincronizados.
                row.handler = tool.handler_id
                row.category_id = category_ids[tool.category_slug]
                row.name = tool.name
                row.short_description = tool.short_description
                row.description = tool.description
                row.icon = tool.icon
                row.input_type = tool.input_type
                # Campos administráveis: só recebem o valor do código na
                # criação; depois disso pertencem ao painel administrativo.
                click.echo(f"= existing tool, preserving toggles: {tool.slug}")

        db.session.commit()

        db_slugs = {t.slug for t in db.session.query(Tool.slug).all()}
        orphaned = db_slugs - known_slugs
        if orphaned:
            click.echo(
                "Warning: tools in database without code match "
                f"(consider deactivating them manually in admin): {sorted(orphaned)}"
            )

        click.echo("Synchronization complete.")
