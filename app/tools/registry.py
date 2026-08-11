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
    from app.tools.dns.traceroute import TracerouteTool
    from app.tools.dns.reverse_nameserver_lookup import ReverseNameserverLookupTool
    from app.tools.dns.dmarc_lookup import DmarcLookupTool
    from app.tools.dns.dns_propagation_checker import DnsPropagationCheckerTool
    from app.tools.dns.dnssec_checker import DnssecCheckerTool
    from app.tools.dns.nameserver_health_check import NameserverHealthCheckTool
    from app.tools.domain.ip_lookup import IpLookupTool
    from app.tools.domain.open_ports_lookup import OpenPortsLookupTool
    from app.tools.domain.ping import PingTool
    from app.tools.domain.reverse_ip import ReverseIpLookupTool
    from app.tools.domain.subdomain_finder import SubdomainFinderTool
    from app.tools.domain.website_hosting import WebsiteHostingTool
    from app.tools.domain.whois_rdap import WhoisRdapTool
    from app.tools.domain.domain_ip_upgrade import CidrCalculatorTool, IpConverterTool, IpRangeLookupTool, Ipv6LookupTool
    from app.tools.domain.domain_network_upgrade import (
        AsnIpRangesTool, AsnLookupTool, CdnCheckerTool, CloudProviderCheckerTool,
        DomainAgeTool, DomainAvailabilityTool, DomainExpirationTool, DomainHealthCheckTool,
        DomainIpHistoryTool, HttpHeadersCheckerTool, HttpStatusTool, IpGeolocationTool,
        IpNeighborsTool, IpReputationTool, IpToAsnTool, NameserverHistoryTool,
        NetworkRouteAnalyzerTool, ProxyVpnCheckerTool, SslCertificateCheckerTool,
        TcpConnectionTool, TlsCheckerTool, TorExitNodeTool, WebServerCheckerTool,
    )
    from app.tools.email.blocklist_lookup import BlocklistLookupTool
    from app.tools.email.spf_checker import SpfCheckerTool
    from app.tools.email.dkim_checker import DkimCheckerTool
    from app.tools.email.header_analyzer import EmailHeaderAnalyzerTool
    from app.tools.email.mta_sts_checker import MtaStsCheckerTool
    from app.tools.email.tls_rpt_checker import TlsRptCheckerTool
    from app.tools.email.smtp_server_test import SmtpServerTestTool
    from app.tools.email.upgrade_tools import (
        ArcAnalyzerTool, BimiCheckerTool, DaneTlsaCheckerTool, DmarcCheckerTool,
        DmarcReportAnalyzerTool, EmailAuthenticationAnalyzerTool,
        EmailDeliverabilityTestTool, EmailHealthCheckTool,
        MailServerHealthCheckTool, OpenRelayTestTool, PtrCheckerTool,
        SmtpCapabilitiesCheckerTool, SmtpDeliveryTestTool,
        SmtpPortCheckerTool, SmtpTlsCheckerTool,
    )
    from app.tools.http.brotli_checker import BrotliCheckerTool
    from app.tools.http.http_headers import HttpHeadersTool
    from app.tools.http.http_version_checker import HttpVersionCheckerTool
    from app.tools.http.redirect_checker import RedirectCheckerTool
    from app.tools.http.tech_detector import TechDetectorTool
    from app.tools.http.cors_checker import CorsCheckerTool
    from app.tools.http.uptime_checker import WebsiteUptimeCheckerTool
    from app.tools.seo.meta_tags import MetaTagsTool
    from app.tools.seo.robots_checker import RobotsCheckerTool
    from app.tools.seo.sitemap_checker import SitemapCheckerTool
    from app.tools.seo.page_size_checker import PageSizeCheckerTool
    from app.tools.seo.open_graph_checker import OpenGraphCheckerTool
    from app.tools.seo.canonical_checker import CanonicalCheckerTool
    from app.tools.seo.hreflang_checker import HreflangCheckerTool
    from app.tools.seo.schema_checker import SchemaMarkupCheckerTool
    from app.tools.seo.broken_link_checker import BrokenLinkCheckerTool
    from app.tools.seo.website_audit import WebsiteAuditTool
    from app.tools.ssl.security_headers import SecurityHeadersTool
    from app.tools.ssl.ssl_certificate import SslCertificateTool
    from app.tools.ssl.ssl_deep_test import SslDeepTestTool
    from app.tools.ssl.hsts_checker import HstsCheckerTool
    from app.tools.ssl.csp_checker import CspCheckerTool
    from app.tools.performance.pagespeed_checker import PageSpeedCheckerTool
    from app.tools.utils.qr_code_generator import QrCodeGeneratorTool
    from app.tools.utils.hash_generator import HashGeneratorTool

    for tool_cls in (
        DnsLookupTool,
        MxLookupTool,
        TxtLookupTool,
        TracerouteTool,
        ReverseNameserverLookupTool,
        DmarcLookupTool,
        DnsPropagationCheckerTool,
        DnssecCheckerTool,
        NameserverHealthCheckTool,
        WhoisRdapTool,
        IpLookupTool,
        OpenPortsLookupTool,
        PingTool,
        ReverseIpLookupTool,
        SubdomainFinderTool,
        WebsiteHostingTool,
        DomainAvailabilityTool,
        DomainExpirationTool,
        DomainAgeTool,
        DomainHealthCheckTool,
        IpGeolocationTool,
        IpReputationTool,
        IpRangeLookupTool,
        Ipv6LookupTool,
        IpConverterTool,
        TorExitNodeTool,
        ProxyVpnCheckerTool,
        AsnLookupTool,
        IpToAsnTool,
        AsnIpRangesTool,
        CidrCalculatorTool,
        NetworkRouteAnalyzerTool,
        IpNeighborsTool,
        WebServerCheckerTool,
        CdnCheckerTool,
        CloudProviderCheckerTool,
        HttpStatusTool,
        HttpHeadersCheckerTool,
        TcpConnectionTool,
        SslCertificateCheckerTool,
        TlsCheckerTool,
        DomainIpHistoryTool,
        NameserverHistoryTool,
        MetaTagsTool,
        RobotsCheckerTool,
        SitemapCheckerTool,
        PageSizeCheckerTool,
        OpenGraphCheckerTool,
        CanonicalCheckerTool,
        HreflangCheckerTool,
        SchemaMarkupCheckerTool,
        BrokenLinkCheckerTool,
        WebsiteAuditTool,
        HttpHeadersTool,
        HttpVersionCheckerTool,
        BrotliCheckerTool,
        RedirectCheckerTool,
        TechDetectorTool,
        CorsCheckerTool,
        WebsiteUptimeCheckerTool,
        SslCertificateTool,
        SslDeepTestTool,
        SecurityHeadersTool,
        HstsCheckerTool,
        CspCheckerTool,
        SpfCheckerTool,
        DkimCheckerTool,
        EmailHeaderAnalyzerTool,
        MtaStsCheckerTool,
        TlsRptCheckerTool,
        SmtpServerTestTool,
        BlocklistLookupTool,
        SmtpDeliveryTestTool,
        DmarcCheckerTool,
        EmailHealthCheckTool,
        SmtpTlsCheckerTool,
        PtrCheckerTool,
        BimiCheckerTool,
        SmtpCapabilitiesCheckerTool,
        SmtpPortCheckerTool,
        OpenRelayTestTool,
        DaneTlsaCheckerTool,
        ArcAnalyzerTool,
        DmarcReportAnalyzerTool,
        EmailDeliverabilityTestTool,
        EmailAuthenticationAnalyzerTool,
        MailServerHealthCheckTool,
        PageSpeedCheckerTool,
        QrCodeGeneratorTool,
        HashGeneratorTool,
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
