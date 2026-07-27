from __future__ import annotations

import xml.etree.ElementTree as ET

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolExecutionError
from app.tools.validators import validate_and_normalize_domain

_SITEMAP_URL_LIMIT = 50000
_SITEMAP_SIZE_LIMIT_BYTES = 50 * 1024 * 1024
_SAMPLE_SIZE = 10


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _parse_sitemap_xml(raw_bytes: bytes) -> dict:
    if b"<!DOCTYPE" in raw_bytes[:2000] or b"<!ENTITY" in raw_bytes[:2000]:
        raise ToolExecutionError("Sitemap contém declarações XML não permitidas.", "unsafe_xml")

    try:
        root = ET.fromstring(raw_bytes)
    except ET.ParseError as exc:
        raise ToolExecutionError(f"XML do sitemap inválido: {exc}", "invalid_xml") from exc

    root_tag = _strip_ns(root.tag)

    if root_tag == "sitemapindex":
        entries = [
            {
                "loc": _child_text(child, "loc"),
                "lastmod": _child_text(child, "lastmod"),
            }
            for child in root
            if _strip_ns(child.tag) == "sitemap"
        ]
        return {"type": "sitemapindex", "url_count": len(entries), "sample": entries[:_SAMPLE_SIZE]}

    if root_tag == "urlset":
        entries = []
        count = 0
        for child in root:
            if _strip_ns(child.tag) != "url":
                continue
            count += 1
            if len(entries) < _SAMPLE_SIZE:
                entries.append(
                    {
                        "loc": _child_text(child, "loc"),
                        "lastmod": _child_text(child, "lastmod"),
                        "changefreq": _child_text(child, "changefreq"),
                        "priority": _child_text(child, "priority"),
                    }
                )
        return {"type": "urlset", "url_count": count, "sample": entries}

    return {"type": "unknown", "url_count": 0, "sample": []}


def _child_text(element, local_name: str) -> str | None:
    for child in element:
        if _strip_ns(child.tag) == local_name:
            return (child.text or "").strip() or None
    return None


class SitemapCheckerTool(BaseTool):
    slug = "sitemap-checker"
    name = "Sitemap Checker"
    category_slug = "seo"
    short_description = "Valide o sitemap XML de um domínio e veja quantas URLs ele declara."
    description = "Busca e valida o sitemap.xml de um domínio, incluindo suporte a sitemap index."
    icon = "list-tree"
    input_type = InputType.DOMAIN
    input_placeholder = "exemplo.com.br"
    public_url_prefix = "seo/sitemap"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        url = f"https://{normalized_input}/sitemap.xml"
        response = SafeHTTPClient().get(url)

        if response.status_code >= 400:
            return ToolResult(
                success=True,
                summary=f"Não foi possível encontrar um sitemap.xml em {normalized_input} (HTTP {response.status_code}).",
                data={"domain": normalized_input, "exists": False},
            )

        parsed = _parse_sitemap_xml(response.content)
        size_bytes = len(response.content)

        issues = []
        if parsed["url_count"] > _SITEMAP_URL_LIMIT:
            issues.append(f"O sitemap excede o limite de {_SITEMAP_URL_LIMIT} URLs por arquivo.")
        if size_bytes > _SITEMAP_SIZE_LIMIT_BYTES:
            issues.append("O sitemap excede o limite recomendado de 50MB.")
        if parsed["type"] == "unknown":
            issues.append("O XML não é um <urlset> nem um <sitemapindex> reconhecido.")

        data = {
            "domain": normalized_input,
            "exists": True,
            "url": url,
            "type": parsed["type"],
            "url_count": parsed["url_count"],
            "sample": parsed["sample"],
            "size_bytes": size_bytes,
            "issues": issues,
        }

        summary = f"Sitemap de {normalized_input}: {parsed['url_count']} URL(s) declaradas ({parsed['type']})."
        if issues:
            summary += f" {len(issues)} ponto(s) de atenção."

        return ToolResult(success=True, summary=summary, data=data, raw={"size_bytes": size_bytes})

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
