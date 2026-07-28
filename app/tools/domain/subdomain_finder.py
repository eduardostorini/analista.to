"""Subdomain Finder: lista subdomínios conhecidos de um domínio.

Fonte primária: Certificate Transparency logs via crt.sh — todo certificado
TLS emitido por uma CA pública desde ~2013 é registrado nesses logs, o que
os torna a fonte passiva mais abrangente disponível, sem exigir força bruta
de DNS (que não encontraria subdomínios fora de um wordlist). O crt.sh,
porém, é um serviço comunitário conhecido por instabilidade/lentidão
ocasional (502s, timeouts em consultas grandes) — por isso há fallback para
a base de DNS do HackerTarget, menos abrangente mas bem mais estável.
"""
from __future__ import annotations

from flask import current_app

from app.security.ssrf import SafeHTTPClient
from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain

_MAX_SUBDOMAINS = 500
_ERROR_MARKERS = ("error", "api count exceeded", "invalid")


def _matches_domain(name: str, apex: str, suffix: str) -> bool:
    return bool(name) and name != apex and name.endswith(suffix)


def _fetch_from_crtsh(domain: str, apex: str, suffix: str) -> list[str] | None:
    url = current_app.config["SUBDOMAIN_CT_LOGS_API_URL"].format(domain=domain)
    try:
        response = SafeHTTPClient().get(url)
        if response.status_code != 200:
            return None
        entries = response.json()
    except Exception:
        return None

    found: set[str] = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if _matches_domain(name, apex, suffix):
                found.add(name)
    return sorted(found)


def _fetch_from_hackertarget(domain: str, apex: str, suffix: str) -> list[str] | None:
    url = current_app.config["SUBDOMAIN_FALLBACK_API_URL"].format(domain=domain)
    try:
        response = SafeHTTPClient().get(url)
        body = response.text.strip()
    except Exception:
        return None

    if response.status_code != 200 or not body or any(marker in body.lower() for marker in _ERROR_MARKERS):
        return None

    found: set[str] = set()
    for line in body.splitlines():
        name = line.split(",")[0].strip().lower()
        if _matches_domain(name, apex, suffix):
            found.add(name)
    return sorted(found)


class SubdomainFinderTool(BaseTool):
    slug = "subdomain-finder"
    name = "Subdomain Finder"
    category_slug = "domain-ip"
    short_description = "Discover subdomains of a domain using public Certificate Transparency logs."
    description = (
        "Searches Certificate Transparency logs for TLS certificates issued to a domain, "
        "revealing subdomains that have ever had a public certificate."
    )
    icon = "list-tree"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "subdomains"
    ttl_seconds = 24 * 3600
    rate_limit_per_minute = 8
    analyzer_version = 2

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        apex = normalized_input.lower()
        suffix = f".{apex}"

        subdomains = _fetch_from_crtsh(normalized_input, apex, suffix)
        source = "Certificate Transparency logs (crt.sh)" if subdomains is not None else None

        if subdomains is None:
            subdomains = _fetch_from_hackertarget(normalized_input, apex, suffix)
            source = "HackerTarget DNS database (fallback)" if subdomains is not None else None

        if subdomains is None:
            return ToolResult(
                success=True,
                summary=f"Subdomain data is temporarily unavailable for {normalized_input}.",
                data={
                    "domain": normalized_input,
                    "subdomains": [],
                    "subdomain_count": 0,
                    "source": None,
                    "note": "unavailable",
                },
            )

        subdomains = subdomains[:_MAX_SUBDOMAINS]

        if not subdomains:
            summary = f"No subdomains found for {normalized_input}."
        else:
            summary = f"{len(subdomains)} subdomain(s) found for {normalized_input}."

        return ToolResult(
            success=True,
            summary=summary,
            data={
                "domain": normalized_input,
                "subdomains": subdomains,
                "subdomain_count": len(subdomains),
                "source": source,
                "note": None if subdomains else "none_found",
            },
        )
