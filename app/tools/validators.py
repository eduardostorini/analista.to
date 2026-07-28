"""Shared input validation and normalization across tools."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from app.tools.exceptions import ToolValidationError

_HOSTNAME_RE = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


def clean_domain_input(raw: str) -> str:
    """Aceita "exemplo.com", "https://exemplo.com/caminho" ou "www.exemplo.com"
    e devolve apenas o hostname, em minúsculas, sem validar ainda o formato.
    """
    value = (raw or "").strip()
    if not value:
        raise ToolValidationError("Please enter a domain.")

    if "://" not in value and value.count("/") == 0 and value.count(" ") == 0:
        candidate = value
    else:
        if "://" not in value:
            value = f"//{value}"
        parts = urlsplit(value, scheme="https")
        candidate = parts.hostname or ""

    candidate = candidate.strip().rstrip(".").lower()
    if not candidate:
        raise ToolValidationError("Could not interpret the provided domain.")
    return candidate


def normalize_domain(hostname: str) -> str:
    """Converte para punycode (suporte a IDN) e valida o formato final."""
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ToolValidationError("Invalid domain.") from exc

    if not _HOSTNAME_RE.match(ascii_hostname):
        raise ToolValidationError("Invalid domain. Use the format example.com.br.")

    return ascii_hostname


def validate_and_normalize_domain(raw: str) -> str:
    return normalize_domain(clean_domain_input(raw))


def clean_url_input(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ToolValidationError("Please enter a URL.")
    if "://" not in value:
        value = f"https://{value}"

    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ToolValidationError("URL must use http:// or https://.")
    if not parts.hostname:
        raise ToolValidationError("Invalid URL.")

    normalize_domain(parts.hostname)
    return value


def normalize_url(url: str) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    hostname = normalize_domain(parts.hostname or "")
    netloc = hostname if not parts.port else f"{hostname}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def validate_ip_input(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ToolValidationError("Please enter an IP address.")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ToolValidationError("Invalid IP address.") from exc
    return value
