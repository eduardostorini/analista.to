"""Validação e normalização de entrada compartilhadas entre ferramentas."""
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
        raise ToolValidationError("Informe um domínio.")

    if "://" not in value and value.count("/") == 0 and value.count(" ") == 0:
        candidate = value
    else:
        if "://" not in value:
            value = f"//{value}"
        parts = urlsplit(value, scheme="https")
        candidate = parts.hostname or ""

    candidate = candidate.strip().rstrip(".").lower()
    if not candidate:
        raise ToolValidationError("Não foi possível interpretar o domínio informado.")
    return candidate


def normalize_domain(hostname: str) -> str:
    """Converte para punycode (suporte a IDN) e valida o formato final."""
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ToolValidationError("Domínio inválido.") from exc

    if not _HOSTNAME_RE.match(ascii_hostname):
        raise ToolValidationError("Domínio inválido. Use o formato exemplo.com.br.")

    return ascii_hostname


def validate_and_normalize_domain(raw: str) -> str:
    return normalize_domain(clean_domain_input(raw))


def clean_url_input(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ToolValidationError("Informe uma URL.")
    if "://" not in value:
        value = f"https://{value}"

    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ToolValidationError("A URL deve usar http:// ou https://.")
    if not parts.hostname:
        raise ToolValidationError("URL inválida.")

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
        raise ToolValidationError("Informe um endereço IP.")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ToolValidationError("Endereço IP inválido.") from exc
    return value
