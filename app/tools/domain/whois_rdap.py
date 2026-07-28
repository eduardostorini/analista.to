"""WHOIS/RDAP: RDAP (via public rdap.org bootstrap) as primary source, with
fallback to raw WHOIS (port 43) on a list of known servers by
TLD, for cases where RDAP is not yet available.
"""
from __future__ import annotations

import re
import socket

from app.models.enums import InputType
from app.security.ssrf import resolve_host_ips
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolExecutionError
from app.tools.validators import validate_and_normalize_domain
from app.security.ssrf import SafeHTTPClient

_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.nic.biz",
    "io": "whois.nic.io",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "xyz": "whois.nic.xyz",
    "br": "whois.registro.br",
    "us": "whois.nic.us",
    "in": "whois.registry.in",
}

_RELEVANT_EVENTS = {"registration", "expiration", "last changed", "transfer"}


def _extract_vcard_fn(vcard_array) -> str | None:
    try:
        properties = vcard_array[1]
    except (TypeError, IndexError):
        return None
    for prop in properties:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
            return prop[3]
    return None


def _parse_rdap(payload: dict, domain: str) -> dict:
    events = {}
    for event in payload.get("events", []):
        action = event.get("eventAction")
        if action in _RELEVANT_EVENTS:
            events[action] = event.get("eventDate")

    registrar = None
    for entity in payload.get("entities", []):
        if "registrar" in entity.get("roles", []):
            registrar = _extract_vcard_fn(entity.get("vcardArray"))
            break

    nameservers = [ns.get("ldhName") for ns in payload.get("nameservers", []) if ns.get("ldhName")]

    return {
        "domain": payload.get("ldhName", domain).lower(),
        "registered": True,
        "source": "rdap",
        "status": payload.get("status", []),
        "registrar": registrar,
        "nameservers": nameservers,
        "registered_at": events.get("registration"),
        "expires_at": events.get("expiration"),
        "updated_at": events.get("last changed"),
    }


_WHOIS_FIELD_PATTERNS = {
    "registrar": re.compile(r"^Registrar:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "registered_at": re.compile(r"^(?:Creation Date|created):\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "expires_at": re.compile(
        r"^(?:Registry Expiry Date|Registrar Registration Expiration Date|expires?):\s*(.+)$",
        re.IGNORECASE | re.MULTILINE,
    ),
    "updated_at": re.compile(r"^(?:Updated Date|changed):\s*(.+)$", re.IGNORECASE | re.MULTILINE),
}


def _raw_whois_query(server: str, domain: str) -> str:
    resolve_host_ips(server)  # valida que o servidor de WHOIS não é privado (defesa em profundidade)
    with socket.create_connection((server, 43), timeout=8) as sock:
        sock.sendall(f"{domain}\r\n".encode())
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(c) for c in chunks) > 262144:
                break
    return b"".join(chunks).decode("utf-8", errors="replace")


class WhoisRdapTool(BaseTool):
    slug = "whois-rdap"
    name = "WHOIS and RDAP"
    category_slug = "domain-ip"
    short_description = "Query the registrar, registration/expiration dates, and nameservers of a domain."
    description = "Queries domain registration data via RDAP, with fallback to traditional WHOIS."
    icon = "id-card"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "whois"
    ttl_seconds = 24 * 3600
    rate_limit_per_minute = 8
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        domain = normalized_input
        client = SafeHTTPClient()

        try:
            response = client.get(f"https://rdap.org/domain/{domain}")
        except Exception:
            return self._fallback_whois(domain)

        if response.status_code == 404:
            return ToolResult(
                success=True,
                summary=f"{domain} is not registered.",
                data={"domain": domain, "registered": False, "source": "rdap"},
            )

        if response.status_code != 200:
            return self._fallback_whois(domain)

        try:
            payload = response.json()
        except ValueError:
            return self._fallback_whois(domain)

        data = _parse_rdap(payload, domain)
        summary = f"{domain} registrado" + (f" via {data['registrar']}" if data["registrar"] else "") + "."
        return ToolResult(success=True, summary=summary, data=data, raw={"rdap": payload})

    def _fallback_whois(self, domain: str) -> ToolResult:
        tld = domain.rsplit(".", 1)[-1]
        server = _WHOIS_SERVERS.get(tld)
        if not server:
            return ToolResult(
                success=False,
                error_code="whois_unsupported_tld",
                error_message=f"WHOIS/RDAP query not available for the .{tld} TLD.",
            )

        try:
            raw_text = _raw_whois_query(server, domain)
        except (OSError, TimeoutError) as exc:
            raise ToolExecutionError(f"Failed to query WHOIS server {server}: {exc}") from exc

        if re.search(r"no match|not found|no data found|no entries found", raw_text, re.IGNORECASE):
            return ToolResult(
                success=True,
                summary=f"{domain} is not registered.",
                data={"domain": domain, "registered": False, "source": "whois"},
            )

        fields = {}
        for key, pattern in _WHOIS_FIELD_PATTERNS.items():
            match = pattern.search(raw_text)
            fields[key] = match.group(1).strip() if match else None

        nameservers = sorted(set(re.findall(r"^Name Server:\s*(.+)$", raw_text, re.IGNORECASE | re.MULTILINE)))

        data = {
            "domain": domain,
            "registered": True,
            "source": "whois",
            "status": [],
            "registrar": fields["registrar"],
            "nameservers": [ns.strip().lower() for ns in nameservers],
            "registered_at": fields["registered_at"],
            "expires_at": fields["expires_at"],
            "updated_at": fields["updated_at"],
        }
        summary = f"{domain} registrado" + (f" via {data['registrar']}" if data["registrar"] else "") + "."
        return ToolResult(success=True, summary=summary, data=data, raw={"whois_text": raw_text})

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("registered"))
