from __future__ import annotations

import socket
import ssl

from app.models.enums import InputType
from app.security.ssrf import resolve_host_ips
from app.tools.base import BaseTool, ToolResult
from app.tools.ssl.ssl_certificate import _fetch_certificate
from app.tools.validators import validate_and_normalize_domain

_PORT = 443
_TIMEOUT = 6

_PROTOCOL_VERSIONS = (
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
)

_WEAK_PROTOCOLS = ("TLS 1.0", "TLS 1.1")


def _probe_protocol(host: str, ip: str, version: ssl.TLSVersion) -> tuple[bool, str | None]:
    ssock = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, OSError):
            return False, None

        sock = socket.create_connection((ip, _PORT), timeout=_TIMEOUT)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        cipher = ssock.cipher()
        return True, cipher[0] if cipher else None
    except (ssl.SSLError, OSError, socket.timeout, ValueError):
        return False, None
    finally:
        if ssock is not None:
            try:
                ssock.close()
            except OSError:
                pass


class SslDeepTestTool(BaseTool):
    slug = "ssl-deep-test"
    name = "SSL Deep Test"
    category_slug = "ssl-security"
    short_description = (
        "Full TLS analysis of a domain: certificate details plus which protocol versions it accepts."
    )
    description = (
        "Connects to port 443 of the domain, inspects the TLS certificate, and probes which TLS "
        "protocol versions (1.0 through 1.3) the server accepts."
    )
    icon = "shield-check"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "ssl/deep-test"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 5
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        cert_data = _fetch_certificate(normalized_input)

        ips = resolve_host_ips(normalized_input)
        ip = str(ips[0])

        protocol_support = []
        for name, version in _PROTOCOL_VERSIONS:
            supported, cipher = _probe_protocol(normalized_input, ip, version)
            protocol_support.append({"name": name, "supported": supported, "cipher": cipher})

        weak_protocols = [
            item["name"] for item in protocol_support if item["supported"] and item["name"] in _WEAK_PROTOCOLS
        ]

        issues: list[str] = []
        if not cert_data["is_trusted"]:
            issues.append("The certificate is not trusted by the standard certificate authority chain.")
        if cert_data["is_expired"]:
            issues.append("The certificate has expired.")
        elif cert_data["expires_soon"]:
            issues.append(f"The certificate expires in {cert_data['days_remaining']} day(s).")
        if weak_protocols:
            issues.append(
                "Server accepts " + ", ".join(weak_protocols) + " — deprecated and insecure, should be disabled."
            )

        data = {
            **cert_data,
            "protocol_support": protocol_support,
            "weak_protocols_enabled": weak_protocols,
            "issues": issues,
        }

        cert_bits = []
        if cert_data["is_expired"]:
            cert_bits.append("certificate expired")
        elif cert_data["expires_soon"]:
            cert_bits.append(f"certificate expires in {cert_data['days_remaining']} day(s)")
        else:
            cert_bits.append(f"certificate valid for {cert_data['days_remaining']} more day(s)")
        if not cert_data["is_trusted"]:
            cert_bits.append("untrusted certificate")

        if weak_protocols:
            protocol_bit = f"accepts weak protocols ({', '.join(weak_protocols)})"
        else:
            protocol_bit = "no weak protocols accepted"

        summary = f"{normalized_input}: {', '.join(cert_bits)}; {protocol_bit}."

        return ToolResult(success=True, summary=summary, data=data)

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and result.data.get("common_name") is not None
