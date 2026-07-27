from __future__ import annotations

import datetime as dt
import socket
import ssl

from app.models.enums import InputType
from app.security.ssrf import resolve_host_ips
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolExecutionError
from app.tools.validators import validate_and_normalize_domain

_PORT = 443
_TIMEOUT = 8


def _dn_to_dict(dn_tuple) -> dict:
    result = {}
    for rdn in dn_tuple:
        for key, value in rdn:
            result[key] = value
    return result


def _parse_cert_time(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)


def _connect(host: str, ip: str, context: ssl.SSLContext):
    sock = socket.create_connection((ip, _PORT), timeout=_TIMEOUT)
    return context.wrap_socket(sock, server_hostname=host)


def _fetch_certificate(host: str) -> dict:
    ips = resolve_host_ips(host)
    ip = str(ips[0])

    is_trusted = True
    context = ssl.create_default_context()
    try:
        ssock = _connect(host, ip, context)
    except ssl.SSLCertVerificationError:
        is_trusted = False
        unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        ssock = _connect(host, ip, unverified)
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        raise ToolExecutionError(f"Não foi possível conectar em {host}:{_PORT}: {exc}", "connection_failed") from exc

    try:
        cert = ssock.getpeercert()
        protocol = ssock.version()
        cipher = ssock.cipher()
    finally:
        ssock.close()

    if not cert:
        raise ToolExecutionError("Não foi possível obter o certificado do servidor.", "no_certificate")

    subject = _dn_to_dict(cert.get("subject", ()))
    issuer = _dn_to_dict(cert.get("issuer", ()))
    san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]

    not_before = _parse_cert_time(cert["notBefore"])
    not_after = _parse_cert_time(cert["notAfter"])
    now = dt.datetime.now(dt.timezone.utc)
    days_remaining = (not_after - now).days

    return {
        "host": host,
        "ip": ip,
        "is_trusted": is_trusted,
        "common_name": subject.get("commonName"),
        "subject_alt_names": san,
        "issuer_common_name": issuer.get("commonName"),
        "issuer_organization": issuer.get("organizationName"),
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "is_expired": days_remaining < 0,
        "expires_soon": 0 <= days_remaining <= 15,
    }


class SslCertificateTool(BaseTool):
    slug = "ssl-certificate"
    name = "SSL Certificate Checker"
    category_slug = "ssl-seguranca"
    short_description = "Verifique a validade, emissor e data de expiração do certificado SSL/TLS de um domínio."
    description = "Conecta na porta 443 do domínio e inspeciona o certificado TLS apresentado."
    icon = "shield-check"
    input_type = InputType.DOMAIN
    input_placeholder = "exemplo.com.br"
    public_url_prefix = "ssl"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 5
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        data = _fetch_certificate(normalized_input)

        status_bits = []
        if not data["is_trusted"]:
            status_bits.append("certificado não confiável")
        if data["is_expired"]:
            status_bits.append("expirado")
        elif data["expires_soon"]:
            status_bits.append(f"expira em {data['days_remaining']} dia(s)")

        if status_bits:
            summary = f"Certificado de {normalized_input}: {', '.join(status_bits)}."
        else:
            summary = f"Certificado de {normalized_input} válido por mais {data['days_remaining']} dia(s)."

        return ToolResult(success=True, summary=summary, data=data)

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and result.data.get("common_name") is not None
