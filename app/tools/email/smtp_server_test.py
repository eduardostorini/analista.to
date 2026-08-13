"""SMTP Server Test: connects to a domain's primary mail server and performs
a read-only banner/capability/STARTTLS probe.

This tool never authenticates, never sends mail, and never attempts relay —
it only issues `EHLO` (to read the advertised capability list) and,
optionally, `STARTTLS` (to observe the negotiated TLS protocol/cipher),
followed by `QUIT`. `MAIL FROM`, `RCPT TO`, `DATA` and `AUTH` are never sent.

Connects directly to port 25 of the chosen MX host, so — unlike HTTP tools —
it cannot go through `SafeHTTPClient`. SSRF protection is applied via
`resolve_host_ips`, and the socket connects to the validated literal IP
(never re-resolving the hostname), mirroring the pattern used by the SSL
Certificate Checker.
"""
from __future__ import annotations

import socket
import ssl

from app.models.enums import InputType
from app.security.ssrf import resolve_host_ips
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import query_records
from app.tools.validators import validate_and_normalize_domain

_SMTP_PORT = 25
_TIMEOUT = 10
_RECV_SIZE = 4096

_KNOWN_CAPABILITIES = (
    "STARTTLS",
    "SIZE",
    "PIPELINING",
    "8BITMIME",
    "AUTH",
    "ENHANCEDSTATUSCODES",
    "DSN",
    "SMTPUTF8",
    "CHUNKING",
    "BINARYMIME",
    "VRFY",
    "ETRN",
    "HELP",
)


def _parse_mx_record(record: str) -> dict:
    priority_str, _, host = record.partition(" ")
    try:
        priority = int(priority_str)
    except ValueError:
        priority = 0
    return {"priority": priority, "host": host.rstrip(".")}


def _recv_line(sock) -> bytes:
    return sock.recv(_RECV_SIZE)


def _parse_ehlo_capabilities(response: bytes) -> list[str]:
    capabilities: list[str] = []
    text = response.decode("ascii", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if len(line) < 4 or not line[:3].isdigit():
            continue
        keyword_part = line[4:].strip()
        if not keyword_part:
            continue
        keyword = keyword_part.split()[0].upper()
        if keyword in _KNOWN_CAPABILITIES and keyword not in capabilities:
            capabilities.append(keyword)
    return capabilities


def _run_smtp_dialogue(ip: str, mx_host: str, tls_context: ssl.SSLContext | None) -> dict:
    """Runs the banner + EHLO + optional STARTTLS dialogue against `ip`.

    When `tls_context` is given and the server advertises STARTTLS, the
    handshake is attempted with that context. A fresh TCP connection is used
    for every call (a TLS handshake cannot be retried on the same stream
    once a certificate-verification failure has occurred), so the caller
    re-invokes this whole function with a different context on failure
    rather than trying to reuse the socket.
    """
    sock = socket.create_connection((ip, _SMTP_PORT), timeout=_TIMEOUT)
    sock.settimeout(_TIMEOUT)
    ssock = None
    try:
        banner = _recv_line(sock).decode("ascii", errors="replace").strip()

        sock.sendall(b"EHLO analista.to\r\n")
        ehlo_response = _recv_line(sock)
        capabilities = _parse_ehlo_capabilities(ehlo_response)
        supports_starttls = "STARTTLS" in capabilities

        starttls_negotiated = False
        tls_protocol = None
        tls_cipher = None

        if supports_starttls and tls_context is not None:
            sock.sendall(b"STARTTLS\r\n")
            starttls_response = _recv_line(sock).decode("ascii", errors="replace")
            if starttls_response.startswith("220"):
                ssock = tls_context.wrap_socket(sock, server_hostname=mx_host)
                starttls_negotiated = True
                tls_protocol = ssock.version()
                cipher = ssock.cipher()
                tls_cipher = cipher[0] if cipher else None
                ssock.sendall(b"QUIT\r\n")
            else:
                sock.sendall(b"QUIT\r\n")
        else:
            sock.sendall(b"QUIT\r\n")

        return {
            "banner": banner,
            "capabilities": capabilities,
            "supports_starttls": supports_starttls,
            "starttls_negotiated": starttls_negotiated,
            "tls_protocol": tls_protocol,
            "tls_cipher": tls_cipher,
        }
    finally:
        active_sock = ssock if ssock is not None else sock
        try:
            active_sock.close()
        except OSError:
            pass


def _probe_mx_host(ip: str, mx_host: str) -> dict:
    try:
        return _run_smtp_dialogue(ip, mx_host, ssl.create_default_context())
    except ssl.SSLCertVerificationError:
        # The server offered STARTTLS but its certificate does not validate.
        # A TLS handshake cannot be resumed on the same TCP stream after a
        # verification failure, so the whole SMTP dialogue is redone on a
        # fresh connection, this time without asserting trust — the goal is
        # only to report which protocol/cipher the server negotiates.
        unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        return _run_smtp_dialogue(ip, mx_host, unverified)


class SmtpServerTestTool(BaseTool):
    slug = "smtp-server-test"
    name = "SMTP Server Test"
    category_slug = "email"
    short_description = (
        "Connect to a domain's primary mail server and check its banner, capabilities and "
        "STARTTLS support."
    )
    description = (
        "Performs a read-only SMTP probe (banner + EHLO + optional STARTTLS handshake) against "
        "a domain's lowest-priority MX host. Never authenticates or sends mail."
    )
    icon = "server"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "email/smtp-test"
    ttl_seconds = 1800
    rate_limit_per_minute = 5
    analyzer_version = 2

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        mx_raw = query_records(normalized_input, "MX")
        if not mx_raw:
            return ToolResult(
                success=True,
                summary=f"{normalized_input} has no MX records — cannot test an SMTP server.",
                data={"domain": normalized_input, "has_mx": False, "tested_host": None},
            )

        records = sorted((_parse_mx_record(r) for r in mx_raw), key=lambda r: r["priority"])
        chosen = records[0]
        mx_host = chosen["host"]
        mx_priority = chosen["priority"]

        # Not caught here on purpose: a disallowed target (private/reserved
        # IP) is an SSRF-blocked failure the Celery task layer already
        # handles correctly (records an AbuseEvent, marks the search as
        # failed) — anticipating it here would just duplicate that handling.
        ips = resolve_host_ips(mx_host)
        ip = str(ips[0])

        try:
            probe = _probe_mx_host(ip, mx_host)
        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as exc:
            if isinstance(exc, (socket.timeout, TimeoutError)):
                connection_status = "timeout"
                detail = (
                    "The SMTP server did not respond on port 25 before the connection timeout. "
                    "The port may be filtered by the local network, hosting provider, or remote server."
                )
            elif isinstance(exc, ConnectionRefusedError):
                connection_status = "refused"
                detail = "The SMTP server actively refused the connection on port 25."
            else:
                connection_status = "connection_error"
                detail = f"The SMTP connection could not be completed: {exc}"

            return ToolResult(
                success=True,
                summary=f"Could not connect to {mx_host} ({ip}) on port 25: {connection_status}.",
                data={
                    "domain": normalized_input,
                    "has_mx": True,
                    "mx_host": mx_host,
                    "mx_priority": mx_priority,
                    "ip": ip,
                    "connected": False,
                    "connection_status": connection_status,
                    "banner": None,
                    "supports_starttls": False,
                    "starttls_negotiated": False,
                    "tls_protocol": None,
                    "tls_cipher": None,
                    "capabilities": [],
                    "issues": [detail],
                },
            )

        supports_starttls = probe["supports_starttls"]
        issues: list[str] = []
        if not supports_starttls:
            issues.append(
                "STARTTLS not supported — mail to this server may be delivered unencrypted."
            )

        data = {
            "domain": normalized_input,
            "has_mx": True,
            "mx_host": mx_host,
            "mx_priority": mx_priority,
            "ip": ip,
            "connected": True,
            "connection_status": "connected",
            "banner": probe["banner"],
            "supports_starttls": supports_starttls,
            "starttls_negotiated": probe["starttls_negotiated"],
            "tls_protocol": probe["tls_protocol"],
            "tls_cipher": probe["tls_cipher"],
            "capabilities": probe["capabilities"],
            "issues": issues,
        }

        summary = f"Connected to {mx_host} ({ip}) for {normalized_input}: "
        summary += "STARTTLS supported" if supports_starttls else "STARTTLS not supported"
        if probe["starttls_negotiated"] and probe["tls_protocol"]:
            summary += f" ({probe['tls_protocol']})"
        summary += "."

        return ToolResult(success=True, summary=summary, data=data)

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("has_mx")) and bool(
            result.data.get("connected")
        )
