"""Proteção contra SSRF para toda requisição de rede feita pelas ferramentas.

Toda ferramenta que precisa buscar uma URL/host informado pelo usuário DEVE
passar por `SafeHTTPClient` (ou por `resolve_and_validate_host` para checagens
que não envolvem HTTP, como DNS/WHOIS). Nunca chame `httpx`/`socket`
diretamente com um host fornecido pelo usuário.

Camadas de proteção (seção 20 da especificação):
- bloqueio de IPs privados/reservados/loopback/link-local/multicast/metadata
  (IPv4 e IPv6), resolvidos via dnspython antes de qualquer conexão;
- bloqueio de esquemas fora de http/https e de credenciais embutidas na URL;
- "pinning" do IP validado na conexão TCP/TLS (mantendo o Host/SNI corretos),
  para reduzir a janela de DNS rebinding entre a validação e a conexão real;
- revalidação do IP a cada redirecionamento, seguido manualmente (nunca
  delegado ao cliente HTTP);
- timeouts de conexão/leitura, limite de tamanho de resposta, limite de
  redirecionamentos, porta permitida e User-Agent próprio, todos vindos de
  configuração.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import dns.exception
import dns.resolver
import httpx
from flask import current_app

_ALLOWED_SCHEMES = {"http", "https"}

# Endereços de metadata de nuvem que já caem nas faixas privadas/link-local
# abaixo, mas são listados explicitamente por serem os alvos mais comuns de
# SSRF em ambientes de nuvem (defesa em profundidade).
_EXTRA_BLOCKED_IPS = {
    "169.254.169.254",  # AWS/GCP/Azure/DigitalOcean metadata
    "100.100.100.200",  # Alibaba Cloud metadata
    "fd00:ec2::254",  # AWS metadata (IPv6)
}


class SSRFBlockedError(Exception):
    """Levantada quando uma URL/host é bloqueado pelas regras de SSRF."""

    def __init__(self, message: str, reason: str):
        super().__init__(message)
        self.reason = reason


class ResponseTooLargeError(Exception):
    pass


@dataclass
class ValidatedTarget:
    scheme: str
    hostname: str
    port: int
    ip: str
    url: str


def _is_blocked_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if str(ip_obj) in _EXTRA_BLOCKED_IPS:
        return True
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or getattr(ip_obj, "is_site_local", False)
    )


def resolve_host_ips(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve A/AAAA de `hostname`. Levanta SSRFBlockedError se algum IP for privado."""
    try:
        ip_obj = ipaddress.ip_address(hostname)
        candidates = [ip_obj]
    except ValueError:
        candidates = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        found_any = False
        for record_type in ("A", "AAAA"):
            try:
                answer = resolver.resolve(hostname, record_type)
                for rdata in answer:
                    candidates.append(ipaddress.ip_address(rdata.to_text()))
                found_any = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except dns.exception.DNSException as exc:
                raise SSRFBlockedError(f"Falha ao resolver {hostname}: {exc}", "dns_error") from exc
        if not found_any or not candidates:
            raise SSRFBlockedError(f"Não foi possível resolver o host {hostname}", "dns_not_found")

    for ip_obj in candidates:
        if _is_blocked_ip(ip_obj):
            raise SSRFBlockedError(
                f"Host resolve para um endereço não permitido ({ip_obj})", "private_ip"
            )

    return candidates


def validate_url(url: str) -> ValidatedTarget:
    parts = urlsplit(url)

    if parts.scheme not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"Esquema não permitido: {parts.scheme!r}", "scheme_blocked")

    if parts.username or parts.password:
        raise SSRFBlockedError("URLs com credenciais embutidas não são permitidas", "credentials_in_url")

    hostname = parts.hostname
    if not hostname:
        raise SSRFBlockedError("URL sem host válido", "missing_host")

    port = parts.port or (443 if parts.scheme == "https" else 80)
    allowed_ports = current_app.config["OUTBOUND_ALLOWED_PORTS"]
    if port not in allowed_ports:
        raise SSRFBlockedError(f"Porta não permitida: {port}", "port_blocked")

    ips = resolve_host_ips(hostname)
    chosen_ip = str(ips[0])

    clean_netloc = hostname if parts.port is None else f"{hostname}:{parts.port}"
    clean_url = urlunsplit((parts.scheme, clean_netloc, parts.path or "/", parts.query, ""))

    return ValidatedTarget(scheme=parts.scheme, hostname=hostname, port=port, ip=chosen_ip, url=clean_url)


class _PinnedTransport(httpx.HTTPTransport):
    """Conecta no IP já validado, mantendo o Host header e o SNI corretos.

    Reduz a janela de DNS rebinding entre `validate_url()` e a conexão TCP
    real, sem exigir reescrever toda a stack de rede.
    """

    def __init__(self, pinned_ip: str, original_host: str, **kwargs):
        super().__init__(**kwargs)
        self._pinned_ip = pinned_ip
        self._original_host = original_host

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        pinned_url = request.url.copy_with(host=self._pinned_ip)
        request.url = pinned_url
        request.headers["host"] = self._original_host
        request.extensions["sni_hostname"] = self._original_host
        return super().handle_request(request)


class SafeHTTPClient:
    """Cliente HTTP com proteção SSRF completa e seguimento manual de redirects."""

    def __init__(self) -> None:
        cfg = current_app.config
        self._connect_timeout = cfg["OUTBOUND_CONNECT_TIMEOUT_SECONDS"]
        self._read_timeout = cfg["OUTBOUND_READ_TIMEOUT_SECONDS"]
        self._max_redirects = cfg["OUTBOUND_MAX_REDIRECTS"]
        self._max_bytes = cfg["OUTBOUND_MAX_RESPONSE_BYTES"]
        self._user_agent = cfg["OUTBOUND_USER_AGENT"]

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response:
        return self.request("GET", url, headers=headers)

    def request(
        self, method: str, url: str, *, headers: dict[str, str] | None = None
    ) -> httpx.Response:
        response, _history = self.request_with_history(method, url, headers=headers)
        return response

    def request_with_history(
        self, method: str, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[httpx.Response, list[dict]]:
        """Como `request()`, mas também devolve a cadeia de redirecionamentos
        seguidos manualmente (usado pelo Redirect Checker)."""
        remaining_redirects = self._max_redirects
        current_url = url
        request_headers = {"User-Agent": self._user_agent, **(headers or {})}
        history: list[dict] = []

        while True:
            target = validate_url(current_url)
            transport = _PinnedTransport(target.ip, target.hostname)
            timeout = httpx.Timeout(connect=self._connect_timeout, read=self._read_timeout, write=self._read_timeout, pool=self._connect_timeout)

            with httpx.Client(transport=transport, timeout=timeout, follow_redirects=False) as client:
                response = self._send_with_size_limit(client, method, target.url, request_headers)

            if response.is_redirect and remaining_redirects > 0:
                location = response.headers.get("location")
                history.append(
                    {"url": target.url, "status_code": response.status_code, "location": location}
                )
                if not location:
                    return response, history
                current_url = str(httpx.URL(target.url).join(location))
                remaining_redirects -= 1
                continue

            history.append({"url": target.url, "status_code": response.status_code, "location": None})
            return response, history

    def _send_with_size_limit(
        self, client: httpx.Client, method: str, url: str, headers: dict[str, str]
    ) -> httpx.Response:
        with client.stream(method, url, headers=headers) as response:
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > self._max_bytes:
                raise ResponseTooLargeError(
                    f"Resposta excede o limite de {self._max_bytes} bytes"
                )

            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > self._max_bytes:
                    raise ResponseTooLargeError(
                        f"Resposta excede o limite de {self._max_bytes} bytes"
                    )
                chunks.append(chunk)

            body = b"".join(chunks)
            return httpx.Response(
                status_code=response.status_code,
                headers=response.headers,
                content=body,
                request=response.request,
            )
