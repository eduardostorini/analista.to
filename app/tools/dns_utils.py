"""Utilitário de consulta DNS compartilhado por ferramentas de DNS e e-mail.

Consultas DNS não passam pelo `SafeHTTPClient`/SSRF guard: não estamos
conectando a um servidor no domínio do usuário, apenas perguntando a um
resolvedor recursivo confiável (configurado no ambiente) quais registros
existem — não há requisição a um destino controlado pelo usuário.
"""
from __future__ import annotations

import dns.exception
import dns.resolver

from app.tools.exceptions import ToolExecutionError

_TIMEOUT = 5
_LIFETIME = 8


def get_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = _TIMEOUT
    resolver.lifetime = _LIFETIME
    return resolver


def query_records(domain: str, record_type: str) -> list[str]:
    """Retorna os registros como texto. Lista vazia se não houver resposta.

    NXDOMAIN é reportado separadamente (ver `domain_exists`) — aqui é
    tratado como "sem registros" para não interromper consultas de outros
    tipos de registro no mesmo domínio.
    """
    resolver = get_resolver()
    try:
        answer = resolver.resolve(domain, record_type)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.resolver.NoNameservers as exc:
        raise ToolExecutionError(f"Nenhum servidor DNS respondeu para {domain}", "no_nameservers") from exc
    except dns.exception.Timeout as exc:
        raise ToolExecutionError(f"Tempo esgotado ao consultar DNS para {domain}", "dns_timeout") from exc

    return [rdata.to_text() for rdata in answer]


def query_txt_clean(domain: str) -> list[str]:
    """Como `query_records(domain, "TXT")`, mas já remove as aspas/concatena
    os pedaços de cada registro TXT (útil para SPF/DMARC).
    """
    raw = query_records(domain, "TXT")
    return [r.strip('"').replace('" "', "") for r in raw]


def domain_exists(domain: str) -> bool:
    """NXDOMAIN em qualquer tipo básico de registro indica que o domínio
    não está registrado/delegado. Usa NS como sonda principal.
    """
    resolver = get_resolver()
    try:
        resolver.resolve(domain, "NS")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True
    except dns.resolver.NoNameservers:
        return True
    except dns.exception.Timeout:
        return True
