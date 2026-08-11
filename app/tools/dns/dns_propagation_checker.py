"""Parallel DNS propagation checks against explicitly configured resolvers."""
from __future__ import annotations

import json
import os
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.resolver

from app import extensions
from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolValidationError
from app.tools.validators import clean_domain_input, normalize_domain

SUPPORTED_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"}


@dataclass(frozen=True)
class PublicResolver:
    provider: str
    server: str
    ip: str


DEFAULT_RESOLVERS = (
    PublicResolver("Cloudflare", "1.1.1.1", "1.1.1.1"),
    PublicResolver("Cloudflare", "1.0.0.1", "1.0.0.1"),
    PublicResolver("Google", "8.8.8.8", "8.8.8.8"),
    PublicResolver("Google", "8.8.4.4", "8.8.4.4"),
    PublicResolver("Quad9", "9.9.9.9", "9.9.9.9"),
    PublicResolver("Quad9", "149.112.112.112", "149.112.112.112"),
    PublicResolver("OpenDNS", "208.67.222.222", "208.67.222.222"),
    PublicResolver("OpenDNS", "208.67.220.220", "208.67.220.220"),
    PublicResolver("AdGuard DNS", "94.140.14.14", "94.140.14.14"),
    PublicResolver("AdGuard DNS", "94.140.15.15", "94.140.15.15"),
)

ERROR_MESSAGES = {
    "nxdomain": "O domínio ou hostname não foi encontrado.",
    "servfail": "O servidor DNS encontrou um erro ao tentar resolver este registro.",
    "refused": "O servidor DNS recusou esta consulta.",
    "timeout": "Este servidor DNS não respondeu dentro do tempo esperado.",
    "no_answer": "O domínio existe, mas não possui este tipo de registro.",
    "no_nameservers": "Nenhum servidor DNS disponível conseguiu responder.",
    "error": "Não foi possível concluir a consulta neste servidor DNS.",
}


def _configured_resolvers() -> tuple[PublicResolver, ...]:
    """Optional format: ``Provider|server|ip,Provider 2|server|ip``."""
    raw = os.environ.get("DNS_PROPAGATION_RESOLVERS", "").strip()
    if not raw:
        return DEFAULT_RESOLVERS
    parsed: list[PublicResolver] = []
    for entry in raw.split(","):
        parts = [part.strip() for part in entry.split("|")]
        if len(parts) == 3 and all(parts):
            parsed.append(PublicResolver(*parts))
    return tuple(parsed) or DEFAULT_RESOLVERS


def _cache_key(domain: str, record_type: str, ip: str) -> str:
    return f"dns-propagation:v2:{domain}:{record_type}:{ip}"


def _cached_result(domain: str, record_type: str, ip: str) -> dict[str, Any] | None:
    if extensions.redis_cache is None:
        return None
    try:
        payload = extensions.redis_cache.get(_cache_key(domain, record_type, ip))
        return json.loads(payload) if payload else None
    except Exception:
        return None


def _store_result(domain: str, record_type: str, ip: str, result: dict[str, Any]) -> None:
    if extensions.redis_cache is None:
        return
    try:
        ttl = int(os.environ.get("DNS_PROPAGATION_CACHE_TTL_SECONDS", "60"))
        extensions.redis_cache.set(_cache_key(domain, record_type, ip), json.dumps(result), ex=max(1, ttl))
    except Exception:
        pass


def _no_nameserver_status(exc: dns.resolver.NoNameservers) -> str:
    detail = str(exc).upper()
    if "SERVFAIL" in detail:
        return "servfail"
    if "REFUSED" in detail:
        return "refused"
    return "no_nameservers"


def _query_resolver(
    provider: str, ip: str, server: str, domain: str, record_type: str
) -> dict[str, Any]:
    cached = _cached_result(domain, record_type, ip)
    if cached is not None:
        cached["cached"] = True
        return cached

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ip]
    timeout = max(0.2, float(os.environ.get("DNS_PROPAGATION_TIMEOUT_SECONDS", "3")))
    resolver.timeout = timeout
    resolver.lifetime = timeout
    started = time.monotonic()
    values: list[str] = []
    ttl: int | None = None
    status = "ok"

    try:
        answer = resolver.resolve(domain, record_type, search=False)
        values = sorted({rdata.to_text() for rdata in answer})
        ttl = answer.rrset.ttl if answer.rrset is not None else None
    except dns.resolver.NXDOMAIN:
        status = "no_record"
    except dns.resolver.NoAnswer:
        status = "no_answer"
    except dns.exception.Timeout:
        status = "timeout"
    except dns.resolver.NoNameservers as exc:
        status = _no_nameserver_status(exc)
    except dns.exception.DNSException:
        status = "error"

    elapsed_ms = round((time.monotonic() - started) * 1000)
    result = {
        "provider": provider,
        "server": server,
        "resolver_ip": ip,
        "values": values,
        "ttl": ttl,
        "response_time_ms": elapsed_ms,
        "status": status,
        "status_message": ERROR_MESSAGES.get(status, ERROR_MESSAGES["error"]),
        "cached": False,
    }
    _store_result(domain, record_type, ip, result)
    return result


def _consolidate(domain: str, record_type: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    successful = [r for r in results if r["status"] == "ok"]
    signatures = [tuple(r["values"]) for r in successful]
    counts = Counter(signatures)
    majority_signature, majority_count = counts.most_common(1)[0] if counts else ((), 0)
    total = len(results)
    score = round(majority_count / total * 100) if total else 0
    failures = total - len(successful)

    if score >= 80 and failures <= max(1, total // 5):
        overall_status, status_label = "propagated", "DNS propagado"
    elif successful and majority_count >= max(2, total // 3):
        overall_status, status_label = "partial", "Propagação parcial"
    else:
        overall_status, status_label = "problem", "Possível problema de DNS"

    for result in results:
        result["matches_majority"] = result["status"] == "ok" and tuple(result["values"]) == majority_signature

    groups = [
        {"values": list(signature), "resolver_count": count}
        for signature, count in counts.most_common()
    ]
    timings = [r["response_time_ms"] for r in results if r["status"] == "ok" and not r.get("cached")]
    average_ms = round(sum(timings) / len(timings)) if timings else None

    if not successful:
        explanation = "Nenhum dos servidores DNS consultados retornou o registro. Verifique o hostname e a configuração DNS."
    elif len(counts) == 1 and len(successful) == total:
        explanation = f"Os {total} servidores DNS consultados retornaram a mesma resposta. Isso indica alta consistência entre os resolvers verificados."
    else:
        explanation = (
            f"{majority_count} dos {total} servidores DNS consultados retornaram a resposta predominante. "
            "Diferenças podem ocorrer após uma alteração recente ou enquanto registros antigos permanecem em cache."
        )

    return {
        "domain": domain,
        "record_type": record_type,
        "resolvers": results,
        "resolver_count": total,
        "response_count": len(successful),
        "matching_count": majority_count,
        "different_count": len(successful) - majority_count,
        "distinct_answer_count": len(counts),
        # "Propagated" is intentionally strict: every successful resolver
        # must agree. The score still communicates the dominant answer when
        # a minority is stale, but disagreement is not full propagation.
        "propagated": len(counts) == 1 and len(successful) == total,
        "overall_status": overall_status,
        "status_label": status_label,
        "score": score,
        "average_response_time_ms": average_ms,
        "answer_groups": groups,
        "explanation": explanation,
    }


class DnsPropagationCheckerTool(BaseTool):
    slug = "dns-propagation-checker"
    name = "DNS Propagation Checker"
    category_slug = "dns"
    short_description = "Verifique a consistência de registros DNS em dez resolvers públicos."
    description = "Consulte registros DNS em paralelo nos servidores da Cloudflare, Google, Quad9, OpenDNS e AdGuard."
    icon = "globe"
    input_type = InputType.DOMAIN
    input_placeholder = "exemplo.com.br"
    public_url_prefix = "dns/propagation"
    ttl_seconds = 60
    rate_limit_per_minute = 2  # 20 consultas por 10 minutos, no limitador existente por minuto
    analyzer_version = 2
    secondary_input_field = "record_type"

    def validate_input(self, raw_input: str) -> str:
        record_type_raw, sep, domain_raw = raw_input.partition("::")
        if not sep:
            record_type_raw, domain_raw = "", raw_input
        record_type = record_type_raw.strip().upper() or "A"
        if record_type not in SUPPORTED_RECORD_TYPES:
            raise ToolValidationError(
                "Tipo de registro não suportado. Use A, AAAA, CNAME, MX, NS, TXT, SOA ou CAA.",
                field_name="record_type",
            )
        if len(domain_raw.strip()) > 2048:
            raise ToolValidationError("O hostname informado é muito longo.", field_name="input_value")
        return f"{record_type}::{clean_domain_input(domain_raw)}"

    def normalize_input(self, cleaned_input: str) -> str:
        record_type, _, domain = cleaned_input.partition("::")
        normalized = normalize_domain(domain)
        if len(normalized) > 253:
            raise ToolValidationError("O hostname deve ter no máximo 253 caracteres.", field_name="input_value")
        return f"{record_type}::{normalized}"

    def execute(self, normalized_input: str) -> ToolResult:
        record_type, domain = normalized_input.split("::", 1)
        resolvers = _configured_resolvers()
        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=len(resolvers), thread_name_prefix="dns-propagation") as executor:
            futures = {
                executor.submit(_query_resolver, r.provider, r.ip, r.server, domain, record_type): r
                for r in resolvers
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    r = futures[future]
                    results.append({
                        "provider": r.provider, "server": r.server, "resolver_ip": r.ip,
                        "values": [], "ttl": None, "response_time_ms": None, "status": "error",
                        "status_message": ERROR_MESSAGES["error"], "cached": False,
                    })
        order = {r.ip: index for index, r in enumerate(resolvers)}
        results.sort(key=lambda item: order[item["resolver_ip"]])
        data = _consolidate(domain, record_type, results)
        summary = f"{data['matching_count']} de {data['resolver_count']} resolvers apresentam a resposta predominante. {data['status_label']}."
        return ToolResult(success=True, summary=summary, data=data, raw={"resolvers": results})

    def public_slug(self, normalized_input: str) -> str:
        record_type, domain = normalized_input.split("::", 1)
        return f"{record_type.lower()}-{domain}"
