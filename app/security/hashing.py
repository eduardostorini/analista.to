"""Hash de IP/User-Agent com salt rotativo, e chaves de deduplicação de consultas.

Nunca armazenamos IP em texto puro (seção 13). O salt "atual" é usado para
gerar novos hashes; salts antigos continuam configurados apenas para permitir
comparações com hashes já persistidos até expirarem naturalmente (TTL/expurgo).
"""
from __future__ import annotations

import hashlib
import hmac

from flask import current_app


def _current_salt() -> str:
    salts = current_app.config["IP_HASH_SALTS"]
    current_id = current_app.config["IP_HASH_CURRENT_SALT_ID"]
    try:
        return salts[current_id]
    except KeyError as exc:
        raise RuntimeError(
            f"IP_HASH_CURRENT_SALT_ID={current_id!r} não encontrado em IP_HASH_SALTS"
        ) from exc


def hash_ip(ip_address: str) -> str:
    return hmac.new(_current_salt().encode(), ip_address.encode(), hashlib.sha256).hexdigest()


def hash_user_agent(user_agent: str) -> str:
    return hmac.new(_current_salt().encode(), user_agent.encode(), hashlib.sha256).hexdigest()


def compute_input_hash(normalized_input: str) -> str:
    return hashlib.sha256(normalized_input.encode()).hexdigest()


def compute_dedupe_key(tool_slug: str, normalized_input: str, analyzer_version: int) -> str:
    payload = f"{tool_slug}:{normalized_input}:{analyzer_version}"
    return hashlib.sha256(payload.encode()).hexdigest()
