"""Bloqueio de origens abusivas por `ip_hash` (seção 23).

Como o IP nunca é armazenado em texto puro (seção 13), não é possível
bloquear "o IP X.X.X.X" diretamente — em vez disso, bloqueamos o hash, que é
determinístico por salt: qualquer requisição futura da mesma origem (mesmo
salt vigente) vai gerar o mesmo hash e ser bloqueada, sem nunca precisarmos
reverter o hash para descobrir o IP original.
"""
from __future__ import annotations

from app import extensions

_BLOCKLIST_KEY = "abuse:blocked_ip_hashes"


def is_blocked(ip_hash: str) -> bool:
    if extensions.redis_rate_limit is None:
        return False
    return bool(extensions.redis_rate_limit.sismember(_BLOCKLIST_KEY, ip_hash))


def block(ip_hash: str) -> None:
    if extensions.redis_rate_limit is not None:
        extensions.redis_rate_limit.sadd(_BLOCKLIST_KEY, ip_hash)


def unblock(ip_hash: str) -> None:
    if extensions.redis_rate_limit is not None:
        extensions.redis_rate_limit.srem(_BLOCKLIST_KEY, ip_hash)


def list_blocked() -> list[str]:
    if extensions.redis_rate_limit is None:
        return []
    return sorted(extensions.redis_rate_limit.smembers(_BLOCKLIST_KEY))
