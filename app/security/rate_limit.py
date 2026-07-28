"""Rate limiting em janela fixa, usando Redis (seção 19).

Cada consulta passa por múltiplas camadas independentes: volume global,
por IP, por IP+ferramenta (usa `tool.rate_limit_per_minute`, mais rígido
para ferramentas de rede), por sessão e por entrada consultada (evita que
uma única entrada seja martelada repetidamente por origens diferentes).
"""
from __future__ import annotations

from dataclasses import dataclass

from flask import current_app

from app import extensions


class RateLimitExceededError(Exception):
    def __init__(self, message: str, scope: str):
        super().__init__(message)
        self.scope = scope


@dataclass
class RateLimitRule:
    scope: str
    key: str
    limit: int
    window_seconds: int = 60


class RateLimiter:
    def __init__(self, redis_client=None) -> None:
        self._redis = redis_client if redis_client is not None else extensions.redis_rate_limit

    def check(self, rule: RateLimitRule) -> int:
        if self._redis is None:
            return 0

        redis_key = f"rl:{rule.key}"
        pipe = self._redis.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, rule.window_seconds, nx=True)
        count, _ = pipe.execute()

        if count > rule.limit:
            raise RateLimitExceededError(
                f"Limit of {rule.limit} requests/{rule.window_seconds}s exceeded ({rule.scope})",
                rule.scope,
            )
        return count


def enforce_rate_limits(*, tool_slug: str, tool_rate_limit: int, ip_hash: str, input_hash: str, session_id: str) -> None:
    cfg = current_app.config
    limiter = RateLimiter()

    limiter.check(RateLimitRule("global", "global", cfg["RATE_LIMIT_GLOBAL_PER_MINUTE"]))
    limiter.check(RateLimitRule("ip", f"ip:{ip_hash}", cfg["RATE_LIMIT_DEFAULT_PER_MINUTE"]))
    limiter.check(
        RateLimitRule("ip_tool", f"ip:{ip_hash}:tool:{tool_slug}", tool_rate_limit)
    )
    limiter.check(RateLimitRule("session", f"session:{session_id}", cfg["RATE_LIMIT_DEFAULT_PER_MINUTE"]))
    limiter.check(
        RateLimitRule("input", f"tool:{tool_slug}:input:{input_hash}", 3, window_seconds=300)
    )
