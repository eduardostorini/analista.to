from __future__ import annotations

import pytest

from app.security.rate_limit import RateLimitExceededError, RateLimitRule, RateLimiter, enforce_rate_limits


def test_rate_limiter_allows_up_to_limit():
    limiter = RateLimiter()
    rule = RateLimitRule("test", "unit-test-key-1", limit=3)
    assert limiter.check(rule) == 1
    assert limiter.check(rule) == 2
    assert limiter.check(rule) == 3


def test_rate_limiter_blocks_after_limit():
    limiter = RateLimiter()
    rule = RateLimitRule("test", "unit-test-key-2", limit=2)
    limiter.check(rule)
    limiter.check(rule)
    with pytest.raises(RateLimitExceededError) as exc_info:
        limiter.check(rule)
    assert exc_info.value.scope == "test"


def test_enforce_rate_limits_blocks_after_tool_specific_limit(app):
    app.config["RATE_LIMIT_GLOBAL_PER_MINUTE"] = 1000
    app.config["RATE_LIMIT_DEFAULT_PER_MINUTE"] = 1000

    kwargs = dict(
        tool_slug="dns-lookup",
        tool_rate_limit=2,
        ip_hash="ip-hash-abc",
        input_hash="input-hash-abc",
        session_id="session-abc",
    )
    enforce_rate_limits(**kwargs)
    enforce_rate_limits(**kwargs)
    with pytest.raises(RateLimitExceededError) as exc_info:
        enforce_rate_limits(**kwargs)
    assert exc_info.value.scope == "ip_tool"


def test_enforce_rate_limits_independent_per_tool(app):
    app.config["RATE_LIMIT_GLOBAL_PER_MINUTE"] = 1000
    app.config["RATE_LIMIT_DEFAULT_PER_MINUTE"] = 1000

    enforce_rate_limits(
        tool_slug="dns-lookup",
        tool_rate_limit=1,
        ip_hash="ip-hash-def",
        input_hash="input-hash-def-1",
        session_id="session-def",
    )
    # Ferramenta diferente, mesmo IP: não deve ser bloqueado pelo limite da outra.
    enforce_rate_limits(
        tool_slug="mx-lookup",
        tool_rate_limit=1,
        ip_hash="ip-hash-def",
        input_hash="input-hash-def-2",
        session_id="session-def",
    )
