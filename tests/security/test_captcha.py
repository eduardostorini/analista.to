from __future__ import annotations

import re

import pytest

from app.security.captcha import CaptchaError, MathCaptchaProvider, NoopCaptchaProvider, AltchaCaptchaProvider


def test_noop_provider_always_passes():
    NoopCaptchaProvider().verify({})


def test_math_captcha_generates_question_and_token():
    provider = MathCaptchaProvider()
    challenge = provider.generate()
    assert re.match(r"^Quanto é \d+ \+ \d+\?$", challenge["question"])
    assert challenge["token"]


def _solve(question: str) -> int:
    a, b = (int(x) for x in re.findall(r"\d+", question))
    return a + b


def test_math_captcha_accepts_correct_answer():
    provider = MathCaptchaProvider()
    challenge = provider.generate()
    answer = _solve(challenge["question"])
    provider.verify({"math_token": challenge["token"], "math_answer": str(answer)})


def test_math_captcha_rejects_wrong_answer():
    provider = MathCaptchaProvider()
    challenge = provider.generate()
    with pytest.raises(CaptchaError) as exc_info:
        provider.verify({"math_token": challenge["token"], "math_answer": "999999"})
    assert exc_info.value.reason == "wrong_answer"


def test_math_captcha_token_is_single_use():
    provider = MathCaptchaProvider()
    challenge = provider.generate()
    answer = _solve(challenge["question"])
    provider.verify({"math_token": challenge["token"], "math_answer": str(answer)})

    with pytest.raises(CaptchaError) as exc_info:
        provider.verify({"math_token": challenge["token"], "math_answer": str(answer)})
    assert exc_info.value.reason == "already_used"


def test_math_captcha_blocks_after_max_attempts(app):
    app.config["MATH_CHALLENGE_MAX_ATTEMPTS"] = 2
    provider = MathCaptchaProvider()
    challenge = provider.generate()

    for _ in range(2):
        with pytest.raises(CaptchaError):
            provider.verify({"math_token": challenge["token"], "math_answer": "-1"})

    with pytest.raises(CaptchaError) as exc_info:
        provider.verify({"math_token": challenge["token"], "math_answer": "-1"})
    assert exc_info.value.reason == "too_many_attempts"


def test_math_captcha_missing_fields():
    provider = MathCaptchaProvider()
    with pytest.raises(CaptchaError) as exc_info:
        provider.verify({})
    assert exc_info.value.reason == "missing_token"


def test_altcha_provider_rejects_missing_payload(app):
    app.config["ALTCHA_HMAC_SECRET"] = "test-secret"
    provider = AltchaCaptchaProvider()
    with pytest.raises(CaptchaError) as exc_info:
        provider.verify({})
    assert exc_info.value.reason == "missing_token"


def test_altcha_provider_rejects_missing_secret(app):
    app.config["ALTCHA_HMAC_SECRET"] = ""
    provider = AltchaCaptchaProvider()
    with pytest.raises(CaptchaError) as exc_info:
        provider.verify({"altcha": "some-payload"})
    assert exc_info.value.reason == "provider_error"
