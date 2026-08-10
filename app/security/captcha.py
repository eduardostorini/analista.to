"""Abstração de CAPTCHA com múltiplos providers (seção 19).

Selecionado por `CAPTCHA_PROVIDER`: altcha | math | none. Altcha
(https://altcha.org) é o provider self-hosted padrão (proof-of-work via
KDF, sem Google e sem telemetria) — validado no backend com a biblioteca
`altcha`. O desafio matemático é gerado no servidor, com token assinado
(itsdangerous) de curta validade; a resposta correta nunca é enviada ao
client e o token é invalidado após o uso (marcado em Redis) ou depois de N
tentativas erradas.
"""
from __future__ import annotations

import random
import secrets
from abc import ABC, abstractmethod

from flask import current_app
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

_MATH_SALT = "analisa-math-captcha"


class CaptchaError(Exception):
    def __init__(self, message: str, reason: str = "captcha_failed"):
        super().__init__(message)
        self.reason = reason


class CaptchaProvider(ABC):
    @abstractmethod
    def verify(self, payload: dict) -> None:
        """Levanta CaptchaError se o desafio não foi resolvido corretamente."""


class NoopCaptchaProvider(CaptchaProvider):
    """Usado apenas em desenvolvimento/testes (`CAPTCHA_PROVIDER=none`)."""

    def verify(self, payload: dict) -> None:
        return None


class AltchaCaptchaProvider(CaptchaProvider):
    """Altcha (https://altcha.org) — proof-of-work via KDF, validado
    localmente no backend com a biblioteca `altcha` (sem chamadas externas)."""

    def verify(self, payload: dict) -> None:
        token = payload.get("altcha")
        if not token:
            raise CaptchaError("Missing ALTCHA payload", "missing_token")

        cfg = current_app.config
        hmac_secret = cfg.get("ALTCHA_HMAC_SECRET")
        if not hmac_secret:
            raise CaptchaError("ALTCHA is not configured (ALTCHA_HMAC_SECRET missing)", "provider_error")

        from altcha import verify_solution

        hmac_key_secret = cfg.get("ALTCHA_HMAC_KEY_SECRET") or None
        result = verify_solution(
            token,
            hmac_secret,
            hmac_key_secret=hmac_key_secret,
        )
        if not result.verified:
            if result.expired:
                raise CaptchaError("ALTCHA challenge expired", "expired")
            if result.invalid_signature:
                raise CaptchaError("Invalid ALTCHA signature", "invalid_signature")
            raise CaptchaError("Invalid CAPTCHA", "invalid_captcha")


class MathCaptchaProvider(CaptchaProvider):
    """Desafio "quanto é X + Y", com token assinado e uso único via Redis."""

    def _serializer(self) -> URLSafeTimedSerializer:
        return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=_MATH_SALT)

    def generate(self) -> dict:
        a, b = random.randint(2, 20), random.randint(2, 20)
        answer = a + b
        nonce = secrets.token_urlsafe(9)
        token = self._serializer().dumps({"answer": answer, "nonce": nonce})
        return {"question": f"Quanto é {a} + {b}?", "token": token}

    def verify(self, payload: dict) -> None:
        token = payload.get("math_token")
        answer = payload.get("math_answer")
        if not token or answer in (None, ""):
            raise CaptchaError("Incomplete math challenge", "missing_token")

        ttl = current_app.config["MATH_CHALLENGE_TTL_SECONDS"]
        try:
            data = self._serializer().loads(token, max_age=ttl)
        except SignatureExpired as exc:
            raise CaptchaError("Challenge expired, generate a new one", "expired") from exc
        except BadSignature as exc:
            raise CaptchaError("Invalid challenge", "invalid_token") from exc

        nonce = data["nonce"]
        from app.extensions import redis_cache

        attempts_key = f"captcha:math:attempts:{nonce}"
        used_key = f"captcha:math:used:{nonce}"

        if redis_cache is not None:
            if redis_cache.get(used_key):
                raise CaptchaError("This challenge has already been used", "already_used")

            max_attempts = current_app.config["MATH_CHALLENGE_MAX_ATTEMPTS"]
            attempts = redis_cache.incr(attempts_key)
            redis_cache.expire(attempts_key, ttl)
            if attempts > max_attempts:
                raise CaptchaError("Maximum number of attempts exceeded", "too_many_attempts")

        try:
            is_correct = int(answer) == int(data["answer"])
        except (TypeError, ValueError):
            is_correct = False

        if not is_correct:
            raise CaptchaError("Incorrect answer", "wrong_answer")

        if redis_cache is not None:
            redis_cache.set(used_key, "1", ex=ttl)


_PROVIDERS: dict[str, type[CaptchaProvider]] = {
    "altcha": AltchaCaptchaProvider,
    "math": MathCaptchaProvider,
    "none": NoopCaptchaProvider,
}


def get_captcha_provider() -> CaptchaProvider:
    name = current_app.config["CAPTCHA_PROVIDER"]
    provider_cls = _PROVIDERS.get(name, NoopCaptchaProvider)
    return provider_cls()


def verify_captcha(payload: dict) -> None:
    get_captcha_provider().verify(payload)
