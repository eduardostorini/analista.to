"""Abstração de CAPTCHA com múltiplos providers (seção 19).

Selecionado por `CAPTCHA_PROVIDER`: cap | math | none. Cap (https://trycap.dev)
é o provider self-hosted padrão (proof-of-work + verificação de instrumentação
do navegador, sem Google e sem telemetria) — validado no backend contra o
próprio serviço `analisa_cap` deste compose. O desafio matemático é gerado no
servidor, com token assinado (itsdangerous) de curta validade; a resposta
correta nunca é enviada ao client e o token é invalidado após o uso (marcado
em Redis) ou depois de N tentativas erradas.
"""
from __future__ import annotations

import random
import secrets
from abc import ABC, abstractmethod

import httpx
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


class CapCaptchaProvider(CaptchaProvider):
    """Cap (https://trycap.dev) — proof-of-work + verificação de
    instrumentação do navegador, validado contra o serviço `analisa_cap`
    self-hosted deste compose (compatível com o formato `siteverify` do
    reCAPTCHA/hCaptcha)."""

    def verify(self, payload: dict) -> None:
        token = payload.get("cap-token")
        if not token:
            raise CaptchaError("Token do Cap ausente", "missing_token")

        cfg = current_app.config
        site_key = cfg["CAP_SITE_KEY"]
        secret = cfg["CAP_SECRET_KEY"]
        if not site_key or not secret:
            raise CaptchaError("Cap não está configurado (CAP_SITE_KEY/CAP_SECRET_KEY ausentes)", "provider_error")

        verify_url = f"{cfg['CAP_INTERNAL_URL'].rstrip('/')}/{site_key}/siteverify"
        try:
            response = httpx.post(
                verify_url,
                json={"secret": secret, "response": token},
                timeout=5,
            )
            result = response.json()
        except httpx.HTTPError as exc:
            raise CaptchaError(f"Falha ao validar Cap: {exc}", "provider_error") from exc

        if not result.get("success"):
            raise CaptchaError("CAPTCHA inválido", "invalid_captcha")


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
            raise CaptchaError("Desafio matemático incompleto", "missing_token")

        ttl = current_app.config["MATH_CHALLENGE_TTL_SECONDS"]
        try:
            data = self._serializer().loads(token, max_age=ttl)
        except SignatureExpired as exc:
            raise CaptchaError("Desafio expirado, gere um novo", "expired") from exc
        except BadSignature as exc:
            raise CaptchaError("Desafio inválido", "invalid_token") from exc

        nonce = data["nonce"]
        from app.extensions import redis_cache

        attempts_key = f"captcha:math:attempts:{nonce}"
        used_key = f"captcha:math:used:{nonce}"

        if redis_cache is not None:
            if redis_cache.get(used_key):
                raise CaptchaError("Este desafio já foi utilizado", "already_used")

            max_attempts = current_app.config["MATH_CHALLENGE_MAX_ATTEMPTS"]
            attempts = redis_cache.incr(attempts_key)
            redis_cache.expire(attempts_key, ttl)
            if attempts > max_attempts:
                raise CaptchaError("Número máximo de tentativas excedido", "too_many_attempts")

        try:
            is_correct = int(answer) == int(data["answer"])
        except (TypeError, ValueError):
            is_correct = False

        if not is_correct:
            raise CaptchaError("Resposta incorreta", "wrong_answer")

        if redis_cache is not None:
            redis_cache.set(used_key, "1", ex=ttl)


_PROVIDERS: dict[str, type[CaptchaProvider]] = {
    "cap": CapCaptchaProvider,
    "math": MathCaptchaProvider,
    "none": NoopCaptchaProvider,
}


def get_captcha_provider() -> CaptchaProvider:
    name = current_app.config["CAPTCHA_PROVIDER"]
    provider_cls = _PROVIDERS.get(name, NoopCaptchaProvider)
    return provider_cls()


def verify_captcha(payload: dict) -> None:
    get_captcha_provider().verify(payload)
