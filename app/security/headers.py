"""Cabeçalhos de segurança aplicados a toda resposta (CSP, HSTS, etc.)."""
from __future__ import annotations

from flask import Flask, Response

_CSP = (
    "default-src 'self'; "
    # 'unsafe-eval' é necessário pelo build padrão do Alpine.js, que avalia
    # expressões de diretiva (x-show, @click etc.) via Function(). script-src
    # continua restrito a 'self' + domínios de CAPTCHA — sem 'unsafe-inline'
    # e sem origens externas arbitrárias, o que limita bastante o risco real.
    # Trocar para o build @alpinejs/csp remove essa necessidade; ver SECURITY.md.
    "script-src 'self' 'unsafe-eval' https://challenges.cloudflare.com https://hcaptcha.com https://*.hcaptcha.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "frame-src https://challenges.cloudflare.com https://hcaptcha.com https://*.hcaptcha.com; "
    "connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'self';"
)


def apply_security_headers(app: Flask) -> None:
    @app.after_request
    def _set_security_headers(response: Response) -> Response:
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"
        )
        if not app.debug and not app.testing:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"
            )
        return response
