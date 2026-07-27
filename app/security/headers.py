"""Cabeçalhos de segurança aplicados a toda resposta (CSP, HSTS, etc.)."""
from __future__ import annotations

from flask import Flask, Response


def _build_csp(cap_public_url: str) -> str:
    # cap_public_url é a origem do serviço `analisa_cap` (CAPTCHA self-hosted,
    # https://trycap.dev) — o navegador do visitante fala diretamente com ele
    # para carregar o widget (script-src), resolver o desafio via fetch/XHR
    # (connect-src) e rodar o worker de proof-of-work (worker-src, via blob:).
    return (
        "default-src 'self'; "
        # 'unsafe-eval' é necessário pelo build padrão do Alpine.js, que avalia
        # expressões de diretiva (x-show, @click etc.) via Function(). script-src
        # continua restrito a 'self' + origem do Cap — sem 'unsafe-inline' e sem
        # outras origens externas arbitrárias, o que limita bastante o risco real.
        # Trocar para o build @alpinejs/csp remove essa necessidade; ver SECURITY.md.
        f"script-src 'self' 'unsafe-eval' {cap_public_url}; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "frame-src https://www.openstreetmap.org; "
        f"connect-src 'self' {cap_public_url}; "
        f"worker-src 'self' blob: {cap_public_url}; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self';"
    )


def apply_security_headers(app: Flask) -> None:
    csp = _build_csp(app.config["CAP_PUBLIC_URL"])

    @app.after_request
    def _set_security_headers(response: Response) -> Response:
        response.headers.setdefault("Content-Security-Policy", csp)
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
