"""Cabeçalhos de segurança aplicados a toda resposta (CSP, HSTS, etc.)."""
from __future__ import annotations

from flask import Flask, Response


def _build_csp() -> str:
    return (
        "default-src 'self'; "
        # www.googletagmanager.com: carrega o container do GTM e o gtag.js.
        # www.google-analytics.com: SDK legado do Universal Analytics/gtag.
        # Liberados especificamente para permitir Google Analytics/Tag
        # Manager (injetados via code/head.txt e code/body.txt) sem abrir
        # 'unsafe-inline'/scripts de qualquer origem.
        "script-src 'self' 'unsafe-eval' https://www.googletagmanager.com https://www.google-analytics.com; "
        "style-src 'self' 'unsafe-inline'; "
        # https: (além de 'self'/data:) é necessário para o preview de imagem
        # do Open Graph Checker, que por natureza aponta para um domínio
        # externo arbitrário informado pelo usuário — sem isso o navegador
        # bloqueia a própria imagem que a ferramenta existe para mostrar.
        # Também cobre os pixels de fallback do Google Analytics.
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "frame-src https://www.openstreetmap.org https://www.googletagmanager.com; "
        # *.google-analytics.com / *.analytics.google.com: os endpoints de
        # coleta do GA4 usam subdomínios regionais (ex.: region1.google-
        # analytics.com), daí o wildcard em vez de listar cada um.
        "connect-src 'self' https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com; "
        "worker-src 'self' blob:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self';"
    )


def apply_security_headers(app: Flask) -> None:
    csp = _build_csp()

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
