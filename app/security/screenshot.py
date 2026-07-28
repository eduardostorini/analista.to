"""Captura de screenshot de sites com Playwright (Website Hosting Checker).

O Chromium faz suas próprias requisições de rede — não passa pelo
`SafeHTTPClient`/httpx — então a proteção contra SSRF daquele módulo não se
aplica aqui automaticamente. Reaproveitamos a mesma política de bloqueio de
IPs privados/reservados (`resolve_host_ips`), mas aplicada via interceptação
de cada requisição do navegador (`page.route`), cobrindo a navegação inicial,
redirecionamentos e sub-recursos da página.

Best-effort por natureza: qualquer falha (timeout, DNS, site fora do ar,
erro do Chromium) resulta em `False`, e a ferramenta chamadora deve tratar
isso como "sem preview disponível" — nunca como erro fatal da consulta.
"""
from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlsplit

from flask import current_app

from app.security.ssrf import SSRFBlockedError, resolve_host_ips

logger = logging.getLogger(__name__)

_ALLOWED_SCHEMES = {"http", "https"}


def _is_request_allowed(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in _ALLOWED_SCHEMES or not parts.hostname:
        return False
    try:
        resolve_host_ips(parts.hostname)
    except SSRFBlockedError:
        return False
    except Exception:
        return False
    return True


def capture_screenshot(url: str, dest_path: Path) -> bool:
    """Navega até `url` num Chromium headless e salva um PNG em `dest_path`.

    Retorna `True` em caso de sucesso, `False` em qualquer falha.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:  # pragma: no cover - binário só existe na imagem do worker
        logger.warning("capture_screenshot: Playwright/Chromium não disponível neste container")
        return False

    if not _is_request_allowed(url):
        return False

    cfg = current_app.config
    timeout_ms = cfg["SCREENSHOT_NAV_TIMEOUT_SECONDS"] * 1000

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"]
            )
            try:
                context = browser.new_context(
                    viewport={
                        "width": cfg["SCREENSHOT_VIEWPORT_WIDTH"],
                        "height": cfg["SCREENSHOT_VIEWPORT_HEIGHT"],
                    },
                    user_agent=cfg["OUTBOUND_USER_AGENT"],
                )
                try:
                    page = context.new_page()
                    page.route("**/*", lambda route: (
                        route.continue_() if _is_request_allowed(route.request.url) else route.abort()
                    ))
                    page.goto(url, timeout=timeout_ms, wait_until="load")
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=str(dest_path), timeout=timeout_ms)
                finally:
                    context.close()
            finally:
                browser.close()
        return True
    except Exception as exc:
        logger.info("capture_screenshot: falha ao capturar %s: %s", url, exc)
        dest_path.unlink(missing_ok=True)
        return False
