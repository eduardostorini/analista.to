"""Configuração da aplicação, carregada inteiramente de variáveis de ambiente."""
from __future__ import annotations

import os
from datetime import timedelta


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def _list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_ip_hash_salts(value: str | None) -> dict[str, str]:
    """Formato: "1:salt-um,2:salt-dois" -> {"1": "salt-um", "2": "salt-dois"}."""
    salts: dict[str, str] = {}
    for entry in _list(value):
        if ":" not in entry:
            continue
        salt_id, salt_value = entry.split(":", 1)
        salts[salt_id.strip()] = salt_value.strip()
    return salts


class BaseConfig:
    """Configuração compartilhada por todos os ambientes."""

    SITE_NAME = os.environ.get("SITE_NAME", "Analista.to")
    SITE_URL = os.environ.get("SITE_URL", "http://localhost:18473").rstrip("/")
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-insecure-key")
    ADMIN_URL_PREFIX = os.environ.get("ADMIN_URL_PREFIX", "/admin")
    VERSION = os.environ.get("VERSION", "0.0.0")

    # --- Banco de dados ---------------------------------------------------
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql+psycopg://analisa:analisa@localhost:5432/analisa_to"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_size": _int(os.environ.get("SQLALCHEMY_POOL_SIZE"), 10),
        "max_overflow": _int(os.environ.get("SQLALCHEMY_MAX_OVERFLOW"), 5),
        "pool_recycle": _int(os.environ.get("SQLALCHEMY_POOL_RECYCLE"), 1800),
        "pool_pre_ping": True,
    }

    # --- Redis / Celery -----------------------------------------------------
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    CACHE_REDIS_URL = os.environ.get("CACHE_REDIS_URL", REDIS_URL)
    RATE_LIMIT_REDIS_URL = os.environ.get("RATE_LIMIT_REDIS_URL", REDIS_URL)
    CELERY = {
        "broker_url": os.environ.get("CELERY_BROKER_URL", REDIS_URL),
        "result_backend": os.environ.get("CELERY_RESULT_BACKEND", REDIS_URL),
        "task_serializer": "json",
        "result_serializer": "json",
        "accept_content": ["json"],
        "timezone": "UTC",
        "enable_utc": True,
        "task_track_started": True,
        "worker_max_tasks_per_child": 200,
        "broker_connection_retry_on_startup": True,
        "task_soft_time_limit": 45,
        "task_time_limit": 60,
        "beat_schedule": {
            "regenerate-sitemaps": {
                "task": "app.tasks.sitemap_tasks.regenerate_sitemaps",
                "schedule": 3600.0,
            },
            "cleanup-expired-pages": {
                "task": "app.tasks.maintenance_tasks.cleanup_expired_searches",
                "schedule": 21600.0,
            },
            "check-monitoring-domains": {
                "task": "app.tasks.monitoring_tasks.run_periodic_checks",
                "schedule": 300.0,  # Run monitoring scanner task every 5 minutes
            },
        },
    }

    # --- Hash de IP / User-Agent com rotação de salt --------------------------
    IP_HASH_SALTS = _parse_ip_hash_salts(os.environ.get("IP_HASH_SALTS", "1:dev-salt"))
    IP_HASH_CURRENT_SALT_ID = os.environ.get("IP_HASH_CURRENT_SALT_ID", "1")

    # --- CAPTCHA ------------------------------------------------------------
    CAPTCHA_PROVIDER = os.environ.get("CAPTCHA_PROVIDER", "altcha")
    ALTCHA_HMAC_SECRET = os.environ.get("ALTCHA_HMAC_SECRET", "")
    ALTCHA_HMAC_KEY_SECRET = os.environ.get("ALTCHA_HMAC_KEY_SECRET", "")
    MATH_CHALLENGE_TTL_SECONDS = _int(os.environ.get("MATH_CHALLENGE_TTL_SECONDS"), 300)
    MATH_CHALLENGE_MAX_ATTEMPTS = _int(os.environ.get("MATH_CHALLENGE_MAX_ATTEMPTS"), 5)

    # --- Rate limiting --------------------------------------------------------
    RATE_LIMIT_ENABLED = _bool(os.environ.get("RATE_LIMIT_ENABLED"), True)
    RATE_LIMIT_DEFAULT_PER_MINUTE = _int(os.environ.get("RATE_LIMIT_DEFAULT_PER_MINUTE"), 10)
    RATE_LIMIT_NETWORK_TOOLS_PER_MINUTE = _int(os.environ.get("RATE_LIMIT_NETWORK_TOOLS_PER_MINUTE"), 5)
    RATE_LIMIT_GLOBAL_PER_MINUTE = _int(os.environ.get("RATE_LIMIT_GLOBAL_PER_MINUTE"), 600)

    # --- DNS Propagation Checker -------------------------------------------
    DNS_PROPAGATION_TIMEOUT_SECONDS = _int(os.environ.get("DNS_PROPAGATION_TIMEOUT_SECONDS"), 3)
    DNS_PROPAGATION_CACHE_TTL_SECONDS = _int(os.environ.get("DNS_PROPAGATION_CACHE_TTL_SECONDS"), 60)

    # --- Requisições externas / SSRF -------------------------------------------
    OUTBOUND_USER_AGENT = os.environ.get(
        "OUTBOUND_USER_AGENT", "AnalistaToBot/1.0 (+https://analista.to/sobre/bot)"
    )
    OUTBOUND_CONNECT_TIMEOUT_SECONDS = _int(os.environ.get("OUTBOUND_CONNECT_TIMEOUT_SECONDS"), 5)
    OUTBOUND_READ_TIMEOUT_SECONDS = _int(os.environ.get("OUTBOUND_READ_TIMEOUT_SECONDS"), 10)
    OUTBOUND_MAX_REDIRECTS = _int(os.environ.get("OUTBOUND_MAX_REDIRECTS"), 5)
    OUTBOUND_MAX_RESPONSE_BYTES = _int(os.environ.get("OUTBOUND_MAX_RESPONSE_BYTES"), 10 * 1024 * 1024)
    OUTBOUND_ALLOWED_PORTS = {int(p) for p in _list(os.environ.get("OUTBOUND_ALLOWED_PORTS", "80,443"))}

    # --- Open Ports Lookup ----------------------------------------------------------
    # Conexões TCP em paralelo para manter o scan de ~85 portas rápido mesmo com
    # portas "filtradas" (sem resposta) que só resolvem no timeout individual.
    PORT_SCAN_TIMEOUT_MS = _int(os.environ.get("PORT_SCAN_TIMEOUT_MS"), 1500)
    PORT_SCAN_MAX_WORKERS = _int(os.environ.get("PORT_SCAN_MAX_WORKERS"), 40)
    TCP_SAFE_PORTS = {int(p) for p in _list(os.environ.get(
        "TCP_SAFE_PORTS", "21,22,25,53,80,110,143,443,465,587,993,995,3306,5432,6379,8080,8443"
    ))}

    # --- Blocklist Lookup (DNSBL/RBL) -----------------------------------------------
    # DNSBL zones costumam responder mais devagar que um connect TCP direto —
    # timeout maior que o do Open Ports Lookup, mas ainda em paralelo.
    DNSBL_TIMEOUT_MS = _int(os.environ.get("DNSBL_TIMEOUT_MS"), 4000)
    DNSBL_MAX_WORKERS = _int(os.environ.get("DNSBL_MAX_WORKERS"), 30)

    # --- Fontes de dados de ferramentas específicas -----------------------------
    IP_GEOLOCATION_API_URL = os.environ.get(
        "IP_GEOLOCATION_API_URL",
        "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,timezone,lat,lon,isp,org,as,proxy,hosting,mobile,query",
    )
    TOR_EXIT_LIST_URL = os.environ.get("TOR_EXIT_LIST_URL", "https://check.torproject.org/torbulkexitlist")
    TOR_EXIT_LIST_CACHE_SECONDS = _int(os.environ.get("TOR_EXIT_LIST_CACHE_SECONDS"), 3600)
    REVERSE_IP_LOOKUP_API_URL = os.environ.get(
        "REVERSE_IP_LOOKUP_API_URL", "https://api.hackertarget.com/reverseiplookup/?q={ip}"
    )
    # Fonte primária (Certificate Transparency) para o Subdomain Finder — mais
    # abrangente, mas o crt.sh é conhecido por instabilidade/lentidão
    # ocasional, daí o fallback abaixo.
    SUBDOMAIN_CT_LOGS_API_URL = os.environ.get(
        "SUBDOMAIN_CT_LOGS_API_URL", "https://crt.sh/?q=%25.{domain}&output=json"
    )
    SUBDOMAIN_FALLBACK_API_URL = os.environ.get(
        "SUBDOMAIN_FALLBACK_API_URL", "https://api.hackertarget.com/hostsearch/?q={domain}"
    )
    # Google PageSpeed Insights (Core Web Vitals / Lighthouse). Funciona sem
    # chave em volume baixo (cota compartilhada); definir uma chave própria
    # evita rate limiting em produção. Ver https://developers.google.com/speed/docs/insights/v5/get-started
    GOOGLE_PAGESPEED_API_URL = os.environ.get(
        "GOOGLE_PAGESPEED_API_URL", "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
    )
    # `PAGESPEED` is kept as a backwards-compatible local alias.
    GOOGLE_PAGESPEED_API_KEY = os.environ.get("GOOGLE_PAGESPEED_API_KEY") or os.environ.get("PAGESPEED", "")
    # Mantido abaixo do soft_time_limit (45s) da task run_search (app/tasks/search_tasks.py)
    # para que o próprio PageSpeed Checker devolva um erro claro antes do worker
    # matar a task — ver app/tools/performance/pagespeed_checker.py.
    PAGESPEED_READ_TIMEOUT_SECONDS = _int(os.environ.get("PAGESPEED_READ_TIMEOUT_SECONDS"), 35)

    # --- Admin ------------------------------------------------------------------
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@analista.to")
    ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")

    # --- Páginas estáticas / SEO --------------------------------------------------
    GENERATED_PAGES_DIR = os.environ.get("GENERATED_PAGES_DIR", "/data/generated-pages")
    SITEMAPS_DIR = os.environ.get("SITEMAPS_DIR", "/data/sitemaps")

    # --- Screenshot de site (Website Hosting Checker) --------------------------
    SCREENSHOTS_DIR = os.environ.get("SCREENSHOTS_DIR", "/data/screenshots")
    SCREENSHOT_NAV_TIMEOUT_SECONDS = _int(os.environ.get("SCREENSHOT_NAV_TIMEOUT_SECONDS"), 10)
    SCREENSHOT_VIEWPORT_WIDTH = _int(os.environ.get("SCREENSHOT_VIEWPORT_WIDTH"), 1280)
    SCREENSHOT_VIEWPORT_HEIGHT = _int(os.environ.get("SCREENSHOT_VIEWPORT_HEIGHT"), 800)
    SITEMAP_MAX_URLS_PER_FILE = _int(os.environ.get("SITEMAP_MAX_URLS_PER_FILE"), 45000)
    # Depois de quantos dias uma página pública gerada é considerada
    # "expirada" (seção 16) e retirada do índice/sitemap automaticamente.
    GENERATED_PAGE_MAX_AGE_DAYS = _int(os.environ.get("GENERATED_PAGE_MAX_AGE_DAYS"), 30)

    # --- Observabilidade -----------------------------------------------------------
    METRICS_ENABLED = _bool(os.environ.get("METRICS_ENABLED"), True)
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    DMARC_REPORT_MAX_BYTES = _int(os.environ.get("DMARC_REPORT_MAX_BYTES"), 10 * 1024 * 1024)

    # --- Cookies / segurança ---------------------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    WTF_CSRF_TIME_LIMIT = None
    MAX_CONTENT_LENGTH = DMARC_REPORT_MAX_BYTES + 256 * 1024

    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True

    # Ative apenas se a aplicação estiver atrás de um proxy reverso confiável
    # que você mesmo controla (ex.: um load balancer gerenciado). Sem um
    # proxy real na frente, X-Forwarded-For pode ser forjado pelo cliente.
    TRUST_PROXY_HEADERS = _bool(os.environ.get("TRUST_PROXY_HEADERS"), False)


class DevelopmentConfig(BaseConfig):
    DEBUG = _bool(os.environ.get("FLASK_DEBUG"), True)
    SESSION_COOKIE_SECURE = False


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(BaseConfig):
    TESTING = True
    DEBUG = True
    RATE_LIMIT_ENABLED = True
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "TEST_DATABASE_URL", "postgresql+psycopg://analisa:analisa@localhost:5432/analisa_to_test"
    )
    CAPTCHA_PROVIDER = "none"


CONFIG_BY_NAME = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(name: str | None) -> type[BaseConfig]:
    return CONFIG_BY_NAME.get(name or os.environ.get("FLASK_ENV", "production"), ProductionConfig)
