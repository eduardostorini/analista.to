# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [0.1.0] — Phase 1 (MVP)

### Added

- Complete architecture: Flask + Celery + PostgreSQL + Redis, 100% via Docker
  Compose (dev and production).
- Central tool registry (`BaseTool`/`ToolRegistry`) with code → database sync via `flask sync-tools`.
- 15 MVP tools: DNS Lookup, MX Lookup, TXT Lookup, WHOIS/RDAP,
  IP Lookup, Title and Meta Tags, Robots.txt Checker, Sitemap Checker,
  HTTP Headers, Redirect Checker, Technology Detector,
  SSL Certificate Checker, Security Headers, SPF Checker, DMARC Checker.
- Asynchronous processing with real-time status bar (SSE + fallback
  to polling).
- Deduplication/cache by configurable TTL per tool.
- Static HTML page generation for eligible public results, with
  indexability rules (`index`/`noindex`) and segmented sitemaps.
- SSRF protection, CAPTCHA (self-hosted/math), rate limiting in multiple
  layers, IP hash with rotating salt, abusive origin blocking.
- Admin panel: categories, tools, queries (with reprocessing/deletion),
  generated pages, sitemaps, abuse events.
- Public result URLs always readable, based on normalized input
  (e.g., `/dns/example.com/`), never on random identifiers.
- Test suite covering security, tools, page generation,
  sitemaps, and admin panel.

[0.1.0]: https://github.com/analisa-to/analisa-to/releases/tag/v0.1.0