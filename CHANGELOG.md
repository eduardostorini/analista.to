# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [0.1.0] — Fase 1 (MVP)

### Adicionado

- Arquitetura completa: Flask + Celery + PostgreSQL + Redis, 100% via Docker
  Compose (dev e produção).
- Registro central de ferramentas (`BaseTool`/`ToolRegistry`) com sincronização
  código → banco via `flask sync-tools`.
- 15 ferramentas do MVP: DNS Lookup, MX Lookup, TXT Lookup, WHOIS/RDAP,
  IP Lookup, Title e Meta Tags, Robots.txt Checker, Sitemap Checker,
  HTTP Headers, Redirect Checker, Detector de Tecnologias,
  SSL Certificate Checker, Security Headers, SPF Checker, DMARC Checker.
- Processamento assíncrono com barra de status em tempo real (SSE + fallback
  para polling).
- Deduplicação/cache por TTL configurável por ferramenta.
- Geração de páginas HTML estáticas para resultados públicos elegíveis, com
  regras de indexabilidade (`index`/`noindex`) e sitemaps segmentados.
- Proteção contra SSRF, CAPTCHA (Cap self-hosted/matemático), rate
  limiting em múltiplas camadas, hash de IP com salt rotativo, bloqueio de
  origens abusivas.
- Painel administrativo: categorias, ferramentas, consultas (com
  reprocessamento/exclusão), páginas geradas, sitemaps, eventos de abuso.
- URLs públicas de resultado sempre legíveis, baseadas na entrada
  normalizada (ex.: `/dns/exemplo.com/`), nunca em identificadores aleatórios.
- Suíte de testes cobrindo segurança, ferramentas, geração de páginas,
  sitemaps e painel administrativo.

[0.1.0]: https://github.com/analisa-to/analisa-to/releases/tag/v0.1.0
