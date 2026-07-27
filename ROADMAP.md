# Roadmap

O Analista.to começou com 15 ferramentas (Fase 1), mas a arquitetura foi
desenhada para suportar mais de 100 sem alterar layout, rotas genéricas ou
banco de dados. A versão sempre atualizada deste roadmap também está
publicada em `/roadmap/` no site.

## Fase 2 (planejada)

- **DNS:** DNSSEC Checker, propagação DNS entre múltiplos resolvedores,
  reverse DNS em lote, comparação entre provedores DNS.
- **Domínio e IP:** ASN Lookup dedicado, reverse IP, detecção de CDN/hosting,
  verificação de IPv6.
- **SEO:** verificador de headings, Schema Markup Checker, verificador de
  indexabilidade, geradores de meta tags/robots.txt/sitemap, visualizador de
  snippet do Google, verificador de hreflang e de `llms.txt`.
- **HTTP e servidor:** Status Code Checker isolado, Compression/Gzip/Brotli
  Checker, verificação de HTTP/2 e HTTP/3, verificador de porta individual.
- **SSL e segurança:** cadeia completa do certificado, TLS Version Checker,
  CSP Checker dedicado, Mixed Content Checker, Cookie Security Checker,
  CORS Checker, MTA-STS/TLS-RPT Checker.
- **E-mail:** DKIM Lookup, verificador de domínio descartável, geradores de
  SPF/DMARC, analisador de cabeçalhos de e-mail.

## Fase 3 (novas categorias)

- **Performance:** tamanho de página, lazy loading, cache de recursos,
  recursos bloqueadores de renderização, scripts de terceiros.
- **Desenvolvedores:** JSON Formatter/Validator, Base64/URL Encode-Decode,
  Hash Generator, UUID Generator, Timestamp Converter, Regex Tester, JWT
  Decoder, minificadores de HTML/CSS/JS, gerador de `.htaccess` e de regras
  Nginx.

## Infraestrutura e plataforma

- PgBouncer para pooling em alto volume (preparado em
  [`docs/postgres-profiles.md`](docs/postgres-profiles.md)).
- Particionamento de `searches`/`search_results` por data.
- Autenticação em dois fatores (TOTP) no painel administrativo.
- Build Alpine.js com CSP-safe (`@alpinejs/csp`), removendo a necessidade de
  `unsafe-eval` na Content-Security-Policy.

## Sugestões

Envie para **sugestoes@analista.to** ou abra uma issue.
