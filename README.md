# Analista.to

Plataforma web de ferramentas técnicas para análise de **DNS, domínio/IP,
SEO, HTTP/servidor, SSL/segurança e e-mail** — consultas rápidas, explicadas,
processadas de forma assíncrona e, quando elegíveis, publicadas como páginas
estáticas otimizadas para buscadores.

> Este é o MVP (Fase 1): 15 ferramentas funcionais sobre uma arquitetura
> pensada para escalar a mais de 100 ferramentas sem alterar layout, rotas
> genéricas ou banco de dados a cada nova ferramenta adicionada.

## Sumário

- [Descrição](#descrição)
- [Stack](#stack)
- [Arquitetura](#arquitetura)
- [Instalação com Docker](#instalação-com-docker)
- [Comandos principais](#comandos-principais)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Como adicionar uma ferramenta](#como-adicionar-uma-ferramenta)
- [Variáveis de ambiente](#variáveis-de-ambiente)
- [Segurança](#segurança)
- [Testes](#testes)
- [Licença](#licença)

## Descrição

O usuário escolhe uma ferramenta, informa um domínio/URL/IP, resolve um
desafio anti-robô e recebe um relatório técnico em segundos — a consulta roda
em segundo plano (Celery) com uma barra de status atualizada em tempo real
via Server-Sent Events (com fallback automático para polling). Resultados
públicos elegíveis geram uma página estática compartilhável e indexável
(`/dns/exemplo.com/`, `/ssl/exemplo.com/` etc.), com regras explícitas de
`index`/`noindex` para nunca gerar páginas doorway ou de baixo valor.

*(Capturas de tela: veja `docs/screenshots/` — adicione as suas após o
primeiro `docker compose up`; nenhuma foi versionada neste MVP.)*

## Stack

**Backend:** Python 3.12, Flask 3, SQLAlchemy 2, Alembic, Celery 5, Redis,
PostgreSQL 16, Gunicorn (`gthread`), dnspython, httpx, marshmallow,
argon2-cffi, Flask-Login, Flask-WTF.

**Frontend:** Tailwind CSS, Alpine.js, JavaScript modular (build via esbuild),
sem React/Vue/jQuery/Bootstrap. Compilado no build da imagem Docker — Node.js
não é necessário para rodar em produção.

## Arquitetura

- **Registro central de ferramentas** (`app/tools/registry.py`): cada
  ferramenta é uma classe Python (`BaseTool`) auto-contida — validação,
  normalização, execução, resumo e metadados de SEO. A tabela `tools` no
  banco espelha o registro (via `flask sync-tools`) e guarda só os toggles
  administráveis (ativa/destaque/rate limit/TTL/indexável).
- **Fluxo de consulta:** formulário → CAPTCHA + rate limit → `SearchService`
  deduplica contra o TTL da ferramenta → Celery executa a ferramenta com
  proteção SSRF completa → status em tempo real via SSE/Redis pubsub →
  página estática gerada para resultados públicos elegíveis.
- **SEO programático:** `PageIndexabilityService` decide `index`/`noindex`
  por regras explícitas (seção 16 da especificação original); sitemaps
  segmentados por tipo de conteúdo, regenerados por Celery Beat.
- **Segurança:** guarda de SSRF com resolução + validação de IP antes de
  qualquer requisição (e a cada redirecionamento), CAPTCHA com múltiplos
  providers, rate limiting em várias camadas, hash de IP com salt rotativo
  (nunca texto puro), bloqueio de origens abusivas por hash.

Veja [`docs/architecture.md`](docs/architecture.md) para o detalhamento
completo (modelo de dados, diagrama do fluxo, decisões de design).

## Instalação com Docker

Pré-requisitos: Docker e Docker Compose.

```bash
cp .env.example .env
# edite pelo menos: SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD, IP_HASH_SALTS

docker compose up --build
```

`docker-compose.override.yml` é carregado automaticamente neste comando —
ele adiciona as portas de desenvolvimento (Postgres/Redis) e o serviço
`analisa_assets` (build de CSS/JS em modo watch). Produção usa só o arquivo
base, sem overrides (veja abaixo).

A aplicação sobe em `http://localhost:18473` (porta configurável via
`APP_HTTP_PORT`). Na primeira vez, rode as migrações e sincronize as
ferramentas:

```bash
docker compose exec analisa_web flask db upgrade
docker compose exec analisa_web flask sync-tools
```

Para gerar o hash da senha do admin:

```bash
docker compose exec analisa_web python scripts/hash_admin_password.py
# copie a linha impressa (ADMIN_PASSWORD_HASH=...) inteira para o seu .env
```

O comando já imprime o valor com cada `$` duplicado (`$$`) — isso é
obrigatório, não opcional: o Docker Compose interpreta `$algumacoisa` como
variável ao ler o `.env` e apaga silenciosamente o que não reconhece, o que
corrompe um hash Argon2 colado sem escapar (o painel passa a rejeitar toda
senha, mesmo a correta). Depois de colar, reinicie os serviços para o novo
valor ser lido:

```bash
docker compose up -d
```

O painel fica em `http://localhost:18473${ADMIN_URL_PREFIX}` (padrão
`/gestor-x7f2` — troque isso em produção).

### Produção

```bash
docker compose -f docker-compose.yml up -d --build
```

Passar `-f docker-compose.yml` explicitamente faz o Docker Compose **não**
carregar `docker-compose.override.yml` automaticamente — sem o serviço
`analisa_assets` e sem portas de Postgres/Redis publicadas, só a aplicação
fica exposta. Coloque um proxy com TLS na frente (fora do escopo deste
compose) se for expor publicamente.

## Comandos principais

| Comando | Descrição |
|---|---|
| `docker compose up --build` | Sobe tudo em desenvolvimento, com hot-reload de assets |
| `flask db migrate -m "..."` / `flask db upgrade` | Cria/aplica migrações |
| `flask sync-tools` | Sincroniza `tool_categories`/`tools` a partir do código |
| `npm run watch` | Build de assets em modo watch (dentro do container `analisa_assets` ou localmente) |
| `pytest` | Roda a suíte de testes |
| `celery -A make_celery.celery_app worker` | Worker Celery (já roda como serviço `analisa_worker`) |
| `celery -A make_celery.celery_app beat` | Agendador (já roda como serviço `analisa_scheduler`) |

## Estrutura do projeto

```text
app/
├── blueprints/       main (site público), admin (painel), public_pages (resultados/sitemaps), live (status/captcha), health
├── models/           Modelos SQLAlchemy 2 (Mapped/mapped_column)
├── security/          SSRF, CAPTCHA, rate limit, hashing, blocklist, headers
├── services/          SearchService, JobService, PageIndexabilityService, PageGenerationService, SitemapService
├── tasks/              Tasks Celery (busca, geração de página, sitemaps, manutenção)
├── tools/              BaseTool + registry + uma pasta por categoria (dns/, seo/, ssl/, http/, email/, domain/)
├── templates/          layout/, partials/, pages/, tools/ (um template único por ferramenta), admin/
└── static/src/         CSS/JS fonte (build gera app/static/dist/)
migrations/            Alembic
docker/                Scripts de entrypoint (ex.: tuning do Postgres)
tests/                 unit/, tools/, security/, test_tool_pages.py
docs/                  Documentação estendida
```

## Como adicionar uma ferramenta

Guia completo em [`docs/adding-a-tool.md`](docs/adding-a-tool.md). Resumo:

1. Crie `app/tools/<categoria>/<slug>.py` com uma subclasse de `BaseTool`
   (`validate_input`, `normalize_input`, `execute`).
2. Registre a classe em `app/tools/registry.py` (`load_tools()`).
3. Crie `app/templates/tools/<slug>.html` — layout próprio, ≥500 palavras de
   conteúdo autoral (aplicado por `tests/test_tool_pages.py`).
4. Rode `flask sync-tools`.

Nenhum outro arquivo (rotas genéricas, sidebar, home, categoria) precisa ser
alterado.

## Variáveis de ambiente

Veja [`.env.example`](.env.example) — todas as variáveis são documentadas
inline, agrupadas por área (app, Postgres, Redis, CAPTCHA, rate limit, SSRF,
admin, SEO, observabilidade). Nada fica hardcoded no código.

## Segurança

Veja [`SECURITY.md`](SECURITY.md) para a política de divulgação de
vulnerabilidades e um resumo dos controles implementados (SSRF, CAPTCHA,
rate limiting, hashing de IP, cabeçalhos de segurança, CSRF).

## Testes

```bash
pip install -r requirements-dev.txt
pytest
```

Os testes cobrem: módulos de segurança (SSRF, CAPTCHA, rate limit), as 15
ferramentas (com mocks de rede), geração de páginas estáticas, sitemaps,
painel administrativo e o requisito de conteúdo mínimo por página de
ferramenta. Requer PostgreSQL e Redis acessíveis (veja `tests/conftest.py`
para as variáveis usadas).

## Licença

[MIT](LICENSE).
