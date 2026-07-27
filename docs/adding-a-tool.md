# Como adicionar uma ferramenta

Adicionar uma ferramenta nova nunca exige alterar layout, rotas genéricas,
sidebar, home ou página de categoria — tudo isso é data-driven a partir do
registro de ferramentas.

## 1. Escolha a categoria

As categorias ativas no MVP estão em `app/tools/categories.py`
(`CATEGORIES`). Se sua ferramenta pertence a uma categoria ainda não lançada
(ver [`ROADMAP.md`](../ROADMAP.md)), adicione a categoria lá primeiro.

## 2. Crie a classe da ferramenta

Em `app/tools/<categoria>/<slug_com_underscore>.py`:

```python
from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain


class MinhaFerramentaTool(BaseTool):
    slug = "minha-ferramenta"
    name = "Minha Ferramenta"
    category_slug = "dns"  # slug de uma categoria existente
    short_description = "Resumo de uma linha para cards e listagens."
    description = "Descrição um pouco mais longa, usada como meta description padrão."
    icon = "search"  # nome de ícone Lucide
    input_type = InputType.DOMAIN
    input_placeholder = "exemplo.com.br"
    public_url_prefix = "minha-ferramenta"  # vira /minha-ferramenta/<slug>/
    ttl_seconds = 3600
    rate_limit_per_minute = 10
    analyzer_version = 1  # incremente ao mudar a lógica de execute()

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        # toda chamada de rede DEVE passar por SafeHTTPClient/resolve_host_ips
        # (app/security/ssrf.py) — nunca use httpx/socket diretamente aqui.
        data = {"domain": normalized_input, "algo": "..."}
        return ToolResult(success=True, summary="Resumo do resultado.", data=data)
```

Reaproveite os validadores em `app/tools/validators.py`
(`validate_and_normalize_domain`, `clean_url_input`, `validate_ip_input`) e
os utilitários DNS em `app/tools/dns_utils.py` quando fizer sentido.

## 3. Registre no registry

Em `app/tools/registry.py`, dentro de `load_tools()`: adicione o import e a
classe na lista passada ao loop de `registry.register(...)`.

## 4. Crie o template

Em `app/templates/tools/<slug>.html`:

- `{% extends "layout/base.html" %}`.
- Defina os blocos `title`, `meta_description`, `canonical` (usando
  `canonical_url`) e `robots_meta` (usando `robots_index`).
- Trate os quatro modos: `mode == "form"` (formulário), `"pending"` (barra de
  status), `"failed"` (erro) e `"result"` (renderize `result.normalized_result`,
  que é exatamente o `ToolResult.data` retornado por `execute()`).
- Inclua **pelo menos 500 palavras** de conteúdo autoral dentro de uma
  `<section class="prose-tool">` — explicando o que a ferramenta faz, como
  interpretar o resultado, casos de uso e limitações. Isso é obrigatório e
  verificado por `tests/test_tool_pages.py`.
- Use as macros de `app/templates/tools/_tool_macros.html`
  (`breadcrumbs`, `captcha_widget`, `status_bar`, `faq_accordion`,
  `related_tools_list`, `recent_searches_list`, `copy_button`) livremente —
  a ordem e o layout são seus, cada ferramenta deve parecer visualmente
  distinta das demais.

## 5. Sincronize e teste

```bash
flask sync-tools
pytest tests/test_tool_pages.py
```

Escreva também um teste em `tests/tools/` mockando qualquer chamada de rede
(veja os testes existentes para o padrão com `pytest-mock`/`respx`).

## Campos administráveis

Depois da primeira sincronização, `is_active`, `is_featured`, `sort_order`,
`rate_limit`, `result_ttl_seconds`, `requires_captcha` e
`is_publicly_indexable` passam a ser controlados pelo painel administrativo
— `flask sync-tools` não os sobrescreve mais.
