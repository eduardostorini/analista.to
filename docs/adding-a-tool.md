# How to Add a Tool

Adding a new tool never requires changing layout, generic routes,
sidebar, home, or category page — all of it is data-driven from the
tool registry.

## 1. Choose the category

The active categories in the MVP are in `app/tools/categories.py`
(`CATEGORIES`). If your tool belongs to a category not yet launched
(see [`ROADMAP.md`](../ROADMAP.md)), add the category there first.

## 2. Create the tool class

In `app/tools/<category>/<slug_with_underscores>.py`:

```python
from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain


class MyToolTool(BaseTool):
    slug = "my-tool"
    name = "My Tool"
    category_slug = "dns"  # slug of an existing category
    short_description = "One-line summary for cards and listings."
    description = "A longer description, used as the default meta description."
    icon = "search"  # Lucide icon name
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "my-tool"  # becomes /my-tool/<slug>/
    ttl_seconds = 3600
    rate_limit_per_minute = 10
    analyzer_version = 1  # increment when changing execute() logic

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        # all network calls MUST go through SafeHTTPClient/resolve_host_ips
        # (app/security/ssrf.py) — never use httpx/socket directly here.
        data = {"domain": normalized_input, "something": "..."}
        return ToolResult(success=True, summary="Result summary.", data=data)
```

Reuse the validators in `app/tools/validators.py`
(`validate_and_normalize_domain`, `clean_url_input`, `validate_ip_input`) and
the DNS utilities in `app/tools/dns_utils.py` when applicable.

## 3. Register in the registry

In `app/tools/registry.py`, inside `load_tools()`: add the import and the
class in the list passed to the `registry.register(...)` loop.

## 4. Create the template

In `app/templates/tools/<slug>.html`:

- `{% extends "layout/base.html" %}`.
- Define the `title`, `meta_description`, `canonical` (using
  `canonical_url`), and `robots_meta` (using `robots_index`) blocks.
- Handle the four modes: `mode == "form"` (form), `"pending"` (status bar),
  `"failed"` (error), and `"result"` (render `result.normalized_result`,
  which is exactly the `ToolResult.data` returned by `execute()`).
- Include **at least 500 words** of original content inside a
  `<section class="prose-tool">` — explaining what the tool does, how to
  interpret the result, use cases, and limitations. This is mandatory and
  checked by `tests/test_tool_pages.py`.
- Use the macros from `app/templates/tools/_tool_macros.html`
  (`breadcrumbs`, `captcha_widget`, `status_bar`, `faq_accordion`,
  `related_tools_list`, `recent_searches_list`, `copy_button`) freely —
  the order and layout are yours; each tool should look visually
  distinct from the others.

## 5. Sync and test

```bash
flask sync-tools
pytest tests/test_tool_pages.py
```

Also write a test in `tests/tools/` mocking any network call
(see existing tests for the pattern with `pytest-mock`/`respx`).

## Administrable fields

After the first sync, `is_active`, `is_featured`, `sort_order`,
`rate_limit`, `result_ttl_seconds`, `requires_captcha`, and
`is_publicly_indexable` become controlled by the admin panel —
`flask sync-tools` no longer overwrites them.