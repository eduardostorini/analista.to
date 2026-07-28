# How to Contribute

Thank you for considering contributing to Analista.to! This document summarizes the
expected workflow.

## Before you start

- For large changes (new tool, architecture change), open an issue
  describing the proposal before investing time in implementation.
- For small bugs and focused improvements, you can open the PR directly.

## Development environment

```bash
cp .env.example .env
docker compose up --build
docker compose exec analisa_web flask db upgrade
docker compose exec analisa_web flask sync-tools
```

## Code standards

- **Python:** follow the style already used in the project (type hints, docstrings only
  when the "why" is not obvious, no premature abstractions). Run `ruff` and
  `mypy` before opening the PR.
- **Templates:** each tool has its own template in
  `app/templates/tools/<slug>.html` — do not create a shared generic
  template across tools.
- **Commits:** messages in the imperative, describing the "why" when it is not
  obvious from the diff.

## Adding a tool

Follow [`docs/adding-a-tool.md`](docs/adding-a-tool.md). Requirements that CI
validates automatically:

- Dedicated template with ≥500 words of original content
  (`tests/test_tool_pages.py`).
- Unit tests for `validate_input`/`normalize_input`/`execute`
  logic with network mocks (never real calls in tests).
- No network requests outside of `SafeHTTPClient`/`resolve_host_ips`.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Every PR must keep the test suite passing. New features must
be accompanied by tests.

## Pull requests

- Describe what changed and why.
- Reference the related issue, if any.
- Keep the PR focused on a single logical change.

## Code of conduct

This project follows the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).