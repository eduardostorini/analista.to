# Como contribuir

Obrigado por considerar contribuir com o Analista.to! Este documento resume o
fluxo esperado.

## Antes de começar

- Para mudanças grandes (nova ferramenta, mudança de arquitetura), abra uma
  issue descrevendo a proposta antes de investir tempo na implementação.
- Para bugs pequenos e melhorias pontuais, pode abrir o PR diretamente.

## Ambiente de desenvolvimento

```bash
cp .env.example .env
docker compose up --build
docker compose exec analisa_web flask db upgrade
docker compose exec analisa_web flask sync-tools
```

## Padrões de código

- **Python:** siga o estilo já usado no projeto (type hints, docstrings só
  quando o "porquê" não é óbvio, sem abstrações prematuras). Rode `ruff` e
  `mypy` antes de abrir o PR.
- **Templates:** cada ferramenta tem um template próprio em
  `app/templates/tools/<slug>.html` — não crie um template genérico
  compartilhado entre ferramentas.
- **Commits:** mensagens no imperativo, descrevendo o "porquê" quando não é
  óbvio pelo diff.

## Adicionando uma ferramenta

Siga [`docs/adding-a-tool.md`](docs/adding-a-tool.md). Requisitos que o CI
valida automaticamente:

- Template dedicado com ≥500 palavras de conteúdo autoral
  (`tests/test_tool_pages.py`).
- Testes unitários da lógica de `validate_input`/`normalize_input`/`execute`
  com mocks de rede (nunca chamadas reais em teste).
- Nenhuma requisição de rede fora de `SafeHTTPClient`/`resolve_host_ips`.

## Testes

```bash
pip install -r requirements-dev.txt
pytest
```

Todo PR deve manter a suíte de testes passando. Novas funcionalidades devem
vir acompanhadas de testes.

## Pull requests

- Descreva o que mudou e por quê.
- Referencie a issue relacionada, se houver.
- Mantenha o PR focado em uma única mudança lógica.

## Código de conduta

Este projeto segue o [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
