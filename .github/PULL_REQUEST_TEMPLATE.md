## O que muda

Descreva a mudança e o porquê.

## Tipo de mudança

- [ ] Correção de bug
- [ ] Nova ferramenta
- [ ] Melhoria/refatoração
- [ ] Documentação
- [ ] Infraestrutura/Docker

## Checklist

- [ ] `pytest` passa localmente
- [ ] Se for nova ferramenta: template dedicado com ≥500 palavras
      (`pytest tests/test_tool_pages.py`)
- [ ] Se houve mudança de schema: migração criada e revisada
- [ ] Nenhuma chamada de rede fora de `SafeHTTPClient`/`resolve_host_ips`
- [ ] Variáveis de ambiente novas documentadas em `.env.example`

## Issue relacionada

Closes #
