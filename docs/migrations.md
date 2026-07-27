# Migrações (Alembic / Flask-Migrate)

## Criando uma migração

Depois de alterar um modelo em `app/models/`:

```bash
flask db migrate -m "descrição curta da mudança"
```

Revise sempre o arquivo gerado em `migrations/versions/` — o autogenerate do
Alembic é um ponto de partida, não a palavra final (não detecta renomeações
de coluna, por exemplo, e as trata como drop+add).

## Aplicando

```bash
flask db upgrade
```

## Revertendo

```bash
flask db downgrade -1
```

## Convenções deste projeto

- Toda mudança de schema passa por migração — nunca edite o banco de
  produção manualmente.
- Novas ferramentas **não** exigem migração (a tabela `tools` já suporta
  qualquer ferramenta via `handler`/`slug`).
- Para colunas com `NOT NULL` em tabelas com dados existentes, adicione com
  um valor padrão ou faça o preenchimento (`op.execute(...)`) antes de
  aplicar a restrição, em duas migrações se necessário.
- Índices em colunas de alto volume (`searches.created_at`,
  `searches.status` etc.) já existem na migração inicial — mantenha esse
  padrão para novas colunas usadas em filtros/relatórios.

## Particionamento (preparação futura)

Com volume alto, `searches`/`search_results` são candidatas a
particionamento por data (mês) ou por `tool_id`. Isso não está implementado
nesta fase — seria prematuro sem dados reais de volume — mas o desenho do
`public_id` (aleatório, não sequencial) e dos índices já foi pensado para
não colidir com uma futura migração de particionamento.
