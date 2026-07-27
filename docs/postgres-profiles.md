# Perfis de configuração do PostgreSQL

O container `analisa_postgres` calcula automaticamente `shared_buffers`,
`effective_cache_size`, `maintenance_work_mem`, `work_mem` e
`max_connections` a partir da variável `POSTGRES_MEMORY_MB`, através do
script [`docker/postgres/generate-conf.sh`](../docker/postgres/generate-conf.sh).
Esse script roda uma única vez, na primeira inicialização do volume de
dados, e grava os valores em `postgresql.auto.conf` (persistente).

Nunca fixamos um valor de RAM específico no código — ajuste
`POSTGRES_MEMORY_MB` no seu `.env` conforme o perfil do servidor.

## Perfis sugeridos

| Perfil              | `POSTGRES_MEMORY_MB` | `POSTGRES_MAX_CONNECTIONS` | Observações |
|----------------------|----------------------:|-----------------------------:|-------------|
| Desenvolvimento local | `512`                | `50`                          | Valor padrão de `.env.example`; roda bem em notebooks. |
| Servidor pequeno      | `1024` – `2048`      | `80` – `100`                  | VPS 2–4 GB dedicados majoritariamente ao banco. |
| Servidor médio        | `4096` – `8192`      | `150` – `200`                 | Considere ativar PgBouncer (ver abaixo) acima de 150 conexões. |
| Alto volume           | `16384`+             | `300`+                        | Combine com réplicas de leitura e particionamento de `searches`/`search_results` por data. |

## Fórmulas aplicadas

- `shared_buffers` = 25% de `POSTGRES_MEMORY_MB`
- `effective_cache_size` = 70% de `POSTGRES_MEMORY_MB`
- `maintenance_work_mem` = 10% de `POSTGRES_MEMORY_MB`, com teto de 1 GB
- `work_mem` = (25% de `POSTGRES_MEMORY_MB` em kB) / (`max_connections` × 3) —
  conservador porque é aplicado por operação e por conexão
- `wal_compression = on`, `random_page_cost = 1.1`,
  `effective_io_concurrency = 200` (assume armazenamento SSD)
- `checkpoint_completion_target = 0.9`
- Autovacuum mais agressivo (`autovacuum_vacuum_cost_delay = 2ms`,
  `autovacuum_naptime = 15s`) para as tabelas de alto volume
  (`searches`, `search_results`, `job_events`)

## Aplicando um novo valor depois da primeira inicialização

O script só roda quando o volume `analisa_postgres_data` é criado do zero.
Para aplicar um novo `POSTGRES_MEMORY_MB` num ambiente já existente, rode os
mesmos comandos `ALTER SYSTEM SET ...` manualmente via `psql` (veja o script)
e depois:

```sql
SELECT pg_reload_conf();
```

Parâmetros que exigem restart (como `shared_buffers` e `max_connections`)
só têm efeito após reiniciar o container:

```bash
docker compose restart analisa_postgres
```

## PgBouncer (preparação futura)

Para volumes altos, recomenda-se colocar um PgBouncer (`transaction` pooling)
entre a aplicação e o Postgres, reduzindo o número de conexões físicas.
O `SQLALCHEMY_ENGINE_OPTIONS` em [`app/config.py`](../app/config.py) já usa
um pool de conexões (`pool_size`/`max_overflow`) do lado da aplicação; o
PgBouncer entra como uma camada adicional quando múltiplos processos
(`analisa_web`, `analisa_worker`) somados excederem `max_connections`. Não
está incluído no `docker-compose.yml` desta fase — adicione um serviço
`analisa_pgbouncer` apontando para `analisa_postgres:5432` e mude
`DATABASE_URL` para apontar para ele quando for necessário.
