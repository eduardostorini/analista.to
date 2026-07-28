# PostgreSQL Configuration Profiles

The `analisa_postgres` container automatically calculates `shared_buffers`,
`effective_cache_size`, `maintenance_work_mem`, `work_mem`, and
`max_connections` from the `POSTGRES_MEMORY_MB` variable, via the
script [`docker/postgres/generate-conf.sh`](../docker/postgres/generate-conf.sh).
This script runs once, on the first initialization of the data volume, and writes
the values to `postgresql.auto.conf` (persistent).

We never hardcode a specific RAM value in the code — adjust
`POSTGRES_MEMORY_MB` in your `.env` according to the server profile.

## Suggested profiles

| Profile              | `POSTGRES_MEMORY_MB` | `POSTGRES_MAX_CONNECTIONS` | Notes |
|----------------------|----------------------:|-----------------------------:|-------|
| Local development | `512`                | `50`                          | Default value in `.env.example`; works well on laptops. |
| Small server      | `1024` – `2048`      | `80` – `100`                  | VPS 2–4 GB dedicated mostly to the database. |
| Medium server     | `4096` – `8192`      | `150` – `200`                 | Consider enabling PgBouncer (see below) above 150 connections. |
| High volume       | `16384+`             | `300+`                        | Combine with read replicas and partitioning of `searches`/`search_results` by date. |

## Applied formulas

- `shared_buffers` = 25% of `POSTGRES_MEMORY_MB`
- `effective_cache_size` = 70% of `POSTGRES_MEMORY_MB`
- `maintenance_work_mem` = 10% of `POSTGRES_MEMORY_MB`, capped at 1 GB
- `work_mem` = (25% of `POSTGRES_MEMORY_MB` in kB) / (`max_connections` × 3) —
  conservative because it is applied per operation and per connection
- `wal_compression = on`, `random_page_cost = 1.1`,
  `effective_io_concurrency = 200` (assumes SSD storage)
- `checkpoint_completion_target = 0.9`
- More aggressive autovacuum (`autovacuum_vacuum_cost_delay = 2ms`,
  `autovacuum_naptime = 15s`) for the high-volume tables
  (`searches`, `search_results`, `job_events`)

## Applying a new value after first initialization

The script only runs when the `analisa_postgres_data` volume is created from scratch.
To apply a new `POSTGRES_MEMORY_MB` on an existing environment, run the
same `ALTER SYSTEM SET ...` commands manually via `psql` (see the script) and then:

```sql
SELECT pg_reload_conf();
```

Parameters that require a restart (such as `shared_buffers` and `max_connections`)
only take effect after restarting the container:

```bash
docker compose restart analisa_postgres
```

## PgBouncer (future preparation)

For high volumes, it is recommended to place a PgBouncer (`transaction` pooling)
between the application and Postgres, reducing the number of physical connections.
The `SQLALCHEMY_ENGINE_OPTIONS` in [`app/config.py`](../app/config.py) already uses
a connection pool (`pool_size`/`max_overflow`) on the application side; PgBouncer
serves as an additional layer when multiple processes
(`analisa_web`, `analisa_worker`) combined exceed `max_connections`. It is not
included in the `docker-compose.yml` of this phase — add an `analisa_pgbouncer`
service pointing to `analisa_postgres:5432` and change `DATABASE_URL` to point to it when needed.