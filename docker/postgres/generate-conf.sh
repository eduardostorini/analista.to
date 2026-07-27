#!/bin/bash
# Executado uma única vez pelo entrypoint oficial do Postgres, durante a
# inicialização do volume de dados (docker-entrypoint-initdb.d). Calcula
# parâmetros proporcionais a POSTGRES_MEMORY_MB e grava via ALTER SYSTEM,
# o que persiste em postgresql.auto.conf no volume — sobrevive a restarts.
#
# Para aplicar um novo POSTGRES_MEMORY_MB depois da primeira inicialização,
# rode manualmente os mesmos comandos ALTER SYSTEM (veja docs/postgres-profiles.md)
# ou recrie o volume em um ambiente novo.
set -euo pipefail

MEMORY_MB="${POSTGRES_MEMORY_MB:-1024}"
MAX_CONNECTIONS="${POSTGRES_MAX_CONNECTIONS:-100}"

shared_buffers_mb=$(( MEMORY_MB * 25 / 100 ))
effective_cache_mb=$(( MEMORY_MB * 70 / 100 ))

# maintenance_work_mem: até 10% da memória, com teto de 1GB para não
# comprometer o sistema em manutenções concorrentes (VACUUM/CREATE INDEX).
maintenance_work_mem_mb=$(( MEMORY_MB * 10 / 100 ))
if [ "$maintenance_work_mem_mb" -gt 1024 ]; then
  maintenance_work_mem_mb=1024
fi
if [ "$maintenance_work_mem_mb" -lt 32 ]; then
  maintenance_work_mem_mb=32
fi

# work_mem: conservador, pois é aplicado por operação de ordenação/hash e
# pode ser usado várias vezes por conexão simultaneamente.
work_mem_kb=$(( (MEMORY_MB * 25 / 100) * 1024 / (MAX_CONNECTIONS * 3) ))
if [ "$work_mem_kb" -lt 1024 ]; then
  work_mem_kb=1024
fi

echo "[generate-conf] POSTGRES_MEMORY_MB=${MEMORY_MB}MB -> shared_buffers=${shared_buffers_mb}MB effective_cache_size=${effective_cache_mb}MB maintenance_work_mem=${maintenance_work_mem_mb}MB work_mem=${work_mem_kb}kB max_connections=${MAX_CONNECTIONS}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
  ALTER SYSTEM SET shared_buffers = '${shared_buffers_mb}MB';
  ALTER SYSTEM SET effective_cache_size = '${effective_cache_mb}MB';
  ALTER SYSTEM SET maintenance_work_mem = '${maintenance_work_mem_mb}MB';
  ALTER SYSTEM SET work_mem = '${work_mem_kb}kB';
  ALTER SYSTEM SET max_connections = ${MAX_CONNECTIONS};
  ALTER SYSTEM SET wal_compression = on;
  ALTER SYSTEM SET random_page_cost = 1.1;
  ALTER SYSTEM SET effective_io_concurrency = 200;
  ALTER SYSTEM SET checkpoint_completion_target = 0.9;
  ALTER SYSTEM SET autovacuum_vacuum_cost_delay = 2;
  ALTER SYSTEM SET autovacuum_naptime = '15s';
SQL

echo "[generate-conf] parâmetros gravados em postgresql.auto.conf"
