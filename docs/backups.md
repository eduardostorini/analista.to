# Backups

## PostgreSQL

O volume `analisa_postgres_data` guarda todos os dados. Para um backup
lógico (recomendado, portável entre versões menores do Postgres):

```bash
docker compose exec analisa_postgres pg_dump -U analisa -d analisa_to -Fc -f /tmp/backup.dump
docker compose cp analisa_postgres:/tmp/backup.dump ./backups/analisa_$(date +%Y%m%d_%H%M).dump
```

Restaurar:

```bash
docker compose cp ./backups/analisa_20260101_0000.dump analisa_postgres:/tmp/restore.dump
docker compose exec analisa_postgres pg_restore -U analisa -d analisa_to --clean --if-exists /tmp/restore.dump
```

Agende isso via cron/CI externo apontando para o host — não há um serviço de
backup automatizado dentro do `docker-compose.yml` nesta fase (evita
acoplar credenciais de storage externo ao compose de desenvolvimento).

## Páginas estáticas geradas

`GENERATED_PAGES_DIR` é reconstruível a partir do banco (`GeneratedPage` +
`Search`/`SearchResult`) via `PageGenerationService.regenerate_from_row`, então
não é estritamente necessário fazer backup do volume `analisa_generated_pages`
— mas copiar o volume é mais rápido que regenerar tudo em caso de restauração
de um site grande.

## Redis

Dados em Redis (cache, rate limit, pubsub, filas) são efêmeros por design —
nenhum deles precisa de backup. O broker do Celery (`appendonly yes`) só
protege contra perda de tarefas em trânsito durante um restart do container,
não é uma fonte de verdade duradoura.

## Retenção

Sem uma política de retenção automatizada de backups nesta fase — defina a
sua conforme o ambiente (ex.: diário por 7 dias + semanal por 4 semanas) na
ferramenta de agendamento externa que você usar.
