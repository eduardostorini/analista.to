# Backups

## PostgreSQL

The volume `analisa_postgres_data` holds all the data. For a logical backup
(recommended, portable between minor Postgres versions):

```bash
docker compose exec analisa_postgres pg_dump -U analisa -d analisa_to -Fc -f /tmp/backup.dump
docker compose cp analisa_postgres:/tmp/backup.dump ./backups/analisa_$(date +%Y%m%d_%H%M).dump
```

To restore:

```bash
docker compose cp ./backups/analisa_20260101_0000.dump analisa_postgres:/tmp/restore.dump
docker compose exec analisa_postgres pg_restore -U analisa -d analisa_to --clean --if-exists /tmp/restore.dump
```

Schedule this via external cron/CI pointing to the host — there is no automated
backup service inside the `docker-compose.yml` in this phase (avoids coupling
external storage credentials to the development compose).

## Generated static pages

`GENERATED_PAGES_DIR` is rebuildable from the database (`GeneratedPage` +
`Search`/`SearchResult`) via `PageGenerationService.regenerate_from_row`, so
it is not strictly necessary to back up the `analisa_generated_pages` volume —
but copying the volume is faster than regenerating everything in case of restoring
a large site.

## Redis

Data in Redis (cache, rate limit, pubsub, queues) is ephemeral by design —
none of it needs to be backed up. The Celery broker (`appendonly yes`) only
protects against loss of in-flight tasks during a container restart,
not a durable source of truth.

## Retention

No automated backup retention policy in this phase — define yours
according to your environment (e.g., daily for 7 days + weekly for 4 weeks) in
the external scheduling tool you use.