# Migrations (Alembic / Flask-Migrate)

## Creating a migration

After modifying a model in `app/models/`:

```bash
flask db migrate -m "short description of the change"
```

Always review the generated file in `migrations/versions/` — Alembic's autogenerate
is a starting point, not the final word (it does not detect column renames,
for example, and treats them as drop+add).

## Applying

```bash
flask db upgrade
```

## Reverting

```bash
flask db downgrade -1
```

## Conventions in this project

- Every schema change goes through a migration — never edit the database
  in production manually.
- New tools **do not** require a migration (the `tools` table already supports
  any tool via `handler`/`slug`).
- For columns with `NOT NULL` in tables with existing data, add them with
  a default value or perform the fill (`op.execute(...)`) before applying the
  constraint, in two migrations if necessary.
- Indexes on high-volume columns (`searches.created_at`,
  `searches.status`, etc.) already exist in the initial migration — maintain this
  pattern for new columns used in filters/reports.

## Partitioning (future preparation)

With high volume, `searches`/`search_results` are candidates for
partitioning by date (month) or by `tool_id`. This is not implemented
in this phase — it would be premature without real volume data — but the design of
`public_id` (random, not sequential) and the indexes has already been thought
through to not conflict with a future partitioning migration.