# Online Duuka Backend

## Database Migrations

Alembic is configured for both common terminal locations:

- From `backend`, it uses `alembic.ini` and `src/migrations`.
- From `backend/src`, it uses `src/alembic.ini` and `src/migrations`.

It reads the same settings as the FastAPI app, including `DATABASE_URL` from
`src/.env.local`.

Run migrations:

```bash
uv run alembic upgrade head
```

Create a new migration after changing SQLModel models:

```bash
uv run alembic revision --autogenerate -m "describe your change"
```

Review generated migrations before applying them. For a SQL preview without
touching the database:

```bash
uv run alembic upgrade head --sql
```
