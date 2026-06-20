# Online Duuka Backend

FastAPI backend for Online Duuka, structured around the project stack.

## Project layout

```text
app/
  main.py
  config.py
  database.py
  core/
  middleware/
  models/
  routers/
  schemas/
  services/
  tasks/
alembic/
  env.py
  versions/
media/
  avatars/
  shops/
  products/
```

Models are grouped by domain while still using SQLModel:

- `app/models/user.py` — user, session, 2FA, password reset and verification models
- `app/models/agent.py` — agent and commission models
- `app/models/shop.py` — shop and location models
- `app/models/product.py` — product models
- `app/models/billing.py` — subscription and billing models
- `app/models/booster.py` — booster pack and active booster models
- `app/models/chat.py` — conversation, participants and messages

## Run locally

```bash
uvicorn app.main:app --reload
```

## Database migrations

Alembic now uses the root `alembic/` folder and imports models from `app.models`.

Run migrations:

```bash
uv run alembic upgrade head
```

Create a new migration after changing SQLModel models:

```bash
uv run alembic revision --autogenerate -m "describe your change"
```

Review generated migrations before applying them:

```bash
uv run alembic upgrade head --sql
```
