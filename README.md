# Online Duuka Backend

FastAPI backend for Online Duuka.

## Current branch layout

This branch is moving the backend from the old `src/` layout toward the requested project-stack layout:

```text
.
├── alembic.ini
├── alembic/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── core/
│   ├── models/
│   ├── routers/
│   ├── schemas/
│   └── services/
├── media/
└── requirements.txt
```

## Auth migration status

The auth module has been started in the new `app/` layout:

- `app/routers/auth.py` contains the merged auth endpoints for registration, login, refresh, logout, session management, password change, password reset, and 2FA.
- `app/routers/users.py` contains user profile routes such as `GET /api/users/me` and `PATCH /api/users/me`.
- `app/services/auth_service.py` contains the auth business logic.
- `app/schemas/auth.py` contains the auth request and response schemas.
- `app/core/security.py` contains password hashing and JWT helpers.
- `app/core/dependencies.py` contains the authenticated-user and admin dependencies.

Google OAuth routes are kept in `app/routers/auth.py` as route-contract placeholders and intentionally return `501` until the Google OAuth service is migrated.

The old `src/` tree has not been deleted yet. It should be removed only after each old feature module has been migrated and verified.

## Local development

Create your environment file:

```bash
cp .env.example .env
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the app:

```bash
uvicorn app.main:app --reload
```

Run Alembic migrations:

```bash
alembic upgrade head
```
