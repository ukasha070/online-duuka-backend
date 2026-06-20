"""Smoke-test auth and user endpoints without requiring a live database.

The checks intentionally use invalid/no-auth requests so FastAPI can validate
route registration, request validation, and auth dependency wiring without
opening a database connection.
"""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def set_test_env() -> None:
    defaults = {
        "ENV": "local",
        "DATABASE_URL": "postgresql+asyncpg://online_duuka:online_duuka@localhost:5432/online_duuka_test",
        "SECRET_KEY": "test-secret-key",
        "JWT_SECRET_KEY": "test-jwt-secret-key",
        "JWT_AUDIENCE": "online-duuka-test-client",
        "GOOGLE_CLIENT_ID": "test-google-client-id",
        "GOOGLE_CLIENT_SECRET": "test-google-client-secret",
        "GOOGLE_REDIRECT_URI": "http://localhost:8000/api/auth/google/callback",
        "SMTP_HOST": "localhost",
        "SMTP_USERNAME": "test@example.com",
        "SMTP_PASSWORD": "test-password",
        "SMTP_FROM_EMAIL": "noreply@example.com",
        "CELERY_BROKER_URL": "redis://localhost:6379/0",
        "CELERY_RESULT_BACKEND": "redis://localhost:6379/1",
        "REDIS_URL": "redis://localhost:6379/2",
    }
    for key, value in defaults.items():
        os.environ.setdefault(key, value)


def assert_not_found(response, method: str, path: str) -> None:
    assert response.status_code != 404, f"Missing route: {method.upper()} {path}"


def main() -> None:
    set_test_env()

    from fastapi.testclient import TestClient

    from app.core import utils
    from app.main import app
    from app.models.user import AuthType, User

    with TestClient(app) as client:
        health = client.get("/api/health")
        assert health.status_code == 200, health.text

        endpoint_checks = [
            ("post", "/api/auth/register", {}),
            ("post", "/api/auth/login", {}),
            ("post", "/api/auth/refresh", {}),
            ("post", "/api/auth/logout", {}),
            ("get", "/api/auth/sessions", None),
            ("post", "/api/auth/change-password", {}),
            ("post", "/api/auth/password-reset/request", {}),
            ("post", "/api/auth/password-reset/confirm", {}),
            ("get", "/api/users/me", None),
            ("patch", "/api/users/me", {}),
        ]
        for method, path, body in endpoint_checks:
            request = getattr(client, method)
            response = request(path, json=body) if body is not None else request(path)
            assert_not_found(response, method, path)

    user = User(
        email="lockout-smoke@example.com",
        password="hashed-password",
        full_name="Lockout Smoke",
        auth_type=AuthType.EMAIL,
        is_verified=True,
    )
    assert user.failed_login_attempts == 0
    assert user.lockdown_left_seconds() == 0

    user.failed_login_attempts = 5
    user.login_locked_until = utils.utc_now() + timedelta(seconds=60)
    assert user.lockdown_left_seconds() > 0
    assert utils.get_lockout_duration(4).total_seconds() == 0
    assert utils.get_lockout_duration(5).total_seconds() == 60
    assert utils.get_lockout_duration(8).total_seconds() == 300

    print("Auth/user smoke test passed.")


if __name__ == "__main__":
    main()
