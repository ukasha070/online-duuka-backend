"""Smoke-test the app auth and user routers without requiring external services.

This script verifies that the FastAPI app imports, that auth/user routes are
registered, and that account-lockout helpers behave as expected. It intentionally
avoids opening database, Redis, or HTTP client connections.
"""

from __future__ import annotations

import os
from datetime import timedelta


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


def assert_route(app, path: str, method: str) -> None:
    method = method.upper()
    for route in app.routes:
        methods = getattr(route, "methods", set()) or set()
        if getattr(route, "path", None) == path and method in methods:
            return
    raise AssertionError(f"Missing route: {method} {path}")


def main() -> None:
    set_test_env()

    from app.core import utils
    from app.main import app
    from app.models.user import AuthType, User

    required_routes = [
        ("/api/health", "GET"),
        ("/api/auth/health", "GET"),
        ("/api/auth/register", "POST"),
        ("/api/auth/login", "POST"),
        ("/api/auth/refresh", "POST"),
        ("/api/auth/logout", "POST"),
        ("/api/auth/sessions", "GET"),
        ("/api/auth/change-password", "POST"),
        ("/api/auth/password-reset/request", "POST"),
        ("/api/auth/password-reset/confirm", "POST"),
        ("/api/users/me", "GET"),
        ("/api/users/me", "PATCH"),
    ]
    for path, method in required_routes:
        assert_route(app, path, method)

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
