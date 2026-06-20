from datetime import datetime, timedelta, timezone
import secrets
import string


def generate_random_id(prefix: str, length: int = 8) -> str:
    characters = string.ascii_letters + string.digits
    length = max(length, 8)
    random_id = "".join(secrets.choice(characters) for _ in range(length))
    return f"{prefix}_{random_id}"


def generate_random_otp(length: int = 6) -> str:
    characters = string.digits
    length = max(length, 6)
    return "".join(secrets.choice(characters) for _ in range(length))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_lockout_duration(failed_attempts: int) -> timedelta:
    if failed_attempts < 5:
        return timedelta(seconds=0)
    if failed_attempts < 8:
        return timedelta(seconds=60)
    if failed_attempts < 10:
        return timedelta(minutes=5)
    if failed_attempts < 20:
        return timedelta(minutes=15)
    return timedelta(hours=1)
