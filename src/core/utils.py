from datetime import datetime, timezone, timedelta
import secrets
import string


def generate_random_id(prefix: str, length: int = 8) -> str:
    characters = string.ascii_letters + string.digits
    length = max(length, 8)

    random_id = "".join(secrets.choice(characters) for _ in range(length))

    return f"{prefix}_{random_id}"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
