from __future__ import annotations

from typing import Final

from redis.asyncio import Redis

from app.config import settings

_REDIS_HEALTH_KEY: Final[str] = "healthcheck"
_redis_client: Redis | None = None


async def get_redis_client() -> Redis:
    """Return a process-wide Redis client.

    The client is lazy so importing modules does not require Redis to be up.
    """
    global _redis_client

    if _redis_client is None:
        _redis_client = Redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            health_check_interval=30,
        )

    return _redis_client


async def ping_redis() -> bool:
    client = await get_redis_client()
    return bool(await client.ping())


async def close_redis_client() -> None:
    global _redis_client

    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


async def add_jti_to_denylist(jti: str, expires_in_seconds: int) -> None:
    if not jti:
        return

    client = await get_redis_client()
    await client.setex(f"jwt:denylist:{jti}", expires_in_seconds, "1")


async def is_jti_denied(jti: str) -> bool:
    if not jti:
        return False

    client = await get_redis_client()
    return await client.exists(f"jwt:denylist:{jti}") > 0
