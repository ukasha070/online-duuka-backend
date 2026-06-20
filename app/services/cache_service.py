from __future__ import annotations

from fastapi import FastAPI

from app.config import settings
from app.core.redis_client import get_redis_client

try:
    from fastapi_cache import FastAPICache
    from fastapi_cache.backends.redis import RedisBackend
    from fastapi_cache.coder import JsonCoder
except ImportError:  # pragma: no cover - optional dependency guard
    FastAPICache = None  # type: ignore[assignment]
    RedisBackend = None  # type: ignore[assignment]
    JsonCoder = None  # type: ignore[assignment]


def is_cache_available() -> bool:
    return FastAPICache is not None and RedisBackend is not None


async def init_cache(app: FastAPI | None = None) -> None:
    """Initialise fastapi-cache2 with Redis.

    Local/test environments can still import the app if fastapi-cache2 is not
    installed yet; caching simply becomes a no-op until the dependency exists.
    """
    if not is_cache_available():
        if app is not None:
            app.state.cache_enabled = False
        return

    redis = await get_redis_client()
    FastAPICache.init(
        RedisBackend(redis),
        prefix=settings.CACHE_PREFIX,
        expire=settings.CACHE_DEFAULT_TTL_SECONDS,
        coder=JsonCoder,
    )

    if app is not None:
        app.state.cache_enabled = True


async def clear_cache_namespace(namespace: str = "*") -> int:
    """Delete cache entries by namespace/pattern.

    Example:
        await clear_cache_namespace("products:*")
    """
    redis = await get_redis_client()
    pattern = f"{settings.CACHE_PREFIX}:{namespace}"
    keys = [key async for key in redis.scan_iter(pattern)]
    if not keys:
        return 0

    return int(await redis.delete(*keys))
