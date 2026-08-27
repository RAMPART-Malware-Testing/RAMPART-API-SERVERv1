import json
from typing import Any, Awaitable, Callable

from cores.redis import redis_client

_KEY_PREFIX = "cache"


def _cache_key(namespace: str, suffix: str | None) -> str:
    if suffix:
        return f"{_KEY_PREFIX}:{namespace}:{suffix}"
    return f"{_KEY_PREFIX}:{namespace}"


def build_suffix(**params: Any) -> str:
    parts = [f"{key}={value}" for key, value in sorted(params.items()) if value is not None]
    return "&".join(parts)


def get_cached(namespace: str, suffix: str | None = None) -> Any | None:
    try:
        raw = redis_client.get(_cache_key(namespace, suffix))
    except Exception:
        return None
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def set_cached(namespace: str, value: Any, ttl_seconds: int, suffix: str | None = None) -> None:
    try:
        redis_client.setex(_cache_key(namespace, suffix), ttl_seconds, json.dumps(value, ensure_ascii=False))
    except Exception:
        pass


def invalidate_cached(namespace: str, suffix: str | None = None) -> None:
    try:
        if suffix:
            redis_client.delete(_cache_key(namespace, suffix))
            return
        for key in redis_client.scan_iter(match=f"{_KEY_PREFIX}:{namespace}*", count=200):
            redis_client.delete(key)
    except Exception:
        pass


async def cached_async(
    namespace: str,
    ttl_seconds: int,
    compute: Callable[[], Awaitable[Any]],
    *,
    suffix: str | None = None,
) -> Any:
    cached = get_cached(namespace, suffix)
    if cached is not None:
        return cached
    value = await compute()
    set_cached(namespace, value, ttl_seconds, suffix)
    return value


def cached_sync(
    namespace: str,
    ttl_seconds: int,
    compute: Callable[[], Any],
    *,
    suffix: str | None = None,
) -> Any:
    cached = get_cached(namespace, suffix)
    if cached is not None:
        return cached
    value = compute()
    set_cached(namespace, value, ttl_seconds, suffix)
    return value
