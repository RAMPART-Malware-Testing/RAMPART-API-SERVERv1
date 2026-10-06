from cores.redis import redis_client

_KEY_PREFIX = "ratelimit"

def is_rate_limited(bucket: str, identity: str, limit: int, window_seconds: int) -> bool:
    key = f"{_KEY_PREFIX}:{bucket}:{identity}"
    try:
        current = redis_client.incr(key)
        if current == 1:
            redis_client.expire(key, window_seconds)
        return current > limit
    except Exception:
        return False
