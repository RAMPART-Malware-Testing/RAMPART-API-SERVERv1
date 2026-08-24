"""Minimal fixed-window rate limiter backed by the shared Redis client.

OWASP A04 - Unrestricted Resource Consumption: without this, an
authenticated user's own token could be used to spam expensive endpoints
(disk-writing avatar uploads, DB-uniqueness-checking username changes)
with no cost to the caller. This is intentionally simple (fixed window,
not sliding/token-bucket) - good enough to blunt casual abuse/scripted
retries without adding a new dependency.

Fails OPEN if Redis is unreachable (matches this codebase's existing
`cores/redis.py` posture of logging connection errors rather than
crashing the app) - availability of the feature takes priority over the
throttle when the cache tier itself is down.
"""

from cores.redis import redis_client

_KEY_PREFIX = "ratelimit"


def is_rate_limited(bucket: str, identity: str, limit: int, window_seconds: int) -> bool:
    """Returns True if `identity` has exceeded `limit` calls to `bucket`
    within the current `window_seconds`-long fixed window.

    `identity` should be something the caller cannot spoof for free, e.g.
    the authenticated user's uid (never a client-supplied header).
    """
    key = f"{_KEY_PREFIX}:{bucket}:{identity}"
    try:
        current = redis_client.incr(key)
        if current == 1:
            redis_client.expire(key, window_seconds)
        return current > limit
    except Exception:
        # Redis down/unreachable: don't let a cache outage take the whole
        # feature down with it.
        return False
