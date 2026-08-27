from typing import Any

from cores.redis import redis_client
from utils.cache import cached_sync, invalidate_cached

PATTERNS = [
    ("otp_lockout:register:*", "OTP Lockout - Register"),
    ("otp_lockout:login:*", "OTP Lockout - Login"),
    ("otp_lockout:reset-passwd:*", "OTP Lockout - Reset Password"),
    ("ratelimit:profile:username:*", "Rate Limit - Username Change"),
    ("ratelimit:profile:avatar:*", "Rate Limit - Avatar Upload"),
]

RATE_LIMIT_CACHE_NAMESPACE = "admin:rate_limits"
RATE_LIMIT_CACHE_TTL_SECONDS = 10


def _scan_pattern(pattern: str) -> list[dict[str, Any]]:
    results = []
    try:
        for key in redis_client.scan_iter(match=pattern, count=200):
            key_str = key if isinstance(key, str) else key.decode("utf-8", errors="replace")
            ttl = redis_client.ttl(key_str)
            identifier = key_str.split(":")[-1]
            results.append({"key": key_str, "identifier": identifier, "ttl_seconds": ttl if isinstance(ttl, int) and ttl > 0 else None})
    except Exception as exc:
        print(f"[RateLimitMonitor] scan failed for {pattern}: {exc}")
    return results


def _fetch_rate_limit_snapshot() -> dict[str, Any]:
    groups = []
    total = 0
    for pattern, label in PATTERNS:
        entries = _scan_pattern(pattern)
        total += len(entries)
        groups.append({"pattern": pattern, "label": label, "count": len(entries), "entries": entries[:50]})
    return {
        "success": True,
        "data": {
            "total_locked": total,
            "groups": groups,
        },
    }


def get_rate_limit_snapshot() -> dict[str, Any]:
    return cached_sync(RATE_LIMIT_CACHE_NAMESPACE, RATE_LIMIT_CACHE_TTL_SECONDS, _fetch_rate_limit_snapshot)


def clear_lockout_key(key: str) -> dict[str, Any]:
    allowed_prefixes = ("otp_lockout:", "ratelimit:")
    if not any(key.startswith(prefix) for prefix in allowed_prefixes):
        return {"success": False, "message": "ไม่สามารถลบ key นี้ได้"}
    try:
        deleted = redis_client.delete(key)
        if deleted:
            invalidate_cached(RATE_LIMIT_CACHE_NAMESPACE)
        return {"success": bool(deleted), "message": "ปลดล็อกสำเร็จ" if deleted else "ไม่พบ key นี้"}
    except Exception as exc:
        return {"success": False, "message": str(exc)[:200]}
