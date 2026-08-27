import asyncio
import os
import shutil
import time
from datetime import datetime, timezone
from typing import Any

import requests
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from utils.cache import cached_async, invalidate_cached

HEALTH_TIMEOUT_SECONDS = 4
HEALTH_CACHE_TTL_SECONDS = 15
HEALTH_CACHE_NAMESPACE = "admin:system_health"


def _check_external_service(name: str, url: str | None, path: str = "/") -> dict[str, Any]:
    if not url:
        return {"name": name, "status": "unconfigured", "latency_ms": None, "detail": "URL is not configured"}
    started = time.monotonic()
    try:
        resp = requests.get(f"{url.rstrip('/')}{path}", timeout=HEALTH_TIMEOUT_SECONDS)
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        healthy = resp.status_code < 500
        return {
            "name": name,
            "status": "up" if healthy else "degraded",
            "latency_ms": latency_ms,
            "detail": f"HTTP {resp.status_code}",
        }
    except requests.exceptions.RequestException as exc:
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        return {"name": name, "status": "down", "latency_ms": latency_ms, "detail": str(exc)[:200]}


async def _check_database(session: AsyncSession) -> dict[str, Any]:
    started = time.monotonic()
    try:
        await session.execute(text("SELECT 1"))
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        return {"name": "postgresql", "status": "up", "latency_ms": latency_ms, "detail": None}
    except Exception as exc:
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        return {"name": "postgresql", "status": "down", "latency_ms": latency_ms, "detail": str(exc)[:200]}


def _check_redis() -> dict[str, Any]:
    started = time.monotonic()
    try:
        from cores.redis import redis_client
        pong = redis_client.ping()
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        return {"name": "redis", "status": "up" if pong else "degraded", "latency_ms": latency_ms, "detail": None}
    except Exception as exc:
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        return {"name": "redis", "status": "down", "latency_ms": latency_ms, "detail": str(exc)[:200]}


def _check_celery_workers() -> dict[str, Any]:
    started = time.monotonic()
    try:
        from bgProcessing.celery_app import celery_app
        inspector = celery_app.control.inspect(timeout=HEALTH_TIMEOUT_SECONDS)
        pong = inspector.ping()
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        if not pong:
            return {"name": "celery_workers", "status": "down", "latency_ms": latency_ms, "detail": "No workers responded", "workers": []}
        active = inspector.active() or {}
        reserved = inspector.reserved() or {}
        workers = [
            {
                "name": worker_name,
                "active_tasks": len(active.get(worker_name, [])),
                "reserved_tasks": len(reserved.get(worker_name, [])),
            }
            for worker_name in pong.keys()
        ]
        return {"name": "celery_workers", "status": "up", "latency_ms": latency_ms, "detail": f"{len(workers)} worker(s) online", "workers": workers}
    except Exception as exc:
        latency_ms = round((time.monotonic() - started) * 1000, 1)
        return {"name": "celery_workers", "status": "down", "latency_ms": latency_ms, "detail": str(exc)[:200], "workers": []}


def _check_disk_space() -> dict[str, Any]:
    try:
        total, used, free = shutil.disk_usage(".")
        percent_used = round((used / total) * 100, 1) if total else 0
        status = "up" if percent_used < 85 else ("degraded" if percent_used < 95 else "down")
        return {
            "name": "disk_space",
            "status": status,
            "detail": f"{percent_used}% used",
            "total_gb": round(total / (1024 ** 3), 2),
            "used_gb": round(used / (1024 ** 3), 2),
            "free_gb": round(free / (1024 ** 3), 2),
            "percent_used": percent_used,
        }
    except Exception as exc:
        return {"name": "disk_space", "status": "down", "detail": str(exc)[:200]}


def _check_memory() -> dict[str, Any]:
    try:
        import psutil
        vm = psutil.virtual_memory()
        status = "up" if vm.percent < 85 else ("degraded" if vm.percent < 95 else "down")
        return {
            "name": "memory",
            "status": status,
            "detail": f"{vm.percent}% used",
            "total_gb": round(vm.total / (1024 ** 3), 2),
            "available_gb": round(vm.available / (1024 ** 3), 2),
            "percent_used": vm.percent,
        }
    except Exception as exc:
        return {"name": "memory", "status": "down", "detail": str(exc)[:200]}


async def _compute_system_health(session: AsyncSession) -> dict[str, Any]:
    # Every check used to run sequentially - each network-bound check
    # (celery/mobsf/cape/rampart_ai) can take up to HEALTH_TIMEOUT_SECONDS
    # on its own when that service is down, so a page load with several
    # dead services could block for 15-20s+ before any response reached
    # the client. Running them concurrently means the whole call now takes
    # roughly as long as the single slowest check, not the sum of all of
    # them.
    checks = await asyncio.gather(
        _check_database(session),
        run_in_threadpool(_check_redis),
        run_in_threadpool(_check_celery_workers),
        run_in_threadpool(_check_external_service, "mobsf", os.getenv("MOBSF_BASE_URL"), "/"),
        run_in_threadpool(_check_external_service, "cape", os.getenv("CAPE_BASE_URL"), "/"),
        run_in_threadpool(_check_external_service, "rampart_ai", os.getenv("RAMPARTAI_URL"), "/"),
        run_in_threadpool(_check_disk_space),
        run_in_threadpool(_check_memory),
    )

    overall = "up"
    for check in checks:
        if check["status"] == "down":
            overall = "down"
            break
        if check["status"] in ("degraded", "unconfigured"):
            overall = "degraded"

    return {
        "success": True,
        "data": {
            "overall_status": overall,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "checks": checks,
        },
    }


async def get_system_health(session: AsyncSession, *, force_refresh: bool = False) -> dict[str, Any]:
    if force_refresh:
        invalidate_cached(HEALTH_CACHE_NAMESPACE)
    return await cached_async(
        HEALTH_CACHE_NAMESPACE,
        HEALTH_CACHE_TTL_SECONDS,
        lambda: _compute_system_health(session),
    )
