from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from cores.Schema.schema_class import Analysis, User
from utils.cache import build_suffix, cached_async, cached_sync, invalidate_cached

ACTIVE_STATUSES = ("dispatching", "queued", "processing")

TASK_LIST_CACHE_NAMESPACE = "admin:tasks:list"
TASK_LIST_CACHE_TTL_SECONDS = 5
QUEUE_DEPTH_CACHE_NAMESPACE = "admin:tasks:depth"
QUEUE_DEPTH_CACHE_TTL_SECONDS = 5

async def _fetch_active_tasks(
    session: AsyncSession,
    *,
    status_filter: str | None,
    q: str | None,
    page: int,
    limit: int,
) -> dict[str, Any]:
    conditions = [Analysis.deleted_at.is_(None)]
    if status_filter:
        conditions.append(Analysis.status == status_filter)
    else:
        conditions.append(Analysis.status.in_(ACTIVE_STATUSES))
    if q:
        search_term = f"%{q}%"
        conditions.append(
            or_(
                Analysis.file_name.ilike(search_term),
                Analysis.task_id.ilike(search_term),
                Analysis.md5.ilike(search_term),
            )
        )

    where_clause = and_(*conditions)

    total = (
        await session.execute(select(func.count()).select_from(Analysis).where(where_clause))
    ).scalar_one()

    stmt = (
        select(Analysis)
        .options(joinedload(Analysis.user))
        .where(where_clause)
        .order_by(desc(Analysis.created_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().unique().all()

    def serialize(a: Analysis) -> dict[str, Any]:
        age_seconds = None
        if a.created_at:
            age_seconds = int((datetime.now(timezone.utc) - a.created_at).total_seconds())
        return {
            "aid": str(a.aid),
            "task_id": a.task_id,
            "file_name": a.file_name,
            "status": a.status,
            "tool_notes": a.tool_notes,
            "owner_username": a.user.username if a.user else None,
            "owner_uid": str(a.uid),
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "age_seconds": age_seconds,
        }

    total_pages = max(1, -(-total // limit))
    return {
        "success": True,
        "data": [serialize(r) for r in rows],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        },
    }

async def list_active_tasks(
    session: AsyncSession,
    *,
    status_filter: str | None,
    q: str | None,
    page: int,
    limit: int,
) -> dict[str, Any]:
    suffix = build_suffix(status=status_filter, q=q, page=page, limit=limit)
    return await cached_async(
        TASK_LIST_CACHE_NAMESPACE,
        TASK_LIST_CACHE_TTL_SECONDS,
        lambda: _fetch_active_tasks(session, status_filter=status_filter, q=q, page=page, limit=limit),
        suffix=suffix,
    )

def _fetch_queue_depth() -> dict[str, Any]:
    try:
        from bgProcessing.celery_app import celery_app
        inspector = celery_app.control.inspect(timeout=3)
        active = inspector.active() or {}
        reserved = inspector.reserved() or {}
        scheduled = inspector.scheduled() or {}
        total_active = sum(len(v) for v in active.values())
        total_reserved = sum(len(v) for v in reserved.values())
        total_scheduled = sum(len(v) for v in scheduled.values())
        return {
            "success": True,
            "data": {
                "active": total_active,
                "reserved": total_reserved,
                "scheduled": total_scheduled,
                "workers_online": len(active.keys()) if active else 0,
            },
        }
    except Exception as exc:
        return {
            "success": True,
            "data": {"active": 0, "reserved": 0, "scheduled": 0, "workers_online": 0, "error": str(exc)[:200]},
        }

def get_queue_depth() -> dict[str, Any]:
    return cached_sync(QUEUE_DEPTH_CACHE_NAMESPACE, QUEUE_DEPTH_CACHE_TTL_SECONDS, _fetch_queue_depth)

def _invalidate_task_caches() -> None:
    invalidate_cached(TASK_LIST_CACHE_NAMESPACE)
    invalidate_cached(QUEUE_DEPTH_CACHE_NAMESPACE)
    invalidate_cached("analy:task_status")

async def retry_task(session: AsyncSession, task_id: str) -> dict[str, Any]:
    result = await session.execute(select(Analysis).where(Analysis.task_id == task_id))
    rows = result.scalars().all()
    if not rows:
        return {"success": False, "message": "ไม่พบ task นี้"}

    from bgProcessing.tasks import analyze_malware_task

    row = rows[0]
    for r in rows:
        r.status = "queued"
        r.tool_notes = None
    await session.commit()

    analyze_malware_task.apply_async(
        args=(row.file_path, row.md5, row.file_hash, row.file_size or 0),
        task_id=task_id,
    )
    _invalidate_task_caches()
    return {"success": True, "message": "ส่ง task เข้าคิวใหม่แล้ว", "task_id": task_id}

async def cancel_task(session: AsyncSession, task_id: str) -> dict[str, Any]:
    result = await session.execute(select(Analysis).where(Analysis.task_id == task_id))
    rows = result.scalars().all()
    if not rows:
        return {"success": False, "message": "ไม่พบ task นี้"}

    try:
        from bgProcessing.celery_app import celery_app
        celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
    except Exception:
        pass

    for r in rows:
        r.status = "failed"
        r.tool_notes = None
    await session.commit()
    _invalidate_task_caches()
    return {"success": True, "message": "ยกเลิก task แล้ว", "task_id": task_id}
