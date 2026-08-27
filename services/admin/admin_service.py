"""Business logic backing the admin panel: user listing, ban/unban, role
changes (master-only), cross-user analysis history, system dashboard, and
audit logging.

Every mutating (and every privileged cross-user read) function here takes
the acting `User` object - not just an actor uid string - so
`services.admin.authz.ensure_can_manage_target` can be enforced right here
in the service layer too, as defense in depth on top of the controller-level
check. A function in this module must never be reachable in a way that
skips that call.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta as _timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import and_, asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager, joinedload

from cores.Schema.schema_class import AuditLog, Analysis, DownloadHistory, LoginHistory, Reports, User
from schemas.admin import AdminUserHistoryParams
from services.admin.authz import (
    ROLE_ADMIN,
    ROLE_MASTER,
    AuthError,
    ensure_can_manage_file_owner,
    ensure_can_manage_target,
)
from utils.cache import build_suffix, cached_async, invalidate_cached

AUDIT_LOG_CACHE_NAMESPACE = "admin:audit_logs"
AUDIT_LOG_CACHE_TTL_SECONDS = 5
USER_LIST_CACHE_NAMESPACE = "admin:users:list"
USER_LIST_CACHE_TTL_SECONDS = 5
USER_HISTORY_CACHE_NAMESPACE = "admin:users:history"
USER_HISTORY_CACHE_TTL_SECONDS = 5
USER_LOGIN_HISTORY_CACHE_NAMESPACE = "admin:users:login_history"
USER_DOWNLOAD_HISTORY_CACHE_NAMESPACE = "admin:users:download_history"
FILE_LIST_CACHE_NAMESPACE = "admin:files:list"
FILE_LIST_CACHE_TTL_SECONDS = 5
REPORT_LIST_CACHE_NAMESPACE = "admin:reports:list"
REPORT_LIST_CACHE_TTL_SECONDS = 5
DASHBOARD_CACHE_NAMESPACE = "admin:dashboard"
DASHBOARD_CACHE_TTL_SECONDS = 20


def _invalidate_user_caches(target_uid: uuid.UUID | None = None) -> None:
    invalidate_cached(USER_LIST_CACHE_NAMESPACE)
    invalidate_cached(DASHBOARD_CACHE_NAMESPACE)
    invalidate_cached(AUDIT_LOG_CACHE_NAMESPACE)
    if target_uid:
        invalidate_cached(USER_HISTORY_CACHE_NAMESPACE, str(target_uid))


def _invalidate_file_caches() -> None:
    invalidate_cached(FILE_LIST_CACHE_NAMESPACE)
    invalidate_cached(REPORT_LIST_CACHE_NAMESPACE)
    invalidate_cached(DASHBOARD_CACHE_NAMESPACE)
    invalidate_cached(AUDIT_LOG_CACHE_NAMESPACE)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


async def write_audit_log(
    session: AsyncSession,
    *,
    actor_uid: uuid.UUID,
    target_uid: uuid.UUID | None,
    action: str,
    detail: str | None = None,
) -> None:
    """Appends one row to `audit_logs`. Caller is responsible for committing
    (or letting the surrounding transaction commit) - this only adds to the
    session so it can be written atomically alongside the mutation it is
    logging (e.g. the ban itself)."""
    session.add(
        AuditLog(
            actor_uid=actor_uid,
            target_uid=target_uid,
            action=action,
            detail=detail,
        )
    )


async def _fetch_audit_logs(
    session: AsyncSession,
    *,
    page: int,
    limit: int,
    actor_uid: uuid.UUID | None,
    action: str | None,
) -> dict[str, Any]:
    conditions = []
    if actor_uid is not None:
        conditions.append(AuditLog.actor_uid == actor_uid)
    if action:
        conditions.append(AuditLog.action.ilike(f"%{action}%"))
    where_clause = and_(*conditions) if conditions else None

    count_stmt = select(func.count()).select_from(AuditLog)
    if where_clause is not None:
        count_stmt = count_stmt.where(where_clause)
    total = (await session.execute(count_stmt)).scalar_one()

    stmt = (
        select(AuditLog)
        .options(joinedload(AuditLog.actor), joinedload(AuditLog.target))
        .order_by(desc(AuditLog.created_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    if where_clause is not None:
        stmt = stmt.where(where_clause)

    rows = (await session.execute(stmt)).scalars().unique().all()

    def serialize(log: AuditLog) -> dict[str, Any]:
        return {
            "log_id": str(log.log_id),
            "actor_uid": str(log.actor_uid),
            "actor_username": log.actor.username if log.actor else None,
            "target_uid": str(log.target_uid) if log.target_uid else None,
            "target_username": log.target.username if log.target else None,
            "action": log.action,
            "detail": log.detail,
            "created_at": log.created_at.isoformat() if log.created_at else None,
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


async def list_audit_logs(
    session: AsyncSession,
    *,
    page: int,
    limit: int,
    actor_uid: uuid.UUID | None = None,
    action: str | None = None,
) -> dict[str, Any]:
    suffix = build_suffix(
        page=page,
        limit=limit,
        actor_uid=str(actor_uid) if actor_uid else None,
        action=action,
    )
    return await cached_async(
        AUDIT_LOG_CACHE_NAMESPACE,
        AUDIT_LOG_CACHE_TTL_SECONDS,
        lambda: _fetch_audit_logs(session, page=page, limit=limit, actor_uid=actor_uid, action=action),
        suffix=suffix,
    )


# ---------------------------------------------------------------------------
# User listing / detail
# ---------------------------------------------------------------------------


def serialize_user(user: User) -> dict[str, Any]:
    return {
        "uid": str(user.uid),
        "username": user.username,
        "email": user.email,
        "avatar_url": user.avatar_url,
        "role": user.role,
        "status": user.status,
        "is_banned": user.is_banned,
        "banned_at": user.banned_at.isoformat() if user.banned_at else None,
        "banned_reason": user.banned_reason,
        "banned_by": str(user.banned_by) if user.banned_by else None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


async def _fetch_users(
    session: AsyncSession,
    *,
    q: str | None,
    role_filter: str | list[str] | None,
    banned_filter: bool | None,
    page: int,
    limit: int,
) -> dict[str, Any]:
    conditions = []
    if q:
        search_term = f"%{q}%"
        conditions.append(
            or_(User.username.ilike(search_term), User.email.ilike(search_term))
        )
    if role_filter:
        if isinstance(role_filter, str):
            conditions.append(User.role == role_filter)
        else:
            conditions.append(User.role.in_(role_filter))
    if banned_filter is not None:
        conditions.append(User.is_banned == banned_filter)

    where_clause = and_(*conditions) if conditions else None

    count_stmt = select(func.count()).select_from(User)
    if where_clause is not None:
        count_stmt = count_stmt.where(where_clause)
    total = (await session.execute(count_stmt)).scalar_one()

    stmt = (
        select(User)
        .order_by(desc(User.created_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    if where_clause is not None:
        stmt = stmt.where(where_clause)

    users = (await session.execute(stmt)).scalars().all()

    total_pages = max(1, -(-total // limit))
    return {
        "success": True,
        "data": [serialize_user(u) for u in users],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        },
    }


async def list_users(
    session: AsyncSession,
    *,
    q: str | None,
    role_filter: str | list[str] | None,
    banned_filter: bool | None,
    page: int,
    limit: int,
) -> dict[str, Any]:
    suffix = build_suffix(
        q=q,
        role=",".join(role_filter) if isinstance(role_filter, list) else role_filter,
        banned=banned_filter,
        page=page,
        limit=limit,
    )
    return await cached_async(
        USER_LIST_CACHE_NAMESPACE,
        USER_LIST_CACHE_TTL_SECONDS,
        lambda: _fetch_users(session, q=q, role_filter=role_filter, banned_filter=banned_filter, page=page, limit=limit),
        suffix=suffix,
    )


async def get_user_admin_view(session: AsyncSession, target_uid: uuid.UUID) -> User | None:
    return await session.get(User, target_uid)


async def _fetch_user_login_history(
    session: AsyncSession,
    target_uid: uuid.UUID,
    *,
    page: int,
    limit: int,
) -> dict[str, Any]:
    total = (
        await session.execute(
            select(func.count()).select_from(LoginHistory).where(LoginHistory.uid == target_uid)
        )
    ).scalar_one()

    stmt = (
        select(LoginHistory)
        .where(LoginHistory.uid == target_uid)
        .order_by(desc(LoginHistory.created_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()

    total_pages = max(1, -(-total // limit))
    return {
        "success": True,
        "data": [
            {
                "id": str(r.id),
                "provider": r.provider,
                "ip": r.ip,
                "user_agent": r.user_agent,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        },
    }


async def get_user_login_history_admin(
    session: AsyncSession,
    target_uid: uuid.UUID,
    *,
    page: int,
    limit: int,
) -> dict[str, Any]:
    suffix = build_suffix(uid=str(target_uid), page=page, limit=limit)
    return await cached_async(
        USER_LOGIN_HISTORY_CACHE_NAMESPACE,
        USER_HISTORY_CACHE_TTL_SECONDS,
        lambda: _fetch_user_login_history(session, target_uid, page=page, limit=limit),
        suffix=suffix,
    )


async def _fetch_user_download_history(
    session: AsyncSession,
    target_uid: uuid.UUID,
    *,
    page: int,
    limit: int,
) -> dict[str, Any]:
    total = (
        await session.execute(
            select(func.count()).select_from(DownloadHistory).where(DownloadHistory.uid == target_uid)
        )
    ).scalar_one()

    stmt = (
        select(DownloadHistory)
        .where(DownloadHistory.uid == target_uid)
        .order_by(desc(DownloadHistory.created_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()

    total_pages = max(1, -(-total // limit))
    return {
        "success": True,
        "data": [
            {
                "id": str(r.id),
                "file_name": r.file_name,
                "tool": r.tool,
                "md5": r.md5,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        },
    }


async def get_user_download_history_admin(
    session: AsyncSession,
    target_uid: uuid.UUID,
    *,
    page: int,
    limit: int,
) -> dict[str, Any]:
    suffix = build_suffix(uid=str(target_uid), page=page, limit=limit)
    return await cached_async(
        USER_DOWNLOAD_HISTORY_CACHE_NAMESPACE,
        USER_HISTORY_CACHE_TTL_SECONDS,
        lambda: _fetch_user_download_history(session, target_uid, page=page, limit=limit),
        suffix=suffix,
    )


async def get_user_analysis_history_admin(
    session: AsyncSession,
    target_uid: uuid.UUID,
    params: AdminUserHistoryParams,
) -> dict[str, Any]:
    """Same shape as services.analy.analy_service.get_analysis_history, but
    deliberately implemented as a separate function rather than a
    parameterized version of that one: the self-service endpoint's
    hard-coded `Analysis.uid == uid` scoping must never be able to
    accidentally acquire an admin-override path through a shared code
    path. Also intentionally does NOT filter on `privacy` - admin/master
    see private files too, per explicit product requirement, and every
    call to this function is expected to have already gone through
    `ensure_can_manage_target` and produced an audit log entry."""
    conditions = [
        Analysis.uid == target_uid,
        Analysis.deleted_at.is_(None),
    ]

    if params.status:
        conditions.append(Analysis.status == params.status)
    if params.file_type:
        conditions.append(Analysis.file_type.ilike(params.file_type.strip()))
    if params.s:
        search_term = f"%{params.s}%"
        conditions.append(
            or_(
                Analysis.file_name.ilike(search_term),
                Analysis.md5.ilike(search_term),
                Analysis.file_hash.ilike(search_term),
            )
        )

    where_clause = and_(*conditions)

    total = (
        await session.execute(
            select(func.count()).select_from(Analysis).where(where_clause)
        )
    ).scalar_one()

    sort_map = {
        "created_at": Analysis.created_at,
        "file_name": Analysis.file_name,
        "file_size": Analysis.file_size,
        "score": Reports.score,
    }
    sort_priority = [
        ("created_at", params.created_at),
        ("file_name", params.file_name),
        ("file_size", params.file_size),
        ("score", params.score),
    ]
    order_by = [
        asc(sort_map[col]) if direction == 1 else desc(sort_map[col])
        for col, direction in sort_priority
        if direction != 0
    ] or [desc(Analysis.created_at)]

    needs_join = params.score != 0
    stmt = (
        select(Analysis)
        .where(where_clause)
        .order_by(*order_by)
        .offset((params.page - 1) * params.limit)
        .limit(params.limit)
    )
    if needs_join:
        stmt = stmt.outerjoin(Reports, Analysis.rid == Reports.rid).options(
            contains_eager(Analysis.report)
        )
    else:
        stmt = stmt.options(joinedload(Analysis.report))

    analyses = (await session.execute(stmt)).scalars().unique().all()

    def serialize(a: Analysis) -> dict[str, Any]:
        item: dict[str, Any] = {
            "aid": str(a.aid),
            "task_id": a.task_id,
            "file_name": a.file_name,
            "file_size": a.file_size,
            "file_type": a.file_type,
            "file_hash": a.file_hash,
            "md5": a.md5,
            "tools": a.tools,
            "status": a.status,
            "privacy": a.privacy,
            "is_malicious": a.is_malicious,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "report": None,
        }
        if a.report:
            r = a.report
            item["report"] = {
                "score": float(r.score) if r.score is not None else None,
                "rampart_score": float(r.rampart_score) if r.rampart_score is not None else None,
                "risk_level": r.risk_level,
                "virustotal_score": r.virustotal_score,
                "mobsf_score": float(r.mobsf_score) if r.mobsf_score is not None else None,
                "cape_score": float(r.cape_score) if r.cape_score is not None else None,
            }
        return item

    total_pages = max(1, -(-total // params.limit))
    return {
        "success": True,
        "data": [serialize(a) for a in analyses],
        "pagination": {
            "page": params.page,
            "limit": params.limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": params.page < total_pages,
            "has_prev": params.page > 1,
        },
    }


# ---------------------------------------------------------------------------
# System-wide file management (all users) and reports (completed only)
# ---------------------------------------------------------------------------


def _serialize_file_row(analysis: Analysis, owner: User | None, report: Reports | None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "aid": str(analysis.aid),
        "task_id": analysis.task_id,
        "file_name": analysis.file_name,
        "file_size": analysis.file_size,
        "file_type": analysis.file_type,
        "file_hash": analysis.file_hash,
        "md5": analysis.md5,
        "tools": analysis.tools,
        "status": analysis.status,
        "privacy": analysis.privacy,
        "is_malicious": analysis.is_malicious,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        "owner_uid": str(owner.uid) if owner else None,
        "owner_username": owner.username if owner else None,
        "report": None,
    }
    if report:
        item["report"] = {
            "score": float(report.score) if report.score is not None else None,
            "risk_level": report.risk_level,
            "virustotal_score": report.virustotal_score,
            "mobsf_score": float(report.mobsf_score) if report.mobsf_score is not None else None,
            "cape_score": float(report.cape_score) if report.cape_score is not None else None,
        }
    return item


async def list_all_files(
    session: AsyncSession,
    *,
    q: str | None,
    status_filter: str | None,
    file_type_filter: str | None,
    privacy_filter: bool | None,
    page: int,
    limit: int,
) -> dict[str, Any]:
    """System-wide file listing across every user, unlike
    get_user_analysis_history_admin (which is scoped to one target uid).
    Always excludes soft-deleted rows."""
    conditions = [Analysis.deleted_at.is_(None)]
    if status_filter:
        conditions.append(Analysis.status == status_filter)
    if file_type_filter:
        conditions.append(Analysis.file_type.ilike(file_type_filter.strip()))
    if privacy_filter is not None:
        conditions.append(Analysis.privacy == privacy_filter)
    if q:
        search_term = f"%{q}%"
        conditions.append(
            or_(
                Analysis.file_name.ilike(search_term),
                Analysis.md5.ilike(search_term),
                Analysis.file_hash.ilike(search_term),
            )
        )

    where_clause = and_(*conditions)

    total = (
        await session.execute(select(func.count()).select_from(Analysis).where(where_clause))
    ).scalar_one()

    stmt = (
        select(Analysis)
        .options(joinedload(Analysis.user), joinedload(Analysis.report))
        .where(where_clause)
        .order_by(desc(Analysis.created_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    analyses = (await session.execute(stmt)).scalars().unique().all()

    total_pages = max(1, -(-total // limit))
    return {
        "success": True,
        "data": [_serialize_file_row(a, a.user, a.report) for a in analyses],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        },
    }


async def list_reports(
    session: AsyncSession,
    *,
    q: str | None,
    risk_level_filter: str | None,
    file_type_filter: str | None,
    page: int,
    limit: int,
) -> dict[str, Any]:
    """Same shape as list_all_files, hard-filtered to completed analyses
    that actually have a report attached (status == 'success' and rid is
    set) - "จัดการ Report" only ever shows finished results, unlike
    "จัดการไฟล์" which shows every file regardless of analysis state."""
    conditions = [
        Analysis.deleted_at.is_(None),
        Analysis.status == "success",
        Analysis.rid.isnot(None),
    ]
    if file_type_filter:
        conditions.append(Analysis.file_type.ilike(file_type_filter.strip()))
    if q:
        search_term = f"%{q}%"
        conditions.append(
            or_(
                Analysis.file_name.ilike(search_term),
                Analysis.md5.ilike(search_term),
                Analysis.file_hash.ilike(search_term),
            )
        )
    if risk_level_filter:
        conditions.append(Reports.risk_level == risk_level_filter)

    where_clause = and_(*conditions)

    count_stmt = (
        select(func.count())
        .select_from(Analysis)
        .join(Reports, Analysis.rid == Reports.rid)
        .where(where_clause)
    )
    total = (await session.execute(count_stmt)).scalar_one()

    stmt = (
        select(Analysis)
        .join(Reports, Analysis.rid == Reports.rid)
        .options(contains_eager(Analysis.report), joinedload(Analysis.user))
        .where(where_clause)
        .order_by(desc(Analysis.created_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    analyses = (await session.execute(stmt)).scalars().unique().all()

    total_pages = max(1, -(-total // limit))
    return {
        "success": True,
        "data": [_serialize_file_row(a, a.user, a.report) for a in analyses],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        },
    }


async def _purge_temp_file_if_unreferenced(session: AsyncSession, file_path: str | None) -> None:
    """Deletes the on-disk upload under temps_files/ ONLY if no other
    (non-soft-deleted) Analysis row still points at the same file_path.

    file_path is content-hash-named and deliberately reused across
    multiple Analysis rows by the dedup logic in
    services.analy.analy_service.attempt_attach_to_existing_analysis (e.g.
    two different users uploading the same APK, or the same user
    re-uploading it under a different display name, all reuse one on-disk
    copy). Soft-deleting ANY one of those rows must never delete the file
    out from under the others still relying on it - this check runs
    within the same DB transaction as the soft-delete itself, right
    before commit, so the count it sees already reflects this call's own
    deleted_at write.
    """
    if not file_path:
        return
    still_referenced = await session.execute(
        select(func.count())
        .select_from(Analysis)
        .where(Analysis.file_path == file_path, Analysis.deleted_at.is_(None))
    )
    if still_referenced.scalar_one() > 0:
        return
    try:
        Path(file_path).unlink(missing_ok=True)
    except OSError:
        # Best-effort - a locked/already-gone file must never fail the
        # surrounding soft-delete transaction.
        pass


async def soft_delete_file(
    session: AsyncSession,
    *,
    actor: User,
    aid: uuid.UUID,
    reason: str,
) -> Analysis:
    """Soft-deletes one Analysis row (sets deleted_at/deleted_by), then
    removes the on-disk upload under temps_files/ if no other row still
    references it (see _purge_temp_file_if_unreferenced). Every existing
    query that reads Analysis already filters `deleted_at IS NULL`
    (get_analysis_history, get_reports_history,
    get_user_analysis_history_admin, list_all_files/list_reports above,
    and the admin dashboard's total_analyses count) - so a deleted file
    disappears from the owner's history, the public feed, and every stat
    automatically, with no other query needing to change.

    Follows the exact same actor/target permission rule as ban/unban:
    admin can delete a plain user's file, but not another admin's or
    master's file; master can delete anyone's file except another
    master's."""
    analysis = await session.get(Analysis, aid, options=[joinedload(Analysis.user)])
    if analysis is None:
        raise AuthError(404, "TARGET_NOT_FOUND", "ไม่พบไฟล์เป้าหมาย")
    if analysis.deleted_at is not None:
        raise AuthError(409, "ALREADY_DELETED", "ไฟล์นี้ถูกลบไปแล้ว")

    owner = analysis.user
    if owner is None:
        # Should not happen (uid is NOT NULL / FK), but fail closed rather
        # than allow a delete with no ownership check.
        raise AuthError(404, "TARGET_NOT_FOUND", "ไม่พบเจ้าของไฟล์")

    ensure_can_manage_file_owner(actor, owner)

    analysis.deleted_at = datetime.now(timezone.utc)
    analysis.deleted_by = actor.uid

    await write_audit_log(
        session,
        actor_uid=actor.uid,
        target_uid=owner.uid,
        action="delete_file",
        detail=f"{analysis.file_name} | reason={reason}",
    )
    await _purge_temp_file_if_unreferenced(session, analysis.file_path)
    await session.commit()
    await session.refresh(analysis)
    return analysis


async def bulk_soft_delete_files(
    session: AsyncSession,
    *,
    actor: User,
    aids: list[uuid.UUID],
    reason: str,
) -> dict[str, Any]:
    succeeded: list[str] = []
    failed: list[dict[str, str]] = []
    for aid in aids:
        try:
            analysis = await session.get(Analysis, aid, options=[joinedload(Analysis.user)])
            if analysis is None:
                failed.append({"aid": str(aid), "reason": "ไม่พบไฟล์"})
                continue
            if analysis.deleted_at is not None:
                failed.append({"aid": str(aid), "reason": "ถูกลบไปแล้ว"})
                continue
            owner = analysis.user
            if owner is None:
                failed.append({"aid": str(aid), "reason": "ไม่พบเจ้าของไฟล์"})
                continue
            ensure_can_manage_file_owner(actor, owner)
            analysis.deleted_at = datetime.now(timezone.utc)
            analysis.deleted_by = actor.uid
            await write_audit_log(
                session,
                actor_uid=actor.uid,
                target_uid=owner.uid,
                action="delete_file",
                detail=f"{analysis.file_name} | reason={reason} | bulk",
            )
            succeeded.append(str(aid))
        except AuthError as exc:
            failed.append({"aid": str(aid), "reason": exc.message})

    # Purge on-disk files only after every row's deleted_at is set (but
    # still pre-commit within this same transaction) so
    # _purge_temp_file_if_unreferenced's "any other still-referencing row"
    # count correctly sees every file in THIS batch as already deleted too
    # - otherwise two rows in the same bulk request sharing a file_path
    # would each see the other as "still referencing it" and neither would
    # ever get purged.
    for aid_str in succeeded:
        analysis = await session.get(Analysis, uuid.UUID(aid_str))
        if analysis is not None:
            await _purge_temp_file_if_unreferenced(session, analysis.file_path)

    await session.commit()
    return {"success": True, "data": {"succeeded": succeeded, "failed": failed}}


# ---------------------------------------------------------------------------
# Ban / unban / role change
# ---------------------------------------------------------------------------


async def ban_user(
    session: AsyncSession,
    *,
    actor: User,
    target_uid: uuid.UUID,
    reason: str,
) -> User:
    target = await session.get(User, target_uid)
    if target is None:
        raise AuthError(404, "TARGET_NOT_FOUND", "ไม่พบผู้ใช้เป้าหมาย")

    ensure_can_manage_target(actor, target)

    target.is_banned = True
    target.banned_at = datetime.now(timezone.utc)
    target.banned_reason = reason
    target.banned_by = actor.uid

    await write_audit_log(
        session,
        actor_uid=actor.uid,
        target_uid=target.uid,
        action="ban_user",
        detail=f"reason={reason}",
    )
    await session.commit()
    await session.refresh(target)
    return target


async def bulk_ban_users(
    session: AsyncSession,
    *,
    actor: User,
    target_uids: list[uuid.UUID],
    reason: str,
) -> dict[str, Any]:
    succeeded: list[str] = []
    failed: list[dict[str, str]] = []
    for target_uid in target_uids:
        try:
            target = await session.get(User, target_uid)
            if target is None:
                failed.append({"uid": str(target_uid), "reason": "ไม่พบผู้ใช้"})
                continue
            ensure_can_manage_target(actor, target)
            target.is_banned = True
            target.banned_at = datetime.now(timezone.utc)
            target.banned_reason = reason
            target.banned_by = actor.uid
            await write_audit_log(
                session,
                actor_uid=actor.uid,
                target_uid=target.uid,
                action="ban_user",
                detail=f"reason={reason} | bulk",
            )
            succeeded.append(str(target_uid))
        except AuthError as exc:
            failed.append({"uid": str(target_uid), "reason": exc.message})

    await session.commit()
    return {"success": True, "data": {"succeeded": succeeded, "failed": failed}}


async def unban_user(
    session: AsyncSession,
    *,
    actor: User,
    target_uid: uuid.UUID,
) -> User:
    target = await session.get(User, target_uid)
    if target is None:
        raise AuthError(404, "TARGET_NOT_FOUND", "ไม่พบผู้ใช้เป้าหมาย")

    ensure_can_manage_target(actor, target)

    target.is_banned = False
    target.banned_at = None
    target.banned_reason = None
    target.banned_by = None

    await write_audit_log(
        session,
        actor_uid=actor.uid,
        target_uid=target.uid,
        action="unban_user",
        detail=None,
    )
    await session.commit()
    await session.refresh(target)
    return target


async def change_user_role(
    session: AsyncSession,
    *,
    actor: User,
    target_uid: uuid.UUID,
    new_role: str,
) -> User:
    """Master-only (enforced by the caller via ensure_role before this is
    ever invoked, and re-checked here). `new_role` is validated by
    schemas.admin.AdminChangeRoleParams against ASSIGNABLE_ROLES
    ({"user", "admin"}) before it ever reaches this function, so "master"
    can never be passed in even by a request crafted by hand."""
    if actor.role != ROLE_MASTER:
        raise AuthError(403, "INSUFFICIENT_ROLE", "เฉพาะ master เท่านั้นที่เปลี่ยน role ได้")

    target = await session.get(User, target_uid)
    if target is None:
        raise AuthError(404, "TARGET_NOT_FOUND", "ไม่พบผู้ใช้เป้าหมาย")

    ensure_can_manage_target(actor, target)

    old_role = target.role
    target.role = new_role

    await write_audit_log(
        session,
        actor_uid=actor.uid,
        target_uid=target.uid,
        action="role_change",
        detail=f"{old_role}->{new_role}",
    )
    await session.commit()
    await session.refresh(target)
    return target


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


async def get_admin_dashboard_summary(session: AsyncSession, *, trend_days: int = 14) -> dict[str, Any]:
    """Aggregate stats for the admin/master backend dashboard: user/role
    counts, ban count, analysis totals, malicious count, a daily upload
    trend for the last `trend_days` days, breakdowns by risk level /
    analysis status / file type, per-tool usage counts, and the most
    recent privileged admin actions. All queries are read-only aggregates
    over the whole system - no per-user scoping (this endpoint is already
    gated to admin/master by the controller)."""
    total_users = (
        await session.execute(select(func.count()).select_from(User))
    ).scalar_one()

    role_counts_rows = (
        await session.execute(select(User.role, func.count()).group_by(User.role))
    ).all()
    role_breakdown = {role: count for role, count in role_counts_rows}

    banned_count = (
        await session.execute(
            select(func.count()).select_from(User).where(User.is_banned.is_(True))
        )
    ).scalar_one()

    total_analyses = (
        await session.execute(select(func.count()).select_from(Analysis))
    ).scalar_one()

    malicious_count = (
        await session.execute(
            select(func.count())
            .select_from(Analysis)
            .where(Analysis.is_malicious.is_(True))
        )
    ).scalar_one()

    # --- Daily upload trend (last `trend_days` days, oldest first) ---
    trend_rows = (
        await session.execute(
            select(func.date(Analysis.created_at).label("day"), func.count())
            .where(Analysis.created_at >= datetime.now(timezone.utc) - _timedelta(days=trend_days))
            .group_by("day")
        )
    ).all()
    trend_map = {str(day): count for day, count in trend_rows}
    today = datetime.now(timezone.utc).date()
    upload_trend = []
    for offset in range(trend_days - 1, -1, -1):
        day = today - _timedelta(days=offset)
        upload_trend.append({"date": day.isoformat(), "count": trend_map.get(day.isoformat(), 0)})

    # --- Analysis status breakdown (pending/processing/success/failed/...) ---
    status_rows = (
        await session.execute(select(Analysis.status, func.count()).group_by(Analysis.status))
    ).all()
    status_breakdown = [{"status": s or "unknown", "count": c} for s, c in status_rows]

    # --- Risk level breakdown (from Reports; Low/Caution/High/Critical) ---
    risk_rows = (
        await session.execute(select(Reports.risk_level, func.count()).group_by(Reports.risk_level))
    ).all()
    risk_level_breakdown = [{"risk_level": r or "N/A", "count": c} for r, c in risk_rows]

    # --- File type breakdown (top 8, rest bucketed as "other") ---
    file_type_rows = (
        await session.execute(
            select(Analysis.file_type, func.count())
            .group_by(Analysis.file_type)
            .order_by(desc(func.count()))
        )
    ).all()
    file_type_breakdown = [
        {"file_type": (ft or "unknown").lower(), "count": c} for ft, c in file_type_rows[:8]
    ]
    other_count = sum(c for _, c in file_type_rows[8:])
    if other_count:
        file_type_breakdown.append({"file_type": "other", "count": other_count})

    # --- Per-tool usage (tools column is a comma-separated string, e.g.
    #     "virustotal,mobsf,cape,rampart_ai,gemini") ---
    tools_rows = (
        await session.execute(select(Analysis.tools).where(Analysis.tools.isnot(None)))
    ).scalars().all()
    tool_usage_counter: dict[str, int] = {}
    for tools_str in tools_rows:
        for tool in {t.strip() for t in tools_str.split(",") if t.strip()}:
            tool_usage_counter[tool] = tool_usage_counter.get(tool, 0) + 1
    tool_usage = [
        {"tool": tool, "count": count}
        for tool, count in sorted(tool_usage_counter.items(), key=lambda kv: kv[1], reverse=True)
    ]

    recent_bans_rows = (
        await session.execute(
            select(AuditLog)
            .options(joinedload(AuditLog.actor), joinedload(AuditLog.target))
            .order_by(desc(AuditLog.created_at))
            .limit(10)
        )
    ).scalars().unique().all()

    recent_actions = [
        {
            "log_id": str(log.log_id),
            "actor_username": log.actor.username if log.actor else None,
            "target_username": log.target.username if log.target else None,
            "action": log.action,
            "detail": log.detail,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in recent_bans_rows
    ]

    return {
        "success": True,
        "data": {
            "total_users": total_users,
            "role_breakdown": {
                "user": role_breakdown.get("user", 0),
                "admin": role_breakdown.get(ROLE_ADMIN, 0),
                "master": role_breakdown.get(ROLE_MASTER, 0),
            },
            "banned_count": banned_count,
            "total_analyses": total_analyses,
            "malicious_count": malicious_count,
            "upload_trend": upload_trend,
            "status_breakdown": status_breakdown,
            "risk_level_breakdown": risk_level_breakdown,
            "file_type_breakdown": file_type_breakdown,
            "tool_usage": tool_usage,
            "recent_actions": recent_actions,
        },
    }


async def export_users_csv(session: AsyncSession) -> str:
    import csv
    import io

    rows = (await session.execute(select(User).order_by(desc(User.created_at)))).scalars().all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["uid", "username", "email", "role", "status", "is_banned", "banned_reason", "created_at"])
    for u in rows:
        writer.writerow([
            str(u.uid), u.username, u.email, u.role, u.status, u.is_banned,
            u.banned_reason or "", u.created_at.isoformat() if u.created_at else "",
        ])
    return buffer.getvalue()


async def export_files_csv(session: AsyncSession) -> str:
    import csv
    import io

    stmt = (
        select(Analysis)
        .options(joinedload(Analysis.user), joinedload(Analysis.report))
        .where(Analysis.deleted_at.is_(None))
        .order_by(desc(Analysis.created_at))
    )
    rows = (await session.execute(stmt)).scalars().unique().all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["aid", "task_id", "file_name", "file_type", "status", "owner", "score", "risk_level", "is_malicious", "created_at"])
    for a in rows:
        writer.writerow([
            str(a.aid), a.task_id or "", a.file_name or "", a.file_type or "", a.status or "",
            a.user.username if a.user else "",
            float(a.report.score) if a.report and a.report.score is not None else "",
            a.report.risk_level if a.report else "",
            a.is_malicious, a.created_at.isoformat() if a.created_at else "",
        ])
    return buffer.getvalue()


async def export_audit_logs_csv(session: AsyncSession) -> str:
    import csv
    import io

    stmt = (
        select(AuditLog)
        .options(joinedload(AuditLog.actor), joinedload(AuditLog.target))
        .order_by(desc(AuditLog.created_at))
        .limit(5000)
    )
    rows = (await session.execute(stmt)).scalars().unique().all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["log_id", "actor", "target", "action", "detail", "created_at"])
    for log in rows:
        writer.writerow([
            str(log.log_id),
            log.actor.username if log.actor else "",
            log.target.username if log.target else "",
            log.action or "",
            log.detail or "",
            log.created_at.isoformat() if log.created_at else "",
        ])
    return buffer.getvalue()


async def broadcast_email(
    session: AsyncSession,
    *,
    actor: User,
    subject: str,
    message: str,
    target_role: str | None,
) -> dict[str, Any]:
    from utils.mailer import send_email

    stmt = select(User.email, User.username)
    if target_role:
        stmt = stmt.where(User.role == target_role)
    rows = (await session.execute(stmt)).all()

    sent = 0
    for email, username in rows:
        if not email:
            continue
        text_body = f"สวัสดีคุณ {username},\n\n{message}\n\n— ทีมงาน RAMPART"
        html_body = f"""
        <div style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:auto">
          <p>สวัสดีคุณ {username},</p>
          <p style="white-space:pre-line">{message}</p>
          <p style="color:#888;font-size:12px">— ทีมงาน RAMPART</p>
        </div>
        """
        if send_email(email, subject, text_body, html_body):
            sent += 1

    await write_audit_log(
        session,
        actor_uid=actor.uid,
        target_uid=None,
        action="broadcast_email",
        detail=f"subject={subject} | role={target_role or 'all'} | sent={sent}",
    )
    await session.commit()

    return {"success": True, "data": {"sent": sent, "total_recipients": len(rows)}}
