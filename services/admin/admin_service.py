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
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager, joinedload

from cores.Schema.schema_class import AuditLog, Analysis, Reports, User
from schemas.admin import AdminUserHistoryParams
from services.admin.authz import (
    ROLE_ADMIN,
    ROLE_MASTER,
    AuthError,
    ensure_can_manage_target,
)


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


async def list_audit_logs(
    session: AsyncSession,
    *,
    page: int,
    limit: int,
    actor_uid: uuid.UUID | None = None,
    action: str | None = None,
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


async def list_users(
    session: AsyncSession,
    *,
    q: str | None,
    role_filter: str | None,
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
        conditions.append(User.role == role_filter)
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


async def get_user_admin_view(session: AsyncSession, target_uid: uuid.UUID) -> User | None:
    return await session.get(User, target_uid)


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


async def get_admin_dashboard_summary(session: AsyncSession) -> dict[str, Any]:
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

    recent_bans_rows = (
        await session.execute(
            select(AuditLog)
            .options(joinedload(AuditLog.actor), joinedload(AuditLog.target))
            .where(AuditLog.action.in_(("ban_user", "unban_user", "role_change")))
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
            "recent_actions": recent_actions,
        },
    }
