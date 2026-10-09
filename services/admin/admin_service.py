from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta as _timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import and_, asc, delete, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import contains_eager, joinedload

from cores.Schema.schema_class import AuditLog, Analysis, DownloadHistory, LoginHistory, Reports, User
from schemas.admin import AdminUserHistoryParams
from utils.evidence_score import rampart_ai_score
from utils.uuid import parse_uuid
from services.admin.authz import (
    ASSIGNABLE_ROLES,
    ROLE_ADMIN,
    ROLE_MASTER,
    AuthError,
    ensure_can_manage_file_owner,
    ensure_can_manage_target,
    ensure_can_manage_non_master_target,
    ensure_can_ban_target,
)
from services.dashboard.dashboars_service import invalidate_public_caches
from utils.cache import build_suffix, cached_async, invalidate_cached
from utils.cypto.PasswordCreateAndVerify import get_password_hash
from utils.email_normalize import normalize_email, normalized_email_expr
from utils.password_policy import validate_password_policy

AUDIT_LOG_CACHE_NAMESPACE = "admin:audit_logs"
AUDIT_LOG_CACHE_TTL_SECONDS = 5
USER_LIST_CACHE_NAMESPACE = "admin:users:list"
USER_LIST_CACHE_TTL_SECONDS = 5
USER_HISTORY_CACHE_NAMESPACE = "admin:users:history"
USER_HISTORY_CACHE_TTL_SECONDS = 5
USER_LOGIN_HISTORY_CACHE_NAMESPACE = "admin:users:login_history"
USER_DOWNLOAD_HISTORY_CACHE_NAMESPACE = "admin:users:download_history"
USER_PASSWORD_HISTORY_CACHE_NAMESPACE = "admin:users:password_history"
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

async def write_audit_log(
    session: AsyncSession,
    *,
    actor_uid: uuid.UUID,
    target_uid: uuid.UUID | None,
    action: str,
    detail: str | None = None,
) -> None:
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
    q: str | None,
    date_from: str | None,
    date_to: str | None,
) -> dict[str, Any]:
    conditions = []
    if actor_uid is not None:
        conditions.append(AuditLog.actor_uid == actor_uid)
    if action:
        conditions.append(AuditLog.action.ilike(f"%{action}%"))
    if q:
        search_term = f"%{q}%"
        conditions.append(
            or_(
                AuditLog.actor.has(User.username.ilike(search_term)),
                AuditLog.target.has(User.username.ilike(search_term)),
                AuditLog.detail.ilike(search_term),
            )
        )
    if date_from:
        conditions.append(
            AuditLog.created_at
            >= datetime.strptime(date_from, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        )
    if date_to:
        conditions.append(
            AuditLog.created_at
            < datetime.strptime(date_to, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            + _timedelta(days=1)
        )
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
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, Any]:
    suffix = build_suffix(
        page=page,
        limit=limit,
        actor_uid=str(actor_uid) if actor_uid else None,
        action=action,
        q=q,
        date_from=date_from,
        date_to=date_to,
    )
    return await cached_async(
        AUDIT_LOG_CACHE_NAMESPACE,
        AUDIT_LOG_CACHE_TTL_SECONDS,
        lambda: _fetch_audit_logs(
            session,
            page=page,
            limit=limit,
            actor_uid=actor_uid,
            action=action,
            q=q,
            date_from=date_from,
            date_to=date_to,
        ),
        suffix=suffix,
    )

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
    status_filter: str | None,
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
    if status_filter and status_filter != "all":
        conditions.append(User.status == status_filter)

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
    status_filter: str | None,
    page: int,
    limit: int,
) -> dict[str, Any]:
    print(f"[DEBUG] list_users: role_filter={role_filter}, banned_filter={banned_filter}, status_filter={status_filter}")
    suffix = build_suffix(
        q=q,
        role=",".join(role_filter) if isinstance(role_filter, list) else role_filter,
        banned=banned_filter,
        status=status_filter,
        page=page,
        limit=limit,
    )
    return await cached_async(
        USER_LIST_CACHE_NAMESPACE,
        USER_LIST_CACHE_TTL_SECONDS,
        lambda: _fetch_users(
            session,
            q=q,
            role_filter=role_filter,
            banned_filter=banned_filter,
            status_filter=status_filter,
            page=page,
            limit=limit,
        ),
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

async def _fetch_user_password_history(
    session: AsyncSession,
    target_uid: uuid.UUID,
    *,
    page: int,
    limit: int,
) -> dict[str, Any]:
    condition = and_(
        AuditLog.target_uid == target_uid,
        AuditLog.action.in_(["change_password", "admin_reset_password"]),
    )
    total = (
        await session.execute(
            select(func.count()).select_from(AuditLog).where(condition)
        )
    ).scalar_one()

    stmt = (
        select(AuditLog)
        .where(condition)
        .order_by(desc(AuditLog.created_at))
        .offset((page - 1) * limit)
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()

    total_pages = max(1, -(-total // limit))
    return {
        "success": True,
        "data": [
            {
                "id": str(r.log_id),
                "ip": (json.loads(r.detail).get("ip") if r.detail and r.detail.startswith("{") else None),
                "user_agent": (json.loads(r.detail).get("user_agent") if r.detail and r.detail.startswith("{") else None),
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

async def get_user_password_history_admin(
    session: AsyncSession,
    target_uid: uuid.UUID,
    *,
    page: int,
    limit: int,
) -> dict[str, Any]:
    suffix = build_suffix(uid=str(target_uid), page=page, limit=limit)
    return await cached_async(
        USER_PASSWORD_HISTORY_CACHE_NAMESPACE,
        USER_HISTORY_CACHE_TTL_SECONDS,
        lambda: _fetch_user_password_history(session, target_uid, page=page, limit=limit),
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
                "rampart_score": rampart_ai_score(r.rampart_ai_score),
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

async def delete_user_history_entry(
    session: AsyncSession,
    *,
    actor: User,
    target_uid: uuid.UUID,
    kind: str,
    entry_id: str,
) -> dict[str, Any]:
    if actor.role != ROLE_MASTER:
        raise AuthError(403, "INSUFFICIENT_ROLE", "เฉพาะ master เท่านั้นที่ลบประวัติได้")

    target = await session.get(User, target_uid)
    if target is None:
        raise AuthError(404, "TARGET_NOT_FOUND", "ไม่พบผู้ใช้เป้าหมาย")
    ensure_can_manage_target(actor, target)

    try:
        parsed_id = parse_uuid(entry_id)
    except (TypeError, ValueError):
        raise AuthError(400, "INVALID_HISTORY_ID", "รหัสรายการประวัติไม่ถูกต้อง")

    detail = kind
    if kind == "analysis":
        row = await session.get(Analysis, parsed_id)
        if row is None or row.uid != target_uid or row.deleted_at is not None:
            raise AuthError(404, "HISTORY_NOT_FOUND", "ไม่พบประวัติที่ต้องการลบ")
        row.deleted_at = datetime.now(timezone.utc)
        detail = f"analysis:{row.file_name or row.aid}"
    elif kind == "login":
        row = await session.get(LoginHistory, parsed_id)
        if row is None or row.uid != target_uid:
            raise AuthError(404, "HISTORY_NOT_FOUND", "ไม่พบประวัติที่ต้องการลบ")
        await session.delete(row)
        detail = f"login:{row.provider or '-'}@{row.created_at}"
    elif kind == "password":
        row = await session.get(AuditLog, parsed_id)
        if row is None or row.actor_uid != target_uid or row.action != "change_password":
            raise AuthError(404, "HISTORY_NOT_FOUND", "ไม่พบประวัติที่ต้องการลบ")
        await session.delete(row)
        detail = f"password:{row.created_at}"
    elif kind == "download":
        row = await session.get(DownloadHistory, parsed_id)
        if row is None or row.uid != target_uid:
            raise AuthError(404, "HISTORY_NOT_FOUND", "ไม่พบประวัติที่ต้องการลบ")
        await session.delete(row)
        detail = f"download:{row.file_name or row.md5 or '-'}"
    else:
        raise AuthError(400, "INVALID_HISTORY_KIND", "ประเภทประวัติไม่ถูกต้อง")

    await write_audit_log(
        session,
        actor_uid=actor.uid,
        target_uid=target.uid,
        action="delete_user_history",
        detail=detail[:500],
    )
    await session.commit()
    _invalidate_user_caches(target.uid)
    invalidate_cached(USER_LOGIN_HISTORY_CACHE_NAMESPACE)
    invalidate_cached(USER_DOWNLOAD_HISTORY_CACHE_NAMESPACE)
    invalidate_cached(USER_PASSWORD_HISTORY_CACHE_NAMESPACE)
    return {"success": True, "data": {"kind": kind, "id": entry_id}}

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
        pass

async def soft_delete_file(
    session: AsyncSession,
    *,
    actor: User,
    aid: uuid.UUID,
    reason: str,
) -> Analysis:
    analysis = await session.get(Analysis, aid, options=[joinedload(Analysis.user)])
    if analysis is None:
        raise AuthError(404, "TARGET_NOT_FOUND", "ไม่พบไฟล์เป้าหมาย")
    if analysis.deleted_at is not None:
        raise AuthError(409, "ALREADY_DELETED", "ไฟล์นี้ถูกลบไปแล้ว")

    owner = analysis.user
    if owner is None:
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
    invalidate_public_caches()
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

    for aid_str in succeeded:
        analysis = await session.get(Analysis, uuid.UUID(aid_str))
        if analysis is not None:
            await _purge_temp_file_if_unreferenced(session, analysis.file_path)

    await session.commit()
    return {"success": True, "data": {"succeeded": succeeded, "failed": failed}}

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
    if (target.status or "").lower() != "active":
        raise AuthError(409, "ACCOUNT_INACTIVE", "ไม่สามารถแบนบัญชีที่ไม่ active ได้")

    ensure_can_ban_target(actor, target)

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
    _invalidate_user_caches(target.uid)
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
            if (target.status or "").lower() != "active":
                failed.append({"uid": str(target_uid), "reason": "บัญชีไม่ active"})
                continue
            ensure_can_ban_target(actor, target)
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
    if succeeded:
        _invalidate_user_caches()
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
    if (target.status or "").lower() != "active":
        raise AuthError(409, "ACCOUNT_INACTIVE", "ไม่สามารถปลดแบนบัญชีที่ไม่ active ได้")

    ensure_can_ban_target(actor, target)

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
    _invalidate_user_caches(target.uid)
    return target

async def delete_user(
    session: AsyncSession,
    *,
    actor: User,
    target_uid: uuid.UUID,
) -> User:
    target = await session.get(User, target_uid)
    if target is None:
        raise AuthError(404, "TARGET_NOT_FOUND", "ไม่พบผู้ใช้เป้าหมาย")
    if actor.uid == target.uid:
        raise AuthError(403, "SELF_DELETE_FORBIDDEN", "ไม่สามารถลบบัญชีของตนเองได้")
    ensure_can_manage_non_master_target(actor, target)
    if target.status == "deleted":
        raise AuthError(409, "ALREADY_DELETED", "บัญชีนี้ถูกลบไปแล้ว")

    target.status = "deleted"
    target.password = None
    target.fcm_token = None
    target.is_banned = False
    target.banned_at = None
    target.banned_reason = None
    target.banned_by = None
    await write_audit_log(
        session,
        actor_uid=actor.uid,
        target_uid=target.uid,
        action="delete_user",
        detail="logical_delete",
    )
    await session.commit()
    await session.refresh(target)
    _invalidate_user_caches(target.uid)
    invalidate_cached(USER_LOGIN_HISTORY_CACHE_NAMESPACE, str(target.uid))
    invalidate_cached(USER_DOWNLOAD_HISTORY_CACHE_NAMESPACE, str(target.uid))
    invalidate_cached(USER_PASSWORD_HISTORY_CACHE_NAMESPACE, str(target.uid))
    invalidate_cached("profile:me", str(target.uid))
    invalidate_cached(DASHBOARD_CACHE_NAMESPACE)
    return target


async def reset_user_password(
    session: AsyncSession,
    *,
    actor: User,
    target_uid: uuid.UUID,
    new_password: str,
) -> User:
    target = await session.get(User, target_uid)
    if target is None:
        raise AuthError(404, "TARGET_NOT_FOUND", "ไม่พบผู้ใช้เป้าหมาย")
    ensure_can_manage_non_master_target(actor, target)
    if target.status == "deleted":
        raise AuthError(409, "ACCOUNT_INACTIVE", "ไม่สามารถตั้งรหัสผ่านให้บัญชีที่ถูกลบได้")

    target.password = get_password_hash(new_password)
    await write_audit_log(
        session,
        actor_uid=actor.uid,
        target_uid=target.uid,
        action="admin_reset_password",
        detail="password_reset_by_admin",
    )
    await session.commit()
    await session.refresh(target)
    invalidate_cached(USER_PASSWORD_HISTORY_CACHE_NAMESPACE, str(target.uid))
    invalidate_cached(AUDIT_LOG_CACHE_NAMESPACE)
    return target


async def create_user_by_master(
    session: AsyncSession,
    *,
    actor: User,
    username: str,
    email: str,
    password: str,
    role: str,
) -> User:
    if actor.role != ROLE_MASTER:
        raise AuthError(403, "INSUFFICIENT_ROLE", "เฉพาะ master เท่านั้นที่สร้างบัญชีได้")
    if role not in ASSIGNABLE_ROLES:
        raise AuthError(400, "INVALID_REQUEST", "สิทธิ์ต้องเป็นผู้ใช้หรือผู้ดูแลเท่านั้น")

    normalized_email = normalize_email(email.strip())

    taken_email = await session.execute(
        select(User.uid).where(normalized_email_expr(User.email) == normalized_email).limit(1)
    )
    if taken_email.scalar_one_or_none() is not None:
        raise AuthError(409, "EMAIL_TAKEN", "มีอีเมลผู้ใช้งานนี้ในระบบแล้ว")

    taken_username = await session.execute(
        select(User.uid).where(User.username == username).limit(1)
    )
    if taken_username.scalar_one_or_none() is not None:
        raise AuthError(409, "USERNAME_TAKEN", "มีชื่อผู้ใช้นี้ในระบบแล้ว")

    policy_error = validate_password_policy(password)
    if policy_error:
        raise AuthError(400, "PASSWORD_POLICY_INVALID", policy_error)

    new_user = User(
        username=username,
        email=normalized_email,
        password=get_password_hash(password),
        role=role,
        status="active",
        created_by=actor.uid,
    )
    session.add(new_user)
    try:
        await session.flush()
        await write_audit_log(
            session,
            actor_uid=actor.uid,
            target_uid=new_user.uid,
            action="create_user",
            detail=f"role={role}",
        )
        await session.commit()
    except IntegrityError:
        await session.rollback()
        taken_email = await session.execute(
            select(User.uid).where(normalized_email_expr(User.email) == normalized_email).limit(1)
        )
        if taken_email.scalar_one_or_none() is not None:
            raise AuthError(409, "EMAIL_TAKEN", "มีอีเมลผู้ใช้งานนี้ในระบบแล้ว")
        taken_username = await session.execute(
            select(User.uid).where(User.username == username).limit(1)
        )
        if taken_username.scalar_one_or_none() is not None:
            raise AuthError(409, "USERNAME_TAKEN", "มีชื่อผู้ใช้นี้ในระบบแล้ว")
        raise
    await session.refresh(new_user)
    _invalidate_user_caches(new_user.uid)
    return new_user

async def delete_audit_logs_older_than(
    session: AsyncSession,
    *,
    actor: User,
    months: int,
) -> dict[str, Any]:
    if actor.role != ROLE_MASTER:
        raise AuthError(403, "INSUFFICIENT_ROLE", "เฉพาะ master เท่านั้นที่ลบ audit log ได้")
    if type(months) is not int or not 1 <= months <= 120:
        raise AuthError(400, "INVALID_REQUEST", "จำนวนเดือนต้องอยู่ระหว่าง 1–120")

    cutoff = datetime.now(timezone.utc) - _timedelta(days=30 * months)
    result = await session.execute(delete(AuditLog).where(AuditLog.created_at < cutoff))
    deleted = result.rowcount or 0

    await write_audit_log(
        session,
        actor_uid=actor.uid,
        target_uid=None,
        action="delete_audit_logs",
        detail=f"months={months} | deleted={deleted}",
    )
    await session.commit()
    invalidate_cached(AUDIT_LOG_CACHE_NAMESPACE)
    invalidate_cached(USER_PASSWORD_HISTORY_CACHE_NAMESPACE)
    invalidate_cached(DASHBOARD_CACHE_NAMESPACE)
    return {"deleted": deleted}

async def get_admin_dashboard_summary(session: AsyncSession, *, trend_days: int = 14) -> dict[str, Any]:
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

    status_rows = (
        await session.execute(select(Analysis.status, func.count()).group_by(Analysis.status))
    ).all()
    status_breakdown = [{"status": s or "unknown", "count": c} for s, c in status_rows]

    risk_rows = (
        await session.execute(select(Reports.risk_level, func.count()).group_by(Reports.risk_level))
    ).all()
    risk_level_breakdown = [{"risk_level": r or "N/A", "count": c} for r, c in risk_rows]

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
