from typing import Any

from sqlalchemy import select, func, case, and_, text
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone

from cores.models_class import Analysis, User, Reports
from schemas.dashboard import ReportsHistoryParams

from datetime import datetime, timezone
from typing import Any, List, Optional
from sqlalchemy import and_, asc, delete, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager, joinedload, selectinload
from cores.models_class import Analysis, User, Reports
from schemas.analy import AnalysisHistoryParams

async def get_dashboard_summary(session: AsyncSession, uid: int, role: str) -> dict:
    # ── 1. Total files (ทั้งระบบ) ──────────────────────────────────────
    total_q = await session.execute(
        select(
            func.count().label("total"),
            func.count(case((Analysis.status == "success", 1))).label("success"),
            func.count(case((Analysis.status == "pending", 1))).label("pending"),
            func.count(case((Analysis.status == "failed",  1))).label("failed"),
        ).where(Analysis.deleted_at.is_(None))
    )
    total_files = total_q.mappings().one()

    # ── 2. User files (เฉพาะของตัวเอง) ───────────────────────────────
    user_q = await session.execute(
        select(
            func.count().label("total"),
            func.count(case((Analysis.status == "success", 1))).label("success"),
            func.count(case((Analysis.status == "pending", 1))).label("pending"),
            func.count(case((Analysis.status == "failed",  1))).label("failed"),
        ).where(
            Analysis.uid == uid,
            Analysis.deleted_at.is_(None)
        )
    )
    user_files = user_q.mappings().one()

    # ── 3. Total users (admin เท่านั้น) ───────────────────────────────
    total_users = 0
    user_count_q = await session.execute(
        select(func.count()).select_from(User).where(User.status == "active", User.role=="user")
    )
    total_users = user_count_q.scalar()

    # ── 4. Top 5 malware types รายวัน/รายเดือน ────────────────────────
    now = datetime.now(timezone.utc)
    day_start   = now.replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    def malware_query(since: datetime):
        return (
            select(
                Reports.type.label("type"),
                func.count().label("count")
            )
            .join(Analysis, Analysis.rid == Reports.rid)
            .where(
                Reports.type.isnot(None),
                Analysis.created_at >= since,
                Analysis.deleted_at.is_(None)
            )
            .group_by(Reports.type)
            .order_by(func.count().desc())
            .limit(5)
        )

    daily_q   = await session.execute(malware_query(day_start))
    monthly_q = await session.execute(malware_query(month_start))

    # ── 5. Risk scores เฉลี่ยแยกตาม file_type ────────────────────────
    risk_q = await session.execute(
        select(
            Analysis.file_type.label("fileType"),
            func.round(func.avg(Reports.rampart_score), 2).label("riskScore")
        )
        .join(Reports, Analysis.rid == Reports.rid)
        .where(
            Analysis.file_type.isnot(None),
            Reports.rampart_score.isnot(None),
            Analysis.deleted_at.is_(None)
        )
        .group_by(Analysis.file_type)
        .order_by(func.avg(Reports.rampart_score).desc())
        .limit(5)
    )

    return {
        "totalFiles": dict(total_files),
        "userFiles":  dict(user_files),
        "totalUsers": total_users,
        "topMalwareTypes": {
            "daily":   [{"type": r.type, "count": r.count} for r in daily_q],
            "monthly": [{"type": r.type, "count": r.count} for r in monthly_q],
        },
        "riskScores": [
            {"fileType": r.fileType, "riskScore": float(r.riskScore)}
            for r in risk_q
        ],
    }


async def get_recent_activities(
    session: AsyncSession,
    uid: int,
    role: str,
    limit: int = 10
) -> list[dict]:
    # admin เห็นทั้งหมด, user เห็นเฉพาะตัวเอง
    filters = [Analysis.deleted_at.is_(None)]
    if role != "admin":
        filters.append(Analysis.uid == uid)

    q = await session.execute(
        select(
            Analysis.aid.label("id"),
            Analysis.file_name.label("fileName"),
            Analysis.file_type.label("fileType"),
            Analysis.status,
            Analysis.created_at.label("timestamp"),
        )
        .where(and_(*filters))
        .order_by(Analysis.created_at.desc())
        .limit(limit)
    )

    return [
        {
            "id":        str(r.id),
            "fileName":  r.fileName,
            "fileType":  r.fileType,
            "status":    r.status,
            "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for r in q.mappings()
    ]


async def get_reports_history(
    session: AsyncSession,
    params: ReportsHistoryParams
) -> dict[str, Any]:
    conditions = [
        Analysis.privacy == False,
        Analysis.deleted_at.is_(None),
    ]
    if params.status:
        conditions.append(Analysis.status == params.status)
    if params.file_type:
        search_term = f"%{params.file_type}%"
        conditions.append(
            Analysis.file_type.ilike(params.file_type.strip())
        )
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
    total: int = (
        await session.execute(
            select(func.count())
            .select_from(Analysis)
            .where(where_clause)
        )
    ).scalar_one()
    sort_map = {
        "created_at": Analysis.created_at,
        "file_name":  Analysis.file_name,
        "file_size":  Analysis.file_size,
        "score":      Reports.score,
    }
    sort_priority = [
        ("created_at", params.created_at),
        ("file_name",  params.file_name),
        ("file_size",  params.file_size),
        ("score",      params.score),
    ]
    order_by = [
        asc(sort_map[col]) if direction == 1 else desc(sort_map[col])
        for col, direction in sort_priority
        if direction != 0
    ] or [desc(Analysis.created_at)]
    needs_join = params.score != 0
    stmt = (
        select(Analysis)
        .options(joinedload(Analysis.report))
        .where(where_clause)
        .order_by(*order_by)
        .offset((params.page - 1) * params.limit)
        .limit(params.limit)
    )
    if needs_join:
        stmt = (
            stmt
            .outerjoin(Reports, Analysis.rid == Reports.rid)
            .options(contains_eager(Analysis.report))
        )
    else:
        stmt = stmt.options(joinedload(Analysis.report))
    analyses = (await session.execute(stmt)).scalars().unique().all()
    def serialize(a: Analysis) -> dict[str, Any]:
        item: dict[str, Any] = {
            "aid":        a.aid,
            "task_id":    a.task_id,
            "file_name":  a.file_name,
            "file_size":  a.file_size,
            "file_type":  a.file_type,
            "file_hash":  a.file_hash,
            "tools":      a.tools,
            "status":     a.status,
            "md5":        a.md5,
            "privacy":    a.privacy,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "report":     None,
        }
        if a.report:
            r = a.report
            item["report"] = {
                # "rid":              r.rid,
                "score":            float(r.score) if r.score is not None else None,
                "rampart_score":    float(r.rampart_score) if r.rampart_score is not None else None,
                # "risk_level":       r.risk_level,
                # "package":          r.package,
                # "type":             r.type,
                # "recommendation":   r.recommendation,
                # "analysis_summary": r.analysis_summary,
                # "risk_indicators":  r.risk_indicators,
                # "created_at":       r.created_at.isoformat() if r.created_at else None,
            }
        return item
    total_pages = max(1, -(-total // params.limit))
    return {
        "success": True,
        "data": [serialize(a) for a in analyses],
        "pagination": {
            "page":        params.page,
            "limit":       params.limit,
            "total":       total,
            "total_pages": total_pages,
            "has_next":    params.page < total_pages,
            "has_prev":    params.page > 1,
        }
    }
