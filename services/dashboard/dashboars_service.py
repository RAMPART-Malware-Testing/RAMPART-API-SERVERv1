from typing import Any

from sqlalchemy import select, func, case, and_, text
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone

from cores.Schema.schema_class import Analysis, User, Reports
from schemas.dashboard import ReportsHistoryParams

from datetime import datetime, timezone
from typing import Any, List, Optional
from sqlalchemy import and_, asc, delete, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager, joinedload, selectinload
from cores.Schema.schema_class import Analysis, User, Reports
from schemas.analy import AnalysisHistoryParams
from uuid import UUID
from utils.cache import build_suffix, cached_async
from decimal import Decimal, ROUND_HALF_UP

DASHBOARD_SUMMARY_CACHE_NAMESPACE = "dashboard:summary"
DASHBOARD_SUMMARY_CACHE_TTL_SECONDS = 60
RECENT_ACTIVITIES_CACHE_NAMESPACE = "dashboard:recent_activities"
RECENT_ACTIVITIES_CACHE_TTL_SECONDS = 30
REPORTS_HISTORY_CACHE_NAMESPACE = "dashboard:reports_history"
REPORTS_HISTORY_CACHE_TTL_SECONDS = 60

FILE_TYPE_LABELS = {
    "apk": "แอป Android",
    "exe": "โปรแกรม Windows",
    "dll": "ไลบรารี Windows",
    "jar": "แอป Java",
    "js": "JavaScript",
    "ps1": "PowerShell",
    "bat": "Batch Script",
    "vbs": "VBScript",
}

# Matches the "อันตราย" tier used by the web dashboard (dangerTier >= 60).
HIGH_RISK_SCORE_THRESHOLD = 60

async def _fetch_dashboard_summary(session: AsyncSession, uid: UUID | str, role: str) -> dict:
    total_q = await session.execute(
        select(
            func.count().label("total"),
            func.count(case((Analysis.status == "success", 1))).label("success"),
            func.count(case((Analysis.status == "pending", 1))).label("pending"),
            func.count(case((Analysis.status == "failed",  1))).label("failed"),
        ).where(Analysis.deleted_at.is_(None))
    )
    total_files = total_q.mappings().one()

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

    total_users = 0
    user_count_q = await session.execute(
        select(func.count()).select_from(User).where(User.status == "active", User.role=="user")
    )
    total_users = user_count_q.scalar()

    high_risk_q = await session.execute(
        select(func.count())
        .select_from(Analysis)
        .join(Reports, Analysis.rid == Reports.rid)
        .where(
            Analysis.deleted_at.is_(None),
            Reports.score >= HIGH_RISK_SCORE_THRESHOLD,
        )
    )
    high_risk_files = high_risk_q.scalar_one()

    now = datetime.now(timezone.utc)
    week_start  = now - timedelta(days=7)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    # Group malware signatures directly from database
    malware_query = text("""
        SELECT sig.signature, COUNT(*) as count, AVG(r.score) as avg_score
        FROM reports r
        JOIN analysis a ON a.rid = r.rid
        CROSS JOIN LATERAL unnest(r.malware_signatures) AS sig(signature)
        WHERE r.malware_signatures IS NOT NULL
        AND array_length(r.malware_signatures, 1) > 0
        AND r.score >= 30
        AND a.created_at >= :since
        AND a.deleted_at IS NULL
        GROUP BY sig.signature
        ORDER BY count DESC, MAX(a.created_at) DESC
        LIMIT 5
    """)

    weekly_q = (await session.execute(malware_query, {"since": week_start})).all()
    monthly_q = (await session.execute(malware_query, {"since": month_start})).all()

    risk_q = await session.execute(
        select(
            Analysis.file_type.label("fileType"),
            func.round(func.avg(Reports.score), 2).label("riskScore"),
            func.round(func.avg(Reports.virustotal_score), 2).label("virustotalScore"),
            func.round(func.avg(Reports.mobsf_score), 2).label("mobsfScore"),
            func.round(func.avg(Reports.cape_score), 2).label("capeScore"),
            func.round(func.avg(Reports.rampart_score), 2).label("aiScore"),
        )
        .join(Reports, Analysis.rid == Reports.rid)
        .where(
            Analysis.file_type.isnot(None),
            Analysis.file_type != "",
            Reports.score.isnot(None),
            Analysis.deleted_at.is_(None)
        )
        .group_by(Analysis.file_type)
        .order_by(func.avg(Reports.score).desc())
        .limit(5)
    )

    return {
        "totalFiles": dict(total_files),
        "userFiles":  dict(user_files),
        "totalUsers": total_users,
        "highRiskFiles": high_risk_files,
        "topMalwareTypes": {
            "weekly": [
                {
                    "type": sig.lower()[:50] if sig else "unknown",
                    "label": sig if sig else "Unknown",
                    "icon": "fas fa-virus",
                    "count": int(count),
                    "avgScore": float(Decimal(str(avg_score)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)) if avg_score else None,
                }
                for sig, count, avg_score in weekly_q
            ],
            "monthly": [
                {
                    "type": sig.lower()[:50] if sig else "unknown",
                    "label": sig if sig else "Unknown",
                    "icon": "fas fa-virus",
                    "count": int(count),
                    "avgScore": float(Decimal(str(avg_score)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)) if avg_score else None,
                }
                for sig, count, avg_score in monthly_q
            ],
        },
        "riskScores": [
            {
                "fileType": r.fileType,
                "riskScore": float(r.riskScore),
                "virustotalScore": float(r.virustotalScore) if r.virustotalScore is not None else None,
                "mobsfScore": float(r.mobsfScore) if r.mobsfScore is not None else None,
                "capeScore": float(r.capeScore) if r.capeScore is not None else None,
                "aiScore": float(r.aiScore) if r.aiScore is not None else None,
            }
            for r in risk_q
        ],
    }

async def get_dashboard_summary(session: AsyncSession, uid: UUID | str, role: str) -> dict:
    suffix = build_suffix(uid=str(uid), role=role)
    return await cached_async(
        DASHBOARD_SUMMARY_CACHE_NAMESPACE,
        DASHBOARD_SUMMARY_CACHE_TTL_SECONDS,
        lambda: _fetch_dashboard_summary(session, uid, role),
        suffix=suffix,
    )

async def _fetch_recent_activities(
    session: AsyncSession,
    uid: UUID | str,
    role: str,
    limit: int = 10
) -> list[dict]:
    # Unlike the aggregate panels, this feed is scoped to the caller: it is the
    # user's own activity, so file names never leak between accounts.
    q = await session.execute(
        select(
            Analysis.aid.label("id"),
            Analysis.file_name.label("fileName"),
            Analysis.file_type.label("fileType"),
            Analysis.status,
            Analysis.created_at.label("timestamp"),
        )
        .where(
            Analysis.uid == uid,
            Analysis.deleted_at.is_(None),
        )
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

async def get_recent_activities(
    session: AsyncSession,
    uid: UUID | str,
    role: str,
    limit: int = 10
) -> list[dict]:
    suffix = build_suffix(uid=str(uid), role=role, limit=limit)
    return await cached_async(
        RECENT_ACTIVITIES_CACHE_NAMESPACE,
        RECENT_ACTIVITIES_CACHE_TTL_SECONDS,
        lambda: _fetch_recent_activities(session, uid, role, limit),
        suffix=suffix,
    )

async def _fetch_reports_history(
    session: AsyncSession,
    params: ReportsHistoryParams
) -> dict[str, Any]:
    conditions = [
        Analysis.privacy == True,
        Analysis.deleted_at.is_(None),
    ]
    if params.status:
        conditions.append(Analysis.status == params.status)
    if params.file_type:
        search_term = f"%{params.file_type}%"
        conditions.append(
            Analysis.file_type.ilike(params.file_type.strip())
        )
    if params.score_min is not None:
        conditions.append(Reports.score >= params.score_min)
    if params.score_max is not None:
        conditions.append(Reports.score <= params.score_max)
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
    needs_reports_join = (
        params.score != 0
        or params.score_min is not None
        or params.score_max is not None
    )
    count_stmt = select(func.count()).select_from(Analysis)
    if needs_reports_join:
        count_stmt = count_stmt.outerjoin(Reports, Analysis.rid == Reports.rid)
    total: int = (
        await session.execute(count_stmt.where(where_clause))
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
    needs_join = needs_reports_join
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
    uids = [a.uid for a in analyses if a.uid]
    owners: dict = {}
    if uids:
        user_rows = (
            await session.execute(select(User).where(User.uid.in_(uids)))
        ).scalars().all()
        owners = {u.uid: u for u in user_rows}
    def serialize(a: Analysis) -> dict[str, Any]:
        item: dict[str, Any] = {
            "aid":        str(a.aid),
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
            "uploaded_by": None,
            "report":     None,
        }
        owner = owners.get(a.uid)
        if owner:
            item["uploaded_by"] = {
                "username": owner.username,
                "avatar_url": owner.avatar_url,
            }
        if a.report:
            r = a.report
            item["report"] = {
                "score":            float(r.score) if r.score is not None else None,
                "rampart_score":    float(r.rampart_score) if r.rampart_score is not None else None,
                "risk_level":       r.risk_level,
                "virustotal_score": r.virustotal_score,
                "mobsf_score":      float(r.mobsf_score) if r.mobsf_score is not None else None,
                "cape_score":       float(r.cape_score) if r.cape_score is not None else None,
                "rampart_ai_score": r.rampart_ai_score,
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

async def get_reports_history(
    session: AsyncSession,
    params: ReportsHistoryParams
) -> dict[str, Any]:
    suffix = build_suffix(
        page=params.page,
        limit=params.limit,
        s=params.s,
        status=params.status,
        file_type=params.file_type,
        created_at=params.created_at,
        file_name=params.file_name,
        file_size=params.file_size,
        score=params.score,
        score_min=params.score_min,
        score_max=params.score_max,
    )
    return await cached_async(
        REPORTS_HISTORY_CACHE_NAMESPACE,
        REPORTS_HISTORY_CACHE_TTL_SECONDS,
        lambda: _fetch_reports_history(session, params),
        suffix=suffix,
    )
