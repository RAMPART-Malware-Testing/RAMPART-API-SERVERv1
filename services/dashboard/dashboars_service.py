from sqlalchemy import select, func, case, and_, text
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone

from cores.models_class import Analysis, User, Reports

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