from datetime import datetime, timezone
from typing import Any, List, Optional
from sqlalchemy import and_, asc, delete, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager, joinedload, selectinload
from cores.models_class import Analysis, User, Reports
from schemas.analy import AnalysisHistoryParams

async def get_file_by_hash(
    session: AsyncSession,
    file_hash: str
) -> Analysis | None:
    result = await session.execute(
        select(
            Analysis.rid,
            Analysis.status,
            Analysis.file_path,
            Analysis.file_type,
            Analysis.file_size,
            Analysis.file_hash,
            Analysis.tools,
            Analysis.md5,
            Analysis.task_id,
        ).where(
            Analysis.file_hash == file_hash,
            Analysis.file_path.isnot(None)
        ).limit(1)
    )
    return result.mappings().one_or_none()



async def insert_table_analy(
    session: AsyncSession,
    *,
    uid: int,
    rid: int | None = None,
    task_id: str | None = None,
    tools: str | None = None,
    status: str | None = None,
    file_name: str,
    file_hash: str,
    file_path: str,
    file_type: str,
    file_size: int,
    privacy: bool,
    md5: str,
) -> Analysis:
    
    stmt = select(Analysis).where(
        Analysis.uid == uid,
        Analysis.file_name == file_name,
        Analysis.file_hash == file_hash,
    )
    existing = await session.execute(stmt)
    analy = existing.scalars().first()

    if analy:
        analy.created_at = datetime.now(timezone.utc)
        analy.privacy = privacy
        await session.commit()
        await session.refresh(analy)
        return analy
    
    if rid:
        analy = Analysis(
            uid=uid,
            rid=rid,
            task_id=task_id,
            tools=tools,
            status=status,
            file_name=file_name,
            file_hash=file_hash,
            file_path=file_path,
            file_type=file_type,
            file_size=file_size,
            privacy=privacy,
            md5=md5,
        )
    else:
        analy = Analysis(
            uid=uid,
            file_name=file_name,
            file_hash=file_hash,
            file_path=file_path,
            file_type=file_type,
            file_size=file_size,
            privacy=privacy,
            md5=md5,
        )
    session.add(analy)
    await session.commit()
    await session.refresh(analy)
    return analy

async def get_analysis_with_report(
    session: AsyncSession,
    task_id: str,
    uid: int
) -> tuple[Analysis, Reports | None] | None:
    result = await session.execute(
        select(Analysis, Reports)
        .outerjoin(Reports, Analysis.rid == Reports.rid)
        .where(Analysis.task_id == task_id, Analysis.uid == uid)
    )
    row = result.first()
    if row is None:
        return None
    return row.Analysis, row.Reports



async def get_analysis_history(
    session: AsyncSession,
    uid: int,
    params: AnalysisHistoryParams
) -> dict[str, Any]:

    # ======================
    # Build WHERE conditions
    # ======================
    conditions = [
        Analysis.uid == uid,
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

    # ======================
    # Count total
    # ======================
    total: int = (
        await session.execute(
            select(func.count())
            .select_from(Analysis)
            .where(where_clause)
        )
    ).scalar_one()

    # ======================
    # Build ORDER BY
    # ======================
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

    # ======================
    # Main query
    # ======================
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

    # ======================
    # Serialize
    # ======================
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

