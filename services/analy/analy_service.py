import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional
from sqlalchemy import and_, asc, delete, desc, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager, joinedload, selectinload
from fastapi.concurrency import run_in_threadpool
from bgProcessing.tasks import analyze_malware_task
from cores.Schema.schema_class import Analysis, User, Reports
from schemas.analy import AnalysisHistoryParams
from uuid import UUID, uuid4

REPORTS_DIR = Path("reports")

# Self-service analysis history listing (/api/analy/v1/history) - mirrors
# the admin equivalent (services.admin.admin_service.get_user_analysis_history_admin),
# which already carries the same short TTL cache.
ANALYSIS_HISTORY_CACHE_NAMESPACE = "analy:history"
ANALYSIS_HISTORY_CACHE_TTL_SECONDS = 5

# Maps a tool name to the (status_kwarg, report_path_kwarg) pair
# analyze_malware_task accepts to be told "this tool already succeeded,
# don't re-call its handler" (see bgProcessing/tasks.py). Used by
# attempt_gap_fill_redispatch to carry forward already-successful tools
# into a fresh re-dispatch and leave only the force-skipped tool(s) unset
# so the task attempts them fresh. Gemini (and RampartAI) are
# intentionally NOT in this map - they must always re-run so the final
# verdict reflects whatever additional evidence the retried tool(s) bring.
_GAP_FILL_TOOL_KWARGS: dict[str, tuple[str, str]] = {
    "virustotal": ("vt_status", "vt_report_path"),
    "mobsf": ("mobsf_status", "mobsf_report_path"),
    "cape": ("cape_status", "cape_report_path"),
}


async def acquire_analysis_hash_lock(session: AsyncSession, file_hash: str) -> None:
    lock_key = int.from_bytes(bytes.fromhex(file_hash)[:8], byteorder="big", signed=True)
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": lock_key},
    )


async def acquire_analysis_task_lock(session: AsyncSession, task_id: str) -> None:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:task_id, 0))"),
        {"task_id": task_id},
    )


async def update_analysis_rows_by_task_id(
    session: AsyncSession,
    task_id: str,
    *,
    status: str,
    rid: Any | None = None,
    from_statuses: tuple[str, ...] | None = None,
) -> int:
    values = {"status": status}
    if rid is not None:
        values["rid"] = rid
    stmt = update(Analysis).where(Analysis.task_id == task_id)
    if from_statuses:
        stmt = stmt.where(Analysis.status.in_(from_statuses))
    result = await session.execute(stmt.values(**values))
    return result.rowcount

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
            Analysis.tool_notes,
            Analysis.md5,
            Analysis.task_id,
        ).where(
            Analysis.file_hash == file_hash,
            Analysis.file_path.isnot(None),
            Analysis.task_id.isnot(None),
            Analysis.status.in_(("dispatching", "queued", "processing", "analyzing", "success")),
        ).order_by(desc(Analysis.created_at)).limit(1)
    )
    return result.mappings().one_or_none()


REUSABLE_ANALYSIS_STATUSES = ("queued", "processing", "analyzing", "success")


async def attempt_attach_to_existing_analysis(
    session: AsyncSession,
    *,
    uid: UUID | str,
    file_hash: str,
    file_name: str,
    file_size: int,
    privacy: bool,
) -> tuple[str, Analysis | None]:
    """Shared dedup logic for both the full-upload path and the
    hash-only pre-check path.

    Looks up any existing analysis for this sha256 content hash and, if one
    is safely reusable, attaches a brand-new `Analysis` row for `uid` to the
    *same* task_id/rid/tools/status - no new Celery task, no re-run of any
    tool, and (for the hash-only caller) no file bytes need to ever be
    uploaded to reach this result.

    Returns a tuple of (outcome, analysis):
      - ("attached", analysis)  - reused an existing task; row committed
      - ("dispatching", None)   - another request is mid-dispatch for this
                                   exact hash right now; not safe to reuse
      - ("none", None)          - no reusable analysis exists; caller should
                                   proceed with a fresh upload/dispatch
    """
    await acquire_analysis_hash_lock(session, file_hash)
    existing = await get_file_by_hash(session, file_hash)
    existing_status = existing.get("status") if existing else None
    existing_task_id = existing.get("task_id") if existing else None

    if existing and existing_status == "dispatching" and existing_task_id:
        return "dispatching", None

    if not (existing and existing_status in REUSABLE_ANALYSIS_STATUSES and existing_task_id):
        return "none", None

    await acquire_analysis_task_lock(session, existing_task_id)
    existing = await get_file_by_task_id(session, existing_task_id)
    existing_status = existing.get("status") if existing else None
    if not existing or existing_status == "failed":
        return "none", None

    analysis = await insert_table_analy(
        session=session,
        uid=uid,
        rid=existing.get("rid"),
        task_id=existing_task_id,
        tools=existing.get("tools"),
        status=existing_status,
        file_name=file_name,
        file_hash=file_hash,
        file_path=existing.get("file_path"),
        file_type=existing.get("file_type"),
        file_size=existing.get("file_size") or file_size,
        privacy=privacy,
        md5=existing.get("md5"),
    )
    return "attached", analysis


async def attempt_gap_fill_redispatch(
    session: AsyncSession,
    *,
    uid: UUID | str,
    file_hash: str,
    file_name: str,
    file_size: int,
    privacy: bool,
) -> tuple[str, Analysis | None]:
    """When the most recent successful analysis for this hash has
    tool_notes (meaning at least one tool was force-skipped after
    exhausting its error/rate-limit retry budget - see
    bgProcessing/tasks.py's apply_tool_outcome), re-dispatch a *fresh*
    Celery task that reuses already-successful tool reports and only
    retries the gap. Returns ("gap_filled", analysis) on a fresh
    re-dispatch, or ("none", None) if there's nothing to gap-fill
    (either no existing analysis, or it has no tool_notes).

    Only acts on a most-recent row whose status is exactly "success" -
    a "dispatching" row (in-flight conflict) or any other in-progress
    status (queued/processing/analyzing) is left untouched for the
    caller's existing dispatching-conflict / attempt_attach_to_existing_
    analysis handling, which must run AFTER this returns "none".

    Never mutates or deletes the old Analysis row / report - it stays
    intact as history and the caller ends up with a brand-new task_id
    and a brand-new Analysis row instead.
    """
    await acquire_analysis_hash_lock(session, file_hash)
    existing = await get_file_by_hash(session, file_hash)
    if not existing:
        return "none", None

    existing_status = existing.get("status")
    tool_notes_raw = existing.get("tool_notes")
    if existing_status != "success" or not tool_notes_raw:
        return "none", None

    existing_md5 = existing.get("md5")
    existing_file_path = existing.get("file_path")
    if not existing_md5 or not existing_file_path or not Path(existing_file_path).is_file():
        # Source file no longer on disk - nothing safe to reuse without a
        # brand-new upload, so there's nothing to gap-fill here.
        return "none", None

    # Ground truth for "this tool already succeeded" is a readable report
    # file on disk (reports/{tool}-{md5}.json) - the `tools` column is
    # only cross-checked as an extra sanity guard against a stale report
    # left behind by some unrelated earlier analysis of the same content,
    # never trusted on its own.
    tools_column = {t.strip() for t in (existing.get("tools") or "").split(",") if t.strip()}
    gap_fill_kwargs: dict[str, Any] = {}
    for tool, (status_kwarg, path_kwarg) in _GAP_FILL_TOOL_KWARGS.items():
        if tools_column and tool not in tools_column:
            continue
        report_path = REPORTS_DIR / f"{tool}-{existing_md5}.json"
        if not report_path.is_file():
            continue
        try:
            with report_path.open("r", encoding="utf-8") as handle:
                json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        gap_fill_kwargs[status_kwarg] = True
        gap_fill_kwargs[path_kwarg] = str(report_path)

    new_task_id = str(uuid4())
    final_file_size = existing.get("file_size") or file_size

    # Deliberately NOT calling insert_table_analy here: that helper
    # upserts-in-place on (uid, file_name, file_hash), which would very
    # likely match *this same* "success" row we just read (same user
    # re-uploading the same file under the same name) and clobber it -
    # exactly the old row this function must leave untouched. A gap-fill
    # re-dispatch always gets its own brand-new row.
    analysis = Analysis(
        uid=uid,
        task_id=new_task_id,
        status="dispatching",
        file_name=file_name,
        file_hash=file_hash,
        file_path=existing_file_path,
        file_type=existing.get("file_type"),
        file_size=final_file_size,
        privacy=privacy,
        md5=existing_md5,
    )
    session.add(analysis)
    await session.commit()
    await session.refresh(analysis)

    try:
        await run_in_threadpool(
            analyze_malware_task.apply_async,
            args=(existing_file_path, existing_md5, file_hash, final_file_size),
            kwargs=gap_fill_kwargs,
            task_id=new_task_id,
        )
    except Exception:
        await acquire_analysis_hash_lock(session, file_hash)
        await update_analysis_rows_by_task_id(
            session,
            new_task_id,
            status="failed",
            from_statuses=("dispatching",),
        )
        await session.commit()
        return "none", None

    await acquire_analysis_hash_lock(session, file_hash)
    await update_analysis_rows_by_task_id(
        session,
        new_task_id,
        status="queued",
        from_statuses=("dispatching",),
    )
    await session.commit()
    analysis.status = "queued"

    return "gap_filled", analysis


async def get_file_by_task_id(session: AsyncSession, task_id: str):
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
            Analysis.task_id == task_id,
            Analysis.status.in_(("dispatching", "queued", "processing", "analyzing", "success", "failed")),
        ).limit(1)
    )
    return result.mappings().one_or_none()



async def insert_table_analy(
    session: AsyncSession,
    *,
    uid: UUID | str,
    rid: Any | None = None,
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
        analy.rid = rid
        analy.task_id = task_id
        analy.tools = tools
        analy.status = status
        analy.file_path = file_path
        analy.file_type = file_type
        analy.file_size = file_size
        analy.md5 = md5
        await session.commit()
        await session.refresh(analy)
        return analy
    
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
    session.add(analy)
    await session.commit()
    await session.refresh(analy)
    return analy

async def get_analysis_with_report(
    session: AsyncSession,
    task_id: str,
    uid: UUID | str
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


async def get_public_analysis_with_report(
    session: AsyncSession,
    task_id: str
) -> tuple[Analysis, Reports | None] | None:
    """Allow viewing a report that the requester does NOT own, as long as it
    is shared publicly (privacy == True) and not deleted."""
    result = await session.execute(
        select(Analysis, Reports)
        .outerjoin(Reports, Analysis.rid == Reports.rid)
        .where(
            Analysis.task_id == task_id,
            Analysis.privacy == True,  # noqa: E712
            Analysis.deleted_at.is_(None),
        )
    )
    row = result.first()
    if row is None:
        return None
    return row.Analysis, row.Reports


async def get_analysis_with_report_admin(
    session: AsyncSession,
    task_id: str
) -> tuple[Analysis, Reports | None] | None:
    result = await session.execute(
        select(Analysis, Reports)
        .outerjoin(Reports, Analysis.rid == Reports.rid)
        .where(Analysis.task_id == task_id)
    )
    row = result.first()
    if row is None:
        return None
    return row.Analysis, row.Reports



async def get_analysis_history(
    session: AsyncSession,
    uid: UUID | str,
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

