import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional
from sqlalchemy import and_, asc, delete, desc, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager, joinedload, selectinload
from fastapi.concurrency import run_in_threadpool
from bgProcessing.tasks import analyze_malware_task
from bgProcessing.task_handlers import CAPE_PACKAGE_MAP, MOBSF_SUPPORTED_EXTS, VIRUSTOTAL_MAX_SIZE
from cores.Schema.schema_class import Analysis, User, Reports
from schemas.analy import AnalysisHistoryParams
from uuid import UUID, uuid4

REPORTS_DIR = Path("reports")

ANALYSIS_HISTORY_CACHE_NAMESPACE = "analy:history"
ANALYSIS_HISTORY_CACHE_TTL_SECONDS = 5

_TERMINAL_SKIP_REASONS = {"unsupported", "oversize"}
_MAX_CONTENT_RERUNS = 3
_CARRY_FORWARD_TOOL_KWARGS: dict[str, tuple[str, str]] = {
    "virustotal": ("vt_status", "vt_report_path"),
    "mobsf": ("mobsf_status", "mobsf_report_path"),
    "cape": ("cape_status", "cape_report_path"),
    "rampart_ai": ("rampart_ai_status", "rampart_ai_report_path"),
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

def row_field(row, key: str, default=None):
    if isinstance(row, dict):
        return row.get(key, default)
    return getattr(row, key, default)

_TOOL_REPORT_PREFIX = {
    "virustotal": "virustotal",
    "mobsf": "mobsf",
    "cape": "cape",
    "rampart_ai": "rampartai",
}

def tool_report_file(md5: str, tool: str) -> Path:
    return REPORTS_DIR / f"{_TOOL_REPORT_PREFIX.get(tool, tool)}-{md5}.json"

def decode_json_dict(raw) -> dict:
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}

def report_file_readable(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8") as handle:
            json.load(handle)
    except (OSError, json.JSONDecodeError):
        return False
    return True

def file_extension(row) -> str:
    path = row_field(row, "file_path")
    if path:
        suffix = Path(path).suffix.lower()
        if suffix:
            return suffix
    file_type = (row_field(row, "file_type") or "").strip().lower()
    return f".{file_type}" if file_type else ""

def succeeded_tools(row) -> set[str]:
    return {tool.strip() for tool in (row_field(row, "tools") or "").split(",") if tool.strip()}

def expected_tools(row, states: dict) -> list[str]:
    ext = file_extension(row)
    expected = ["virustotal"]
    if ext in MOBSF_SUPPORTED_EXTS:
        expected.append("mobsf")
    if ext in CAPE_PACKAGE_MAP:
        expected.append("cape")
    return expected

def resolve_tool_state(tool: str, md5, done: set[str], states: dict, blocked_by, file_size: int) -> dict:
    entry = states.get(tool) or {}
    state = entry.get("state")
    if state in ("success", "gap", "terminal"):
        if state == "success" and not (md5 and report_file_readable(tool_report_file(md5, tool))):
            return {"state": "gap", "reason": "missing_report"}
        return dict(entry)
    if tool == "virustotal" and file_size > VIRUSTOTAL_MAX_SIZE:
        return {"state": "terminal", "reason": "oversize"}
    if blocked_by == "virustotal" and tool != "virustotal":
        return {"state": "terminal", "reason": "short_circuit"}
    if tool in done and md5 and report_file_readable(tool_report_file(md5, tool)):
        return {"state": "success"}
    return {"state": "gap", "reason": "no_report"}

def evaluate_tool_completeness(row) -> dict:
    md5 = row_field(row, "md5")
    states = decode_json_dict(row_field(row, "tool_states"))
    done = succeeded_tools(row)
    blocked_by = row_field(row, "blocked_by")
    file_size = row_field(row, "file_size") or 0
    resolved: dict[str, dict] = {}

    for tool in expected_tools(row, states):
        resolved[tool] = resolve_tool_state(tool, md5, done, states, blocked_by, file_size)
    if (resolved.get("mobsf") or {}).get("state") == "success":
        resolved["rampart_ai"] = resolve_tool_state("rampart_ai", md5, done, states, blocked_by, file_size)

    missing = [tool for tool, state in resolved.items() if state["state"] == "gap"]
    terminal = [tool for tool, state in resolved.items() if state["state"] == "terminal"]
    return {"complete": not missing, "missing": missing, "terminal": terminal, "states": resolved}

def completeness_summary(analysis) -> dict | None:
    if analysis is None or row_field(analysis, "status") != "success":
        return None
    plan = evaluate_tool_completeness(analysis)
    return {"complete": plan["complete"], "missing": plan["missing"], "terminal": plan["terminal"]}

def carry_forward_states(row) -> dict | None:
    return decode_json_dict(row_field(row, "tool_states")) or None

def build_carry_forward_kwargs(row, completeness: dict) -> tuple[dict, dict]:
    md5 = row_field(row, "md5")
    notes = decode_json_dict(row_field(row, "tool_notes"))
    kwargs: dict[str, Any] = {}
    carried_notes: dict[str, str] = {}
    mobsf_carried = (completeness["states"].get("mobsf") or {}).get("state") == "success"
    for tool, (status_keyword, path_keyword) in _CARRY_FORWARD_TOOL_KWARGS.items():
        state = (completeness["states"].get(tool) or {}).get("state")
        if tool == "rampart_ai" and not mobsf_carried:
            continue
        if state == "success":
            kwargs[status_keyword] = True
            kwargs[path_keyword] = str(tool_report_file(md5, tool))
        elif state == "terminal":
            kwargs[status_keyword] = "skipped"
            if notes.get(tool):
                carried_notes[tool] = notes[tool]
    return kwargs, carried_notes

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
            Analysis.detected_type,
            Analysis.detected_source,
            Analysis.file_type_mismatch,
            Analysis.file_size,
            Analysis.file_hash,
            Analysis.file_name,
            Analysis.tools,
            Analysis.tool_notes,
            Analysis.tool_states,
            Analysis.blocked_by,
            Analysis.is_malicious,
            Analysis.md5,
            Analysis.task_id,
        ).where(
            Analysis.file_hash == file_hash,
            Analysis.file_path.isnot(None),
            Analysis.task_id.isnot(None),
            Analysis.status.in_(("dispatching", "queued", "processing", "analyzing", "success")),
            Analysis.deleted_at.is_(None),
        ).order_by(desc(Analysis.created_at)).limit(1)
    )
    return result.mappings().one_or_none()

REUSABLE_ANALYSIS_STATUSES = ("queued", "processing", "analyzing", "success")

async def count_content_runs(session: AsyncSession, file_hash: str) -> int:
    result = await session.execute(
        select(func.count(func.distinct(Analysis.task_id))).where(
            Analysis.file_hash == file_hash,
            Analysis.task_id.isnot(None),
            Analysis.deleted_at.is_(None),
        )
    )
    return int(result.scalar_one() or 0)

async def get_content_row_for_recovery(session: AsyncSession, file_hash: str) -> Analysis | None:
    result = await session.execute(
        select(
            Analysis.rid,
            Analysis.status,
            Analysis.file_path,
            Analysis.file_type,
            Analysis.detected_type,
            Analysis.detected_source,
            Analysis.file_type_mismatch,
            Analysis.file_size,
            Analysis.file_hash,
            Analysis.file_name,
            Analysis.tools,
            Analysis.tool_notes,
            Analysis.tool_states,
            Analysis.blocked_by,
            Analysis.is_malicious,
            Analysis.md5,
            Analysis.task_id,
        ).where(
            Analysis.file_hash == file_hash,
            Analysis.file_path.isnot(None),
            Analysis.task_id.isnot(None),
            Analysis.deleted_at.is_(None),
        ).order_by(desc(Analysis.created_at)).limit(1)
    )
    return result.mappings().one_or_none()

async def attempt_attach_to_existing_analysis(
    session: AsyncSession,
    *,
    uid: UUID | str,
    file_hash: str,
    file_name: str,
    file_size: int,
    privacy: bool,
) -> tuple[str, Analysis | None]:
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

    analysis = await upsert_user_analysis(
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
        detected_type=existing.get("detected_type"),
        detected_source=existing.get("detected_source"),
        file_type_mismatch=bool(existing.get("file_type_mismatch")),
        tool_notes=existing.get("tool_notes"),
        tool_states=existing.get("tool_states"),
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
    await acquire_analysis_hash_lock(session, file_hash)
    existing = await get_file_by_hash(session, file_hash)
    if not existing:
        return "none", None

    if existing.get("status") != "success":
        return "none", None

    completeness = evaluate_tool_completeness(existing)
    if completeness["complete"]:
        return "none", None

    if await count_content_runs(session, file_hash) > _MAX_CONTENT_RERUNS:
        return "none", None

    existing_md5 = existing.get("md5")
    existing_file_path = existing.get("file_path")
    if not existing_md5 or not existing_file_path or not Path(existing_file_path).is_file():
        return "none", None

    gap_fill_kwargs, carried_notes = build_carry_forward_kwargs(existing, completeness)
    new_task_id = str(uuid4())
    final_file_size = existing.get("file_size") or file_size

    analysis = await upsert_user_analysis(
        session=session,
        uid=uid,
        rid=existing.get("rid"),
        task_id=new_task_id,
        status="dispatching",
        tools=existing.get("tools"),
        file_name=file_name,
        file_hash=file_hash,
        file_path=existing_file_path,
        file_type=existing.get("file_type"),
        file_size=final_file_size,
        privacy=privacy,
        md5=existing_md5,
        detected_type=existing.get("detected_type"),
        detected_source=existing.get("detected_source"),
        file_type_mismatch=bool(existing.get("file_type_mismatch")),
        tool_notes=json.dumps(carried_notes, ensure_ascii=False) if carried_notes else None,
        tool_states=existing.get("tool_states"),
    )

    try:
        await run_in_threadpool(
            analyze_malware_task.apply_async,
            args=(existing_file_path, existing_md5, file_hash, final_file_size),
            kwargs={
                **gap_fill_kwargs,
                "tool_notes": carried_notes or None,
                "tool_states": carry_forward_states(existing),
            },
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
            Analysis.detected_type,
            Analysis.detected_source,
            Analysis.file_type_mismatch,
            Analysis.file_size,
            Analysis.file_hash,
            Analysis.file_name,
            Analysis.tools,
            Analysis.tool_notes,
            Analysis.tool_states,
            Analysis.blocked_by,
            Analysis.is_malicious,
            Analysis.md5,
            Analysis.task_id,
        ).where(
            Analysis.task_id == task_id,
            Analysis.status.in_(("dispatching", "queued", "processing", "analyzing", "success", "failed")),
            Analysis.deleted_at.is_(None),
        ).limit(1)
    )
    return result.mappings().one_or_none()

async def upsert_user_analysis(
    session: AsyncSession,
    *,
    uid: UUID | str,
    file_name: str,
    file_hash: str,
    file_path: str,
    file_type: str,
    file_size: int,
    privacy: bool,
    md5: str,
    detected_type: str | None = None,
    detected_source: str | None = None,
    file_type_mismatch: bool = False,
    rid: Any | None = None,
    task_id: str | None = None,
    tools: str | None = None,
    status: str | None = None,
    tool_notes: str | None = None,
    tool_states: dict | None = None,
) -> Analysis:
    stmt = (
        select(Analysis)
        .where(
            Analysis.uid == uid,
            Analysis.file_hash == file_hash,
            Analysis.deleted_at.is_(None),
        )
        .order_by(desc(Analysis.created_at))
        .limit(1)
    )
    existing = await session.execute(stmt)
    analy = existing.scalars().first()

    if analy is None and task_id:
        same_task = await session.execute(
            select(Analysis).where(
                Analysis.uid == uid,
                Analysis.task_id == task_id,
                Analysis.deleted_at.is_(None),
            )
        )
        analy = same_task.scalars().first()
        if analy is not None:
            analy.file_name = file_name

    if analy:
        analy.created_at = datetime.now(timezone.utc)
        analy.privacy = privacy
        analy.rid = rid
        analy.task_id = task_id
        analy.tools = tools
        analy.status = status
        analy.file_path = file_path
        analy.file_name = file_name
        analy.file_type = file_type
        analy.file_size = file_size
        analy.md5 = md5
        if detected_type is not None:
            analy.detected_type = detected_type
            analy.detected_source = detected_source
            analy.file_type_mismatch = file_type_mismatch
        if tool_notes is not None:
            analy.tool_notes = tool_notes
        if tool_states is not None:
            analy.tool_states = tool_states
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
        detected_type=detected_type,
        detected_source=detected_source,
        file_type_mismatch=file_type_mismatch,
        file_size=file_size,
        privacy=privacy,
        md5=md5,
        tool_notes=tool_notes,
        tool_states=tool_states,
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
        .where(
            Analysis.task_id == task_id,
            Analysis.uid == uid,
            Analysis.deleted_at.is_(None),
        )
        .order_by(Analysis.created_at.desc())
    )
    row = result.first()
    if row is None:
        return None
    return row.Analysis, row.Reports

async def get_public_analysis_with_report(
    session: AsyncSession,
    task_id: str
) -> tuple[Analysis, Reports | None] | None:
    result = await session.execute(
        select(Analysis, Reports)
        .outerjoin(Reports, Analysis.rid == Reports.rid)
        .where(
            Analysis.task_id == task_id,
            Analysis.privacy.is_(False),
            Analysis.deleted_at.is_(None),
        )
        .order_by(Analysis.created_at.desc())
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
        .where(Analysis.task_id == task_id, Analysis.deleted_at.is_(None))
        .order_by(Analysis.created_at.desc())
    )
    row = result.first()
    if row is None:
        return None
    return row.Analysis, row.Reports

async def get_analysis_access_rows_by_md5(
    session: AsyncSession,
    md5: str,
) -> list:
    result = await session.execute(
        select(Analysis.uid, Analysis.privacy, Analysis.rid).where(
            Analysis.md5 == md5,
            Analysis.deleted_at.is_(None),
        )
    )
    return result.all()

async def get_analysis_history(
    session: AsyncSession,
    uid: UUID | str,
    params: AnalysisHistoryParams
) -> dict[str, Any]:

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

