"""Behaviour tests for the content-level reuse model (docs/analysis-dedup-design.md).

One report per file (sha256), one live analysis row per (user, content), and a
repair run that re-executes only the tools whose report is missing - while
keeping the content's existing report id so no second report row appears.
"""

import json
from types import SimpleNamespace

import pytest

from services.analy import analy_service


class FakeResult:
    def __init__(self, scalar=0, row=None):
        self._scalar = scalar
        self._row = row

    def scalar_one(self):
        return self._scalar

    def scalars(self):
        return self

    def first(self):
        return self._row

    def mappings(self):
        return self

    def one_or_none(self):
        return self._row


class FakeSession:
    def __init__(self, content_runs=1, existing_row=None):
        self.content_runs = content_runs
        self.existing_row = existing_row
        self.added = []
        self.commits = 0
        self.statements = []

    async def execute(self, statement, parameters=None):
        self.statements.append(str(statement))
        if "count(" in str(statement).lower():
            return FakeResult(scalar=self.content_runs)
        return FakeResult(row=self.existing_row)

    def add(self, value):
        self.added.append(value)

    async def commit(self):
        self.commits += 1

    async def refresh(self, value):
        return None


async def _noop(*args, **kwargs):
    return None


def _returns(value):
    async def factory(*args, **kwargs):
        return value
    return factory


def write_reports(directory, md5, tools):
    directory.mkdir(exist_ok=True)
    prefix = {"rampart_ai": "rampartai"}.get(tools, tools)
    (directory / f"{prefix}-{md5}.json").write_text(json.dumps({"ok": True}), encoding="utf-8")


def success_row(tmp_path, md5="deadbeef", tools="virustotal,mobsf", **overrides):
    file_path = tmp_path / "sample.apk"
    file_path.write_bytes(b"content")
    row = {
        "status": "success",
        "task_id": "old-task",
        "rid": "report-1",
        "md5": md5,
        "file_path": str(file_path),
        "file_type": "apk",
        "file_size": 7,
        "file_hash": "a" * 64,
        "file_name": "sample.apk",
        "tools": tools,
        "tool_notes": None,
        "tool_states": None,
        "blocked_by": None,
    }
    row.update(overrides)
    return row


@pytest.mark.asyncio
async def test_attach_takes_hash_lock_then_task_lock_then_upserts(monkeypatch, tmp_path):
    order = []
    session = FakeSession()

    async def hash_lock(session, file_hash):
        order.append("hash-lock")

    async def task_lock(session, task_id):
        order.append("task-lock")

    async def upsert(session, **kwargs):
        order.append("upsert")
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", hash_lock)
    monkeypatch.setattr(analy_service, "acquire_analysis_task_lock", task_lock)
    monkeypatch.setattr(analy_service, "get_file_by_hash", _returns(success_row(tmp_path)))
    monkeypatch.setattr(
        analy_service,
        "get_file_by_task_id",
        _returns(success_row(tmp_path, status="success")),
    )
    monkeypatch.setattr(analy_service, "upsert_user_analysis", upsert)

    outcome, analysis = await analy_service.attempt_attach_to_existing_analysis(
        session, uid="user-1", file_hash="a" * 64, file_name="renamed.apk", file_size=10, privacy=True,
    )

    assert outcome == "attached"
    assert order == ["hash-lock", "task-lock", "upsert"]


@pytest.mark.asyncio
async def test_upsert_updates_the_users_row_for_the_same_content_under_a_new_name(monkeypatch, tmp_path):
    existing = SimpleNamespace(
        uid="user-1", file_hash="a" * 64, file_name="original.apk", status="success",
        task_id="old-task", rid="report-1", tools="virustotal", tool_notes=None,
        tool_states=None, md5="deadbeef", privacy=True, file_size=7,
        file_path="temps_files/old.apk", file_type="apk", created_at=None,
    )
    session = FakeSession(existing_row=existing)

    analysis = await analy_service.upsert_user_analysis(
        session,
        uid="user-1",
        file_name="renamed.apk",
        file_hash="a" * 64,
        file_path="temps_files/a.apk",
        file_type="apk",
        file_size=11,
        privacy=False,
        md5="deadbeef",
        rid="report-1",
        task_id="new-task",
        status="success",
        tools="virustotal,mobsf",
        tool_states={"mobsf": {"state": "success"}},
    )

    assert analysis is existing
    assert session.added == []
    assert existing.task_id == "new-task"
    assert existing.file_name == "original.apk"
    assert existing.privacy is False
    assert existing.tool_states == {"mobsf": {"state": "success"}}


@pytest.mark.asyncio
async def test_upsert_inserts_for_a_user_who_has_no_row_for_this_content():
    session = FakeSession(existing_row=None)

    analysis = await analy_service.upsert_user_analysis(
        session,
        uid="user-2",
        file_name="sample.apk",
        file_hash="a" * 64,
        file_path="temps_files/a.apk",
        file_type="apk",
        file_size=7,
        privacy=True,
        md5="deadbeef",
        rid="report-1",
        task_id="task-1",
        status="queued",
        tools="virustotal",
    )

    assert session.added == [analysis]
    assert analysis.rid == "report-1"


@pytest.mark.asyncio
async def test_gap_fill_keeps_report_id_and_reruns_only_missing_tools(monkeypatch, tmp_path):
    session = FakeSession()
    reports_dir = tmp_path / "reports"
    row = success_row(
        tmp_path,
        tools="virustotal,mobsf,rampart_ai",
        tool_states={
            "virustotal": {"state": "success"},
            "mobsf": {"state": "success"},
            "rampart_ai": {"state": "success"},
            "cape": {"state": "gap", "reason": "exhausted"},
        },
    )
    for tool in ("virustotal", "mobsf", "rampart_ai"):
        write_reports(reports_dir, row["md5"], tool)

    monkeypatch.setattr(analy_service, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(analy_service, "get_file_by_hash", _returns(row))

    dispatched = {}
    monkeypatch.setattr(
        analy_service.analyze_malware_task,
        "apply_async",
        lambda **kwargs: dispatched.update(kwargs),
    )
    monkeypatch.setattr(analy_service, "update_analysis_rows_by_task_id", _returns(1))

    outcome, analysis = await analy_service.attempt_gap_fill_redispatch(
        session, uid="user-1", file_hash="a" * 64, file_name="sample.apk", file_size=7, privacy=True,
    )

    assert outcome == "gap_filled"
    assert analysis.rid == "report-1"
    assert analysis.task_id != "old-task"
    assert dispatched["kwargs"]["vt_status"] is True
    assert dispatched["kwargs"]["mobsf_status"] is True
    assert dispatched["kwargs"]["rampart_ai_status"] is True
    assert "cape_status" not in dispatched["kwargs"]
    assert dispatched["kwargs"]["tool_states"]["mobsf"] == {"state": "success"}
    assert analysis in session.added


@pytest.mark.asyncio
async def test_gap_fill_never_reruns_a_virustotal_short_circuit(monkeypatch, tmp_path):
    session = FakeSession()
    reports_dir = tmp_path / "reports"
    row = success_row(
        tmp_path,
        tools="virustotal,gemini",
        tool_notes=json.dumps({
            "mobsf": "Skipped: VirusTotal already detected malware",
            "cape": "Skipped: VirusTotal already detected malware",
            "rampart_ai": "Skipped: VirusTotal already detected malware",
        }),
        blocked_by="virustotal",
        is_malicious=True,
    )
    write_reports(reports_dir, row["md5"], "virustotal")

    monkeypatch.setattr(analy_service, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(analy_service, "get_file_by_hash", _returns(row))

    outcome, analysis = await analy_service.attempt_gap_fill_redispatch(
        session, uid="user-1", file_hash="a" * 64, file_name="sample.apk", file_size=7, privacy=True,
    )

    assert outcome == "none"
    assert analysis is None
    assert session.added == []


@pytest.mark.asyncio
async def test_gap_fill_never_reruns_tools_that_do_not_apply_to_the_file_type(monkeypatch, tmp_path):
    session = FakeSession()
    reports_dir = tmp_path / "reports"
    row = success_row(tmp_path, tools="virustotal", tool_notes=json.dumps({"mobsf": "unsupported"}))
    row["file_type"] = "bin"
    row["file_path"] = str(tmp_path / "sample.bin")
    (tmp_path / "sample.bin").write_bytes(b"content")
    write_reports(reports_dir, row["md5"], "virustotal")

    monkeypatch.setattr(analy_service, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(analy_service, "get_file_by_hash", _returns(row))

    outcome, analysis = await analy_service.attempt_gap_fill_redispatch(
        session, uid="user-1", file_hash="a" * 64, file_name="sample.bin", file_size=7, privacy=True,
    )

    assert outcome == "none"
    assert session.added == []


@pytest.mark.asyncio
async def test_gap_fill_stops_once_the_content_spent_its_rerun_budget(monkeypatch, tmp_path):
    session = FakeSession(content_runs=4)
    reports_dir = tmp_path / "reports"
    row = success_row(tmp_path)
    write_reports(reports_dir, row["md5"], "virustotal")

    monkeypatch.setattr(analy_service, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(analy_service, "get_file_by_hash", _returns(row))

    outcome, analysis = await analy_service.attempt_gap_fill_redispatch(
        session, uid="user-1", file_hash="a" * 64, file_name="sample.apk", file_size=7, privacy=True,
    )

    assert outcome == "none"
    assert analysis is None


def test_completeness_treats_oversize_and_unsupported_as_terminal(monkeypatch, tmp_path):
    reports_dir = tmp_path / "reports"
    monkeypatch.setattr(analy_service, "REPORTS_DIR", reports_dir)
    oversize = success_row(tmp_path, tools="mobsf,cape,rampart_ai", file_size=33 * 1024 * 1024)
    write_reports(reports_dir, oversize["md5"], "mobsf")
    write_reports(reports_dir, oversize["md5"], "cape")
    write_reports(reports_dir, oversize["md5"], "rampart_ai")
    unsupported = success_row(tmp_path, tools="virustotal", file_type="bin", file_path=str(tmp_path / "x.bin"))
    write_reports(reports_dir, unsupported["md5"], "virustotal")

    assert analy_service.evaluate_tool_completeness(oversize)["complete"] is True
    assert analy_service.evaluate_tool_completeness(oversize)["states"]["virustotal"]["reason"] == "oversize"
    assert analy_service.evaluate_tool_completeness(unsupported)["complete"] is True


def test_completeness_reports_tools_listed_as_done_but_missing_on_disk(monkeypatch, tmp_path):
    monkeypatch.setattr(analy_service, "REPORTS_DIR", tmp_path / "reports")
    row = success_row(tmp_path, tools="virustotal,mobsf")

    plan = analy_service.evaluate_tool_completeness(row)

    assert plan["complete"] is False
    assert set(plan["missing"]) == {"virustotal", "mobsf", "cape"}


def test_completeness_honours_recorded_tool_states(monkeypatch, tmp_path):
    reports_dir = tmp_path / "reports"
    monkeypatch.setattr(analy_service, "REPORTS_DIR", reports_dir)
    row = success_row(
        tmp_path,
        tools="virustotal,mobsf",
        tool_states={
            "virustotal": {"state": "success"},
            "mobsf": {"state": "terminal", "reason": "unsupported"},
            "cape": {"state": "terminal", "reason": "unsupported"},
        },
    )
    write_reports(reports_dir, row["md5"], "virustotal")

    plan = analy_service.evaluate_tool_completeness(row)

    assert plan["complete"] is True
    assert set(plan["terminal"]) == {"mobsf", "cape"}
