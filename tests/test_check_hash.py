"""Tests for the hash-only pre-upload dedup check.

Covers services.analy.analy_service.attempt_attach_to_existing_analysis
(the shared dedup logic), services.analy.analy_service.
attempt_gap_fill_redispatch (the retry-the-gap re-dispatch logic), and
controller.Analysis.CheckHash_controller (the HTTP-facing wrapper).
"""

import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from controller.Analysis import CheckHash_controller as controller
from services.analy import analy_service

class FakeSession:
    def __init__(self):
        self.rollback_called = False
        self.added = []
        self.commits = 0

    async def rollback(self):
        self.rollback_called = True

    def add(self, value):
        self.added.append(value)

    async def commit(self):
        self.commits += 1

    async def refresh(self, value):
        return None

@pytest.mark.asyncio
async def test_attach_returns_none_when_no_existing_analysis(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(analy_service, "get_file_by_hash", _returns(None))

    outcome, analysis = await analy_service.attempt_attach_to_existing_analysis(
        session, uid="user-1", file_hash="a" * 64, file_name="f.apk", file_size=10, privacy=True,
    )

    assert outcome == "none"
    assert analysis is None

@pytest.mark.asyncio
async def test_attach_reports_dispatching_without_touching_db(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(
        analy_service,
        "get_file_by_hash",
        _returns({"status": "dispatching", "task_id": "task-1"}),
    )

    outcome, analysis = await analy_service.attempt_attach_to_existing_analysis(
        session, uid="user-1", file_hash="a" * 64, file_name="f.apk", file_size=10, privacy=True,
    )

    assert outcome == "dispatching"
    assert analysis is None

@pytest.mark.asyncio
async def test_attach_reuses_existing_success_task(monkeypatch):
    session = FakeSession()
    inserted = {}

    async def fake_insert(session, **kwargs):
        inserted.update(kwargs)
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(analy_service, "acquire_analysis_task_lock", _noop)
    monkeypatch.setattr(
        analy_service,
        "get_file_by_hash",
        _returns({"status": "success", "task_id": "task-1"}),
    )
    monkeypatch.setattr(
        analy_service,
        "get_file_by_task_id",
        _returns({
            "status": "success", "task_id": "task-1", "rid": "report-1",
            "tools": "virustotal,mobsf,cape,gemini", "file_path": "temps_files/a.apk",
            "file_type": "apk", "file_size": 999, "md5": "deadbeef",
        }),
    )
    monkeypatch.setattr(analy_service, "insert_table_analy", fake_insert)

    outcome, analysis = await analy_service.attempt_attach_to_existing_analysis(
        session, uid="user-2", file_hash="a" * 64, file_name="f.apk", file_size=10, privacy=False,
    )

    assert outcome == "attached"
    assert inserted["task_id"] == "task-1"
    assert inserted["rid"] == "report-1"
    assert inserted["md5"] == "deadbeef"
    assert inserted["file_size"] == 999

@pytest.mark.asyncio
async def test_attach_falls_through_to_none_when_existing_task_failed(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(analy_service, "acquire_analysis_task_lock", _noop)
    monkeypatch.setattr(
        analy_service,
        "get_file_by_hash",
        _returns({"status": "processing", "task_id": "task-1"}),
    )
    monkeypatch.setattr(
        analy_service,
        "get_file_by_task_id",
        _returns({"status": "failed", "task_id": "task-1"}),
    )

    outcome, analysis = await analy_service.attempt_attach_to_existing_analysis(
        session, uid="user-1", file_hash="a" * 64, file_name="f.apk", file_size=10, privacy=True,
    )

    assert outcome == "none"
    assert analysis is None

@pytest.mark.asyncio
async def test_gap_fill_returns_none_when_no_existing_analysis(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(analy_service, "get_file_by_hash", _returns(None))

    outcome, analysis = await analy_service.attempt_gap_fill_redispatch(
        session, uid="user-1", file_hash="a" * 64, file_name="f.apk", file_size=10, privacy=True,
    )

    assert outcome == "none"
    assert analysis is None

@pytest.mark.asyncio
async def test_gap_fill_returns_none_when_success_but_no_tool_notes(monkeypatch, tmp_path):
    session = FakeSession()
    file_path = tmp_path / "sample.apk"
    file_path.write_bytes(b"content")

    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(
        analy_service,
        "get_file_by_hash",
        _returns({
            "status": "success", "task_id": "task-1", "tool_notes": None,
            "md5": "deadbeef", "file_path": str(file_path), "file_type": "apk",
            "file_size": 7, "tools": "virustotal,mobsf,cape,gemini",
        }),
    )

    outcome, analysis = await analy_service.attempt_gap_fill_redispatch(
        session, uid="user-1", file_hash="a" * 64, file_name="f.apk", file_size=10, privacy=True,
    )

    assert outcome == "none"
    assert analysis is None

@pytest.mark.asyncio
async def test_gap_fill_does_not_apply_to_in_flight_analysis(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(
        analy_service,
        "get_file_by_hash",
        _returns({
            "status": "processing", "task_id": "task-1",
            "tool_notes": json.dumps({"cape": "CAPE skipped after 40 status checks with no result"}),
            "md5": "deadbeef", "file_path": "temps_files/a.apk", "file_type": "apk",
            "file_size": 7, "tools": "virustotal,mobsf",
        }),
    )

    outcome, analysis = await analy_service.attempt_gap_fill_redispatch(
        session, uid="user-1", file_hash="a" * 64, file_name="f.apk", file_size=10, privacy=True,
    )

    assert outcome == "none"
    assert analysis is None

@pytest.mark.asyncio
async def test_gap_fill_dispatches_fresh_task_carrying_forward_succeeded_tools(monkeypatch, tmp_path):
    session = FakeSession()
    file_path = tmp_path / "sample.apk"
    file_path.write_bytes(b"content")

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    md5 = "deadbeef"
    (reports_dir / f"virustotal-{md5}.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
    (reports_dir / f"mobsf-{md5}.json").write_text(json.dumps({"ok": True}), encoding="utf-8")

    monkeypatch.setattr(analy_service, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(analy_service, "acquire_analysis_hash_lock", _noop)
    monkeypatch.setattr(
        analy_service,
        "get_file_by_hash",
        _returns({
            "status": "success", "task_id": "old-task",
            "tool_notes": json.dumps({"cape": "CAPE skipped after 40 status checks with no result"}),
            "md5": md5, "file_path": str(file_path), "file_type": "apk",
            "file_size": 7, "tools": "virustotal,mobsf,gemini",
        }),
    )

    apply_async_calls = []

    class FakeAsyncResult:
        def __init__(self, task_id):
            self.id = task_id

    def fake_apply_async(args=None, kwargs=None, task_id=None):
        apply_async_calls.append({"args": args, "kwargs": kwargs, "task_id": task_id})
        return FakeAsyncResult(task_id)

    monkeypatch.setattr(analy_service.analyze_malware_task, "apply_async", fake_apply_async)

    update_calls = []

    async def fake_update(session, task_id, **kwargs):
        update_calls.append((task_id, kwargs))
        return 1

    monkeypatch.setattr(analy_service, "update_analysis_rows_by_task_id", fake_update)

    outcome, analysis = await analy_service.attempt_gap_fill_redispatch(
        session, uid="user-1", file_hash="a" * 64, file_name="f.apk", file_size=10, privacy=True,
    )

    assert outcome == "gap_filled"
    assert analysis is not None
    assert analysis.task_id != "old-task"
    assert analysis.status == "queued"
    assert analysis in session.added

    assert len(apply_async_calls) == 1
    call = apply_async_calls[0]
    assert call["task_id"] == analysis.task_id
    assert call["task_id"] != "old-task"
    assert call["args"] == (str(file_path), md5, "a" * 64, 7)

    assert call["kwargs"]["vt_status"] is True
    assert call["kwargs"]["vt_report_path"] == str(reports_dir / f"virustotal-{md5}.json")
    assert call["kwargs"]["mobsf_status"] is True
    assert call["kwargs"]["mobsf_report_path"] == str(reports_dir / f"mobsf-{md5}.json")
    assert "cape_status" not in call["kwargs"]
    assert "cape_report_path" not in call["kwargs"]

    assert update_calls == [(analysis.task_id, {"status": "queued", "from_statuses": ("dispatching",)})]

@pytest.mark.asyncio
async def test_check_hash_controller_rejects_malformed_sha256():
    with pytest.raises(HTTPException) as raised:
        await controller.check_hash_controller("user-1", "not-a-hash", "f.apk", 10, True)
    assert raised.value.status_code == 400

@pytest.mark.asyncio
async def test_check_hash_controller_rejects_invalid_uid(monkeypatch):
    with pytest.raises(HTTPException) as raised:
        await controller.check_hash_controller("not-a-uuid", "a" * 64, "f.apk", 10, True)
    assert raised.value.status_code == 401

class _DbSession:
    """Minimal SessionLocal() context stand-in for check_hash_controller's
    active-user lookup - only `.get(User, uid)` and `.rollback()` are
    exercised by this controller."""

    def __init__(self, user):
        self._user = user

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, model, uid):
        return self._user

    async def rollback(self):
        pass

@pytest.mark.asyncio
async def test_check_hash_controller_surfaces_gap_filled_outcome(monkeypatch):
    """When attempt_gap_fill_redispatch reports a fresh re-dispatch, the
    controller's JSON response must carry gap_filled=True with the NEW
    task_id/status so the frontend can distinguish this from a fully
    cached prior result (see check_hash_controller's response-shape
    comment for the documented contract)."""
    active_user = SimpleNamespace(status="active", is_banned=False)
    monkeypatch.setattr(controller, "SessionLocal", lambda: _DbSession(active_user))
    monkeypatch.setattr(controller, "User", object)

    new_analysis = SimpleNamespace(
        task_id="new-task-id", status="queued", md5="deadbeef",
        file_hash="a" * 64, file_name="f.apk",
    )

    async def fake_gap_fill(session, **kwargs):
        return "gap_filled", new_analysis

    monkeypatch.setattr(controller, "attempt_gap_fill_redispatch", fake_gap_fill)

    response = await controller.check_hash_controller(
        "00000000-0000-4000-8000-000000000001", "a" * 64, "f.apk", 10, True,
    )

    assert response["success"] is True
    assert response["found"] is True
    assert response["gap_filled"] is True
    assert response["task_id"] == "new-task-id"
    assert response["status"] == "queued"

@pytest.mark.asyncio
async def test_check_hash_controller_falls_back_to_attach_when_no_gap_to_fill(monkeypatch):
    """When there's nothing to gap-fill (attempt_gap_fill_redispatch
    returns "none"), the controller must fall through to the existing
    attempt_attach_to_existing_analysis reuse path unchanged, and the
    response must NOT claim gap_filled."""
    active_user = SimpleNamespace(status="active", is_banned=False)
    monkeypatch.setattr(controller, "SessionLocal", lambda: _DbSession(active_user))
    monkeypatch.setattr(controller, "User", object)

    async def fake_gap_fill(session, **kwargs):
        return "none", None

    attached_analysis = SimpleNamespace(
        task_id="existing-task", status="success", md5="deadbeef",
        file_hash="a" * 64, file_name="f.apk",
    )

    async def fake_attach(session, **kwargs):
        return "attached", attached_analysis

    monkeypatch.setattr(controller, "attempt_gap_fill_redispatch", fake_gap_fill)
    monkeypatch.setattr(controller, "attempt_attach_to_existing_analysis", fake_attach)
    monkeypatch.setattr(controller, "get_analysis_with_report", _returns(None))

    response = await controller.check_hash_controller(
        "00000000-0000-4000-8000-000000000001", "a" * 64, "f.apk", 10, True,
    )

    assert response["success"] is True
    assert response["found"] is True
    assert "gap_filled" not in response
    assert response["task_id"] == "existing-task"

def _noop(*args, **kwargs):
    return _AwaitableNone()

def _returns(value):
    def factory(*args, **kwargs):
        return _Awaitable(value)
    return factory

class _Awaitable:
    def __init__(self, value):
        self.value = value

    def __await__(self):
        async def _inner():
            return self.value
        return _inner().__await__()

class _AwaitableNone(_Awaitable):
    def __init__(self):
        super().__init__(None)
