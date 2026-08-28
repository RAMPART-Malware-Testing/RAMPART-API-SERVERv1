import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from celery.exceptions import MaxRetriesExceededError, Retry
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import text

from bgProcessing import task_handlers, tasks
from controller import analysis_controller
from schemas.analy import AnalysisReportParamsTarget

class ScalarResult:
    def __init__(self, value=None, rows=None):
        self.value = value
        self.rows = rows or []

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return FinalizeScalars(self.rows)

class FakeSession:
    def __init__(self, report=None):
        self.report = report
        self.rows = [analysis_row("queued"), analysis_row("queued")]
        self.added = []
        self.statements = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def execute(self, statement, parameters=None):
        self.statements.append(statement)
        if str(statement).lstrip().startswith("SELECT"):
            if "pg_advisory_xact_lock" in str(statement):
                return ScalarResult()
            return ScalarResult(self.report, self.rows)
        params = statement.compile().params
        target = next(value for value in params.values() if value in ("processing", "success", "failed"))
        statuses = next(value for value in params.values() if isinstance(value, list))
        matching = [row for row in self.rows if row.status in statuses]
        rid = next((value for value in params.values() if value == "report-id"), None)
        for row in matching:
            row.status = target
            if rid:
                row.rid = rid
        return SimpleNamespace(rowcount=len(matching))

    def get(self, model, rid):
        return self.report if self.report and self.report.rid == rid else None

    def add(self, value):
        self.added.append(value)
        if getattr(value, "rid", None) is None:
            value.rid = "report-id"

    def flush(self):
        if self.added and getattr(self.added[-1], "rid", None) is None:
            self.added[-1].rid = "report-id"

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True

def update_values(session):
    return [statement.compile().params for statement in session.statements if str(statement).lstrip().startswith("UPDATE")]

def run_task(monkeypatch, tmp_path, vt_result, retries=0, retry_error=None, report=None, **extra_kwargs):
    session = FakeSession(report)
    monkeypatch.setattr(tasks, "SyncSessionLocal", lambda: session)
    monkeypatch.setattr(tasks, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(tasks, "task_is_complete", lambda *args: False)
    def handle_virustotal(*args, **kwargs):
        path = kwargs["report_path"]
        if vt_result["state"] == "complete":
            Path(path).write_text(json.dumps(vt_result["report"]), encoding="utf-8")
            return {"status": True, "report_path": str(path)}
        if vt_result["state"] == "pending":
            return {"status": "pending", "report_path": str(path), "retry_in": vt_result.get("retry_in", 60)}
        return {"status": "failed", "report_path": str(path), "error": vt_result.get("error", "VT failed")}

    monkeypatch.setattr(tasks, "handle_virustotal", handle_virustotal)
    monkeypatch.setattr(tasks, "handle_mobsf", lambda *args, **kwargs: {"status": "skipped", "report_path": kwargs["report_path"]})
    monkeypatch.setattr(tasks, "handle_cape", lambda *args, **kwargs: {"status": "skipped", "report_path": kwargs["report_path"]})
    monkeypatch.setattr(tasks, "build_gemini_evidence", lambda *args: {"evidence": True})
    monkeypatch.setattr(tasks, "GeminiAPI", lambda: SimpleNamespace(AnalysisGemini=lambda evidence: {
        "danger_score": 0,
        "risk_level": "Low",
        "confidence": "medium",
        "verdict": "No malicious evidence observed",
        "summary": "No malicious evidence observed",
        "recommendation": "Use normal caution",
        "key_evidence": [],
        "tool_disagreements": [],
        "limitations": [],
    }))

    retry_calls = []

    def retry(**kwargs):
        retry_calls.append(kwargs)
        if retry_error:
            raise retry_error
        raise Retry()

    monkeypatch.setattr(tasks.analyze_malware_task, "retry", retry)
    tasks.analyze_malware_task.push_request(id="task-1", retries=retries)
    try:
        about_to_exhaust = vt_result["state"] == "error" and extra_kwargs.get("vt_attempts", 0) + 1 >= 3
        expect_retry = retry_error is None and not about_to_exhaust and (
            vt_result["state"] == "pending" or vt_result["state"] == "error"
        )
        if expect_retry:
            with pytest.raises(Retry):
                tasks.analyze_malware_task.run("sample.bin", "md5", "sha256", 10, **extra_kwargs)
            result = None
        else:
            result = tasks.analyze_malware_task.run("sample.bin", "md5", "sha256", 10, **extra_kwargs)
    finally:
        tasks.analyze_malware_task.pop_request()
    return result, session, retry_calls

def complete_report(malicious=0):
    return {
        "scan_summary": {
            "malicious_count": malicious,
            "suspicious_count": 0,
            "total_scanners": 20,
            "reputation": 0,
        },
        "threats_found": {"malicious": ["Engine: Trojan"] if malicious else [], "suspicious": []},
        "security_analysis": {"sigma_rules": {}},
    }

def raw_report(*, malicious_engines=0, undetected_engines=0):
    results = {
        f"Malicious-{index}": {
            "category": "malicious",
            "result": "Trojan.AndroidOS.Banker",
        }
        for index in range(malicious_engines)
    }
    results.update({
        f"Undetected-{index}": {"category": "undetected", "result": None}
        for index in range(undetected_engines)
    })
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious_engines,
                    "undetected": undetected_engines,
                },
                "last_analysis_results": results,
            }
        }
    }

def test_single_malicious_engine_completes_immediately_with_maximum_score():
    report = raw_report(malicious_engines=1)

    assert task_handlers.is_reportvt_complete(report) is True
    assert task_handlers.calculate_threat_scoreVT(report) == 100

def test_handler_prefers_sha256_hash_hit(monkeypatch, tmp_path):
    calls = []

    class VT:
        def get_report_by_hash(self, value):
            calls.append(value)
            return {"state": "found", "data": complete_report()}

    path = tmp_path / "vt.json"
    result = task_handlers.handle_virustotal("sample.bin", "md5", "sha256", 10, client=VT(), report_path=path)

    assert result == {"status": True, "report_path": str(path)}
    assert json.loads(path.read_text(encoding="utf-8")) == complete_report()
    assert calls == ["sha256"]

def test_handler_uploads_missing_eligible_file_once(monkeypatch, tmp_path):
    calls = []

    class VT:
        def get_report_by_hash(self, value):
            return {"state": "missing", "error": "not found"}

        def upload_file(self, file_path):
            calls.append(file_path)
            return {"state": "uploaded", "analysis_id": "analysis-1"}

    path = tmp_path / "vt.json"
    result = task_handlers.handle_virustotal("sample.bin", "md5", "sha256", 10, client=VT(), report_path=path)

    assert result == {"status": "pending", "report_path": str(path), "retry_in": 300}
    assert calls == ["sample.bin"]

def test_handler_rejects_upload_without_analysis_id(tmp_path):
    class VT:
        def get_report_by_hash(self, value):
            return {"state": "missing", "error": "not found"}

        def upload_file(self, file_path):
            return {"state": "uploaded", "analysis_id": None}

    assert task_handlers.handle_virustotal(
        "sample.bin", "md5", "sha256", 10, client=VT(), report_path=tmp_path / "vt.json"
    )["status"] == "failed"

def test_handler_does_not_reupload_while_polling(monkeypatch, tmp_path):
    class VT:
        def get_report_by_hash(self, value):
            return {"state": "missing", "error": "not found"}

        def upload_file(self, file_path):
            raise AssertionError("must not upload during polling")

    assert task_handlers.handle_virustotal(
        "sample.bin", "md5", "sha256", 10, is_retry=True, client=VT(), report_path=tmp_path / "vt.json"
    )["status"] == "pending"

def test_incomplete_hash_report_is_pending(monkeypatch, tmp_path):
    class VT:
        def get_report_by_hash(self, value):
            return {"state": "found", "data": {"scan_summary": {"total_scanners": 2}}}

    assert task_handlers.handle_virustotal(
        "sample.bin", "md5", "sha256", 10, client=VT(), report_path=tmp_path / "vt.json"
    )["status"] == "pending"

@pytest.mark.parametrize("malicious", [0, 5])
def test_completed_report_persists_score_and_succeeds_all_rows(monkeypatch, tmp_path, malicious):
    report = complete_report(malicious)
    result, session, retry_calls = run_task(
        monkeypatch, tmp_path, {"state": "complete", "report": report}
    )

    assert result["success"] is True
    assert result["task_id"] == "task-1"
    assert result["virustotal_score"] == task_handlers.calculate_threat_scoreVT(report)
    assert len(session.added) == 1
    assert session.added[0].virustotal_score == result["virustotal_score"]
    assert session.added[0].malware_signatures == report["threats_found"]["malicious"]
    values = update_values(session)
    assert any("processing" in params.values() for params in values)
    assert any("success" in params.values() and "report-id" in params.values() for params in values)
    if malicious:
        assert any(True in params.values() and "virustotal" in params.values() for params in values)
    assert json.loads((tmp_path / "virustotal-md5.json").read_text()) == report
    assert retry_calls == []

def test_pending_report_retries_without_marking_failed(monkeypatch, tmp_path):
    _, session, retry_calls = run_task(
        monkeypatch, tmp_path, {"state": "pending", "retry_in": 17}, retries=1
    )

    assert retry_calls[0]["countdown"] == 17
    assert retry_calls[0]["kwargs"]["vt_status"] == "pending"
    assert not any("failed" in params.values() for params in update_values(session))

def test_retry_exhaustion_marks_all_rows_failed(monkeypatch, tmp_path):
    result, session, _ = run_task(
        monkeypatch,
        tmp_path,
        {"state": "pending", "retry_in": 17},
        retries=10,
        retry_error=MaxRetriesExceededError(),
    )

    assert result == {"success": False, "task_id": "task-1", "error": "VirusTotal polling exhausted"}
    assert any("failed" in params.values() for params in update_values(session))

def test_single_vt_error_retries_instead_of_failing_immediately(monkeypatch, tmp_path):
    """A lone VirusTotal error (rate limit, transient API failure, etc.)
    must not abort the whole pipeline anymore - it's counted against a
    3-attempt retry budget and retried like a pending poll."""
    result, session, retry_calls = run_task(
        monkeypatch, tmp_path, {"state": "error", "error": RuntimeError("VT unavailable")}
    )

    assert result is None
    assert retry_calls[0]["kwargs"]["vt_status"] == "pending"
    assert retry_calls[0]["kwargs"]["vt_attempts"] == 1
    assert not any("failed" in params.values() for params in update_values(session))

def test_vt_error_force_skips_after_exhausting_retry_budget_without_failing_task(monkeypatch, tmp_path):
    """After MAX_TOOL_ERROR_RETRIES (3) consecutive VirusTotal errors,
    VT is force-skipped (not the whole task failed) - the pipeline still
    finishes successfully via Gemini synthesis without a VT signal, and
    the skip reason is recorded in tool_notes."""
    result, session, retry_calls = run_task(
        monkeypatch,
        tmp_path,
        {"state": "error", "error": RuntimeError("VT unavailable")},
        vt_status="pending",
        vt_submitted=True,
        vt_attempts=2,
    )

    assert result["success"] is True
    assert result["tool_notes"]["virustotal"].startswith("VirusTotal skipped after 3 failed attempts")
    assert result["virustotal_score"] is None
    assert not any("failed" in params.values() for params in update_values(session))

def test_vt_client_returns_string_errors(monkeypatch, tmp_path):
    from calling.VirusTotal import VirusToTalAPI

    client = object.__new__(VirusToTalAPI)
    client._make_request = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("safe error"))
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")

    assert client.get_report_by_hash("sha256") == {"state": "error", "error": "safe error"}
    assert client.upload_file(str(sample)) == {"state": "error", "error": "safe error"}

def test_vt_base64_error_is_json_safe_string():
    from calling.VirusTotal import VirusToTalAPI

    client = object.__new__(VirusToTalAPI)
    client._make_request = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("safe error"))

    result = client.get_report_by_base64("bWQ1OjE=")

    assert result == {"success": False, "message": "safe error"}

def test_vt_base64_decode_error_is_json_safe_string():
    from calling.VirusTotal import VirusToTalAPI

    client = object.__new__(VirusToTalAPI)

    result = client.get_report_by_base64("/w==")

    assert result["success"] is False
    assert isinstance(result["message"], str)

def test_vt_client_distinguishes_missing_hash():
    from calling.VirusTotal import VirusToTalAPI

    client = object.__new__(VirusToTalAPI)
    client._make_request = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("HTTP Error 404: not found"))

    assert client.get_report_by_hash("sha256") == {
        "state": "missing",
        "error": "HTTP Error 404: not found",
    }

def test_vt_request_preserves_falsey_http_error_status():
    from calling.VirusTotal import VirusToTalAPI

    response = requests.Response()
    response.status_code = 404
    response.url = "https://example.test/files/sha256"

    client = object.__new__(VirusToTalAPI)
    client.api_keys = ["test-key"]
    client.current_key_index = 0
    client.session = SimpleNamespace(request=lambda *args, **kwargs: response)

    with pytest.raises(RuntimeError, match="HTTP Error 404"):
        client._make_request("GET", response.url)

@pytest.mark.asyncio
async def test_status_uses_string_uid_and_current_report_schema(monkeypatch):
    analysis = SimpleNamespace(
        aid="analysis-id", task_id="task-1", uid="00000000-0000-4000-8000-000000000001", privacy=True,
        file_name="sample.bin", file_size=10, file_hash="sha256", file_path="sample.bin",
        file_type="bin", tools="virustotal", tool_notes=None, md5="md5", status="success", deleted_at=None,
        deleted_by=None, created_at=None,
    )
    report = SimpleNamespace(
        rid="report-id", file_type="bin", virustotal_score=42, mobsf_score=20,
        cape_score=70, rampart_ai_score=55, score=60, risk_level="High",
        recommendation="Isolate", analysis_summary="summary", risk_indicators=["a"],
        gemini_recommendation="verdict", malware_signatures=["Trojan"], created_at=None
    )
    captured = {}
    fake_user = SimpleNamespace(is_banned=False)

    class Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return fake_user

    async def lookup(session, task_id, uid):
        captured["uid"] = uid
        return analysis, report

    monkeypatch.setattr(analysis_controller, "SessionLocal", Context)
    monkeypatch.setattr(analysis_controller, "get_analysis_with_report", lookup)

    response = await analysis_controller.analysisReport_controller("00000000-0000-4000-8000-000000000001", "task-1")

    assert str(captured["uid"]) == "00000000-0000-4000-8000-000000000001"
    assert response["report"]["virustotal_score"] == 42
    assert response["report"]["mobsf_score"] == 20
    assert response["report"]["cape_score"] == 70
    assert response["report"]["rampart_ai_score"] == 55
    assert response["report"]["malware_signatures"] == ["Trojan"]

@pytest.mark.asyncio
async def test_success_without_report_is_defensive(monkeypatch):
    analysis = SimpleNamespace(status="success")
    fake_user = SimpleNamespace(is_banned=False)

    class Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return fake_user

    async def lookup(session, task_id, uid):
        return analysis, None

    monkeypatch.setattr(analysis_controller, "SessionLocal", Context)
    monkeypatch.setattr(analysis_controller, "get_analysis_with_report", lookup)

    response = await analysis_controller.analysisReport_controller("00000000-0000-4000-8000-000000000001", "task-1")

    assert response == {
        "success": True,
        "task_id": "task-1",
        "status": "success",
        "report": None,
        "message": "Analysis completed without a report",
    }

@pytest.mark.asyncio
async def test_raw_report_status_uses_string_uid(monkeypatch):
    captured = {}
    analysis = SimpleNamespace(status="processing")
    fake_user = SimpleNamespace(is_banned=False)

    class Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return fake_user

    async def lookup(session, task_id, uid):
        captured["uid"] = uid
        return analysis, None

    monkeypatch.setattr(analysis_controller, "SessionLocal", Context)
    monkeypatch.setattr(analysis_controller, "get_analysis_with_report", lookup)

    response = await analysis_controller.get_file_by_hash_controller("task-1", "00000000-0000-4000-8000-000000000001")

    assert str(captured["uid"]) == "00000000-0000-4000-8000-000000000001"
    assert response["status"] == "processing"

@pytest.mark.asyncio
async def test_raw_report_reads_persisted_virustotal_name(monkeypatch, tmp_path):
    md5 = "a" * 32
    report = {"scan_summary": {"total_scanners": 20}}
    (tmp_path / f"virustotal-{md5}.json").write_text(json.dumps(report), encoding="utf-8")
    analysis = SimpleNamespace(status="success", md5=md5)
    fake_user = SimpleNamespace(is_banned=False)

    class Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return fake_user

    async def lookup(session, task_id, uid):
        return analysis, SimpleNamespace()

    monkeypatch.setattr(analysis_controller, "SessionLocal", Context)
    monkeypatch.setattr(analysis_controller, "get_analysis_with_report", lookup)
    monkeypatch.setattr(analysis_controller, "BASE_REPORT_PATH", tmp_path)

    response = await analysis_controller.get_file_by_hash_controller("task-1", "00000000-0000-4000-8000-000000000001")

    assert response["report"] == report

@pytest.mark.asyncio
async def test_download_accepts_exact_persisted_virustotal_basename(monkeypatch, tmp_path):
    name = f"virustotal-{'a' * 32}.json"
    expected = tmp_path / name
    expected.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(analysis_controller, "BASE_REPORT_PATH", tmp_path)

    assert await analysis_controller.downloadReport_controller(name) == expected.resolve()

@pytest.mark.asyncio
@pytest.mark.parametrize("name", [
    f"cape-{'a' * 32}.json",
    f"mobsf-{'a' * 32}.json",
    f"rampartai-{'a' * 32}.json",
])
async def test_download_accepts_all_known_tool_basenames(name, monkeypatch, tmp_path):
    """Users need to be able to download the full VT+MobSF+CAPE+RampartAI
    raw report set for research purposes - not just VirusTotal."""
    expected = tmp_path / name
    expected.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(analysis_controller, "BASE_REPORT_PATH", tmp_path)

    assert await analysis_controller.downloadReport_controller(name) == expected.resolve()

@pytest.mark.asyncio
@pytest.mark.parametrize("name", [
    f"virustotal-{'a' * 32}",
    f"unknown-tool-{'a' * 32}.json",
    "../virustotal-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
])
async def test_download_rejects_malformed_or_unknown_tool_names(name):
    with pytest.raises(HTTPException) as raised:
        await analysis_controller.downloadReport_controller(name)
    assert raised.value.status_code == 400

def test_raw_report_request_accepts_known_tool_selector():
    params = AnalysisReportParamsTarget(task_id="task-1", token="token", tool="cape")
    assert params.tool == "cape"

def test_raw_report_request_rejects_unknown_tool_selector():
    with pytest.raises(ValidationError):
        AnalysisReportParamsTarget(task_id="task-1", token="token", tool="not-a-real-tool")

class FinalizeScalars:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows

class FinalizeResult:
    def __init__(self, rows=None, rowcount=0):
        self.rows = rows or []
        self.rowcount = rowcount

    def scalars(self):
        return FinalizeScalars(self.rows)

class FinalizeSession:
    def __init__(self, rows, reports=None, update_rowcount=None):
        self.rows = rows
        self.reports = reports or {}
        self.update_rowcount = update_rowcount
        self.added = []
        self.statements = []
        self.rollbacks = 0

    def execute(self, statement, parameters=None):
        self.statements.append((statement, parameters))
        sql = str(statement)
        if "pg_advisory_xact_lock" in sql:
            return FinalizeResult()
        if sql.lstrip().startswith("SELECT"):
            return FinalizeResult(self.rows)
        count = self.update_rowcount
        if count is None:
            count = sum(row.status in ("processing", "success") for row in self.rows)
        if count:
            params = statement.compile().params
            rid = next(value for value in params.values() if value == "report-id")
            for row in self.rows:
                if row.status in ("processing", "success"):
                    row.status = "success"
                    row.rid = rid
        return FinalizeResult(rowcount=count)

    def get(self, model, rid):
        return self.reports.get(rid)

    def add(self, report):
        report.rid = "report-id"
        self.added.append(report)

    def flush(self):
        return None

    def rollback(self):
        self.rollbacks += 1

def analysis_row(status="processing", rid=None):
    return SimpleNamespace(status=status, rid=rid)

def test_finalization_acquires_task_advisory_lock_before_reading_rows():
    session = FinalizeSession([analysis_row()])

    tasks.finalize_virustotal_report(session, "task-1", "sample.bin", complete_report())

    lock, parameters = session.statements[0]
    assert "pg_advisory_xact_lock" in str(lock)
    assert parameters == {"task_id": "task-1"}
    assert str(session.statements[1][0]).lstrip().startswith("SELECT")

def test_duplicate_delivery_reuses_associated_report_without_orphan():
    existing = SimpleNamespace(
        rid="report-id", virustotal_score=0, malware_signatures=[]
    )
    session = FinalizeSession(
        [analysis_row("success", "report-id"), analysis_row("success", "report-id")],
        {"report-id": existing},
    )

    report, score = tasks.finalize_virustotal_report(
        session, "task-1", "sample.bin", complete_report(5)
    )

    assert report is existing
    assert score > 0
    assert session.added == []

def test_missing_task_rolls_back_and_does_not_create_report():
    session = FinalizeSession([])

    with pytest.raises(tasks.TaskFinalizationError, match="Task rows not found"):
        tasks.finalize_virustotal_report(session, "task-1", "sample.bin", complete_report())

    assert session.rollbacks == 1
    assert session.added == []

def test_inconsistent_existing_report_association_rolls_back():
    session = FinalizeSession([
        analysis_row("success", "report-a"), analysis_row("success", "report-b")
    ])

    with pytest.raises(tasks.TaskFinalizationError, match="Inconsistent report association"):
        tasks.finalize_virustotal_report(session, "task-1", "sample.bin", complete_report())

    assert session.rollbacks == 1
    assert session.added == []

def test_finalization_requires_terminal_update_rowcount():
    session = FinalizeSession([analysis_row()], update_rowcount=0)

    with pytest.raises(tasks.TaskFinalizationError, match="did not associate"):
        tasks.finalize_virustotal_report(session, "task-1", "sample.bin", complete_report())

    assert session.rollbacks == 1

def test_finalization_verifies_every_task_row_is_success_and_associated():
    session = FinalizeSession(
        [analysis_row(), analysis_row("queued")], update_rowcount=1
    )

    with pytest.raises(tasks.TaskFinalizationError, match="not in a finalizable state"):
        tasks.finalize_virustotal_report(session, "task-1", "sample.bin", complete_report())

    assert session.rollbacks == 1
