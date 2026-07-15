import json
from types import SimpleNamespace

import pytest
import requests
from celery.exceptions import Retry

from bgProcessing import task_handlers, tasks
from calling.MobSF import MobSFCall


class MobSFClient:
    def __init__(self, report=None, upload=None, scan=None):
        self.report = report or {"status": "pending", "error": "Report not ready"}
        self.upload = upload or {"success": True, "data": {"hash": "mobsf-hash"}}
        self.scan = scan or {"success": True}
        self.upload_calls = 0

    def generate_json_report(self, md5):
        return self.report

    def upload_file(self, path):
        self.upload_calls += 1
        return self.upload

    def scan_uploaded_file(self, file_hash, timeout=None):
        return self.scan


def test_mobsf_connection_error_is_retryable(monkeypatch):
    client = object.__new__(MobSFCall)
    client.base_url = "http://mobsf.test"
    client.api_key = "test-key"
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.ConnectionError("offline")),
    )

    assert client.generate_json_report("a" * 32) == {
        "status": "pending",
        "error": "offline",
    }


def test_fail_task_removes_partial_report(monkeypatch, tmp_path):
    path = tmp_path / "mobsf-partial.json"
    path.write_text('{"partial": true}', encoding="utf-8")
    session = TaskSession()
    monkeypatch.setattr(tasks, "update_task_rows", lambda *args, **kwargs: 1)

    result = tasks.fail_task(
        session,
        "task-1",
        "MobSF analysis failed",
        report_paths=(path,),
    )

    assert result["success"] is False
    assert path.exists() is False
    assert session.commits == 1


class CAPEClient:
    def __init__(self, existing=None, created=None, status=None, report=None):
        self.existing = existing if existing is not None else []
        self.created = created or {"status": "created", "task_id": 42}
        self.status = status or {"data": "running"}
        self.report = report or {"status": "success", "data": {"score": 7.5}}

    def cheack_analyer(self, path):
        return self.existing

    def create_file_task(self, path, machine=None):
        return self.created

    def get_task_status(self, task_id):
        return self.status

    def get_report(self, task_id, md5):
        return self.report


@pytest.mark.parametrize(("security_score", "danger"), [(100, 0), (82.5, 17.5), (0, 100), (140, 0)])
def test_mobsf_danger_score(security_score, danger):
    assert task_handlers.calculate_mobsf_danger_score({"security_score": security_score}) == danger


@pytest.mark.parametrize(("malscore", "danger"), [(0, 0), (7.5, 75), (10, 100), (15, 100)])
def test_cape_danger_score(malscore, danger):
    assert task_handlers.calculate_cape_danger_score({"score": malscore}) == danger


def test_mobsf_report_is_written_and_returned_by_path(tmp_path):
    client = MobSFClient(report={"status": True, "data": {"appsec": {"security_score": 80}}})
    path = tmp_path / f"mobsf-{'a' * 32}.json"

    result = task_handlers.handle_mobsf("sample.apk", "a" * 32, client=client, report_path=path)

    assert result == {"status": True, "report_path": str(path)}
    assert json.loads(path.read_text()) == {"appsec": {"security_score": 80}}


def test_mobsf_submits_once_then_retries_with_scalar_state(tmp_path):
    client = MobSFClient()

    path = tmp_path / "mobsf.json"
    first = task_handlers.handle_mobsf("sample.apk", "b" * 32, client=client, report_path=path)
    second = task_handlers.handle_mobsf("sample.apk", "b" * 32, submitted=True, client=client, report_path=path)

    assert first["status"] == "pending"
    assert first["submitted"] is True
    assert second["status"] == "pending"
    assert second["submitted"] is True
    assert client.upload_calls == 1


def test_mobsf_unsupported_is_skipped(tmp_path):
    client = MobSFClient(upload={"success": False, "error": "File format not supported"})
    result = task_handlers.handle_mobsf(
        "sample.txt",
        "c" * 32,
        client=client,
        report_path=tmp_path / "mobsf.json",
    )
    assert result["status"] == "skipped"


def test_cape_existing_task_polls_then_writes_report(tmp_path):
    pending_client = CAPEClient(existing=[{"id": 77}], status={"data": "running"})
    pending = task_handlers.handle_cape("sample.exe", "d" * 32, client=pending_client, reports_dir=tmp_path)
    complete_client = CAPEClient(status={"data": "reported"}, report={"status": "success", "data": {"score": 6}})
    complete = task_handlers.handle_cape("sample.exe", "d" * 32, task_id=77, client=complete_client, reports_dir=tmp_path)

    assert pending["status"] == "pending"
    assert pending["task_id"] == 77
    assert pending["retry_in"] == 30
    assert complete == {"status": True, "report_path": str(tmp_path / f"cape-{'d' * 32}.json"), "task_id": 77}
    assert json.loads((tmp_path / f"cape-{'d' * 32}.json").read_text()) == {"score": 6}


def test_cape_submission_returns_only_task_id(tmp_path):
    result = task_handlers.handle_cape("sample.exe", "e" * 32, client=CAPEClient(), reports_dir=tmp_path)
    assert result["status"] == "pending"
    assert result["task_id"] == 42
    assert result["retry_in"] == 60


def test_raw_cape_report_is_written_by_path_and_scored(tmp_path):
    class Client(CAPEClient):
        def get_report(self, task_id, md5):
            return {"status": "success", "data": {"malscore": 7.5}}

    report_path = tmp_path / "cape.json"
    result = task_handlers.handle_cape(
        "sample.exe",
        "f" * 32,
        task_id=77,
        client=Client(status={"data": "reported"}),
        report_path=report_path,
    )

    assert result == {"status": True, "task_id": 77, "report_path": str(report_path)}
    assert json.loads(report_path.read_text(encoding="utf-8")) == {"malscore": 7.5}
    assert task_handlers.calculate_cape_danger_score(report_path) == 75


class TaskSession:
    def __init__(self):
        self.commits = 0
        self.closed = False

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass

    def close(self):
        self.closed = True


def run_pipeline(monkeypatch, tmp_path, vt_report, mobsf_result=None, cape_result=None, **state):
    session = TaskSession()
    finalized = []
    retry_calls = []
    calls = []
    monkeypatch.setattr(tasks, "SyncSessionLocal", lambda: session)
    monkeypatch.setattr(tasks, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(tasks, "update_task_rows", lambda *args, **kwargs: 1)
    monkeypatch.setattr(tasks, "task_is_complete", lambda *args: False)
    def handle_virustotal(*args, **kwargs):
        path = kwargs["report_path"]
        with open(path, "w", encoding="utf-8") as file:
            json.dump(vt_report, file)
        return {"status": True, "report_path": str(path)}

    monkeypatch.setattr(tasks, "handle_virustotal", handle_virustotal)
    monkeypatch.setattr(tasks, "handle_mobsf", lambda *args, **kwargs: calls.append("mobsf") or mobsf_result)
    monkeypatch.setattr(tasks, "handle_cape", lambda *args, **kwargs: calls.append("cape") or cape_result)
    monkeypatch.setattr(tasks, "finalize_analysis_report", lambda *args, **kwargs: finalized.append((args, kwargs)) or (SimpleNamespace(), {"virustotal_score": 0, "mobsf_score": 20, "cape_score": 70}))
    monkeypatch.setattr(tasks, "build_gemini_evidence", lambda *args: {"evidence": True})
    monkeypatch.setattr(tasks, "GeminiAPI", lambda: SimpleNamespace(AnalysisGemini=lambda evidence: {
        "danger_score": 50,
        "risk_level": "Caution",
        "confidence": "medium",
        "verdict": "Review required",
        "summary": "Conflicting evidence",
        "recommendation": "Review before execution",
        "key_evidence": [],
        "tool_disagreements": [],
        "limitations": [],
    }))

    def retry(**kwargs):
        retry_calls.append(kwargs)
        raise Retry()

    monkeypatch.setattr(tasks.analyze_malware_task, "retry", retry)
    tasks.analyze_malware_task.push_request(id="task-1", retries=state.pop("retries", 0))
    try:
        try:
            result = tasks.analyze_malware_task.run("sample.bin", "md5", "sha256", 10, **state)
        except Retry:
            result = None
    finally:
        tasks.analyze_malware_task.pop_request()
    return result, calls, retry_calls, finalized


def test_clean_vt_dispatches_mobsf_and_cape_before_retry(monkeypatch, tmp_path):
    vt_path = tmp_path / "virustotal-md5.json"
    vt_path.write_text(json.dumps(pipeline_vt_report()), encoding="utf-8")
    session = TaskSession()
    calls = []
    retry_calls = []
    monkeypatch.setattr(tasks, "SyncSessionLocal", lambda: session)
    monkeypatch.setattr(tasks, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(tasks, "update_task_rows", lambda *args, **kwargs: 1)
    monkeypatch.setattr(tasks, "task_is_complete", lambda *args: False)
    monkeypatch.setattr(tasks, "calculate_threat_scoreVT", lambda *args: 0)
    monkeypatch.setattr(
        tasks,
        "handle_mobsf",
        lambda *args, **kwargs: calls.append("mobsf") or {
            "status": "pending",
            "report_path": str(tmp_path / "mobsf-md5.json"),
            "submitted": True,
            "retry_in": 30,
        },
    )
    monkeypatch.setattr(
        tasks,
        "handle_cape",
        lambda *args, **kwargs: calls.append("cape") or {
            "status": "pending",
            "report_path": str(tmp_path / "cape-md5.json"),
            "task_id": 42,
            "retry_in": 60,
        },
    )

    def retry(**kwargs):
        retry_calls.append(kwargs)
        raise Retry()

    monkeypatch.setattr(tasks.analyze_malware_task, "retry", retry)
    tasks.analyze_malware_task.push_request(id="task-1", retries=0)
    try:
        with pytest.raises(Retry):
            tasks.analyze_malware_task.run(
                "sample.bin",
                "md5",
                "sha256",
                10,
                vt_status=True,
                vt_report_path=str(vt_path),
            )
    finally:
        tasks.analyze_malware_task.pop_request()

    assert calls == ["mobsf", "cape"]
    assert retry_calls[0]["countdown"] == 30
    assert retry_calls[0]["kwargs"]["cape_task_id"] == 42
    assert all(not isinstance(value, dict) for value in retry_calls[0]["kwargs"].values())


def test_mobsf_unsupported_finalizes_with_cape_only(monkeypatch, tmp_path):
    vt_path = tmp_path / "virustotal-md5.json"
    cape_path = tmp_path / "cape-md5.json"
    vt_path.write_text(json.dumps(pipeline_vt_report()), encoding="utf-8")
    cape_path.write_text('{"malscore": 7}', encoding="utf-8")
    session = TaskSession()
    finalized = []
    monkeypatch.setattr(tasks, "SyncSessionLocal", lambda: session)
    monkeypatch.setattr(tasks, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(tasks, "update_task_rows", lambda *args, **kwargs: 1)
    monkeypatch.setattr(tasks, "task_is_complete", lambda *args: False)
    monkeypatch.setattr(tasks, "calculate_threat_scoreVT", lambda *args: 0)
    monkeypatch.setattr(
        tasks,
        "handle_mobsf",
        lambda *args, **kwargs: {
            "status": "skipped",
            "report_path": str(tmp_path / "mobsf-md5.json"),
            "error": "File format not Supported!",
        },
    )
    monkeypatch.setattr(
        tasks,
        "finalize_analysis_report",
        lambda *args, **kwargs: finalized.append(kwargs) or (
            SimpleNamespace(),
            {"virustotal_score": 0, "mobsf_score": None, "cape_score": 70},
        ),
    )
    monkeypatch.setattr(tasks, "build_gemini_evidence", lambda *args: {"evidence": True})
    monkeypatch.setattr(tasks, "GeminiAPI", lambda: SimpleNamespace(AnalysisGemini=lambda evidence: {
        "danger_score": 70,
        "risk_level": "High",
        "confidence": "medium",
        "verdict": "High risk",
        "summary": "CAPE evidence",
        "recommendation": "Isolate",
        "key_evidence": [],
        "tool_disagreements": [],
        "limitations": [],
    }))
    tasks.analyze_malware_task.push_request(id="task-1", retries=0)
    try:
        result = tasks.analyze_malware_task.run(
            "sample.exe",
            "md5",
            "sha256",
            10,
            vt_status=True,
            vt_report_path=str(vt_path),
            cape_status=True,
            cape_report_path=str(cape_path),
            cape_task_id=42,
        )
    finally:
        tasks.analyze_malware_task.pop_request()

    assert result["success"] is True
    assert result["mobsf_status"] == "skipped"
    assert result["mobsf_score"] is None
    assert finalized[0]["mobsf_report_path"] is None
    assert finalized[0]["tools"] == "virustotal,cape,gemini"


def pipeline_vt_report(malicious=0):
    return {
        "scan_summary": {"malicious_count": malicious, "total_scanners": 20},
        "threats_found": {"malicious": ["Engine: Trojan"] if malicious else []},
        "security_analysis": {"sigma_rules": {}},
    }


def test_malicious_vt_never_calls_sandboxes(monkeypatch, tmp_path):
    result, calls, retry_calls, finalized = run_pipeline(
        monkeypatch, tmp_path, pipeline_vt_report(1)
    )

    assert result["success"] is True
    assert calls == []
    assert retry_calls == []
    assert finalized[0][1]["tools"] == "virustotal"


def test_malformed_sandbox_scores_are_null():
    assert task_handlers.calculate_mobsf_danger_score({"security_score": "invalid"}) is None
    assert task_handlers.calculate_cape_danger_score({"score": "invalid"}) is None
    assert task_handlers.calculate_mobsf_danger_score({"security_score": "NaN"}) is None
    assert tasks.read_sandbox_score(None, task_handlers.calculate_cape_danger_score) is None


def test_non_object_sandbox_report_is_null(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("[]", encoding="utf-8")
    assert tasks.read_sandbox_score(str(path), task_handlers.calculate_cape_danger_score) is None


def test_duplicate_original_delivery_does_not_repeat_external_tools(monkeypatch):
    session = TaskSession()
    monkeypatch.setattr(tasks, "SyncSessionLocal", lambda: session)
    monkeypatch.setattr(tasks, "update_task_rows", lambda *args, **kwargs: 0)
    monkeypatch.setattr(tasks, "task_is_complete", lambda *args: False)
    monkeypatch.setattr(tasks, "handle_virustotal", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not repeat")))
    tasks.analyze_malware_task.push_request(id="task-1", retries=0)
    try:
        result = tasks.analyze_malware_task.run("sample.bin", "md5", "sha256", 10)
    finally:
        tasks.analyze_malware_task.pop_request()

    assert result == {"success": True, "task_id": "task-1", "state": "already_started"}


def test_stale_retry_after_success_does_not_repeat_external_tools(monkeypatch, tmp_path):
    session = TaskSession()
    vt_path = tmp_path / "virustotal-md5.json"
    vt_path.write_text(json.dumps(pipeline_vt_report()), encoding="utf-8")
    monkeypatch.setattr(tasks, "SyncSessionLocal", lambda: session)
    monkeypatch.setattr(tasks, "update_task_rows", lambda *args, **kwargs: 0)
    monkeypatch.setattr(tasks, "task_is_complete", lambda *args: True)
    monkeypatch.setattr(tasks, "handle_mobsf", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not repeat")))
    tasks.analyze_malware_task.push_request(id="task-1", retries=2)
    try:
        result = tasks.analyze_malware_task.run(
            "sample.bin", "md5", "sha256", 10, vt_report_path=str(vt_path), mobsf_submitted=True
        )
    finally:
        tasks.analyze_malware_task.pop_request()

    assert result == {"success": True, "task_id": "task-1", "state": "already_started"}
