import json
from types import SimpleNamespace

import pytest
from celery.exceptions import Retry

from bgProcessing import task_handlers, tasks


class MobSFClient:
    def __init__(self, report=None, upload=None, scan=None):
        self.report = report or {"success": False, "error": "Report not ready"}
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
    client = MobSFClient(report={"success": True, "data": {"security_score": 80}})

    result = task_handlers.handle_mobsf("sample.apk", "a" * 32, client=client, reports_dir=tmp_path)

    assert result == {"state": "complete", "report_path": str(tmp_path / f"mobsf-{'a' * 32}.json")}
    assert json.loads((tmp_path / f"mobsf-{'a' * 32}.json").read_text()) == {"security_score": 80}


def test_mobsf_submits_once_then_retries_with_scalar_state(tmp_path):
    client = MobSFClient()

    first = task_handlers.handle_mobsf("sample.apk", "b" * 32, client=client, reports_dir=tmp_path)
    second = task_handlers.handle_mobsf("sample.apk", "b" * 32, submitted=True, client=client, reports_dir=tmp_path)

    assert first == {"state": "pending", "submitted": True, "retry_in": 30}
    assert second == {"state": "pending", "submitted": True, "retry_in": 30}
    assert client.upload_calls == 1


def test_mobsf_unsupported_is_skipped(tmp_path):
    client = MobSFClient(upload={"success": False, "error": "File format not supported"})
    result = task_handlers.handle_mobsf("sample.txt", "c" * 32, client=client, reports_dir=tmp_path)
    assert result["state"] == "skipped"


def test_cape_existing_task_polls_then_writes_report(tmp_path):
    pending_client = CAPEClient(existing=[{"id": 77}], status={"data": "running"})
    pending = task_handlers.handle_cape("sample.exe", "d" * 32, client=pending_client, reports_dir=tmp_path)
    complete_client = CAPEClient(status={"data": "reported"}, report={"status": "success", "data": {"score": 6}})
    complete = task_handlers.handle_cape("sample.exe", "d" * 32, task_id=77, client=complete_client, reports_dir=tmp_path)

    assert pending == {"state": "pending", "task_id": 77, "retry_in": 30}
    assert complete == {"state": "complete", "report_path": str(tmp_path / f"cape-{'d' * 32}.json"), "task_id": 77}
    assert json.loads((tmp_path / f"cape-{'d' * 32}.json").read_text()) == {"score": 6}


def test_cape_submission_returns_only_task_id(tmp_path):
    result = task_handlers.handle_cape("sample.exe", "e" * 32, client=CAPEClient(), reports_dir=tmp_path)
    assert result == {"state": "pending", "task_id": 42, "retry_in": 60}


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
    monkeypatch.setattr(tasks, "handle_virustotal", lambda *args, **kwargs: {"state": "complete", "report": vt_report})
    monkeypatch.setattr(tasks, "handle_mobsf", lambda *args, **kwargs: calls.append("mobsf") or mobsf_result)
    monkeypatch.setattr(tasks, "handle_cape", lambda *args, **kwargs: calls.append("cape") or cape_result)
    monkeypatch.setattr(tasks, "finalize_analysis_report", lambda *args, **kwargs: finalized.append((args, kwargs)) or (SimpleNamespace(), {"virustotal_score": 0, "mobsf_score": 20, "cape_score": 70}))

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


def pipeline_vt_report(malicious=0):
    return {
        "scan_summary": {"malicious_count": malicious, "total_scanners": 20},
        "threats_found": {"malicious": []},
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


def test_clean_vt_finalizes_without_calling_sandboxes(monkeypatch, tmp_path):
    result, calls, retry_calls, finalized = run_pipeline(
        monkeypatch,
        tmp_path,
        pipeline_vt_report(),
    )

    assert result["success"] is True
    assert calls == []
    assert retry_calls == []
    assert finalized[0][1] == {"tools": "virustotal"}


def test_existing_vt_report_path_finalizes_without_sandboxes(monkeypatch, tmp_path):
    vt_path = tmp_path / "virustotal-md5.json"
    vt_path.write_text(json.dumps(pipeline_vt_report()), encoding="utf-8")
    result, calls, retry_calls, finalized = run_pipeline(
        monkeypatch,
        tmp_path,
        pipeline_vt_report(),
        vt_report_path=str(vt_path),
    )

    assert result["success"] is True
    assert calls == []
    assert retry_calls == []
    assert finalized[0][0][3] == str(vt_path)
    assert finalized[0][1] == {"tools": "virustotal"}


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
