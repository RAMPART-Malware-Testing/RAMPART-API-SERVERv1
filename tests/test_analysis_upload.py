import hashlib
import importlib
import io
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.testclient import TestClient


class FakeRedis:
    def __init__(self, values=None, fail=False):
        self.values = values or {}
        self.fail = fail

    def get(self, key):
        if self.fail:
            raise RuntimeError("redis unavailable")
        return self.values.get(key)


class FakeSession:
    def __init__(self, user=None, events=None):
        self.user = user
        self.events = events
        self.commits = 0
        self.rollbacks = 0
        self.added = []

    async def get(self, model, uid):
        return self.user

    def add(self, value):
        self.added.append(value)

    async def commit(self):
        self.commits += 1
        if self.events is not None:
            self.events.append("commit")

    async def rollback(self):
        self.rollbacks += 1

    async def refresh(self, value):
        return None


class SessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class FakeTask:
    def __init__(self, error=None, events=None):
        self.error = error
        self.calls = []
        self.events = events

    def apply_async(self, args=None, kwargs=None, task_id=None):
        if self.events is not None:
            self.events.append("dispatch")
        self.status_at_dispatch = self.persisted.status
        self.commits_at_dispatch = self.session.commits
        self.calls.append({"args": args, "kwargs": kwargs, "task_id": task_id})
        if self.error:
            raise self.error
        return SimpleNamespace(id=task_id)


@pytest.fixture
def upload_modules(monkeypatch):
    monkeypatch.setattr("redis.Redis", lambda **kwargs: SimpleNamespace(ping=lambda: True))
    router = importlib.import_module("routers.analysis")
    controller = importlib.import_module("controller.Analysis.ScanFile_controller")
    auth = importlib.import_module("controller.analysis_controller")
    return router, controller, auth


def test_upload_route_uses_validated_uuid_subject(monkeypatch, upload_modules):
    router, _, _ = upload_modules
    captured = {}

    async def require(token):
        assert token == "upload-token"
        return "baeb1c2b-3190-431a-a769-69e06e6264d9"

    async def scan(file, uid, privacy):
        captured.update(uid=uid, privacy=privacy)
        return {"task_id": "task-id"}

    monkeypatch.setattr(router, "require_upload_token", require)
    monkeypatch.setattr(router, "scan_file_controller", scan)
    app = FastAPI()
    app.include_router(router.router)

    response = TestClient(app).post(
        "/api/analy/v1/upload",
        params={"token": "upload-token"},
        files={"file": ("sample.bin", b"content")},
        data={"privacy": "true"},
    )

    assert response.status_code == 200
    assert captured == {"uid": "baeb1c2b-3190-431a-a769-69e06e6264d9", "privacy": True}


@pytest.mark.asyncio
async def test_require_upload_token_rejects_invalid_token(monkeypatch, upload_modules):
    _, _, auth = upload_modules
    monkeypatch.setattr(auth.TokenService, "verify_token", lambda token, kind: (None, {"error": True}))

    with pytest.raises(HTTPException) as raised:
        await auth.require_upload_token("invalid")

    assert raised.value.status_code == 401


@pytest.mark.asyncio
async def test_require_upload_token_validates_redis_session_and_returns_string(monkeypatch, upload_modules):
    _, _, auth = upload_modules
    uid = "baeb1c2b-3190-431a-a769-69e06e6264d9"
    monkeypatch.setattr(auth.TokenService, "verify_token", lambda token, kind: ({"sub": uid}, None))
    monkeypatch.setattr(auth, "redis_client", FakeRedis({f"upload_session:{uid}": "upload-token"}))

    assert await auth.require_upload_token("upload-token") == uid

    monkeypatch.setattr(auth, "redis_client", FakeRedis({f"upload_session:{uid}": "other-token"}))
    with pytest.raises(HTTPException) as raised:
        await auth.require_upload_token("upload-token")
    assert raised.value.status_code == 401


def active_user(status="active", is_banned=False):
    return SimpleNamespace(status=status, is_banned=is_banned)


async def run_upload(monkeypatch, controller, tmp_path, content=b"payload", filename="sample.bin", user=None, existing=None, refreshed=None, task=None, events=None, gap_fill=("none", None)):
    session = FakeSession(user if user is not None else active_user(), events)
    if task:
        task.session = session
    inserted = []

    async def find_existing(db, sha256):
        if events is not None:
            events.append("lookup")
        return existing

    async def find_task(db, task_id):
        if events is not None:
            events.append("refresh")
        return existing if refreshed is None else refreshed

    async def insert(session, **values):
        if events is not None:
            events.append("insert")
        record = SimpleNamespace(**values)
        inserted.append(record)
        if task:
            task.persisted = record
        await session.commit()
        return record

    async def lock(session, sha256):
        if events is not None:
            events.append("lock")

    async def task_lock(session, task_id):
        if events is not None:
            events.append("task-lock")

    async def update_task_rows(session, task_id, **values):
        if events is not None:
            events.append(f"update:{values['status']}")
        matching = [record for record in inserted if record.task_id == task_id]
        for record in matching:
            for key, value in values.items():
                setattr(record, key, value)
        return len(matching)

    async def gap_fill_redispatch(db, **kwargs):
        if events is not None:
            events.append("gap-fill-check")
        return gap_fill

    monkeypatch.setattr(controller, "UPLOAD_DIR", tmp_path)
    monkeypatch.setattr(controller, "SessionLocal", lambda: SessionContext(session))
    monkeypatch.setattr(controller, "attempt_gap_fill_redispatch", gap_fill_redispatch, raising=False)
    monkeypatch.setattr(controller, "get_file_by_hash", find_existing)
    monkeypatch.setattr(controller, "get_file_by_task_id", find_task, raising=False)
    monkeypatch.setattr(controller, "insert_table_analy", insert)
    monkeypatch.setattr(controller, "acquire_analysis_hash_lock", lock, raising=False)
    monkeypatch.setattr(controller, "acquire_analysis_task_lock", task_lock, raising=False)
    monkeypatch.setattr(controller, "update_analysis_rows_by_task_id", update_task_rows, raising=False)
    monkeypatch.setattr(controller, "analyze_malware_task", task or FakeTask())
    upload = UploadFile(filename=filename, file=io.BytesIO(content))
    response = await controller.scan_file_controller(upload, "baeb1c2b-3190-431a-a769-69e06e6264d9", True)
    return response, session, inserted, controller.analyze_malware_task


@pytest.mark.asyncio
async def test_upload_locks_hash_before_lookup_insert_and_dispatch(monkeypatch, upload_modules, tmp_path):
    _, controller, _ = upload_modules
    events = []

    await run_upload(
        monkeypatch,
        controller,
        tmp_path,
        task=FakeTask(events=events),
        events=events,
    )

    assert events == [
        "gap-fill-check",
        "lock",
        "lookup",
        "insert",
        "commit",
        "dispatch",
        "lock",
        "update:queued",
        "commit",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(("user", "status_code"), [(None, 401), (active_user(is_banned=True), 403)])
async def test_upload_requires_existing_active_user(monkeypatch, upload_modules, tmp_path, user, status_code):
    _, controller, _ = upload_modules
    session = FakeSession(user)
    monkeypatch.setattr(controller, "UPLOAD_DIR", tmp_path)
    monkeypatch.setattr(controller, "SessionLocal", lambda: SessionContext(session))

    with pytest.raises(HTTPException) as raised:
        await controller.scan_file_controller(
            UploadFile(filename="sample.bin", file=io.BytesIO(b"payload")), "00000000-0000-4000-8000-000000000001", True
        )

    assert raised.value.status_code == status_code
    assert not list(tmp_path.iterdir())


@pytest.mark.asyncio
async def test_upload_rejects_empty_file_and_cleans_temp_file(monkeypatch, upload_modules, tmp_path):
    _, controller, _ = upload_modules

    with pytest.raises(HTTPException) as raised:
        await run_upload(monkeypatch, controller, tmp_path, content=b"")

    assert raised.value.status_code == 400
    assert not list(tmp_path.iterdir())


@pytest.mark.asyncio
async def test_upload_rejects_over_limit_and_cleans_temp_file(monkeypatch, upload_modules, tmp_path):
    _, controller, _ = upload_modules
    monkeypatch.setattr(controller, "MAX_FILE_SIZE", 4)

    with pytest.raises(HTTPException) as raised:
        await run_upload(monkeypatch, controller, tmp_path, content=b"12345")

    assert raised.value.status_code == 413
    assert not list(tmp_path.iterdir())


@pytest.mark.asyncio
async def test_upload_persists_task_id_before_explicit_dispatch_and_sanitizes_path(monkeypatch, upload_modules, tmp_path):
    _, controller, _ = upload_modules
    content = b"safe payload"
    response, session, inserted, task = await run_upload(
        monkeypatch, controller, tmp_path, content=content, filename="../../unsafe.EXE", task=FakeTask()
    )

    sha256 = hashlib.sha256(content).hexdigest()
    assert response == {
        "success": True,
        "task_id": inserted[0].task_id,
        "status": "queued",
        "md5": hashlib.md5(content).hexdigest(),
        "sha256": sha256,
        "filename": "unsafe.EXE",
        "deduplicated": False,
        "queue_state": "dispatched",
    }
    assert session.commits == 2
    assert task.status_at_dispatch == "dispatching"
    assert task.commits_at_dispatch == 1
    assert inserted[0].status == "queued"
    assert task.calls == [{
        "args": (str(tmp_path / f"{sha256}.exe"), hashlib.md5(content).hexdigest(), sha256, len(content)),
        "kwargs": None,
        "task_id": inserted[0].task_id,
    }]
    assert (tmp_path / f"{sha256}.exe").read_bytes() == content


@pytest.mark.asyncio
@pytest.mark.parametrize("existing_status", ["queued", "processing", "success"])
async def test_upload_attaches_to_reusable_job_without_dispatch(monkeypatch, upload_modules, tmp_path, existing_status):
    _, controller, _ = upload_modules
    existing = {
        "rid": "report-id" if existing_status == "success" else None,
        "status": existing_status,
        "file_path": str(tmp_path / "stored.bin"),
        "file_type": "bin",
        "file_size": 7,
        "file_hash": "hash",
        "tools": "virustotal",
        "md5": "md5",
        "task_id": "existing-task",
    }
    task = FakeTask()

    response, _, inserted, _ = await run_upload(
        monkeypatch, controller, tmp_path, existing=existing, task=task
    )

    assert response["task_id"] == "existing-task"
    assert response["status"] == existing_status
    assert response["deduplicated"] is True
    assert response["queue_state"] == "reused"
    assert inserted[0].task_id == "existing-task"
    assert inserted[0].status == existing_status
    assert not task.calls
    assert not any(path.name.startswith("upload_") for path in tmp_path.iterdir())


@pytest.mark.asyncio
async def test_reusable_attachment_lock_order_is_hash_then_task_then_refresh_then_insert(monkeypatch, upload_modules, tmp_path):
    _, controller, _ = upload_modules
    events = []
    existing = {
        "rid": None,
        "status": "processing",
        "file_path": str(tmp_path / "stored.bin"),
        "file_type": "bin",
        "file_size": 7,
        "file_hash": "hash",
        "tools": "virustotal",
        "md5": "md5",
        "task_id": "existing-task",
    }

    await run_upload(monkeypatch, controller, tmp_path, existing=existing, events=events)

    assert events[:7] == ["gap-fill-check", "lock", "lookup", "task-lock", "refresh", "insert", "commit"]


@pytest.mark.asyncio
async def test_attachment_uses_success_state_refreshed_after_task_lock(monkeypatch, upload_modules, tmp_path):
    _, controller, _ = upload_modules
    existing = {
        "rid": None,
        "status": "processing",
        "file_path": str(tmp_path / "stored.bin"),
        "file_type": "bin",
        "file_size": 7,
        "file_hash": "hash",
        "tools": "virustotal",
        "md5": "md5",
        "task_id": "existing-task",
    }
    refreshed = {**existing, "status": "success", "rid": "report-id"}

    response, _, inserted, task = await run_upload(
        monkeypatch, controller, tmp_path, existing=existing, refreshed=refreshed
    )

    assert response["status"] == "success"
    assert inserted[0].status == "success"
    assert inserted[0].rid == "report-id"
    assert not task.calls


@pytest.mark.asyncio
async def test_attachment_does_not_reuse_task_refreshed_as_failed(monkeypatch, upload_modules, tmp_path):
    _, controller, _ = upload_modules
    existing = {
        "rid": None,
        "status": "processing",
        "file_path": str(tmp_path / "stored.bin"),
        "file_type": "bin",
        "file_size": 7,
        "file_hash": "hash",
        "tools": "virustotal",
        "md5": "md5",
        "task_id": "existing-task",
    }
    refreshed = {**existing, "status": "failed"}
    task = FakeTask()

    response, _, inserted, task = await run_upload(
        monkeypatch,
        controller,
        tmp_path,
        existing=existing,
        refreshed=refreshed,
        task=task,
    )

    assert response["deduplicated"] is False
    assert response["status"] == "queued"
    assert inserted[0].task_id != "existing-task"
    assert task.calls[0]["task_id"] == inserted[0].task_id


@pytest.mark.asyncio
async def test_concurrent_dispatching_upload_returns_retry_without_attachment_or_dispatch(monkeypatch, upload_modules, tmp_path):
    _, controller, _ = upload_modules
    shared_file = tmp_path / "shared.bin"
    shared_file.write_bytes(b"shared")
    existing = {
        "rid": None,
        "status": "dispatching",
        "file_path": str(shared_file),
        "file_type": "bin",
        "file_size": 7,
        "file_hash": "hash",
        "tools": None,
        "md5": "md5",
        "task_id": "dispatching-task",
    }
    task = FakeTask()

    with pytest.raises(HTTPException) as raised:
        await run_upload(monkeypatch, controller, tmp_path, existing=existing, task=task)

    assert raised.value.status_code == 409
    assert raised.value.detail == "Analysis dispatch is in progress. Retry shortly."
    assert not task.calls
    assert not hasattr(task, "persisted")
    assert shared_file.read_bytes() == b"shared"
    assert not any(path.name.startswith("upload_") for path in tmp_path.iterdir())


@pytest.mark.asyncio
async def test_broker_failure_marks_persisted_analysis_failed_and_returns_503(monkeypatch, upload_modules, tmp_path):
    _, controller, _ = upload_modules
    events = []
    task = FakeTask(RuntimeError("broker unavailable"), events)

    with pytest.raises(HTTPException) as raised:
        await run_upload(monkeypatch, controller, tmp_path, task=task, events=events)

    assert raised.value.status_code == 503
    assert raised.value.detail == "Analysis queue is unavailable."
    assert task.calls[0]["task_id"]
    assert task.persisted.status == "failed"
    assert task.session.commits == 2
    assert task.status_at_dispatch == "dispatching"
    assert events == [
        "gap-fill-check",
        "lock",
        "lookup",
        "insert",
        "commit",
        "dispatch",
        "lock",
        "update:failed",
        "commit",
    ]
    assert not any(path.name.startswith("upload_") for path in tmp_path.iterdir())


@pytest.mark.asyncio
async def test_require_upload_token_returns_503_when_redis_is_unavailable(monkeypatch, upload_modules):
    _, _, auth = upload_modules
    uid = "baeb1c2b-3190-431a-a769-69e06e6264d9"
    monkeypatch.setattr(auth.TokenService, "verify_token", lambda token, kind: ({"sub": uid}, None))
    monkeypatch.setattr(auth, "redis_client", FakeRedis(fail=True))

    with pytest.raises(HTTPException) as raised:
        await auth.require_upload_token("upload-token")

    assert raised.value.status_code == 503
    assert raised.value.detail == "Upload session service is unavailable."


def test_redis_configuration_uses_redis_host(monkeypatch):
    captured = {}

    class RedisClient:
        def ping(self):
            return True

    def create(**kwargs):
        captured.update(kwargs)
        return RedisClient()

    monkeypatch.setenv("REDIS_HOST", "redis.internal")
    monkeypatch.setenv("HOST_MAIN", "wrong.internal")
    monkeypatch.setattr("redis.Redis", create)
    import cores.redis

    importlib.reload(cores.redis)

    assert captured["host"] == "redis.internal"
