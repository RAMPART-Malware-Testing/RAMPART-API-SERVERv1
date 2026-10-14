"""Integration tests for the file-upload endpoint (POST /api/analy/v1/upload).

These tests run against a *running* API server (default http://localhost:8006).
They mint a short-lived access token with the repo's own token helper for an
existing active user, so no credentials are stored here, then exchange it for an
upload token exactly like the web app does.

Run from the repo root:

    venv/bin/python -m pytest tests/test_upload_flow.py -v

The successful-upload test enqueues a real analysis task for a tiny generated
text file: this stack is a demo environment with a single database, so there is
no separate test database to point at.

Set RAMPART_E2E=1 to additionally run the full-pipeline test that polls a
task until the analysis reaches a terminal state (slow: minutes).
"""

import hashlib
import os
import sys
import time
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv

load_dotenv(REPO_ROOT / ".env")

BASE_URL = os.getenv("RAMPART_API_BASE_URL", "http://localhost:8006").rstrip("/")
TEST_FILE_NAME = "rampart_upload_smoke.txt"
TEST_FILE_CONTENT = b"RAMPART upload smoke test\n" * 16


def _server_is_up() -> bool:
    try:
        return requests.get(f"{BASE_URL}/", timeout=5).status_code == 200
    except requests.RequestException:
        return False


@pytest.fixture(scope="module")
def active_user_uid() -> str:
    if not _server_is_up():
        pytest.skip(f"API server is not running at {BASE_URL}")

    from sqlalchemy import func, select

    from cores.Schema.schema_class import User
    from cores.sync_pg_db import SyncSessionLocal

    with SyncSessionLocal() as session:
        uid = session.execute(
            select(User.uid)
            .where(func.lower(User.status) == "active", User.is_banned.is_(False))
            .limit(1)
        ).scalar_one_or_none()

    if uid is None:
        pytest.skip("no active user in the database to mint a test token for")
    return str(uid)


@pytest.fixture(scope="module")
def access_token(active_user_uid: str) -> str:
    from utils.jwt import create_token

    return create_token(
        subject=active_user_uid,
        token_type="access",
        expires_minutes=15,
    )


@pytest.fixture(scope="module")
def upload_token(access_token: str) -> str:
    response = requests.post(
        f"{BASE_URL}/api/analy/v1/generate-token",
        json={"token": access_token},
        timeout=30,
    )
    assert response.status_code == 200, f"generate-token failed: {response.status_code} {response.text[:300]}"
    token = (response.json().get("data") or {}).get("upload_token")
    assert token, f"generate-token response has no upload_token: {response.text[:300]}"
    return token


def test_upload_accepts_valid_file_and_returns_task_id(upload_token: str):
    response = requests.post(
        f"{BASE_URL}/api/analy/v1/upload",
        params={"token": upload_token},
        data={"privacy": "true"},
        files={"file": (TEST_FILE_NAME, TEST_FILE_CONTENT)},
        timeout=120,
    )

    assert response.status_code == 200, (
        f"upload must succeed, got {response.status_code}: {response.text[:300]}"
    )
    body = response.json()
    assert body["success"] is True
    assert body["task_id"], "a task_id must be returned so the UI can poll the analysis"
    assert body["filename"] == TEST_FILE_NAME
    assert body["sha256"] == hashlib.sha256(TEST_FILE_CONTENT).hexdigest()


def test_upload_rejects_invalid_token():
    response = requests.post(
        f"{BASE_URL}/api/analy/v1/upload",
        params={"token": "not-a-real-upload-token"},
        data={"privacy": "true"},
        files={"file": (TEST_FILE_NAME, TEST_FILE_CONTENT)},
        timeout=60,
    )

    assert response.status_code == 401


def test_upload_rejects_empty_file(upload_token: str):
    response = requests.post(
        f"{BASE_URL}/api/analy/v1/upload",
        params={"token": upload_token},
        data={"privacy": "true"},
        files={"file": (TEST_FILE_NAME, b"")},
        timeout=60,
    )

    assert response.status_code == 400


@pytest.mark.skipif(
    os.getenv("RAMPART_E2E") != "1",
    reason="set RAMPART_E2E=1 to poll a real analysis through the worker pipeline",
)
def test_uploaded_file_analysis_reaches_terminal_state(access_token: str, upload_token: str):
    # RAMPART_E2E_FILE lets a real sample (e.g. the demo corpus) be pushed through
    # the pipeline; without it a tiny generated text file is used.
    e2e_file = os.getenv("RAMPART_E2E_FILE")
    if e2e_file:
        path = Path(e2e_file)
        assert path.is_file(), f"RAMPART_E2E_FILE does not exist: {path}"
        content = path.read_bytes()
        file_name = path.name
    else:
        content = TEST_FILE_CONTENT + f"run={time.time()}\n".encode()
        file_name = TEST_FILE_NAME

    response = requests.post(
        f"{BASE_URL}/api/analy/v1/upload",
        params={"token": upload_token},
        data={"privacy": "true"},
        files={"file": (file_name, content)},
        timeout=600,
    )
    assert response.status_code == 200, f"upload failed: {response.status_code} {response.text[:300]}"
    task_id = response.json()["task_id"]
    print(f"\n[e2e] uploaded {file_name} -> task_id={task_id}")

    deadline = time.monotonic() + float(os.getenv("RAMPART_E2E_TIMEOUT", "900"))
    status = "unknown"
    body: dict = {}
    while time.monotonic() < deadline:
        poll = requests.post(
            f"{BASE_URL}/api/analy/v1/task_id",
            json={"token": access_token, "task_id": task_id},
            timeout=30,
        )
        assert poll.status_code == 200, f"task_id poll failed: {poll.status_code} {poll.text[:300]}"
        body = poll.json()
        status = body.get("status", "unknown")
        if status in ("success", "failed"):
            break
        time.sleep(5)

    assert status == "success", (
        f"analysis for task {task_id} ended as '{status}': "
        f"tool_notes={body.get('report', {}).get('tool_notes') or body.get('tool_notes')}"
    )
