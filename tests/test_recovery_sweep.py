"""Unit tests for the orphaned-task sweep in bgProcessing/recovery.py.

The sweep re-dispatches tasks whose DB row says processing/analyzing while the
Celery state looks dead. Two failure modes are covered here:

* A task parked on a countdown retry (state RETRY) is alive - it is sitting in
  the broker with an ETA - so re-dispatching it double-runs every tool and
  drops the per-task kwargs (e.g. the VirusTotal config flag).
* A re-dispatched task must keep the current VirusTotal hash-check setting so a
  recovery does not silently send data to VirusTotal while it is disabled.

Run from the repo root:

    venv/bin/python -m pytest tests/test_recovery_sweep.py -v
"""

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv

load_dotenv(REPO_ROOT / ".env")

from bgProcessing import recovery


def _fake_result(state: str, info=None) -> SimpleNamespace:
    return SimpleNamespace(state=state, info=info)


def test_retry_waiting_task_is_treated_as_alive(monkeypatch):
    monkeypatch.setattr(recovery, "AsyncResult", lambda **_: _fake_result("RETRY"))

    assert recovery._task_owner_alive("task-retry") is True


def test_started_task_with_live_pid_is_alive(monkeypatch):
    monkeypatch.setattr(
        recovery, "AsyncResult", lambda **_: _fake_result("STARTED", {"pid": os.getpid()})
    )

    assert recovery._task_owner_alive("task-running") is True


def test_started_task_with_dead_pid_is_orphaned(monkeypatch):
    monkeypatch.setattr(
        recovery, "AsyncResult", lambda **_: _fake_result("STARTED", {"pid": 2**31 - 1})
    )

    assert recovery._task_owner_alive("task-dead") is False


def test_started_task_without_pid_metadata_is_alive(monkeypatch):
    monkeypatch.setattr(
        recovery, "AsyncResult", lambda **_: _fake_result("STARTED", "no-meta")
    )

    assert recovery._task_owner_alive("task-nometa") is True


def test_pending_task_is_orphaned(monkeypatch):
    monkeypatch.setattr(recovery, "AsyncResult", lambda **_: _fake_result("PENDING"))

    assert recovery._task_owner_alive("task-pending") is False


def test_sweep_requeues_orphan_with_current_vt_hash_check_flag(monkeypatch, tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"RAMPART recovery sweep test")
    row = SimpleNamespace(
        task_id="task-orphan",
        file_path=str(source),
        md5="d41d8cd98f00b204e9800998ecf8427e",
        file_hash="e3b0c44298fc1c149afbf4c8996fb924",
        file_size=source.stat().st_size,
    )

    fake_db = MagicMock()
    fake_db.execute.return_value.scalars.return_value.all.return_value = [row]

    captured = {}
    monkeypatch.setattr(recovery, "SyncSessionLocal", lambda: fake_db)
    monkeypatch.setattr(recovery, "_task_owner_alive", lambda _task_id: False)
    monkeypatch.setattr(recovery, "_recovery_attempts", lambda _task_id: 1)
    monkeypatch.setattr(recovery, "update_task_rows", lambda *args, **kwargs: 1)
    monkeypatch.setattr(recovery, "publish_progress", lambda *args, **kwargs: None)
    monkeypatch.setattr(recovery, "vt_hash_check_enabled_from_config", lambda: False)
    monkeypatch.setattr(
        recovery.analyze_malware_task, "apply_async", lambda **kwargs: captured.update(kwargs)
    )

    counts = recovery.sweep_orphaned_tasks()

    assert counts["requeued"] == 1
    assert captured["task_id"] == "task-orphan"
    assert captured["args"] == (str(source), row.md5, row.file_hash, row.file_size)
    assert captured["kwargs"] == {"enable_vt_hash_check": False}
