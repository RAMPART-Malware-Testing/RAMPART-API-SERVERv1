import os
import platform
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent
WATCH_EXTENSIONS = {".py"}
IGNORED_DIR_NAMES = {
    ".venv", "__pycache__", ".git", "node_modules",
    "reports", "results", "temps_files", "avatars", "Files",
}
DEBOUNCE_SECONDS = 1.5

def _is_watchable(path: str) -> bool:
    p = Path(path)
    if p.suffix.lower() not in WATCH_EXTENSIONS:
        return False
    return not any(part in IGNORED_DIR_NAMES for part in p.parts)

class _RestartOnChangeHandler(FileSystemEventHandler):
    def __init__(self, on_change):
        super().__init__()
        self._on_change = on_change
        self._last_triggered = 0.0

    def _maybe_trigger(self, path: str):
        if not _is_watchable(path):
            return
        now = time.monotonic()
        if now - self._last_triggered < DEBOUNCE_SECONDS:
            return
        self._last_triggered = now
        self._on_change(path)

    def on_modified(self, event):
        if not event.is_directory:
            self._maybe_trigger(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._maybe_trigger(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._maybe_trigger(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._maybe_trigger(event.dest_path)

def _pool_type() -> str:
    return "solo" if platform.system() == "Windows" else "prefork"

def _build_worker_command() -> list[str]:
    return [
        sys.executable,
        "-m", "celery",
        "-A", "bgProcessing.celery_app",
        "worker",
        "--loglevel=info",
        f"--pool={_pool_type()}",
    ]

def _spawn_worker() -> subprocess.Popen:
    print(f"\n[RAMPART-AI] Starting Celery worker: {' '.join(_build_worker_command())}\n")
    return subprocess.Popen(_build_worker_command(), cwd=str(PROJECT_ROOT))

def _terminate_worker(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    print("[RAMPART-AI] Restarting worker: stopping current process...")
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        print("[RAMPART-AI] Worker did not exit in time, killing...")
        proc.kill()
        proc.wait()

def main() -> None:
    print("\n[RAMPART-AI] Celery Worker Starter (auto-reload)")
    print("=" * 30)
    print(f"Redis Host: {os.getenv('REDIS_HOST', '127.0.0.1')}")
    print(f"OS Platform: {platform.system()}")
    print(f"Pool: {_pool_type()}")
    print("Watching *.py files for changes - the worker restarts automatically on save.\n")

    state = {"proc": _spawn_worker(), "crashed_logged": False}

    def restart(path: str) -> None:
        print(f"[RAMPART-AI] Change detected: {path}")
        _terminate_worker(state["proc"])
        state["proc"] = _spawn_worker()
        state["crashed_logged"] = False

    observer = Observer()
    observer.schedule(_RestartOnChangeHandler(restart), str(PROJECT_ROOT), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
            proc = state["proc"]
            if proc.poll() is not None and not state["crashed_logged"]:
                print(f"[RAMPART-AI] Worker exited (code {proc.returncode}). Waiting for a code change to restart...")
                state["crashed_logged"] = True
    except KeyboardInterrupt:
        print("\n[RAMPART-AI] Shutting down...")
    finally:
        observer.stop()
        observer.join()
        _terminate_worker(state["proc"])

if __name__ == "__main__":
    main()
