import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import requests

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
TERMINAL = {"success", "failed"}


def call(base, method, path, *, token=None, timeout=120, **kwargs):
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.request(method, f"{base}{path}", headers=headers, timeout=timeout, **kwargs)
    try:
        body = response.json()
    except ValueError:
        body = {"_raw": response.text[:500]}
    return response.status_code, body


def bootstrap(base):
    status = call(base, "GET", "/test/api/status")
    print(f"[bootstrap] /test/api/status -> {status[0]} {status[1]}")
    if status[0] != 200:
        raise SystemExit("test mode is not enabled on this server")
    created = call(base, "POST", "/test/api/user")
    print(f"[bootstrap] /test/api/user   -> {created[0]} {created[1].get('state')}")
    tokens = call(base, "POST", "/test/api/token")
    if tokens[0] != 200:
        raise SystemExit(f"token issue failed: {tokens}")
    print(f"[bootstrap] /test/api/token  -> 200 uid={json.loads(json.dumps(tokens[1]))}")
    return tokens[1]["access_token"], tokens[1]["upload_token"]


def upload(base, upload_token, name, content, privacy="true"):
    status, body = call(
        base,
        "POST",
        "/api/analy/v1/upload",
        params={"token": upload_token},
        files={"file": (name, content, "application/octet-stream")},
        data={"privacy": privacy},
        timeout=600,
    )
    return status, body


def wait_terminal(base, access_token, task_id, label, max_wait=420):
    deadline = time.time() + max_wait
    last = None
    while time.time() < deadline:
        status, body = call(
            base, "POST", "/api/analy/v1/task_id", json={"token": access_token, "task_id": task_id}
        )
        if status != 200:
            print(f"[{label}] poll http {status}: {body}")
            time.sleep(5)
            continue
        last = body
        if body.get("status") in TERMINAL:
            print(f"[{label}] terminal status={body.get('status')} in {round(max_wait - (deadline - time.time()))}s")
            return body
        time.sleep(5)
    print(f"[{label}] still not terminal after {max_wait}s; last={last}")
    return last


def history_rows(base, access_token, sha256):
    status, body = call(
        base,
        "POST",
        "/api/analy/v1/history",
        json={"token": access_token, "limit": 50, "s": sha256},
    )
    if status != 200:
        return status, body
    rows = [row for row in body.get("data", []) if row.get("file_hash") == sha256]
    return status, rows


def diagnostics(base, task_id):
    return call(base, "GET", f"/test/api/analysis/{task_id}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://10.212.51.8:8006")
    parser.add_argument("--wait", type=int, default=420)
    args = parser.parse_args()
    base = args.base.rstrip("/")

    content = EICAR
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    print(f"[file] EICAR {len(content)} bytes md5={md5} sha256={sha256}")

    access_token, upload_token = bootstrap(base)

    status, body = upload(base, upload_token, "dedup-repro-1.com", content)
    print(f"\n[upload#1] http {status}\n{json.dumps(body, ensure_ascii=False, indent=2)}")
    if status != 200:
        raise SystemExit("upload #1 failed")
    task1 = body.get("task_id")
    wait_terminal(base, access_token, task1, "upload#1", max_wait=args.wait)
    code, diag1 = diagnostics(base, task1)
    print(f"[diag#1] {code} rid={diag1.get('database', {}).get('rid')} tools={diag1.get('database', {}).get('tools')}")
    print(f"[diag#1] reports on disk: {diag1.get('reports')}")

    code, rows_before = history_rows(base, access_token, sha256)
    print(f"\n[history before upload#2] http {code} rows={len(rows_before)}")
    for row in rows_before:
        print(f"  task={row.get('task_id')} name={row.get('file_name')} status={row.get('status')} tools={row.get('tools')}")

    status2, body2 = upload(base, upload_token, "dedup-repro-2.com", content)
    print(f"\n[upload#2 same bytes, different name] http {status2}\n{json.dumps(body2, ensure_ascii=False, indent=2)}")
    task2 = body2.get("task_id") if isinstance(body2, dict) else None

    time.sleep(3)
    code, rows_after = history_rows(base, access_token, sha256)
    print(f"\n[history after upload#2] http {code} rows={len(rows_after)}")
    for row in rows_after:
        print(f"  task={row.get('task_id')} name={row.get('file_name')} status={row.get('status')} tools={row.get('tools')}")

    verdict_dup_rows = len(rows_after) > len(rows_before)
    verdict_new_task = bool(task2) and task2 != task1
    print("\n================ VERDICT ================")
    print(f"duplicate analysis rows created: {verdict_dup_rows} ({len(rows_before)} -> {len(rows_after)})")
    print(f"second upload dispatched a new task: {verdict_new_task} (task1={task1} task2={task2})")
    print(f"queue_state of upload#2: {body2.get('queue_state') if isinstance(body2, dict) else None}")
    if task2 and task2 != task1:
        code, diag2 = diagnostics(base, task2)
        print(f"[diag#2] {code} rid={diag2.get('database', {}).get('rid')}")
        print(f"[diag#2] run1_rid={diag1.get('database', {}).get('rid')} -> same_report={diag2.get('database', {}).get('rid') == diag1.get('database', {}).get('rid')}")
    print("========================================")
    return 1 if (verdict_dup_rows or verdict_new_task) else 0


if __name__ == "__main__":
    sys.exit(main())
