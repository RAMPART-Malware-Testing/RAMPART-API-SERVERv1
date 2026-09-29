# Dashboard, Privacy Semantics And Cache Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** ทำให้ความหมายของ `analysis.privacy` ตรงกับที่ผู้ใช้นิยาม (true = ส่วนตัว), บังคับ login กับฟีดสาธารณะ, แก้ตัวเลข/ตัวกรองของ dashboard ที่คืนค่าไม่ถูก, และทำให้ cache ของ dashboard อัปเดตทันเมื่อข้อมูลเปลี่ยน

**Architecture:** แก้ที่ "จุดอ่าน" (read paths) ของ `privacy` ทั้ง 3 จุดให้ตีความ `true = private` โดยไม่แตะค่าในฐานข้อมูลและไม่เปลี่ยนชื่อฟิลด์ใน API (client ส่ง/อ่าน `privacy` เหมือนเดิม) จากนั้นเพิ่มการยืนยันตัวตนให้ endpoint เดียวที่ยังเปิดอยู่ ปิดช่องว่างของ dashboard summary 3 จุด และเพิ่มการ invalidate cache ที่จุดเขียน (upload / เปลี่ยน privacy / ลบไฟล์)

**Tech Stack:** Python, FastAPI, SQLAlchemy (async สำหรับ routes, sync สำหรับ Celery), PostgreSQL 16 (container port 5433), Redis, pytest

## Global Constraints

- `Analysis.privacy = true` หมายถึง **ไฟล์เป็นส่วนตัว** (ผู้ใช้ยืนยัน 2026-09-28) — ทุกโค้ดที่อ่านค่าต้องตีความแบบนี้ ห้ามกลับด้าน
- คงชื่อฟิลด์ `privacy` ใน request/response ทุก endpoint (ค่า `true` = ส่วนตัว) เพื่อไม่ให้ frontend/admin console ต้องแก้ตาม — ห้ามเปลี่ยนชื่อฟิลด์
- `/api/analy/v1/dashboard/reports` ต้องยืนยันตัวตน (access token ใน JSON body เหมือน `summary` และ `recent-activities`)
- ห้ามคอมเมนต์/docstring ในโค้ดที่เขียนใหม่ (AGENTS.md) และไฟล์ `.sql` ต้องไม่มีความคิดเห็นทุกรูปแบบ
- การเปลี่ยน schema ต้องเป็นไฟล์ครบชุดใน `docs/migrations/` และต้องรันก่อน deploy โค้ด
- ข้อความที่ผู้ใช้เห็นเป็นภาษาไทย, รูปแบบ response ผ่าน `utils/response.py` (`{"success", "status", "message", "data"}`)
- ห้าม commit / ห้ามใช้ GitHub operations ระหว่างทำตามแผน
- รันเทสต์เดี่ยว: `python -m pytest tests/<file>.py -q` — เทสต์ทั้งชุด: `python -m pytest tests/ -q` (ใช้เวลา ~5 นาที)
- ห้ามทำให้ 13 เทสต์ที่แดงอยู่เดิมเพิ่มขึ้นระหว่างทำ Task 1–8; Task 9 คือการปิดหนี้ทั้ง 13 ตัว

---

### Task 1: Public report view ต้องซ่อนไฟล์ที่เป็นส่วนตัว

**Files:**
- Modify: `services/analy/analy_service.py` (ฟังก์ชัน `get_public_analysis_with_report`, บรรทัด ~498-515)
- Test: `tests/test_privacy_semantics.py` (สร้างใหม่)

**Interfaces:**
- Consumes: `Analysis.privacy` (Boolean, nullable), `build_suffix`, `cached_async`
- Produces: `get_public_analysis_with_report(session, task_id)` — คืนแถวเฉพาะที่ `privacy IS false` (สาธารณะจริง)

- [x] เขียนเทสต์ที่ล้มก่อน (สร้าง `tests/test_privacy_semantics.py`):

```python
from types import SimpleNamespace

import pytest

from services.analy import analy_service


class FakeResult:
    def __init__(self, rows=None):
        self.rows = rows or []

    def scalar_one(self):
        return len(self.rows)

    def scalars(self):
        return self

    def unique(self):
        return self

    def all(self):
        return self.rows

    def mappings(self):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def one_or_none(self):
        return self.rows[0] if self.rows else None


class RecordingSession:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.statements = []

    async def execute(self, statement, parameters=None):
        self.statements.append(str(statement))
        return FakeResult(self.rows)


@pytest.mark.asyncio
async def test_public_report_view_only_matches_rows_marked_public():
    session = RecordingSession()

    await analy_service.get_public_analysis_with_report(session, "task-1")

    query = session.statements[0]
    assert "analysis.privacy IS false" in query
    assert "analysis.privacy = true" not in query
```

- [x] รัน `python -m pytest tests/test_privacy_semantics.py -q` → ต้อง FAIL ด้วย `assert 'analysis.privacy IS false' in '...analysis.privacy = true...'`
- [x] แก้ `services/analy/analy_service.py` ตรงเงื่อนไขของ query และ docstring ที่อธิบายผิด:
  - `Analysis.privacy == True,  # noqa: E712` → `Analysis.privacy.is_(False),`
  - ปรับข้อความ docstring จาก `is shared publicly (privacy == True) and not deleted` → `is shared publicly (privacy == False) and not deleted`
- [x] รัน `python -m pytest tests/test_privacy_semantics.py tests/test_analy_service.py -q` → PASS ทั้งหมด
- [x] Commit: `git add services/analy/analy_service.py tests/test_privacy_semantics.py && git commit -m "fix(privacy): treat privacy=true as private in public report view"`

---

### Task 2: Download authorization ต้องใช้กติกาเดียวกัน (และปิดเทสต์ดาวน์โหลดที่ค้าง 4 ตัว)

**Files:**
- Modify: `controller/analysis_controller.py` (`downloadReport_controller`, บรรทัด ~365)
- Test: `tests/test_privacy_semantics.py` (เพิ่มเคส), `tests/test_virustotal_task.py` (แก้ 4 เทสต์ที่แดง)

**Interfaces:**
- Consumes: `get_analysis_access_rows_by_md5(session, md5) -> list[Row(uid, privacy, rid)]`, `get_current_user(session, token)`
- Produces: `downloadReport_controller(file_name, token=None) -> Path` — กติกา (ผู้ใช้ยืนยัน 2026-09-28):
  1. ถ้ามีแถวใดของ md5 นี้ `privacy IS false` (สาธารณะ) → **อนุญาตทันที** ไม่ต้องตรวจอย่างอื่น
  2. ถ้าทุกแถวเป็นส่วนตัว → อนุญาตเมื่อผู้เรียก **เคยวิเคราะห์ไฟล์นี้เอง** (มีแถวที่ `uid` ตรงกัน) **และ** เนื้อหานี้มี report (`rid` ไม่เป็น NULL)
  3. นอกเหนือจากนั้น → 403 (admin ยังผ่านได้พร้อมเขียน audit log ตามเดิม)

- [x] เขียนเทสต์ที่ล้มก่อน (ต่อใน `tests/test_privacy_semantics.py`) — ใช้แพตเทิร์น harness เดียวกับ `tests/test_virustotal_task.py::test_raw_report_status_uses_string_uid`:

```python
from fastapi import HTTPException

from controller import analysis_controller


def _download_context(user):
    class Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return user

    return Context


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("requester_uid", "rows", "allowed"),
    [
        ("other-1", [("owner-1", False, "rid-1")], True),
        ("other-1", [("owner-1", False, None)], True),
        ("owner-1", [("owner-1", True, "rid-1")], True),
        ("owner-1", [("owner-1", True, None)], False),
        ("other-1", [("owner-1", True, "rid-1")], False),
        ("other-1", [("owner-1", None, "rid-1")], False),
    ],
)
async def test_download_requires_owner_or_public_row(monkeypatch, tmp_path, requester_uid, rows, allowed):
    report = tmp_path / f"virustotal-{'a' * 32}.json"
    report.write_text("{}", encoding="utf-8")
    user = SimpleNamespace(uid=requester_uid, role="user", is_banned=False)

    monkeypatch.setattr(analysis_controller, "BASE_REPORT_PATH", tmp_path)
    monkeypatch.setattr(analysis_controller, "SessionLocal", _download_context(user))
    monkeypatch.setattr(
        analysis_controller, "get_current_user", lambda session, token: _await(user)
    )
    monkeypatch.setattr(
        analysis_controller,
        "get_analysis_access_rows_by_md5",
        lambda session, md5: _await([SimpleNamespace(uid=u, privacy=p, rid=r) for u, p, r in rows]),
    )

    if allowed:
        result = await analysis_controller.downloadReport_controller(report.name, "token")
        assert result == report.resolve()
    else:
        with pytest.raises(HTTPException) as raised:
            await analysis_controller.downloadReport_controller(report.name, "token")
        assert raised.value.status_code == 403


async def _await(value):
    return value
```

- [x] รัน `python -m pytest tests/test_privacy_semantics.py -q` → เคส private+ไม่ใช่เจ้าของ, private+ไม่มี report, และ `privacy IS NULL` ต้อง FAIL (ปัจจุบันอ่าน `row.privacy` เป็น truthy)
- [x] แก้ `services/analy/analy_service.py` (`get_analysis_access_rows_by_md5`): เพิ่ม `Analysis.rid` ใน select และปรับ docstring ให้ตรง
- [x] แก้ `controller/analysis_controller.py`:
  - `owner_or_public = any(row.uid == user.uid or row.privacy for row in rows)` → `public_or_owned = any(row.privacy is False for row in rows) or (any(row.uid == user.uid for row in rows) and any(row.rid for row in rows))` พร้อมเปลี่ยนชื่อตัวแปรในสองเงื่อนไขถัดไปให้ตรง
- [x] แก้เทสต์ดาวน์โหลดที่ค้าง 4 ตัวใน `tests/test_virustotal_task.py` (`test_download_accepts_exact_persisted_virustotal_basename`, `test_download_accepts_all_known_tool_basenames[...]` ×3) ให้ส่ง token + monkeypatch `analysis_controller.get_current_user` และ `get_analysis_access_rows_by_md5` (ปัจจุบันเรียกโดยไม่มี token → 401)
- [x] รัน `python -m pytest tests/test_privacy_semantics.py tests/test_virustotal_task.py -q` → PASS (4 ตัวที่ค้างต้องหายไป)
- [x] Commit: `git add controller/analysis_controller.py tests/test_privacy_semantics.py tests/test_virustotal_task.py && git commit -m "fix(privacy): gate report downloads on owner or explicitly public rows"`

---

### Task 3: ฟีดสาธารณะของ dashboard ต้องแสดงเฉพาะไฟล์ที่ตั้งใจแชร์

**Files:**
- Modify: `services/dashboard/dashboars_service.py` (`_fetch_reports_history`, บรรทัด ~185)
- Test: `tests/test_privacy_semantics.py`

**Interfaces:**
- Produces: `_fetch_reports_history(session, params)` — ทุก query (count + list) กรองด้วย `Analysis.privacy IS false`

- [x] เขียนเทสต์ที่ล้มก่อน:

```python
from schemas.dashboard import ReportsHistoryParams
from services.dashboard import dashboars_service


@pytest.mark.asyncio
async def test_public_feed_queries_only_match_rows_marked_public():
    session = RecordingSession()
    params = ReportsHistoryParams(page=1, limit=10)

    await dashboars_service._fetch_reports_history(session, params)

    privacy_queries = [q for q in session.statements if "analysis.privacy" in q]
    assert privacy_queries
    assert all("analysis.privacy IS false" in q for q in privacy_queries)
```

- [x] รัน `python -m pytest tests/test_privacy_semantics.py::test_public_feed_queries_only_match_rows_marked_public -q` → FAIL
- [x] แก้ `services/dashboard/dashboars_service.py:185`: `Analysis.privacy == True,` → `Analysis.privacy.is_(False),`
- [x] รัน `python -m pytest tests/test_privacy_semantics.py -q` → PASS
- [x] Commit: `git add services/dashboard/dashboars_service.py tests/test_privacy_semantics.py && git commit -m "fix(dashboard): list only explicitly public analyses in the public feed"`

---

### Task 4: บังคับ login กับ `/api/analy/v1/dashboard/reports`

**Files:**
- Modify: `schemas/dashboard.py` (`ReportsHistoryParams`)
- Modify: `controller/dashboard_controller.py` (`reports_history_controller`)
- Test: `tests/test_dashboard.py` (สร้างใหม่)

**Interfaces:**
- Consumes: `get_current_user`, `ensure_not_banned` (`services/admin/authz.py`), `AuthError`
- Produces: `ReportsHistoryParams(token: str, page: int = 1, limit: int = 10, ...)`; `reports_history_controller(body)` ตรวจ token ก่อนเรียก service

**ผลกระทบต่อ client (ต้องแจ้ง frontend):** หลัง deploy ผู้เรียกที่ **ไม่ส่ง** `token` จะได้ `422 Unprocessable Entity` จาก Pydantic (ไม่ใช่ 401) เพราะฟิลด์เป็น required — frontend/admin console ต้องส่ง access token มาด้วยทุกครั้งที่เรียก endpoint นี้

- [x] เขียนเทสต์ที่ล้มก่อน (`tests/test_dashboard.py`) — ตรวจ 401 เมื่อ token ไม่ผ่าน, 403 เมื่อถูกแบน, 200 เมื่อผ่าน และ query ยังกรอง public:

```python
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from controller import dashboard_controller
from schemas.dashboard import ReportsHistoryParams
from services.admin.authz import AuthError


def _context(user=None):
    class Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return user

    return Context


@pytest.mark.asyncio
async def test_dashboard_reports_rejects_invalid_token(monkeypatch):
    def reject(session, token):
        raise AuthError(401, "INVALID_TOKEN", "token ไม่ถูกต้อง")

    monkeypatch.setattr(dashboard_controller, "SessionLocal", _context())
    monkeypatch.setattr(dashboard_controller, "get_current_user", reject)

    with pytest.raises(HTTPException) as raised:
        await dashboard_controller.reports_history_controller(ReportsHistoryParams(token="bad"))

    assert raised.value.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_reports_rejects_banned_user(monkeypatch):
    user = SimpleNamespace(uid="uid-1", role="user", is_banned=True)

    def banned(user_value):
        raise AuthError(403, "USER_NOT_ACTIVE", "บัญชีนี้ถูกระงับการใช้งาน")

    monkeypatch.setattr(dashboard_controller, "SessionLocal", _context(user))
    monkeypatch.setattr(dashboard_controller, "get_current_user", lambda session, token: _await(user))
    monkeypatch.setattr(dashboard_controller, "ensure_not_banned", banned)

    with pytest.raises(HTTPException) as raised:
        await dashboard_controller.reports_history_controller(ReportsHistoryParams(token="ok"))

    assert raised.value.status_code == 403


@pytest.mark.asyncio
async def test_dashboard_reports_passes_authenticated_request_to_service(monkeypatch):
    user = SimpleNamespace(uid="uid-1", role="user", is_banned=False)
    captured = {}

    async def service(session, params):
        captured["params"] = params
        return {"success": True, "data": []}

    monkeypatch.setattr(dashboard_controller, "SessionLocal", _context(user))
    monkeypatch.setattr(dashboard_controller, "get_current_user", lambda session, token: _await(user))
    monkeypatch.setattr(dashboard_controller, "get_reports_history", service)

    response = await dashboard_controller.reports_history_controller(ReportsHistoryParams(token="ok", limit=5))

    assert response == {"success": True, "data": []}
    assert captured["params"].limit == 5


async def _await(value):
    return value
```

- [x] รัน `python -m pytest tests/test_dashboard.py -q` → FAIL (import `token` / auth ยังไม่มี)
- [x] `schemas/dashboard.py`: เพิ่ม `token: str` เป็นฟิลด์แรกของ `ReportsHistoryParams`
- [x] `controller/dashboard_controller.py`: ใน `reports_history_controller` เปิด session, เรียก `get_current_user(session, body.token)` + `ensure_not_banned(user)` โดยแปลง `AuthError` เป็น `HTTPException` (คัดลอกแพตเทิร์นจาก `recent_activities_controller`) แล้วจึงเรียก `get_reports_history(session, body)`
- [x] อัปเดต `docs/api.md` สองจุด: ตาราง auth (บรรทัด ~314) `ไม่` → `access token ใน body`, และหัวข้อ `8.3` ให้ระบุว่าต้อง login และคืนเฉพาะแถวที่ `privacy: false`
- [x] อัปเดตเทสต์ของ Task 3 (`test_public_feed_queries_only_match_rows_marked_public`) ให้ส่ง `token="token"` ด้วย เพราะ `ReportsHistoryParams` บังคับฟิลด์นี้แล้ว
- [x] รัน `python -m pytest tests/test_dashboard.py -q` → PASS
- [x] Commit: `git add schemas/dashboard.py controller/dashboard_controller.py tests/test_dashboard.py docs/api.md && git commit -m "feat(dashboard): require an access token for the public reports feed"`

---

### Task 5: แก้ตัวเลข/ตัวกรองของ dashboard summary ที่คืนค่าไม่ถูก

**Files:**
- Modify: `services/dashboard/dashboars_service.py` (`_fetch_dashboard_summary`)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Produces: `_fetch_dashboard_summary(session, uid, role)` — `totalFiles.pending`/`userFiles.pending` นับทุกสถานะที่ยังทำงานอยู่, `totalUsers` ไม่นับผู้ใช้ที่ถูกแบน, ตัวกรอง `file_type` ค้นแบบ contains

- [x] เขียนเทสต์ที่ล้มก่อน (เพิ่มใน `tests/test_dashboard.py`) — ตรวจข้อความ SQL ที่สร้าง:
  - in-flight: query ของ `totalFiles` ต้องมีทั้ง `dispatching`, `queued`, `processing`, `analyzing` (ไม่ใช่ `pending` เดี่ยว)
  - `total_users`: มี `users.is_banned IS false`
- [x] รัน → FAIL
- [x] แก้ `_fetch_dashboard_summary`:
  - ประกาศค่าคงที่ระดับโมดูล `IN_FLIGHT_STATUSES = ("dispatching", "queued", "processing", "analyzing")` และเปลี่ยน `case((Analysis.status == "pending", 1))` ทั้งสอง query เป็น `case((Analysis.status.in_(IN_FLIGHT_STATUSES), 1))`
  - `select(func.count()).select_from(User).where(User.status == "active", User.role == "user")` → `.where(User.is_banned.is_(False), User.role == "user")`
  - ตัวกรอง `file_type` ใน `_fetch_reports_history`: `Analysis.file_type.ilike(params.file_type.strip())` → `Analysis.file_type.ilike(f"%{params.file_type.strip()}%")`
- [x] รัน `python -m pytest tests/test_dashboard.py -q` → PASS
- [x] Commit: `git add services/dashboard/dashboars_service.py tests/test_dashboard.py && git commit -m "fix(dashboard): count in-flight analyses, exclude banned users, contains-match file type"`

---

### Task 6: `recent-activities` ต้องให้สิทธิ์ master เท่า admin

**Files:**
- Modify: `services/dashboard/dashboars_service.py` (`_fetch_recent_activities`, บรรทัด ~139)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: `ADMIN_ROLES` จาก `services/admin/authz.py` (`{admin, master}`)
- Produces: `_fetch_recent_activities(session, uid, role, limit=10)` — role ที่อยู่ใน `ADMIN_ROLES` เห็นกิจกรรมของทุกคน

- [x] เขียนเทสต์ที่ล้มก่อน: เรียก `_fetch_recent_activities(session, "uid-1", "master")` แล้วยืนยันว่า query **ไม่มี** เงื่อนไข `analysis.uid = uid-1`
- [x] รัน → FAIL (ปัจจุบัน master ถูกกรอง uid)
- [x] แก้: `if role != "admin":` → `if role not in ADMIN_ROLES:` พร้อม import `ADMIN_ROLES`
- [x] รัน `python -m pytest tests/test_dashboard.py -q` → PASS
- [x] Commit: `git add services/dashboard/dashboars_service.py tests/test_dashboard.py && git commit -m "fix(dashboard): treat master as an admin role in recent activities"`

---

### Task 7: Invalidate cache ของ dashboard/history เมื่อข้อมูลเปลี่ยน

**Files:**
- Modify: `controller/Analysis/ScanFile_controller.py` (หลัง upsert/attach สำเร็จ), `controller/analysis_controller.py` (`update_privacy_controller`), `services/admin/admin_service.py` (หลัง soft delete)
- Test: `tests/test_dashboard.py` (หรือ `tests/test_privacy_semantics.py`)

**Interfaces:**
- Consumes: `invalidate_cached(namespace)` จาก `utils/cache.py`
- Produces: helper `invalidate_public_caches()` ใน `services/dashboard/dashboars_service.py` ที่ล้าง 3 namespace ของ dashboard + `analy:history` (`ANALYSIS_HISTORY_CACHE_NAMESPACE`)

- [x] เขียนเทสต์ที่ล้มก่อน: monkeypatch `invalidate_cached` แล้วยืนยันว่าเรียกครบ 4 namespace หลัง upload สำเร็จ และหลัง `PATCH /{task_id}/privacy`
- [x] รัน → FAIL
- [x] เพิ่ม helper ใน `services/dashboard/dashboars_service.py` แล้วเรียกจาก 3 จุดเขียน (upload/attach/gap-fill, เปลี่ยน privacy, ลบไฟล์ของ admin)
- [x] รัน `python -m pytest tests/test_dashboard.py tests/test_analysis_upload.py tests/test_dedup_reuse.py -q` → PASS (ห้ามให้ lock-order/event-order ของเทสต์เดิมพัง — เรียก invalidate หลัง commit เท่านั้น)
- [x] Commit: `git add -A && git commit -m "fix(cache): invalidate dashboard and history caches on upload, privacy change and delete"`

---

### Task 8: เอกสารและกฎกันถดถอย

**Files:**
- Modify: `docs/api.md` (บรรทัด ~33, ~870, ~957, ~1457), `AGENTS.md`, `docs/sql-arshitackture.md`

- [x] `docs/api.md:33` — แก้เป็น `ค่า privacy: true หมายถึงรายงานส่วนตัว (ค่าเริ่มต้น) ส่วน privacy: false หมายถึงรายงานสาธารณะ`
- [x] `docs/api.md:870, 957` — แก้คำอธิบาย default จาก `ค่าเริ่มต้น true = สาธารณะ` → `ค่าเริ่มต้น true = ส่วนตัว`
- [x] `docs/api.md:1457` — ระบุว่าต้องส่ง access token และคืนเฉพาะแถว `privacy: false`
- [x] `AGENTS.md` — เพิ่มบรรทัดในหัวข้อ Style: `analysis.privacy = true` means the row is **private** (default); only `privacy = false` rows are visible to non-owners and in the public dashboard feed
- [x] `docs/sql-arshitackture.md` — ระบุความหมายของ `analysis.privacy` ในหัวข้อ `analysis` (true = ส่วนตัว)
- [x] รัน `python -m pytest tests/ -q` และบันทึกจำนวนที่เหลือ (คาดว่าเหลือ 9 ตัวจากหนี้เทสต์ — ดู Task 9)
- [x] Commit: `git add docs AGENTS.md && git commit -m "docs: state that analysis.privacy=true means private"`

---

### Task 9: ปิดหนี้เทสต์ 13 ตัวที่แดงอยู่ก่อน (ไม่นับของใหม่จาก Task 1–8)

**Files:**
- Modify: `tests/test_admin.py`, `tests/test_virustotal_task.py`, `tests/test_analysis_pipeline.py`, `tests/test_test_mode.py`, `tests/test_uuid_flows.py`, `start_server.py`

| # | เทสต์ที่แดง | สาเหตุที่ตรวจพบ | วิธีปิด |
|---|---|---|---|
| 1-3 | `tests/test_admin.py` ×3 | `services/admin/admin_service.py:725` เรียก `analysis.file_path` (ลบไฟล์ต้นฉบับ) แต่ fake row ในเทสต์ไม่มีฟิลด์นี้ | เพิ่ม `file_path` ใน fixture (ชี้ไปไฟล์จริงใน `tmp_path` เพื่อทดสอบการลบไฟล์ด้วย) |
| 4-7 | `tests/test_virustotal_task.py` download ×4 | เรียก `downloadReport_controller(name)` โดยไม่ส่ง token แต่ endpoint บังคับ token แล้ว | ใช้แพตเทิร์นเดียวกับ Task 2 (ส่ง token + monkeypatch `get_current_user`/`get_analysis_access_rows_by_md5`) |
| 8-9 | `tests/test_analysis_pipeline.py` cape ×2 | `handle_cape` เช็คว่าไฟล์ต้นฉบับมีอยู่จริง `sample.exe` จึงได้ `failed` ไม่ใช่ `pending` | สร้างไฟล์จริงใน `tmp_path` แล้วส่งพาธนั้นเข้า `handle_cape` |
| 10 | `tests/test_analysis_pipeline.py::test_malicious_vt_never_calls_sandboxes` | คาด `tools == "virustotal"` แต่โค้ดปัจจุบันรวม Gemini → `"virustotal,gemini"` | อัปเดตความคาดหวังให้ตรงพฤติกรรมปัจจุบัน (Gemini รันในเส้นทางนี้) |
| 11 | `tests/test_test_mode.py::test_disabled_test_mode_returns_404_and_omits_openapi` | **โค้ดผิด ไม่ใช่เทสต์**: `start_server.py` import `test_router` ซ้ำ 2 ครั้ง และเรียก `app.include_router(test_router)` แบบไม่มีเงื่อนไขอีกครั้ง → เส้นทาง `/test/*` โผล่ใน OpenAPI ตลอดแม้ `TEST_MODE` ปิด | ลบ import ซ้ำและ `include_router` ที่ไม่ผูกเงื่อนไขออก เหลือเฉพาะ `app.include_router(test_router, include_in_schema=test_mode_enabled())` |
| 12 | `tests/test_test_mode.py::test_console_contains_complete_analysis_flow` | เทสต์หา `"Analysis progress"` แต่ template ใช้ `Pipeline progress` | sync assertion กับ heading ปัจจุบันของ `templates/test_analysis.html` |
| 13 | `tests/test_uuid_flows.py::test_analysis_history_passes_uuid_to_service` | service ใช้ `params.page` แต่ fake params ไม่มีฟิลด์นี้ | ใช้ `AnalysisHistoryParams(token=...)` จริงแทน SimpleNamespace |

- [x] แก้ทีละแถวตามตาราง (แต่ละแถวรันเทสต์เดี่ยวก่อนไปแถวถัดไป)
- [x] รัน `python -m pytest tests/ -q` → คาด `0 failed` (หรือเหลือเฉพาะที่อธิบายได้และบันทึกในรายงาน)
- [x] Commit แยกตามไฟล์: `git commit -m "test: close stale fixtures and expectations, unmount unconditional test router"`

---

### Task 10 (ต้องขออนุมัติก่อนทำ): คอลัมน์ที่ไม่มีใครใช้ และ widget ที่ไม่มีข้อมูล

**Files:**
- Modify: `bgProcessing/tasks.py` (`finalize_analysis_report`), `services/dashboard/dashboars_service.py`, `docs/migrations/<ใหม่>-drop-dead-columns.sql`

- [ ] ตัดสินใจ 2 ทางเลือกกับ `Reports.rampart_score`: **แนะนำ** เติมค่าใน `finalize_analysis_report` จากผล RampartAI (`calculate_rampart_ai_score` = `malware_probability * 100`) เพื่อให้ `aiScore` ใน dashboard ทำงานจริง — หรือลบคอลัมน์และเอา widget ออก
- [ ] ตัดสินใจกับ `topMalwareTypes`: **แนะนำ** เปลี่ยนไป group ด้วย `Analysis.file_type` (มีข้อมูลจริง) แทนการฟื้น `Reports.type` ที่ไม่มีแหล่งข้อมูลแล้ว
- [ ] ลบคอลัมน์ที่ยืนยันว่าไม่มีใครใช้ 5 ตัว (`users.fcm_token`, `users.created_by`, `users.updated_at`, `reports.package`, `oauth_accounts.provider_email`) ด้วยไฟล์ migration ที่ไม่มีคอมเมนต์ + mirror ใน `CREATE-SQL.sql` + ลบออกจาก `cores/Schema/schema_class.py` และ `tools/rebuild_database_uuid.py`
- [ ] รันเทสต์ทั้งหมดและอัปเดต `docs/sql-arshitackture.md`

---

### Task 11 (ต้องยืนยันก่อนทำ): ขอบเขตของ dashboard summary

- [ ] ยืนยันว่า `totalFiles`/`topMalwareTypes`/`riskScores` ควรเป็น **ทั้งระบบ** (ปัจจุบัน) หรือ **เฉพาะของผู้เรียก** สำหรับ role `user`
- [ ] ถ้าเลือก "เฉพาะของผู้เรียก": เพิ่มเงื่อนไข `Analysis.uid == uid` ให้ 3 query เมื่อ `role not in ADMIN_ROLES` แล้วอัปเดต cache suffix ตาม และเพิ่มเทสต์คู่ (user เห็นของตัวเอง / admin เห็นทั้งระบบ)

---

## Self-Review

- ความครอบคลุม: คำถามทั้ง 4 ข้อจากผู้ใช้ถูกปิดครบ — ความถูกต้องของข้อมูล (Task 5, 6), cache (Task 7), public จริง (Task 1, 2, 3), login (Task 4), pagination (มีอยู่แล้ว ตรวจใน Task 4 ว่าไม่ถูกกระทบ)
- ไม่มี placeholder: ทุก task มีไฟล์ บรรทัด และโค้ด/คำสั่งที่รันได้จริง
- ความสอดคล้องของชื่อ: `get_public_analysis_with_report`, `_fetch_reports_history`, `_fetch_recent_activities`, `reports_history_controller` ตรงกับโค้ดปัจจุบัน; ค่าคงที่ใหม่ `IN_FLIGHT_STATUSES` ใช้เฉพาะ Task 5
- ความเสี่ยงที่ต้องแจ้งผู้ใช้ก่อนเริ่ม: หลัง Task 1–3 ทำงาน ไฟล์ที่เคยถูกมองว่า "สาธารณะ" (เพราะอ่านค่ากลับด้าน) จะกลายเป็นส่วนตัวทันที → ฟีดสาธารณะจะเหลือเฉพาะไฟล์ที่ frontend ส่ง `privacy: false` มาจริง ต้องยืนยันว่า frontend ไม่ได้พึ่งพฤติกรรมกลับด้านนี้
