# Test Analysis Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve existing users while migrating their identifiers to UUID strings in PostgreSQL `TEXT`, then provide a test-only console that creates a test user, issues real tokens, uploads a file, and follows a VirusTotal-only Celery task.

**Architecture:** An idempotent migration converts user identity columns with a verified integer-to-UUID mapping. FastAPI exposes a guarded test router and a real token-protected upload flow; Celery owns VirusTotal polling and persists a minimal report and terminal status.

**Tech Stack:** Python 3.13, FastAPI, Pydantic v2, SQLAlchemy 2 async/sync, PostgreSQL, Redis, Celery, pytest, HTTPX, vanilla HTML/CSS/JavaScript.

## Global Constraints

- Preserve all existing users, analyses, and audit references.
- Store UUID user identifiers as PostgreSQL `TEXT`, represented as `String(36)` in SQLAlchemy.
- Enable test routes only when `TEST_MODE=TRUE`.
- Analyze with VirusTotal only; do not implement or call MobSF, CAPE, Gemini, or RampartAI.
- Use real access and upload tokens; do not retain hard-coded users or mock tokens.
- A queued response means broker acceptance, not completed analysis.
- Do not commit unless the user explicitly requests it.

---

### Task 1: Test Harness And User-ID Migration

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/test_user_id_migration.py`
- Create: `cores/user_id_migration.py`
- Modify: `cores/Schema/schema_class.py`
- Modify: `CREATE-SQL.sql`
- Modify: `requirements.txt`

**Interfaces:**
- Produces: `async migrate_user_ids_to_text(connection) -> None` and ORM user identity columns represented by strings.
- Consumes: SQLAlchemy async connection from application startup.

- [ ] Add `pytest`, `pytest-asyncio`, and compatible test fixtures without requiring live external services during collection.
- [ ] Write failing tests for integer-to-UUID mapping, preservation of nullable references, orphan rejection, and idempotence.
- [ ] Run `python -m pytest tests/test_user_id_migration.py -v` and verify failures are caused by the missing migration.
- [ ] Implement a transactional, advisory-locked migration that detects integer source columns, creates UUID-string shadow columns, maps all user references, validates counts/references, swaps constraints and columns, and exits when already migrated.
- [ ] Change `users.uid`, `users.created_by`, `analysis.uid`, `analysis.deleted_by`, `audit_logs.actor_uid`, and `audit_logs.target_uid` to `String(36)` while retaining existing non-user key types.
- [ ] Update `CREATE-SQL.sql` to use `TEXT DEFAULT gen_random_uuid()::text` for user IDs and `TEXT` for matching references.
- [ ] Run migration tests and the full suite.

### Task 2: Test-Mode User And Token API

**Files:**
- Create: `tests/test_test_mode.py`
- Create: `utils/test_mode.py`
- Create: `services/test_mode_service.py`
- Create: `routers/test_route.py`
- Modify: `start_server.py`
- Modify: `.env.test.example`

**Interfaces:**
- Produces: `test_mode_enabled() -> bool`, `require_test_mode() -> None`, and `/test/api/status`, `/test/api/user`, `/test/api/token`.
- Consumes: `SessionLocal`, `redis_client`, password hashing, and JWT creation.

- [ ] Write failing API tests proving disabled routes return 404, status reports missing/active/conflicting users, creation is idempotent, conflicts return 409, and tokens have correct types and Redis upload-session state.
- [ ] Run `python -m pytest tests/test_test_mode.py -v` and verify expected failures.
- [ ] Implement validated environment identity (`TEST_USER_USERNAME`, `TEST_USER_EMAIL`) and a role `test` account with a random unusable password.
- [ ] Implement access/upload token issuance and Redis session storage, with dependency failures converted to stable HTTP errors.
- [ ] Register the router and ensure test API operations are omitted from OpenAPI when disabled.
- [ ] Run focused and full tests.

### Task 3: Secure Upload And Queue State

**Files:**
- Create: `tests/test_analysis_upload.py`
- Modify: `routers/analysis.py`
- Modify: `controller/Analysis/ScanFile_controller.py`
- Modify: `services/analy/analy_service.py`
- Modify: `cores/redis.py`

**Interfaces:**
- Produces: token-protected `POST /api/analy/v1/upload` returning `task_id`, `status`, hashes, and deduplication state.
- Consumes: `require_upload_token(token) -> str`, `analyze_malware_task.apply_async`, UUID-string user IDs.

- [ ] Write failing tests for invalid tokens, missing/inactive users, empty files, size rejection, accepted dispatch, deduplication, and broker failure.
- [ ] Run focused tests and confirm failures reproduce the hard-coded UUID and unsafe queue behavior.
- [ ] Restore upload-token validation and remove the fixed UUID.
- [ ] Stream MD5/SHA-256 safely, sanitize extensions, reject empty files, and preserve files by SHA-256.
- [ ] Persist a task ID before dispatch, use `apply_async(..., task_id=task_id)`, attach duplicate user records to reusable jobs, and mark rows failed when dispatch raises.
- [ ] Make Redis use `REDIS_HOST` consistently.
- [ ] Run focused and full tests.

### Task 4: VirusTotal-Only Worker And Report Contract

**Files:**
- Create: `tests/test_virustotal_task.py`
- Modify: `bgProcessing/tasks.py`
- Modify: `bgProcessing/task_handlers.py`
- Modify: `calling/VirusTotal.py`
- Modify: `controller/analysis_controller.py`
- Modify: `services/analy/analy_service.py`

**Interfaces:**
- Produces: Celery task `analyze_malware_task(file_path, md5, sha256, total_size)` and task-status response containing a minimal VirusTotal report.
- Consumes: normalized VirusTotal lookup/upload/poll result and `calculate_threat_scoreVT`.

- [ ] Write failing tests for hash hits, upload then retry, incomplete reports, completed clean/malicious reports, score persistence, and terminal failure.
- [ ] Run focused tests and verify failures expose missing report persistence and terminal-state handling.
- [ ] Refine VirusTotal client methods to return JSON-safe error strings and explicit lookup/poll states.
- [ ] Implement bounded Celery retries, `processing` state, normalized raw report storage, Reports upsert, `virustotal_score`, Analysis/report association, and `success`/`failed` terminal state.
- [ ] Remove calls and placeholder branches for MobSF, CAPE, Gemini, and RampartAI from the active task path.
- [ ] Align report/status serialization with the current Reports schema and handle success without a report defensively.
- [ ] Run focused and full tests.

### Task 5: Test Console

**Files:**
- Create: `templates/test_analysis.html`
- Modify: `routers/test_route.py`
- Delete: `scan.html`
- Modify: `start_server.py`
- Delete: `test_analy.py`

**Interfaces:**
- Produces: `GET /test` test console.
- Consumes: test status/user/token endpoints, upload endpoint, and task-status endpoint.

- [ ] Write a failing route test that checks the console is test-mode gated and contains controls for user, token, upload, task polling, and VirusTotal result display.
- [ ] Run the focused test and verify failure because the template is absent.
- [ ] Build a responsive single-page console with no embedded credential or fixed user ID, session-scoped tokens, explicit queue-vs-completion copy, and resilient JSON/error rendering.
- [ ] Poll task state until success or failed and render VirusTotal score/report.
- [ ] Remove `/scan`, `scan.html`, and the broken local pipeline script superseded by the console; retain `test_virustotal.py` as a manual VirusTotal utility.
- [ ] Run focused and full tests.

### Task 6: Runtime Migration And End-To-End Verification

**Files:**
- Modify: `start_server.py`
- Modify: `README.md`
- Modify: `.env.test.example`

**Interfaces:**
- Consumes all prior tasks.
- Produces documented startup and smoke-test procedure.

- [ ] Add migration execution before `init_db()` and test that startup ordering cannot create conflicting UUID-native columns over integer data.
- [ ] Run the migration against the configured PostgreSQL database and verify user/reference row counts, UUID-string formatting, foreign keys, and idempotence using read-only validation queries.
- [ ] Start FastAPI and Celery, then verify root, `/test`, status, user creation, token issuance, upload, task polling, and VirusTotal terminal state with a benign sample.
- [ ] Run `python -m pytest -v`, `python -m compileall -q .`, `python -m pip check`, and `git diff --check`.
- [ ] Update README with exact `TEST_MODE`, test-user, server, worker, migration, and `/test` instructions.
- [ ] Inspect `git status --short` and `git diff` to confirm only intended files changed and no credentials were added.
