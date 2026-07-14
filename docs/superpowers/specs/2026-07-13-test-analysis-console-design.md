# Test Analysis Console Design

## Goal

Provide a test-only web console that creates or reuses one test user, issues real access and upload tokens, uploads a file, and follows a VirusTotal-only analysis job to completion.

## Scope

- Preserve existing database records while migrating user identifiers from integer values to UUID strings stored as PostgreSQL `TEXT`.
- Enable the console and supporting routes only when `TEST_MODE=TRUE`.
- Restore real upload-token validation and remove the hard-coded user identifier and mock token flow.
- Run only VirusTotal in the Celery analysis task.
- Persist queue state, VirusTotal score, terminal status, and report metadata needed by the console.
- Remove the obsolete `scan.html` flow and dead test-analysis code replaced by the console.

MobSF, CAPE, Gemini, and RampartAI implementation is excluded.

## Database Migration

The migration changes these user identity columns to UUID strings stored as `TEXT`:

- `users.uid`
- `users.created_by`
- `analysis.uid`
- `analysis.deleted_by`
- `audit_logs.actor_uid`
- `audit_logs.target_uid`

Analysis, report, and audit-log primary keys remain in their existing database types. The migration creates a stable mapping from each old integer user ID to a UUID string, fills shadow columns, verifies every foreign-key reference, replaces constraints and columns inside a transaction, and removes legacy columns only after validation succeeds.

The runtime ORM uses `String(36)` for all user identity columns and generates new values with `str(uuid.uuid4())`. The migration is idempotent: it exits successfully when the target schema is already present and rejects partially migrated or inconsistent schemas.

## Test Mode API

A `/test` router is registered for all environments but protected by a dependency that returns 404 unless `TEST_MODE=TRUE`. Test routes are omitted from OpenAPI when test mode is disabled.

Endpoints:

- `GET /test` serves the console.
- `GET /test/api/status` reports dependency health and whether the configured test user exists and is active.
- `POST /test/api/user` creates the configured test user or reactivates the matching test account. Conflicting username or email returns 409.
- `POST /test/api/token` issues access and upload tokens for the active test user and stores the upload session in Redis.

The identity is read from `TEST_USER_USERNAME` and `TEST_USER_EMAIL`; the browser cannot choose arbitrary account attributes.

## Upload And Queue Flow

The console requests a real upload token and sends it to `POST /api/analy/v1/upload`. The endpoint validates token type, expiry, Redis upload session, user existence, and active status.

The upload controller streams and hashes the file, rejects empty or oversized files, deduplicates by SHA-256, stores an Analysis row, and sends a Celery task with an explicit task ID. A successful response means the broker accepted the task, not that analysis completed.

If dispatch fails, the Analysis row receives `failed` status and the API returns 503. Existing successful VirusTotal results can be reused; an active queued or processing job can be attached to without duplicate dispatch.

## VirusTotal Task

The worker handles only VirusTotal:

1. Mark matching Analysis rows as `processing`.
2. Look up the file by hash.
3. Upload eligible files when no report exists.
4. Retry with bounded polling until the report is complete.
5. Save the normalized raw report.
6. Calculate and persist `virustotal_score` in a Reports row.
7. Mark Analysis rows as `success`, associate the report, and preserve the task ID.
8. Mark rows as `failed` after terminal errors or exhausted retries.

VirusTotal detection does not short-circuit before a Reports row is created. MobSF, CAPE, Gemini, and RampartAI are not called.

## Console Behavior

The responsive single-page console presents these ordered steps:

1. Dependency and test-user status.
2. Create or reuse the test account.
3. Issue access and upload tokens.
4. Select and upload a file.
5. Poll task status and display queued, processing, success, or failed.
6. Display the VirusTotal score and normalized report when available.

Tokens remain in session storage only. The page never embeds credentials or a fixed user ID.

## Error Handling

- Disabled test mode: 404.
- Test identity conflict: 409.
- Invalid or expired token: 401.
- Missing or inactive user: 401 or 403.
- Empty or oversized upload: 400 or 413.
- Database, Redis, broker, or VirusTotal failure: stable error response without secrets.
- Broker rejection: Analysis is marked failed and upload returns 503.
- Task exhaustion: Analysis is marked failed and remains queryable by task ID.

## Verification

- Migration tests verify row counts, UUID formatting, reference preservation, no orphan foreign keys, and idempotence.
- API tests cover test-mode gating, user creation/conflict, token issuance, invalid upload tokens, empty files, inactive users, successful dispatch, and broker failure.
- Worker tests mock VirusTotal and Celery retry behavior for hash hit, upload and polling, score persistence, success, and terminal failure.
- A runtime smoke test verifies PostgreSQL and Redis connectivity, starts FastAPI and Celery, creates the test user, issues tokens, uploads a benign sample, and confirms the task reaches a terminal state.

Automated tests do not submit malware or consume the live VirusTotal API.
