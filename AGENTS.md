# RAMPART API Server — AGENTS.md

## Code Style

- **No comments in code.** Never add inline comments, docstrings explaining behavior, or block comments — write self-explanatory code instead. This applies to every file in this repo.

## Startup

- **Two processes required**: `python start_server.py` (FastAPI on port 8006) and `python start_celery.py` (Celery worker).
- Docker network `rampart` must exist before `docker-compose up -d`.
- MobSF container runs on port **8001** (host) → 8000 (container).
- RampartAI container runs on port **8081** (host) → 8000 (container).
- Default root credentials: `rampart` / `rampart` (from `.env`).

## Database & Redis

- PostgreSQL container port: **5433** (not 5432). Both `cores/async_pg_db.py` and `cores/sync_pg_db.py` hardcode `:5433`.
- Redis requires password (`REDIS_PASSWORD`). Celery broker/backend URL format: `redis://:{password}@{host}:{port}/0`.
- **Two DB engines**: `cores/async_pg_db.py` (asyncpg, used by FastAPI routes) and `cores/sync_pg_db.py` (psycopg2-binary, used by Celery tasks). Always use the correct one.
- Tables auto-created on server startup via `init_db()` in `cores/Schema/schema_class.py`. `Base.metadata.create_all` only creates missing tables — it never `ALTER TABLE`s an existing one. New columns on an existing table must be applied manually against the live Postgres container, and mirrored in `CREATE-SQL.sql`.
- `cores/models_class.py` is dead code (stale integer-PK schema). The live schema is `cores/Schema/schema_class.py` only.

## Architecture

- **Layers**: `routers/` → `controller/` → `services/` → `cores/` (DB/Redis). Controllers are thin; business logic lives in `services/`.
- **Routers**: `auth.py` (prefix `/api/auth`), `analysis.py` (prefix `/api/analy/v1`), `admin.py` (prefix `/api/admin`), `profile.py` (prefix `/api/profile`), `dashboar_route.py` (note filename typo, prefix `/api/analy/v1/dashboard`).
- **Celery tasks**: `bgProcessing/tasks.py` — single task `analyze_malware_task` orchestrates VirusTotal → MobSF → CAPE → RampartAI → Gemini pipeline with per-tool retry-then-skip. Imports from `calling/` for each external service.
- **Auth**: dual-path — Google/GitHub OAuth (`services/oauth/oauth_service.py`) and local email+password+OTP (`services/auth/auth_service.py`) both resolve to the same `users` row. `User.password` is nullable (NULL for OAuth-only accounts). Accounts with any linked `oauth_accounts` row always require OTP on password login, regardless of device-token state.
- **Device token**: minted only by `login_confirm` and the OAuth callback, embeds `{sub: uid, email}`. `login()`'s bypass check requires both to match the account being logged into — never trust a device token by validity alone.
- **OTP**: 6-digit codes in Redis under `otp:{action}:{token}`, 5-minute TTL. Delivery via Gmail SMTP (`GMAIL_USERNAME`/`GMAIL_PASSWORD`) or generic `SMTP_*`, falls back to console print if neither is set. Wrong-attempt lockout is keyed by `otp_lockout:{action}:{identifier}` (identifier = email for register, uid for login/reset-passwd) — NOT by token, so retrying with a fresh token cannot bypass an active lockout. Max 5 wrong attempts before lockout.
- **RBAC**: three-tier `master`/`admin`/`user` on `User.role`. `master` can only be granted via `ROOT_EMAIL` env var at OAuth login — never via any API. Every authorization decision funnels through `services/admin/authz.py::ensure_can_manage_target`.
- **Upload flow**: POST `/api/analy/v1/upload` with upload token → file chunked, hashed (md5/sha1/sha256) → deduped by sha256 → Celery task dispatched.
- **Dedup / reuse model** (see `docs/analysis-dedup-design.md`): report identity is the **sha256** (one `reports.rid` per content, shared by every user row), user row identity is **`(uid, file_hash)`** — never keyed on file name. `services/analy/analy_service.py` holds the decision: `attempt_gap_fill_redispatch` (repair run that re-executes only tools whose report is missing, carrying the existing rid so no second report appears), `attempt_attach_to_existing_analysis` (points the caller's row at a finished or in-flight run — `queue_state` `reused`/`waiting`), `upsert_user_analysis` (in-place update of the caller's row for that content). `Analysis.tool_states` (JSONB) is the machine-readable per-tool outcome `{state: success|terminal|gap, reason}` written by the pipeline; `tool_notes` stays the human-readable message. Repair runs are capped at `MAX_CONTENT_RERUNS=3` per content (counted as distinct `task_id`s for that hash).

## Celery

- Windows: uses `--pool=solo`. Linux: uses `--pool=prefork` (default).
- Task `max_retries=150` with dynamic countdowns (30s for MobSF/CAPE polling, 5s for RampartAI, 60s for CAPE initial submit). MobSF polls up to `MAX_MOBSF_POLL_ATTEMPTS=120` (~60 min), CAPE up to `MAX_CAPE_POLL_ATTEMPTS=40` (~20 min) — the MobSF cap must stay below the task's retry budget (VT polls + MobSF/CAPE joint polls).
- 1-hour timeout (`task_time_limit=3600`), timezone `Asia/Bangkok`.

## Testing

| Task | Command |
|------|---------|
| Full suite | `python -m pytest tests/ -q` |
| Single file | `python -m pytest tests/test_admin.py -q` |
| Single test | `python -m pytest tests/test_admin.py::test_name -q` |

`tests/test_virustotal_task.py` may error with `WinError 10013` on Windows (socketpair sandboxing, not a code defect) — run other files individually if that happens.

## Known Typos / Gotchas

- Filename: `dashboar_route.py` (missing 'd').
- `auth_service.py` variable `deiveToken` (kept for backend-compat, do not silently rename without checking every caller on both repos).
- `.env` has duplicate key `VIRUSTOTAL_KEY2` defined twice; second overwrites first.
- File size limit: 1 GB max, 32 MB threshold for VirusTotal hash-only analysis.

## Style

- User-facing messages are in **Thai** with English status codes.
- Response format: `{"success": bool, "status": str, "message": str, "data": ...}` via `utils/response.py`.
- Password hashing uses **Argon2** via `argon2-cffi` (not bcrypt or pbkdf2).
- JWT via `python-jose` (`from jose import jwt`), not PyJWT. Every endpoint takes the token in the JSON request body, not an `Authorization` header.

## Agent Operating Mode (Pre-Approved)

- **Full auto, never ask.** The user has pre-approved all agent actions. Execute directly — commands, file edits, installs, service restarts — then report results. Do not ask "should I proceed?".
- All tool capabilities are allow-all via the user-level file `~/.kiro/settings/permissions.yaml`.
- **Sudo**: the password is in the global steering file `~/.kiro/steering/agent-rules.md` (kept outside this repo so it is never committed). It is already loaded into your context every session — use `echo <password> | sudo -S <command>` and never ask the user for a password.
