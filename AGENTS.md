# RAMPART API Server — AGENTS.md

## Startup

- **Two processes required**: `python start_server.py` (FastAPI on port 8006) and `python start_celery.py` (Celery worker).
- Docker network `rampart` must exist before `docker-compose up -d`.
- MobSF container runs on port **8001** (host) → 8000 (container).
- RampartAI container runs on port **8081** (host) → 8000 (container).
- Default root credentials: `rampart` / `rampart` (from `.env`).

## Database & Redis

- PostgreSQL container port: **5433** (not 5432). Both `async_pg_db.py` and `sync_pg_db.py` hardcode `:5433`.
- Redis requires password (`REDIS_PASSWORD`). Celery broker/backend URL format: `redis://:{password}@{host}:{port}/0`.
- **Two DB engines**: `cores/async_pg_db.py` (asyncpg, used by FastAPI routes) and `cores/sync_pg_db.py` (psycopg2-binary, used by Celery tasks). Always use the correct one.
- Tables auto-created on server startup via `init_db()` in `models_class.py:105`. The `CREATE-SQL.sql` file documents the schema but is not run directly.

## Architecture

- **Layers**: `routers/` → `controller/` → `services/` → `cores/` (DB/Redis). Controllers are thin; business logic lives in `services/`.
- **Routers**: `auth.py` (prefix `/api`), `analysis.py` (prefix `/api/analy/v1`), `dashboar_route.py` (note filename typo).
- **Celery tasks**: `bgProcessing/tasks.py` — single task `analyze_malware_task` orchestrates VirusTotal → MobSF → CAPE → Gemini AI → RampartAI pipeline. Imports from `calling/` for each external service.
- **Auth flow**: login → OTP via Gmail → JWT tokens (access, refresh, device, upload). OTP stored in Redis under `otp:*` keys.
- **Upload flow**: POST `/api/analy/v1/upload` with upload token → file chunked, hashed (md5/sha1/sha256) → deduped by sha256 → Celery task dispatched with `analysis_tool='mobsf,cape'`.

## JWT Quirk

`utils/jwt.py` reads `SUPER_SECRET_KEY` env var, but `.env` only sets `JWT_SECRET`. Either rename the env var or `JWT` will crash at runtime. Algorithm is HS256.

## Celery

- Windows: uses `--pool=solo`. Linux: uses `--pool=prefork` (default).
- Task `max_retries=100` with dynamic countdowns (30s for MobSF/CAPE polling, 5s for RampartAI, 60s for CAPE initial submit).
- 1-hour timeout (`task_time_limit=3600`), timezone `Asia/Bangkok`.
- Task imports from `bgProcessing.tasks` (configured in `celery_app.py`).

## Testing & CI

- No test framework, no test files, no CI/CD workflows exist.

## Known Typos / Gotchas

- Filename: `dashboar_route.py` (missing 'd').
- Schema ToolEnum: `capr = "cape"` (should be `cape`).
- `auth_service.py` variable `deiveToken` (should be `deviceToken`).
- `.env` has duplicate key `VIRUSTOTAL_KEY2` defined twice; second overwrites first.
- File size limit: 1 GB max, 32 MB threshold for VirusTotal hash-only analysis.
- External service URLs: `RAMPARTAI_URL=http://localhost:8081`, `MOBSF_BASE_URL=http://localhost:8001`, `CAPE_BASE_URL=http://localhost:8000`.

## Style

- User-facing messages are in **Thai** with English status codes.
- Response format: `{"success": bool, "status": str, "message": str, "data": ...}` via `utils/response.py`.
- Password hashing uses **Argon2** via `argon2-cffi` (not bcrypt or pbkdf2).
- File hashing via `utils/calculate_hash.py` — computes md5, sha1, sha256 in one pass.
