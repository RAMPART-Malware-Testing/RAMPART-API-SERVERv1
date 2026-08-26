# Admin RBAC System — Design Spec

Date: 2026-08-25
Status: Approved, implementing

## Goal

Add a three-tier role system (`master`, `admin`, `user`) to RAMPART with a full
admin panel: user management (view profile + full upload history including
private files), ban/unban, role promotion/demotion (user↔admin only), a
system-wide dashboard, and an audit log — enforced end-to-end with JWT auth,
fresh DB-backed authorization checks on every request, and OWASP Top 10
discipline (especially A01 Broken Access Control).

## Roles & Rules (locked in by user)

- **master**: can do everything `admin` can, plus ban/unban `admin` accounts
  and promote/demote `user ↔ admin`. Cannot be created via API/UI — only via
  `ROOT_EMAIL` env var at OAuth login time (existing mechanism, currently
  wrongly promotes to `"admin"` — must promote to `"master"` instead).
- **admin**: can view any user's profile, full upload history (public +
  private), ban/unban `user` accounts, view system dashboard, view audit log.
  **Cannot** touch (view-as-target-of-mutation, ban, unban, role-change)
  another `admin` or `master` account at all — any admin action where the
  target's role is `admin` or `master` is rejected with 403, no exceptions.
- **user**: existing behavior, unchanged, minus being subject to the new
  `is_banned` hard-block on every endpoint.
- **master accounts can never be banned** — by anyone, including another
  master or themselves. Enforced at the service layer unconditionally.
- No account deletion. Ban/unban only. No UI/API path to create a `master`.

## Data Model Changes

### `users` table — new columns

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_at TIMESTAMPTZ NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_reason TEXT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_by UUID NULL REFERENCES users(uid);
```

`role` column stays a free-text `String(20)`, but the accepted value set
becomes `{"user", "admin", "master"}`. The existing `status` column
(`"active"` free-text flag) is left as-is for backward compatibility but is
no longer the source of truth for access control — `is_banned` is.

`oauth_service.find_or_create_user`: ROOT_EMAIL match now sets/enforces
`role = "master"` (was `"admin"`). This is the *only* code path that can ever
assign the `master` role.

Applied live via `docker exec postgres-rampart psql -U rampart -d rampart -c
"ALTER TABLE ..."` since `Base.metadata.create_all` does not alter existing
tables (no Alembic in this project).

### `audit_logs` table — already exists, unused. First real consumer.

Every privileged admin action (ban, unban, role change, and — per explicit
user requirement — viewing another user's private file/report) writes one
row: `actor_uid`, `target_uid`, `action` (short machine string, e.g.
`"ban_user"`, `"unban_user"`, `"role_change"`, `"view_private_history"`),
`detail` (human-readable JSON/text, e.g. reason, old_role→new_role).

## Backend Architecture

### New shared authorization helpers — `services/admin/authz.py`

- `async def get_current_user(session, token: str) -> User` — verifies JWT via
  existing `TokenService.verify_token`, then re-fetches the user row **fresh
  from the DB** (never trusts role/ban state baked into the JWT, since access
  tokens live 7 days). Raises a typed `AuthError` on invalid token or user not
  found.
- `def ensure_not_banned(user: User) -> None` — raises `AuthError("ACCOUNT_BANNED")`
  if `user.is_banned`. Called from **every** authenticated controller —
  existing ones (`profile`, `dashboard`, `analysis`, `ScanFile`, `CheckHash`)
  get this added; today only `ScanFile`/`CheckHash` had an equivalent
  (`status != "active"`) check, and it's now replaced by this shared, actually
  banned-flag-based function on all of them.
- `def ensure_role(user: User, allowed: set[str]) -> None` — raises
  `AuthError("INSUFFICIENT_ROLE")` if `user.role not in allowed`.
- `def ensure_can_manage_target(actor: User, target: User) -> None` — the
  single choke point for "can actor perform a mutating admin action on
  target":
  - `target.role == "master"` → always reject (`"MASTER_PROTECTED"`), even if
    actor is also master (self-protection included since actor could be the
    same row).
  - `actor.role == "admin" and target.role in {"admin", "master"}` → reject
    (`"ADMIN_TARGET_FORBIDDEN"`).
  - `actor.role == "master"` → allowed against `admin`/`user` targets.
  - Anything else falls through to allowed (admin acting on plain user).

This function is the **single source of truth** for the "admin can't touch
admin" and "nobody bans master" rules — all mutating admin endpoints call it
before writing anything, so the rule can't be forgotten per-endpoint.

### New service — `services/admin/admin_service.py`

```python
async def list_users(session, *, q, role_filter, banned_filter, page, page_size) -> dict
async def get_user_admin_view(session, target_uid) -> User | None
async def get_user_analysis_history_admin(session, target_uid, params: AnalysisHistoryParams) -> dict
async def ban_user(session, *, actor, target_uid, reason) -> User
async def unban_user(session, *, actor, target_uid) -> User
async def change_user_role(session, *, actor, target_uid, new_role) -> User   # master-only, new_role in {"user","admin"}
async def get_admin_dashboard_summary(session) -> dict
async def list_audit_logs(session, *, actor_uid_filter, action_filter, page, page_size) -> dict
async def write_audit_log(session, *, actor_uid, target_uid, action, detail) -> None
```

`get_user_analysis_history_admin` reuses the existing pagination/filter shape
of `analy_service.get_analysis_history` but drops the `Analysis.uid == uid`
hard-scope and the `privacy` filter (admin/master see private files too, per
explicit requirement) — implemented as a new function rather than mutating
the existing user-facing one, to avoid any risk of accidentally loosening the
self-service endpoint's scoping.

Every mutating function takes `actor: User` (not just `actor_uid`) so
`ensure_can_manage_target` can run inside the service layer itself as well as
the controller — defense in depth, not just a controller-level gate.

### New controller — `controller/admin_controller.py`

Thin wrappers: decode token → `get_current_user` → `ensure_not_banned` →
`ensure_role(actor, {"admin","master"})` → call service → for
mutating/privileged-read actions, call `write_audit_log` → return via
existing `utils/response.py` shape.

### New router — `routers/admin.py`, prefix `/api/admin`

```
POST /api/admin/users                    list_users_controller
POST /api/admin/users/detail             get_user_detail_controller       (writes "view_private_history" audit log)
POST /api/admin/users/history            get_user_history_controller      (paginated analysis history, writes audit log)
POST /api/admin/users/ban                ban_user_controller              (master-only vs admin target, else admin ok)
POST /api/admin/users/unban              unban_user_controller
POST /api/admin/users/role               change_role_controller           (master-only endpoint entirely)
POST /api/admin/dashboard/summary        admin_dashboard_summary_controller
POST /api/admin/audit-logs               audit_logs_controller
```

All bodies carry `token` (existing project convention — body-token, not
`Authorization` header — kept for consistency with every other router).
Mounted in `start_server.py` alongside the existing routers.

### Existing endpoints retrofitted with `ensure_not_banned`

`profile_controller.py` (get/update profile, avatar upload),
`dashboard_controller.py` (summary, recent-activities),
`analysis_controller.py` (upload-token, history, task lookups),
`Analysis/ScanFile_controller.py` and `Analysis/CheckHash_controller.py`
(replace the old `status != "active"` check with `ensure_not_banned`, keeping
the same `USER_NOT_ACTIVE`-style error code/message for the upload path so
frontend error handling doesn't need to change there, while every other
endpoint gets the *new* `ACCOUNT_BANNED` error code for the first time).

### `dashboars_service.get_dashboard_summary` — fix existing no-op role gap

Currently accepts `role` but never uses it to restrict `total_files`/
`total_users` visibility for regular users (bug noted in research). Left
as-is for the *user*-facing dashboard (out of scope — not part of this admin
work, would be a separate fix), but the new `admin_service.get_admin_dashboard_summary`
is a clean, separate implementation purpose-built for the admin panel with
richer stats (banned count, role breakdown, recent bans, etc.) so this isn't
blocked by that pre-existing gap.

## Frontend Architecture

### New pages — `src/app/(pages)/admin/`

```
admin/page.tsx                 dashboard: user counts, role breakdown, banned count, recent admin actions
admin/users/page.tsx           user list: search, filter by role/banned, card-list rows (existing pattern), ban/unban/role-change actions
admin/users/[uid]/page.tsx     target user's profile + full analysis history (public+private), with a clear "private" badge per item
admin/audit-logs/page.tsx      audit log table/list: actor, target, action, detail, timestamp, filter by actor/action
```

### New service — `src/services/admin.service.ts`

Follows the existing `profile.service.ts`/`dashboard.service.ts` convention
exactly: class with `SERVER_URL` from env, methods doing `axios.post` with
`{ token, ...params }` body to the new `/api/admin/*` backend routes, same
`ERROR_RESPONSE` fallback shape.

### New Next.js Route Handlers — `src/app/(routes)/api/admin/...`

Mirror the existing pattern (`profile/route.ts`, `dashboard/route.ts`): pull
`access_token` httpOnly cookie via `cookies()`, `jwtService.verify()`, extract
`verify.token` (raw backend JWT), forward to `admin.service.ts`. Each route
handler **also** independently checks `verify.data.role` before proxying
(defense in depth — don't rely solely on the backend rejecting it, though the
backend is and remains the authoritative enforcement point).

### `src/proxy.ts` — new role gate

Add `/admin` to a new `ROLE_PROTECTED_ROUTES` map (path prefix → allowed
roles). Decode the already-verified session JWT's `payload.data.role`; if the
path starts with `/admin` and role isn't `admin`/`master`, redirect to
`/dashboard`. This runs *before* any admin page ever renders.

### Global banned-account hard-logout

Add a small axios response interceptor (new `src/lib/http-interceptors.ts` or
inline in a shared axios instance) that, on receiving the new `ACCOUNT_BANNED`
error code/status from *any* backend-proxied call, immediately calls the
logout route and redirects to a new `/banned` page — so a banned user's
already-open browser tab gets kicked out on their very next action instead of
waiting for their 7-day JWT to expire naturally.

### Types — `src/types/admin.type.ts`

`AdminUserListItem`, `AdminUserListResponse`, `AdminUserDetail`,
`BanUserPayload`, `RoleChangePayload`, `AuditLogItem`, `AuditLogResponse`.
`src/types/auth.type.ts`'s `RampartUser.role` tightened from
`"user" | "admin" | string` to `"user" | "admin" | "master"`.

### UI conventions followed

Card-list rows (not `<table>`) matching `reports/page.tsx`; dark
slate/cyan-blue gradient theme; `sweetalert2` (already installed, unused
elsewhere) for ban/unban/role-change confirmation dialogs with a required
reason field for ban; Thai text throughout; toast-based error/success
feedback via existing `useToast()`.

## Security Checklist (OWASP Top 10 — explicit gates before calling this done)

- **A01 Broken Access Control**: every admin endpoint re-verifies role from a
  fresh DB read, never trusts the JWT's embedded role claim for
  authorization decisions (claim is informational/UX-only on the frontend).
  `ensure_can_manage_target` is the single choke point for the
  admin-vs-admin and master-protection rules — tested with explicit negative
  cases (see Testing).
- **A04 Insecure Design**: no code path anywhere can set `role="master"`
  except the ROOT_EMAIL OAuth login branch. No role-change endpoint accepts
  `"master"` as a target value — validated server-side, not just hidden in
  the UI.
- **A07 Identification & Auth Failures**: banned users are rejected on every
  authenticated endpoint by a fresh DB check, not a stale JWT claim — a user
  banned mid-session loses access on their very next request.
- **A09 Security Logging Failures**: every ban/unban/role-change/private-view
  writes an `audit_logs` row with actor, target, action, detail, timestamp.

## Testing Plan

Backend: extend `tests/` with `test_admin.py` covering —
- user cannot call any `/api/admin/*` endpoint (403)
- admin can ban/unban a plain user; audit log row created
- admin **cannot** ban/unban/role-change another admin or the master (403,
  no audit log side effect, no DB mutation)
- admin cannot promote anyone (role endpoint is master-only)
- master can ban/unban admin, cannot ban another master or self
- master can promote user→admin and demote admin→user, cannot set role to
  `"master"` via the endpoint even if forced in the request body
- banned user is rejected on profile/dashboard/analysis/scan/check-hash
  endpoints, not just upload
- admin/master can view another user's private analysis history; audit log
  row created for that view
- `get_current_user` re-fetches fresh state — a role/ban change takes effect
  on the *next* request without needing a new token

Frontend: `tsc --noEmit` clean against existing 34-line baseline; manual
verification via authenticated session (master via ROOT_EMAIL, and a
separately test-mode-provisioned `admin`/`user` account) that `/admin/*`
redirects correctly for non-privileged roles, and that the ban action on a
live test user actually blocks their next API call.
