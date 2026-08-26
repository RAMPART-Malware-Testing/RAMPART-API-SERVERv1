# Admin Back-Office Redesign — Design Spec

Date: 2026-08-25
Status: Approved, implementing

## Goal

Turn `/admin` from a single dashboard page into a proper back-office
console with a persistent left sidebar and six distinct sections:
Dashboard, User Management, Admin Management, File Management, Report
Management, Audit Log. Visually and structurally separate from the
user-facing app (own layout, own navigation), matching the conventions of
professional admin panels (Stripe/Vercel/Linear-style sidebar).

## Sidebar Navigation

New `src/app/(pages)/admin/layout.tsx` wraps every `/admin/*` page:

- **Left sidebar**: RAMPART brand mark, 6 nav items (icon + label, active
  state highlighted), collapse/expand toggle (persisted to
  `localStorage`), "กลับสู่หน้าหลัก" link back to `/dashboard` pinned at
  the bottom.
- **Topbar**: current section title, user chip (fetched once via
  `/api/profile`), logout button.
- Replaces `NavbarComponent` on every admin page - the admin section gets
  its own chrome entirely, it does not reuse the user-facing navbar.

Menu items:
1. Dashboard → `/admin`
2. จัดการผู้ใช้ → `/admin/users`
3. จัดการแอดมิน → `/admin/admins`
4. จัดการไฟล์ → `/admin/files`
5. จัดการ Report → `/admin/reports`
6. ประวัติการจัดการ → `/admin/audit-logs`

## Page-by-page scope

### `/admin` (Dashboard) — unchanged
Already has the charts/stat-cards from the previous iteration. Only
change: render inside the new sidebar layout instead of `NavbarComponent`.

### `/admin/users` (existing page, refactored)
Existing `AdminUsersPage` component's role filter is fixed to `user` only
(no dropdown - this page IS the user-only view now). Ban/unban actions
unchanged. Role-change button ("ตั้งเป็นผู้ดูแล", promote to admin)
stays master-only, same as before.

### `/admin/admins` (new page)
Same list UI pattern as `/admin/users`, but the backend list call is
fixed to `role=admin,master` (a new multi-role filter capability). Shows
ban/unban and "ถอดสิทธิ์ผู้ดูแล" (demote to user) buttons - both
master-only per existing `ensure_can_manage_target` rules (admin viewers
see the list but with data-only rows, no action buttons, since an admin
can never act on another admin/master - this matches the pre-existing
rule, just applied to a page that is now 100% admin/master rows). Master
rows show no action buttons (can't self-manage, can't be managed by
peers) - same as today.

### `/admin/files` (new page)
Full system-wide file listing across all users - not scoped to one
target uid like `/admin/users/[uid]`. Card-list rows: filename, owner
username, status badge, privacy badge, file type, size, malicious badge,
date. Filters: search (filename/hash/md5), status, file_type, privacy.
Each row has a "ลบไฟล์" (soft-delete) button that opens a
reason-required confirm dialog (same UX pattern as ban). Deleting sets
`Analysis.deleted_at`/`deleted_by` - every existing query already filters
`deleted_at IS NULL` (verified: `analy_service.py`, `dashboars_service.py`,
`admin_service.get_user_analysis_history_admin`), so a deleted file
disappears from the owner's history, the public reports feed, and the
admin dashboard's `total_analyses` count automatically, no other query
needs touching. Deletion follows the exact same actor/target rule as ban
(`ensure_can_manage_target(actor, file_owner)`): admin can delete a plain
user's file, but not another admin's or master's file; master can delete
anyone's except another master's. Writes an audit log entry
(`delete_file`, detail = filename + reason).

### `/admin/reports` (new page)
Same system-wide listing, but hard-filtered to `Analysis.status ==
'success' AND Analysis.rid IS NOT NULL` (only files with a completed
report). Adds a risk-level filter (Low/Caution/High/Critical) and shows
score/risk badges per row. Read-only - links out to `/reports/[id]` for
the full report, no delete action here (deletion lives on the Files
page only, to avoid two different delete entry points for the same
underlying row).

### `/admin/audit-logs` — unchanged
Existing page, just moves under the new sidebar layout.

## Backend changes

### `services/admin/admin_service.py`

- `list_users` gains a `role_filter` that already accepts a single role
  string - extend it to accept a set/list of roles (backward compatible:
  single string still works) so `/admin/admins` can request
  `role IN ('admin', 'master')` in one call instead of two.
- New `list_all_files(session, *, q, status_filter, file_type_filter,
  privacy_filter, page, limit) -> dict` - joins `Analysis` + `User`
  (owner) + `Reports` (nullable) across the whole system, always filters
  `deleted_at IS NULL`. Returns owner username/uid alongside each file so
  the frontend can link to `/admin/users/[uid]`.
- New `list_reports(session, *, risk_level_filter, file_type_filter, q,
  page, limit) -> dict` - same shape as `list_all_files` but hard-filters
  `status == 'success' AND rid IS NOT NULL`.
- New `soft_delete_file(session, *, actor, aid, reason) -> Analysis` -
  loads the `Analysis` row and its owner `User`, calls
  `ensure_can_manage_target(actor, owner)` (reusing the exact same choke
  point ban/unban/role-change already go through), sets
  `deleted_at`/`deleted_by`, writes an audit log entry
  (`action="delete_file"`, `detail="<file_name> | reason=<reason>"`).

### `schemas/admin.py`
- `AdminListUsersParams.role` becomes `str | list[str] | None` (Pydantic
  validates each entry against the existing role enum).
- New `AdminListFilesParams`, `AdminDeleteFileParams`,
  `AdminListReportsParams`.

### `controller/admin_controller.py` / `routers/admin.py`
New endpoints, all behind the existing `_resolve_admin_actor` gate
(fresh-DB role check, unchanged pattern):
```
POST /api/admin/files            list_files_controller
POST /api/admin/files/delete     delete_file_controller
POST /api/admin/reports          list_reports_controller
```

## Frontend changes

- `src/app/(pages)/admin/layout.tsx` - the new sidebar+topbar chrome,
  `'use client'`, reads/writes `localStorage` for collapse state.
- `src/components/admin/AdminSidebar.tsx`, `AdminTopbar.tsx` - extracted
  components used by the layout.
- `src/app/(pages)/admin/users/page.tsx` - drop `NavbarComponent`, fix
  role filter to `user`.
- `src/app/(pages)/admin/admins/page.tsx` - new, near-identical structure
  to the users page but fixed to `role=admin,master` and swaps the
  promote button for a demote button.
- `src/app/(pages)/admin/files/page.tsx` - new, card-list + filters +
  delete confirm dialog (sweetalert2, reason required, matches the ban
  dialog pattern already established).
- `src/app/(pages)/admin/reports/page.tsx` - new, read-only card-list +
  risk-level filter.
- `src/app/(pages)/admin/page.tsx`, `admin/users/[uid]/page.tsx`,
  `admin/audit-logs/page.tsx` - drop `NavbarComponent` (now supplied by
  the shared layout).
- `src/services/admin.service.ts` - add `listFiles`, `deleteFile`,
  `listReports`.
- New Next.js route handlers under `src/app/(routes)/api/admin/files/`,
  `.../files/delete/`, `.../reports/` mirroring the existing admin route
  handler pattern (role re-check via `requireAdminSession`, forward to
  backend).
- `src/types/admin.type.ts` - new `AdminFileListItem`,
  `AdminFileListResponse`, `AdminReportListItem`,
  `AdminReportListResponse`.

## Testing

Backend: extend `tests/test_admin.py` with `list_all_files`/`
list_reports` scoping tests, `soft_delete_file` negative cases mirroring
the existing ban tests (admin cannot delete another admin's/master's
file, admin can delete a plain user's file, master can delete an admin's
file but not another master's), and a test confirming a soft-deleted
file's `aid` no longer appears in `get_user_analysis_history_admin`
results. Full suite must stay green (currently 211 passed, 2 pre-existing
unrelated failures - no regressions expected or acceptable).

Frontend: `tsc --noEmit` against the existing 34-line baseline. Live E2E
via a real browser session (master role): sidebar renders and every menu
item navigates correctly, collapse/expand persists across a reload,
`/admin/admins` shows only admin/master rows, `/admin/files` lists
cross-user files and a test delete removes the row and appears in the
audit log, `/admin/reports` shows only completed analyses with risk
badges.
