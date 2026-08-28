"""Single choke point for every authorization decision in the admin/RBAC
system (OWASP A01 - Broken Access Control).

Design principles this module enforces:

1. Never trust role/ban state embedded in a JWT for an authorization
   decision. Access tokens live 7 days (see
   services/oauth/oauth_service.ACCESS_TOKEN_EXPIRE_MINUTES) - a user
   banned or demoted mid-session must lose access on their *very next*
   request, not whenever they happen to get a fresh token. `get_current_user`
   re-fetches the user row from the database on every call.
2. The "can actor mutate/view target" rule set (admin can't touch another
   admin or master, master can never be banned by anyone) lives in exactly
   one function - `ensure_can_manage_target` - so every admin endpoint that
   calls it gets the same guarantee, and the rule can't be silently
   forgotten or reimplemented slightly differently on a new endpoint later.
"""

from __future__ import annotations

import uuid

from cores.Schema.schema_class import User
from services.token_service import TokenService
from utils.uuid import parse_uuid

ROLE_USER = "user"
ROLE_ADMIN = "admin"
ROLE_MASTER = "master"

ASSIGNABLE_ROLES = {ROLE_USER, ROLE_ADMIN}

ADMIN_ROLES = {ROLE_ADMIN, ROLE_MASTER}

class AuthError(Exception):
    """Raised by every function in this module on any auth/authz failure.

    Carries the same (status_code, error_code, message) shape controllers
    already use everywhere else in this codebase, so callers can catch this
    once and translate it into the project's standard error response
    without each controller re-inventing the status-code mapping.
    """

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message

def _resolve_uid(payload: dict) -> uuid.UUID:
    try:
        return parse_uuid(payload.get("sub"))
    except (TypeError, ValueError, KeyError):
        raise AuthError(401, "TOKEN_INVALID", "ข้อมูลผู้ใช้ในโทเค็นไม่ถูกต้อง")

async def get_current_user(session, token: str) -> User:
    """Verifies `token` as an access token, then re-fetches the
    corresponding `users` row fresh from the database.

    This is the ONLY function in the admin system that is allowed to turn a
    raw token into a `User` object - every controller must go through this,
    never read `role`/`status` directly off the decoded JWT payload for an
    authorization decision.
    """
    payload, err = TokenService.verify_token(token, "access")
    if err:
        raise AuthError(401, "TOKEN_INVALID", "โทเค็นไม่ถูกต้องหรือหมดอายุ")

    uid = _resolve_uid(payload)
    user = await session.get(User, uid)
    if user is None:
        raise AuthError(401, "USER_NOT_FOUND", "ไม่พบบัญชีผู้ใช้")
    return user

def ensure_not_banned(user: User) -> None:
    """Hard-blocks any banned account, including a master somehow left
    marked banned by a stale/manual DB edit - the check is unconditional,
    it does not special-case role."""
    if user.is_banned:
        raise AuthError(
            403,
            "ACCOUNT_BANNED",
            "บัญชีของคุณถูกระงับการใช้งาน" + (f": {user.banned_reason}" if user.banned_reason else ""),
        )

def ensure_role(user: User, allowed: set[str]) -> None:
    if user.role not in allowed:
        raise AuthError(403, "INSUFFICIENT_ROLE", "คุณไม่มีสิทธิ์เข้าถึงส่วนนี้")

def ensure_can_manage_target(actor: User, target: User) -> None:
    """The single source of truth for "can `actor` perform a mutating (or
    privileged read of private data) admin action on `target`".

    Rules, in order, first match wins:
      1. target is master  -> always rejected, unconditionally, even if
         actor is also master (covers "master bans/unbans itself" and
         "master bans another master").
      2. actor is admin AND target is admin or master -> rejected. Admins
         cannot touch other admins or master at all, per product
         requirement ("admin แตะต้อง admin ด้วยกันไม่ได้เลย").
      3. actor is master -> allowed (target is guaranteed to be admin or
         user at this point, since rule 1 already excluded master targets).
      4. Otherwise (actor is admin, target is a plain user) -> allowed.
    """
    if target.role == ROLE_MASTER:
        raise AuthError(403, "MASTER_PROTECTED", "ไม่สามารถดำเนินการกับบัญชี master ได้")

    if actor.role == ROLE_ADMIN and target.role in ADMIN_ROLES:
        raise AuthError(403, "ADMIN_TARGET_FORBIDDEN", "ผู้ดูแลไม่สามารถดำเนินการกับผู้ดูแลด้วยกันได้")

    if actor.role not in ADMIN_ROLES:
        raise AuthError(403, "INSUFFICIENT_ROLE", "คุณไม่มีสิทธิ์เข้าถึงส่วนนี้")

    return None

def ensure_can_manage_file_owner(actor: User, owner: User) -> None:
    """Same permission rule as ensure_can_manage_target, with one addition:
    an admin/master is always allowed to delete their OWN uploaded files.

    ensure_can_manage_target's "target is master -> always rejected, even
    self" rule exists to stop a master account from ever being banned/
    demoted, by itself or anyone else (see that function's docstring) -
    that identity-protection concern does not apply to deleting one's own
    file. Without this carve-out, any admin/master account whose own
    uploads are the delete target (e.g. a test/seed account, or simply an
    admin who uploaded a file themselves) would see every single-file and
    bulk-delete call rejected with MASTER_PROTECTED/ADMIN_TARGET_FORBIDDEN,
    with no way to ever delete their own files via the admin panel."""
    if actor.uid == owner.uid:
        return None
    ensure_can_manage_target(actor, owner)
