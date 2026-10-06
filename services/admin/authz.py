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
    payload, err = TokenService.verify_token(token, "access")
    if err:
        raise AuthError(401, "TOKEN_INVALID", "โทเค็นไม่ถูกต้องหรือหมดอายุ")

    uid = _resolve_uid(payload)
    user = await session.get(User, uid)
    if user is None:
        raise AuthError(401, "USER_NOT_FOUND", "ไม่พบบัญชีผู้ใช้")
    return user

def ensure_not_banned(user: User) -> None:
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
    if target.role == ROLE_MASTER:
        raise AuthError(403, "MASTER_PROTECTED", "ไม่สามารถดำเนินการกับบัญชี master ได้")

    if actor.role == ROLE_ADMIN and target.role in ADMIN_ROLES:
        raise AuthError(403, "ADMIN_TARGET_FORBIDDEN", "ผู้ดูแลไม่สามารถดำเนินการกับผู้ดูแลด้วยกันได้")

    if actor.role not in ADMIN_ROLES:
        raise AuthError(403, "INSUFFICIENT_ROLE", "คุณไม่มีสิทธิ์เข้าถึงส่วนนี้")

    return None

def ensure_can_manage_file_owner(actor: User, owner: User) -> None:
    if actor.uid == owner.uid:
        return None
    ensure_can_manage_target(actor, owner)
