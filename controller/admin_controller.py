"""HTTP-facing wrappers for the admin panel.

Every function here follows the same gate sequence, in order:

    1. get_current_user(session, token)   -- fresh-from-DB, never trusts JWT claims
    2. ensure_not_banned(actor)           -- a banned admin/master loses access too
    3. ensure_role(actor, ADMIN_ROLES)    -- must be admin or master
    4. (mutating/privileged-read actions) service call, which itself also
       runs ensure_can_manage_target as defense in depth, then writes an
       audit_logs row atomically with the mutation.

AuthError is caught once, here, and translated into this project's existing
{"success": False, "status": ..., "message": ...} response shape via
utils/response.py - controllers never construct that shape by hand for an
authz failure, so every admin endpoint reports errors identically.
"""

from __future__ import annotations

from fastapi import HTTPException

from cores.async_pg_db import SessionLocal
from schemas.admin import (
    AdminAuditLogParams,
    AdminBanUserParams,
    AdminChangeRoleParams,
    AdminDeleteFileParams,
    AdminListFilesParams,
    AdminListReportsParams,
    AdminListUsersParams,
    AdminTargetUserParams,
    AdminTokenParams,
    AdminUnbanUserParams,
    AdminUserHistoryParams,
)
from services.admin import admin_service
from services.admin.authz import ADMIN_ROLES, AuthError, ensure_not_banned, ensure_role, get_current_user
from utils.response import error, success
from utils.status_code import AuthStatus
from utils.uuid import parse_uuid


def _auth_error_response(exc: AuthError):
    return error(exc.code, exc.message)


async def _resolve_admin_actor(session, token: str):
    """Shared gate 1-3. Raises AuthError on any failure - callers must be
    inside a try/except AuthError block."""
    actor = await get_current_user(session, token)
    ensure_not_banned(actor)
    ensure_role(actor, ADMIN_ROLES)
    return actor


def _parse_target_uid(raw: str):
    try:
        return parse_uuid(raw)
    except (TypeError, ValueError):
        raise AuthError(400, "INVALID_ROLE_TARGET", "target_uid ไม่ถูกต้อง")


async def list_users_controller(body: AdminListUsersParams):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, body.token)
            return await admin_service.list_users(
                session,
                q=body.q,
                role_filter=body.role,
                banned_filter=body.banned,
                page=body.page,
                limit=body.limit,
            )
        except AuthError as exc:
            return _auth_error_response(exc)


async def get_user_detail_controller(body: AdminTargetUserParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            target = await admin_service.get_user_admin_view(session, target_uid)
            if target is None:
                return error(AuthStatus.TARGET_NOT_FOUND, "ไม่พบผู้ใช้เป้าหมาย")

            # Viewing another user's full profile (including whatever
            # private files they have) is itself a privileged action worth
            # an audit trail entry, per explicit product requirement.
            await admin_service.write_audit_log(
                session,
                actor_uid=actor.uid,
                target_uid=target.uid,
                action="view_user_detail",
                detail=None,
            )
            await session.commit()

            return success(
                AuthStatus.LOGIN_SUCCESS,
                "ดึงข้อมูลผู้ใช้สำเร็จ",
                admin_service.serialize_user(target),
            )
        except AuthError as exc:
            return _auth_error_response(exc)


async def get_user_history_controller(body: AdminUserHistoryParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            target = await admin_service.get_user_admin_view(session, target_uid)
            if target is None:
                return error(AuthStatus.TARGET_NOT_FOUND, "ไม่พบผู้ใช้เป้าหมาย")

            history = await admin_service.get_user_analysis_history_admin(session, target_uid, body)

            # Reading another user's upload history - including private
            # files - is exactly the "view private data" action the product
            # spec requires an audit trail for.
            await admin_service.write_audit_log(
                session,
                actor_uid=actor.uid,
                target_uid=target.uid,
                action="view_private_history",
                detail=f"page={body.page}",
            )
            await session.commit()

            return history
        except AuthError as exc:
            return _auth_error_response(exc)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="Internal server error")


async def ban_user_controller(body: AdminBanUserParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            target = await admin_service.ban_user(
                session, actor=actor, target_uid=target_uid, reason=body.reason
            )
            return success(
                AuthStatus.BAN_SUCCESS,
                "แบนผู้ใช้สำเร็จ",
                admin_service.serialize_user(target),
            )
        except AuthError as exc:
            return _auth_error_response(exc)


async def unban_user_controller(body: AdminUnbanUserParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            target = await admin_service.unban_user(session, actor=actor, target_uid=target_uid)
            return success(
                AuthStatus.UNBAN_SUCCESS,
                "ปลดแบนผู้ใช้สำเร็จ",
                admin_service.serialize_user(target),
            )
        except AuthError as exc:
            return _auth_error_response(exc)


async def change_role_controller(body: AdminChangeRoleParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            target = await admin_service.change_user_role(
                session, actor=actor, target_uid=target_uid, new_role=body.new_role
            )
            return success(
                AuthStatus.ROLE_CHANGE_SUCCESS,
                "เปลี่ยน role สำเร็จ",
                admin_service.serialize_user(target),
            )
        except AuthError as exc:
            return _auth_error_response(exc)


async def admin_dashboard_summary_controller(body: AdminTokenParams):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, body.token)
            return await admin_service.get_admin_dashboard_summary(session)
        except AuthError as exc:
            return _auth_error_response(exc)


async def audit_logs_controller(body: AdminAuditLogParams):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, body.token)
            actor_uid = _parse_target_uid(body.actor_uid) if body.actor_uid else None
            return await admin_service.list_audit_logs(
                session,
                page=body.page,
                limit=body.limit,
                actor_uid=actor_uid,
                action=body.action,
            )
        except AuthError as exc:
            return _auth_error_response(exc)


async def list_files_controller(body: AdminListFilesParams):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, body.token)
            return await admin_service.list_all_files(
                session,
                q=body.q,
                status_filter=body.status,
                file_type_filter=body.file_type,
                privacy_filter=body.privacy,
                page=body.page,
                limit=body.limit,
            )
        except AuthError as exc:
            return _auth_error_response(exc)


async def delete_file_controller(body: AdminDeleteFileParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            try:
                aid = parse_uuid(body.aid)
            except (TypeError, ValueError):
                return error("INVALID_ROLE_TARGET", "aid ไม่ถูกต้อง")
            target = await admin_service.soft_delete_file(
                session, actor=actor, aid=aid, reason=body.reason
            )
            return success(
                "DELETE_FILE_SUCCESS",
                "ลบไฟล์สำเร็จ",
                {"aid": str(target.aid), "deleted_at": target.deleted_at.isoformat() if target.deleted_at else None},
            )
        except AuthError as exc:
            return _auth_error_response(exc)


async def list_reports_controller(body: AdminListReportsParams):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, body.token)
            return await admin_service.list_reports(
                session,
                q=body.q,
                risk_level_filter=body.risk_level,
                file_type_filter=body.file_type,
                page=body.page,
                limit=body.limit,
            )
        except AuthError as exc:
            return _auth_error_response(exc)
