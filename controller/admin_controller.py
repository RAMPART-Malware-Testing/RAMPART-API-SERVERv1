from __future__ import annotations

import logging

from fastapi import HTTPException

from cores.async_pg_db import SessionLocal
from schemas.admin import (
    AdminAuditLogParams,
    AdminBanUserParams,
    AdminBroadcastEmailParams,
    AdminBulkBanUsersParams,
    AdminBulkDeleteFilesParams,
    AdminClearLockoutParams,
    AdminCreateUserParams,
    AdminDashboardParams,
    AdminDeleteAuditLogsParams,
    AdminDeleteFileParams,
    AdminDeleteHistoryParams,
    AdminDeleteUserParams,
    AdminResetUserPasswordParams,
    AdminListFilesParams,
    AdminListReportsParams,
    AdminListUsersParams,
    AdminTargetUserParams,
    AdminTaskActionParams,
    AdminTaskQueueParams,
    AdminTokenParams,
    AdminUnbanUserParams,
    AdminUserHistoryParams,
    AdminUserSubHistoryParams,
)
from services.admin import admin_service
from services.admin.authz import (
    ADMIN_ROLES,
    AuthError,
    ensure_can_manage_target,
    ensure_not_banned,
    ensure_role,
    get_current_user,
)
from utils.response import error, success
from utils.status_code import AuthStatus
from utils.uuid import parse_uuid

logger = logging.getLogger("rampart.admin")

def _auth_error_response(exc: AuthError):
    return error(exc.code, exc.message)

async def _resolve_admin_actor(session, token: str):
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
            actor = await _resolve_admin_actor(session, body.token)
            print(f"[DEBUG] list_users_controller: actor.uid={actor.uid}, actor.role={actor.role}")
            return await admin_service.list_users(
                session,
                q=body.q,
                role_filter=body.role,
                banned_filter=body.banned,
                status_filter=body.status,
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
            ensure_can_manage_target(actor, target)

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
            ensure_can_manage_target(actor, target)

            history = await admin_service.get_user_analysis_history_admin(session, target_uid, body)

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
            logger.exception("admin user history failed")
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

async def create_user_controller(body: AdminCreateUserParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target = await admin_service.create_user_by_master(
                session,
                actor=actor,
                username=body.username,
                email=body.email,
                password=body.password,
                role=body.role,
            )
            return success(
                AuthStatus.REGISTER_SUCCESS,
                "สร้างบัญชีผู้ใช้สำเร็จ",
                admin_service.serialize_user(target),
            )
        except AuthError as exc:
            return _auth_error_response(exc)

async def delete_user_controller(body: AdminDeleteUserParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            target = await admin_service.delete_user(
                session, actor=actor, target_uid=target_uid
            )
            return success(
                AuthStatus.ADMIN_ACTION_SUCCESS,
                "ลบบัญชีผู้ใช้สำเร็จ",
                admin_service.serialize_user(target),
            )
        except AuthError as exc:
            return _auth_error_response(exc)


async def reset_user_password_controller(body: AdminResetUserPasswordParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            target = await admin_service.reset_user_password(
                session,
                actor=actor,
                target_uid=target_uid,
                new_password=body.new_password,
            )
            return success(
                AuthStatus.ADMIN_ACTION_SUCCESS,
                "ตั้งรหัสผ่านผู้ใช้สำเร็จ",
                admin_service.serialize_user(target),
            )
        except AuthError as exc:
            return _auth_error_response(exc)


async def delete_audit_logs_controller(body: AdminDeleteAuditLogsParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            result = await admin_service.delete_audit_logs_older_than(
                session,
                actor=actor,
                months=body.months,
            )
            return success(
                AuthStatus.ADMIN_ACTION_SUCCESS,
                "ลบ audit log เก่าสำเร็จ",
                {"deleted": result.get("deleted")},
            )
        except AuthError as exc:
            return _auth_error_response(exc)

async def admin_dashboard_summary_controller(body: AdminDashboardParams):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, body.token)
            return await admin_service.get_admin_dashboard_summary(session, trend_days=body.trend_days)
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
                q=body.q,
                date_from=body.date_from,
                date_to=body.date_to,
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

async def get_user_login_history_controller(body: AdminUserSubHistoryParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            target = await admin_service.get_user_admin_view(session, target_uid)
            if target is None:
                return error(AuthStatus.TARGET_NOT_FOUND, "ไม่พบผู้ใช้เป้าหมาย")
            ensure_can_manage_target(actor, target)
            return await admin_service.get_user_login_history_admin(
                session, target_uid, page=body.page, limit=body.limit
            )
        except AuthError as exc:
            return _auth_error_response(exc)

async def get_user_password_history_controller(body: AdminUserSubHistoryParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            target = await admin_service.get_user_admin_view(session, target_uid)
            if target is None:
                raise AuthError(404, "TARGET_NOT_FOUND", "ไม่พบผู้ใช้เป้าหมาย")
            ensure_can_manage_target(actor, target)
            return await admin_service.get_user_password_history_admin(
                session, target_uid, page=body.page, limit=body.limit
            )
        except AuthError as exc:
            return _auth_error_response(exc)

async def get_user_download_history_controller(body: AdminUserSubHistoryParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            target = await admin_service.get_user_admin_view(session, target_uid)
            if target is None:
                return error(AuthStatus.TARGET_NOT_FOUND, "ไม่พบผู้ใช้เป้าหมาย")
            ensure_can_manage_target(actor, target)
            return await admin_service.get_user_download_history_admin(
                session, target_uid, page=body.page, limit=body.limit
            )
        except AuthError as exc:
            return _auth_error_response(exc)

async def bulk_ban_users_controller(body: AdminBulkBanUsersParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uids = []
            for raw in body.target_uids:
                target_uids.append(_parse_target_uid(raw))
            return await admin_service.bulk_ban_users(
                session, actor=actor, target_uids=target_uids, reason=body.reason
            )
        except AuthError as exc:
            return _auth_error_response(exc)

async def bulk_delete_files_controller(body: AdminBulkDeleteFilesParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            aids = []
            for raw in body.aids:
                try:
                    aids.append(parse_uuid(raw))
                except (TypeError, ValueError):
                    return error("INVALID_ROLE_TARGET", "aid ไม่ถูกต้อง")
            return await admin_service.bulk_soft_delete_files(
                session, actor=actor, aids=aids, reason=body.reason
            )
        except AuthError as exc:
            return _auth_error_response(exc)

async def export_users_csv_controller(token: str):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, token)
            return await admin_service.export_users_csv(session)
        except AuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)

async def export_files_csv_controller(token: str):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, token)
            return await admin_service.export_files_csv(session)
        except AuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)

async def export_audit_logs_csv_controller(token: str):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, token)
            return await admin_service.export_audit_logs_csv(session)
        except AuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)

async def broadcast_email_controller(body: AdminBroadcastEmailParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            return await admin_service.broadcast_email(
                session,
                actor=actor,
                subject=body.subject,
                message=body.message,
                target_role=body.target_role,
            )
        except AuthError as exc:
            return _auth_error_response(exc)

async def system_health_controller(body: AdminTokenParams):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, body.token)
        except AuthError as exc:
            return _auth_error_response(exc)
    from services.admin.health_service import get_system_health
    async with SessionLocal() as session:
        return await get_system_health(session)

async def task_queue_list_controller(body: AdminTaskQueueParams):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, body.token)
            from services.admin.task_queue_service import list_active_tasks
            return await list_active_tasks(
                session, status_filter=body.status, q=body.q, page=body.page, limit=body.limit
            )
        except AuthError as exc:
            return _auth_error_response(exc)

async def task_queue_depth_controller(body: AdminTokenParams):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, body.token)
        except AuthError as exc:
            return _auth_error_response(exc)
    from services.admin.task_queue_service import get_queue_depth
    return get_queue_depth()

async def task_retry_controller(body: AdminTaskActionParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            from services.admin.task_queue_service import retry_task
            result = await retry_task(session, body.task_id)
            await admin_service.write_audit_log(
                session, actor_uid=actor.uid, target_uid=None,
                action="retry_task", detail=f"task_id={body.task_id}",
            )
            await session.commit()
            return result
        except AuthError as exc:
            return _auth_error_response(exc)

async def task_cancel_controller(body: AdminTaskActionParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            from services.admin.task_queue_service import cancel_task
            result = await cancel_task(session, body.task_id)
            await admin_service.write_audit_log(
                session, actor_uid=actor.uid, target_uid=None,
                action="cancel_task", detail=f"task_id={body.task_id}",
            )
            await session.commit()
            return result
        except AuthError as exc:
            return _auth_error_response(exc)

async def rate_limit_snapshot_controller(body: AdminTokenParams):
    async with SessionLocal() as session:
        try:
            await _resolve_admin_actor(session, body.token)
        except AuthError as exc:
            return _auth_error_response(exc)
    from services.admin.rate_limit_monitor_service import get_rate_limit_snapshot
    return get_rate_limit_snapshot()

async def rate_limit_clear_controller(body: AdminClearLockoutParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            from services.admin.rate_limit_monitor_service import clear_lockout_key
            result = clear_lockout_key(body.key)
            await admin_service.write_audit_log(
                session, actor_uid=actor.uid, target_uid=None,
                action="clear_rate_limit", detail=f"key={body.key}",
            )
            await session.commit()
            return result
        except AuthError as exc:
            return _auth_error_response(exc)

async def delete_user_history_controller(body: AdminDeleteHistoryParams):
    async with SessionLocal() as session:
        try:
            actor = await _resolve_admin_actor(session, body.token)
            target_uid = _parse_target_uid(body.target_uid)
            result = await admin_service.delete_user_history_entry(
                session,
                actor=actor,
                target_uid=target_uid,
                kind=body.kind,
                entry_id=body.entry_id,
            )
            return success(AuthStatus.ADMIN_ACTION_SUCCESS, "ลบประวัติสำเร็จ", result.get("data"))
        except AuthError as exc:
            return _auth_error_response(exc)
