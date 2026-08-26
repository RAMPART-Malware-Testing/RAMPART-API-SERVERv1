from fastapi import APIRouter

from controller.admin_controller import (
    admin_dashboard_summary_controller,
    audit_logs_controller,
    ban_user_controller,
    change_role_controller,
    delete_file_controller,
    get_user_detail_controller,
    get_user_history_controller,
    list_files_controller,
    list_reports_controller,
    list_users_controller,
    unban_user_controller,
)
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

router = APIRouter(prefix="/api/admin", tags=["Admin"])


@router.post("/users")
async def list_users(body: AdminListUsersParams):
    return await list_users_controller(body)


@router.post("/users/detail")
async def get_user_detail(body: AdminTargetUserParams):
    return await get_user_detail_controller(body)


@router.post("/users/history")
async def get_user_history(body: AdminUserHistoryParams):
    return await get_user_history_controller(body)


@router.post("/users/ban")
async def ban_user(body: AdminBanUserParams):
    return await ban_user_controller(body)


@router.post("/users/unban")
async def unban_user(body: AdminUnbanUserParams):
    return await unban_user_controller(body)


@router.post("/users/role")
async def change_role(body: AdminChangeRoleParams):
    return await change_role_controller(body)


@router.post("/dashboard/summary")
async def admin_dashboard_summary(body: AdminTokenParams):
    return await admin_dashboard_summary_controller(body)


@router.post("/audit-logs")
async def audit_logs(body: AdminAuditLogParams):
    return await audit_logs_controller(body)


@router.post("/files")
async def list_files(body: AdminListFilesParams):
    return await list_files_controller(body)


@router.post("/files/delete")
async def delete_file(body: AdminDeleteFileParams):
    return await delete_file_controller(body)


@router.post("/reports")
async def list_reports(body: AdminListReportsParams):
    return await list_reports_controller(body)
