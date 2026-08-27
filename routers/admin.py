from fastapi import APIRouter
from fastapi.responses import Response

from controller.admin_controller import (
    admin_dashboard_summary_controller,
    audit_logs_controller,
    ban_user_controller,
    broadcast_email_controller,
    bulk_ban_users_controller,
    bulk_delete_files_controller,
    change_role_controller,
    delete_file_controller,
    export_audit_logs_csv_controller,
    export_files_csv_controller,
    export_users_csv_controller,
    get_user_detail_controller,
    get_user_download_history_controller,
    get_user_history_controller,
    get_user_login_history_controller,
    list_files_controller,
    list_reports_controller,
    list_users_controller,
    rate_limit_clear_controller,
    rate_limit_snapshot_controller,
    system_health_controller,
    task_cancel_controller,
    task_queue_depth_controller,
    task_queue_list_controller,
    task_retry_controller,
    unban_user_controller,
)
from schemas.admin import (
    AdminAuditLogParams,
    AdminBanUserParams,
    AdminBroadcastEmailParams,
    AdminBulkBanUsersParams,
    AdminBulkDeleteFilesParams,
    AdminChangeRoleParams,
    AdminClearLockoutParams,
    AdminDashboardParams,
    AdminDeleteFileParams,
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


@router.post("/users/login-history")
async def get_user_login_history(body: AdminUserSubHistoryParams):
    return await get_user_login_history_controller(body)


@router.post("/users/download-history")
async def get_user_download_history(body: AdminUserSubHistoryParams):
    return await get_user_download_history_controller(body)


@router.post("/users/ban")
async def ban_user(body: AdminBanUserParams):
    return await ban_user_controller(body)


@router.post("/users/unban")
async def unban_user(body: AdminUnbanUserParams):
    return await unban_user_controller(body)


@router.post("/users/role")
async def change_role(body: AdminChangeRoleParams):
    return await change_role_controller(body)


@router.post("/users/bulk-ban")
async def bulk_ban_users(body: AdminBulkBanUsersParams):
    return await bulk_ban_users_controller(body)


@router.post("/dashboard/summary")
async def admin_dashboard_summary(body: AdminDashboardParams):
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


@router.post("/files/bulk-delete")
async def bulk_delete_files(body: AdminBulkDeleteFilesParams):
    return await bulk_delete_files_controller(body)


@router.post("/reports")
async def list_reports(body: AdminListReportsParams):
    return await list_reports_controller(body)


@router.post("/export/users")
async def export_users(body: AdminTokenParams):
    csv_data = await export_users_csv_controller(body.token)
    return Response(content=csv_data, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=users.csv"})


@router.post("/export/files")
async def export_files(body: AdminTokenParams):
    csv_data = await export_files_csv_controller(body.token)
    return Response(content=csv_data, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=files.csv"})


@router.post("/export/audit-logs")
async def export_audit_logs(body: AdminTokenParams):
    csv_data = await export_audit_logs_csv_controller(body.token)
    return Response(content=csv_data, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit_logs.csv"})


@router.post("/broadcast-email")
async def broadcast_email(body: AdminBroadcastEmailParams):
    return await broadcast_email_controller(body)


@router.post("/system/health")
async def system_health(body: AdminTokenParams):
    return await system_health_controller(body)


@router.post("/tasks")
async def task_queue_list(body: AdminTaskQueueParams):
    return await task_queue_list_controller(body)


@router.post("/tasks/depth")
async def task_queue_depth(body: AdminTokenParams):
    return await task_queue_depth_controller(body)


@router.post("/tasks/retry")
async def task_retry(body: AdminTaskActionParams):
    return await task_retry_controller(body)


@router.post("/tasks/cancel")
async def task_cancel(body: AdminTaskActionParams):
    return await task_cancel_controller(body)


@router.post("/rate-limits")
async def rate_limit_snapshot(body: AdminTokenParams):
    return await rate_limit_snapshot_controller(body)


@router.post("/rate-limits/clear")
async def rate_limit_clear(body: AdminClearLockoutParams):
    return await rate_limit_clear_controller(body)
