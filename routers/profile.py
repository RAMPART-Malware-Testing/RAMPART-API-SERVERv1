from fastapi import APIRouter, File, Form, Request, UploadFile

from controller.profile_controller import (
    change_email_controller,
    change_password_controller,
    confirm_email_controller,
    resend_email_otp_controller,
    verify_old_email_controller,
    download_avatar_controller,
    get_download_history_controller,
    get_login_history_controller,
    get_notification_counts_controller,
    get_password_history_controller,
    get_profile_controller,
    record_download_controller,
    update_avatar_controller,
    update_username_controller,
)
from schemas.profile import (
    ChangeEmailParams,
    ChangePasswordParams,
    ConfirmEmailParams,
    VerifyOldEmailParams,
    DownloadRecordParams,
    HistoryPageParams,
    NotificationCountsParams,
    ProfileTokenParams,
    UpdateProfileParams,
)

router = APIRouter(prefix="/api/profile", tags=["Profile"])


@router.post("")
async def get_profile(body: ProfileTokenParams):
    """Returns the current user's profile, including `avatar_url`.

    `avatar_url` is `null` until the user uploads a picture via
    `POST /api/profile/avatar`.
    """
    return await get_profile_controller(body.token)


@router.patch("")
async def update_profile(body: UpdateProfileParams):
    return await update_username_controller(body.token, body.username)


@router.post("/login-history")
async def get_login_history(body: HistoryPageParams):
    return await get_login_history_controller(body.token, page=body.page, limit=body.limit)


@router.post("/download")
async def record_download(body: DownloadRecordParams):
    return await record_download_controller(body.token, body.file_name, body.tool, body.md5)


@router.post("/download-history")
async def get_download_history(body: HistoryPageParams):
    return await get_download_history_controller(body.token, page=body.page, limit=body.limit)


@router.post("/change-password")
async def change_password(body: ChangePasswordParams, request: Request):
    return await change_password_controller(
        body.token,
        body.currentPasswd,
        body.newPasswd,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
    )


@router.post("/password-history")
async def get_password_history(body: HistoryPageParams):
    return await get_password_history_controller(body.token, page=body.page, limit=body.limit)


@router.post("/notifications")
async def get_notification_counts(body: NotificationCountsParams):
    return await get_notification_counts_controller(
        body.token,
        reports_since=body.reports_since,
        public_since=body.public_since,
    )


@router.post("/avatar")
async def upload_avatar(token: str = Form(...), file: UploadFile = File(...)):
    """Uploads/replaces the user's profile picture (PNG/JPEG/WEBP, max 5MB).

    On success, `users.avatar_url` is set to a URL path serving the stored
    file (`/api/profile/avatar/{uid}.{ext}`), replacing the NULL default.
    """
    return await update_avatar_controller(token, file)


@router.get("/avatar/{file_name}")
async def get_avatar(file_name: str):
    return await download_avatar_controller(file_name)


@router.post("/change-email")
async def change_email(body: ChangeEmailParams):
    return await change_email_controller(body.token, body.email)


@router.post("/confirm-email")
async def confirm_email(body: ConfirmEmailParams):
    return await confirm_email_controller(body.token, body.otp_token, body.otp)


@router.post("/verify-old-email")
async def verify_old_email(body: VerifyOldEmailParams):
    return await verify_old_email_controller(body.token, body.otp_token, body.otp)


@router.post("/resend-email-otp")
async def resend_email_otp(body: ProfileTokenParams):
    return await resend_email_otp_controller(body.token)
