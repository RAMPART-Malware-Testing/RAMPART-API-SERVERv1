from fastapi import APIRouter, File, Form, UploadFile

from controller.profile_controller import (
    download_avatar_controller,
    get_profile_controller,
    update_avatar_controller,
    update_username_controller,
)
from schemas.profile import ProfileTokenParams, UpdateProfileParams

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
