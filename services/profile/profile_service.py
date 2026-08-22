"""Profile read/update logic: username changes and avatar picture uploads.

A brand-new OAuth user always has `avatar_url = NULL` (see
`services/oauth/oauth_service.find_or_create_user`). This module is the only
place that ever sets it to a non-NULL value, once the user explicitly
uploads a picture via `POST /api/profile/avatar`.
"""

import uuid
from pathlib import Path

from fastapi import HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cores.Schema.schema_class import User

AVATAR_DIR = Path("avatars")
AVATAR_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_AVATAR_TYPES = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
}
MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB
AVATAR_CHUNK_SIZE = 1024 * 1024


async def get_user_or_404(session: AsyncSession, uid: uuid.UUID) -> User:
    user = await session.get(User, uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def update_username(session: AsyncSession, uid: uuid.UUID, username: str) -> User:
    user = await get_user_or_404(session, uid)

    existing = await session.execute(
        select(User.uid).where(User.username == username, User.uid != uid)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Username is already taken")

    user.username = username
    await session.commit()
    await session.refresh(user)
    return user


async def update_avatar(session: AsyncSession, uid: uuid.UUID, file: UploadFile) -> User:
    user = await get_user_or_404(session, uid)

    content_type = (file.content_type or "").lower()
    extension = ALLOWED_AVATAR_TYPES.get(content_type)
    if not extension:
        raise HTTPException(
            status_code=400,
            detail="Unsupported image type. Allowed: PNG, JPEG, WEBP.",
        )

    accumulated_size = 0
    target_path = AVATAR_DIR / f"{uid}{extension}"
    temp_path = AVATAR_DIR / f"{uid}.tmp"

    try:
        with open(temp_path, "wb") as out_file:
            while chunk := await file.read(AVATAR_CHUNK_SIZE):
                accumulated_size += len(chunk)
                if accumulated_size > MAX_AVATAR_SIZE:
                    raise HTTPException(status_code=413, detail="Avatar image exceeds the 5MB limit.")
                out_file.write(chunk)

        if accumulated_size == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        # Remove any previous avatar under a different extension before
        # replacing it, so stale files don't accumulate on disk.
        for existing_ext in ALLOWED_AVATAR_TYPES.values():
            stale = AVATAR_DIR / f"{uid}{existing_ext}"
            if stale.exists() and stale != target_path:
                stale.unlink()

        temp_path.replace(target_path)
    except HTTPException:
        temp_path.unlink(missing_ok=True)
        raise
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Failed to store avatar image.")

    user.avatar_url = f"/api/profile/avatar/{target_path.name}"
    await session.commit()
    await session.refresh(user)
    return user
