import io
import secrets
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import HTTPException, UploadFile
from PIL import Image, UnidentifiedImageError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cores.Schema.schema_class import Analysis, Reports, User
from utils.cypto.PasswordCreateAndVerify import get_password_hash, verify_password

AVATAR_DIR = Path("avatars")
AVATAR_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg", "image/webp"}

ALLOWED_IMAGE_FORMATS = {
    "PNG": ".png",
    "JPEG": ".jpg",
    "WEBP": ".webp",
}

MAX_AVATAR_SIZE = 5 * 1024 * 1024
AVATAR_CHUNK_SIZE = 1024 * 1024

MAX_AVATAR_DIMENSION = 4096
MAX_AVATAR_PIXELS = MAX_AVATAR_DIMENSION * MAX_AVATAR_DIMENSION

AVATAR_TOKEN_BYTES = 16

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

async def change_password(
    session: AsyncSession, uid: uuid.UUID, current_password: str, new_password: str
) -> User:
    user = await get_user_or_404(session, uid)

    if not user.password:
        raise HTTPException(
            status_code=409,
            detail="บัญชีนี้เข้าสู่ระบบผ่านผู้ให้บริการภายนอก กรุณาใช้เมนูลืมรหัสผ่านเพื่อตั้งรหัสผ่านใหม่",
        )
    if not verify_password(user.password, current_password):
        raise HTTPException(status_code=401, detail="รหัสผ่านปัจจุบันไม่ถูกต้อง")
    if verify_password(user.password, new_password):
        raise HTTPException(status_code=400, detail="รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสผ่านเดิม")

    user.password = get_password_hash(new_password)
    await session.commit()
    await session.refresh(user)
    return user

async def unread_notification_counts(
    session: AsyncSession,
    uid: uuid.UUID,
    reports_since: datetime | None,
    public_since: datetime | None,
) -> dict[str, int]:
    finished_reports = 0
    if reports_since is not None:
        finished_reports = (
            await session.execute(
                select(func.count())
                .select_from(Analysis)
                .join(Reports, Analysis.rid == Reports.rid)
                .where(
                    Analysis.uid == uid,
                    Analysis.deleted_at.is_(None),
                    Analysis.status == "success",
                    func.greatest(Analysis.created_at, Reports.created_at) > reports_since,
                )
            )
        ).scalar_one()

    new_public_files = 0
    if public_since is not None:
        new_public_files = (
            await session.execute(
                select(func.count())
                .select_from(Analysis)
                .where(
                    Analysis.privacy.is_(False),
                    Analysis.deleted_at.is_(None),
                    Analysis.created_at > public_since,
                )
            )
        ).scalar_one()

    return {"reports": int(finished_reports), "public": int(new_public_files)}

def _assert_within_size_cap(total_size: int) -> None:
    if total_size > MAX_AVATAR_SIZE:
        raise HTTPException(status_code=413, detail="Avatar image exceeds the 5MB limit.")

def _decode_and_normalize_image(raw: bytes) -> tuple[bytes, str]:
    try:
        with Image.open(io.BytesIO(raw)) as probe:
            probe.verify()
    except (UnidentifiedImageError, OSError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Unsupported image type. Allowed: PNG, JPEG, WEBP.",
        )

    try:
        with Image.open(io.BytesIO(raw)) as img:
            image_format = (img.format or "").upper()
            extension = ALLOWED_IMAGE_FORMATS.get(image_format)
            if not extension:
                raise HTTPException(
                    status_code=400,
                    detail="Unsupported image type. Allowed: PNG, JPEG, WEBP.",
                )

            width, height = img.size
            if width <= 0 or height <= 0 or width > MAX_AVATAR_DIMENSION or height > MAX_AVATAR_DIMENSION:
                raise HTTPException(
                    status_code=400,
                    detail=f"Image dimensions must be at most {MAX_AVATAR_DIMENSION}x{MAX_AVATAR_DIMENSION}px.",
                )
            if width * height > MAX_AVATAR_PIXELS:
                raise HTTPException(status_code=400, detail="Image resolution is too large.")

            img.load()

            output = io.BytesIO()
            if image_format == "JPEG":
                rgb_img = img.convert("RGB")
                rgb_img.save(output, format="JPEG", quality=90, optimize=True)
            elif image_format == "WEBP":
                img.save(output, format="WEBP", quality=90)
            else:
                img.save(output, format="PNG", optimize=True)

            return output.getvalue(), extension
    except HTTPException:
        raise
    except Image.DecompressionBombError:
        raise HTTPException(status_code=400, detail="Image resolution is too large.")
    except (UnidentifiedImageError, OSError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Unsupported image type. Allowed: PNG, JPEG, WEBP.",
        )

def _generate_avatar_token() -> str:
    return secrets.token_hex(AVATAR_TOKEN_BYTES)

def _delete_stored_avatar(avatar_url: str | None) -> None:
    if not avatar_url:
        return
    file_name = avatar_url.rsplit("/", 1)[-1]
    if not file_name:
        return
    candidate = (AVATAR_DIR / file_name).resolve()
    if candidate.parent != AVATAR_DIR.resolve():
        return
    if candidate.is_file():
        candidate.unlink(missing_ok=True)

async def update_avatar(session: AsyncSession, uid: uuid.UUID, file: UploadFile) -> User:
    user = await get_user_or_404(session, uid)

    content_type = (file.content_type or "").lower()
    if content_type and content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Unsupported image type. Allowed: PNG, JPEG, WEBP.",
        )

    chunks: list[bytes] = []
    accumulated_size = 0
    while chunk := await file.read(AVATAR_CHUNK_SIZE):
        accumulated_size += len(chunk)
        _assert_within_size_cap(accumulated_size)
        chunks.append(chunk)

    if accumulated_size == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    raw = b"".join(chunks)
    del chunks

    encoded, extension = _decode_and_normalize_image(raw)
    del raw

    token = _generate_avatar_token()
    target_path = AVATAR_DIR / f"{token}{extension}"
    temp_path = AVATAR_DIR / f"{token}.tmp"

    try:
        with open(temp_path, "wb") as out_file:
            out_file.write(encoded)
        temp_path.replace(target_path)
    except OSError:
        temp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Failed to store avatar image.")

    previous_avatar_url = user.avatar_url
    user.avatar_url = f"/api/profile/avatar/{target_path.name}"
    try:
        await session.commit()
    except Exception:
        target_path.unlink(missing_ok=True)
        raise
    await session.refresh(user)

    _delete_stored_avatar(previous_avatar_url)

    return user
