"""Profile read/update logic: username changes and avatar picture uploads.

A brand-new OAuth user always has `avatar_url = NULL` (see
`services/oauth/oauth_service.find_or_create_user`). This module is the only
place that ever sets it to a non-NULL value, once the user explicitly
uploads a picture via `POST /api/profile/avatar`.

Avatar uploads are treated as untrusted input end-to-end (OWASP A03/A04 -
Injection / Unrestricted File Upload):
  - The client-supplied `Content-Type` is only a cheap pre-filter; the real
    gate is actually decoding the bytes with Pillow and re-encoding them
    from scratch, which rejects anything that isn't a genuine, bounded-size
    raster image (defeats mislabeled files, polyglots, and disguised
    scripts such as HTML/SVG-with-script or PHP saved with a `.png` name).
  - Re-encoding also strips EXIF/metadata and any trailing bytes a polyglot
    file might smuggle after valid image data.
  - Stored filenames are an unguessable random token, not the user's own
    uid (OWASP A01 - Broken Access Control): the old `{uid}.ext` naming let
    anyone who learned/guessed a uid fetch that user's picture directly,
    since the download route requires no authentication.
"""

import io
import secrets
import uuid
from pathlib import Path

from fastapi import HTTPException, UploadFile
from PIL import Image, UnidentifiedImageError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cores.Schema.schema_class import User

AVATAR_DIR = Path("avatars")
AVATAR_DIR.mkdir(parents=True, exist_ok=True)

# Cheap pre-filter only - fully attacker-controlled multipart metadata, never
# trusted on its own. See `_decode_and_normalize_image` for the real check.
ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg", "image/webp"}

# Canonical format -> extension, keyed off what Pillow actually detected
# after decoding the bytes (not the client's claimed Content-Type/filename).
ALLOWED_IMAGE_FORMATS = {
    "PNG": ".png",
    "JPEG": ".jpg",
    "WEBP": ".webp",
}

MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB
AVATAR_CHUNK_SIZE = 1024 * 1024

# Guards against decompression-bomb style images (huge pixel dimensions in a
# tiny file) - OWASP A04, Unrestricted Resource Consumption.
MAX_AVATAR_DIMENSION = 4096
MAX_AVATAR_PIXELS = MAX_AVATAR_DIMENSION * MAX_AVATAR_DIMENSION

# 16 random bytes -> 32 hex chars: unguessable, does not leak the uid.
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


def _assert_within_size_cap(total_size: int) -> None:
    """Raises 413 the moment the running total crosses the size cap."""
    if total_size > MAX_AVATAR_SIZE:
        raise HTTPException(status_code=413, detail="Avatar image exceeds the 5MB limit.")


def _decode_and_normalize_image(raw: bytes) -> tuple[bytes, str]:
    """Decodes `raw` as a real raster image and re-encodes it from scratch.

    This is the actual security boundary for the upload (OWASP A04 -
    Unrestricted File Upload): the client's `Content-Type` header and
    filename are never trusted. Only bytes that Pillow can successfully
    decode as PNG/JPEG/WEBP - and that fit within the configured pixel-count
    ceiling - are accepted. Re-encoding (rather than saving the original
    bytes) also drops EXIF metadata and discards any extra bytes appended
    after the image data (a common polyglot-file trick).

    Returns (encoded_bytes, extension).
    """
    try:
        with Image.open(io.BytesIO(raw)) as probe:
            probe.verify()
    except (UnidentifiedImageError, OSError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Unsupported image type. Allowed: PNG, JPEG, WEBP.",
        )

    # `verify()` leaves the image unusable for further ops (Pillow's own
    # documented behaviour) - re-open a fresh handle on the same bytes.
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

            img.load()  # fully decode now, while we still control the size cap

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
    """Unguessable filename stem, independent of the user's uid.

    The download route (`GET /api/profile/avatar/{file_name}`) has no
    auth check by design (avatars are meant to be publicly viewable once
    set), so the filename itself is the only thing standing between "you
    know the URL" and "you can see anyone's picture". A uid-based name is
    disclosed everywhere the profile is rendered/returned; a random token
    is not guessable from anything else the API exposes.
    """
    return secrets.token_hex(AVATAR_TOKEN_BYTES)


def _delete_stored_avatar(avatar_url: str | None) -> None:
    """Best-effort removal of a previously stored avatar file.

    Resolves the filename the same way the download route does (basename
    only, must resolve inside AVATAR_DIR) so a corrupted/legacy
    `avatar_url` value can never be used to delete an arbitrary path.
    """
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

    # Cheap pre-filter on the client-supplied Content-Type: rejects obvious
    # non-image uploads early, before spending any I/O on them. This is
    # NOT the security boundary - it's fully attacker-controlled multipart
    # metadata - so it never grants trust by itself.
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

    # The real validation: decode as a genuine image and re-encode it,
    # ignoring whatever the client claimed about content type/filename.
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
        # DB write failed after the file was already placed on disk - clean
        # up the orphaned new file rather than leaking it, then re-raise.
        target_path.unlink(missing_ok=True)
        raise
    await session.refresh(user)

    # Only delete the old file once the new one is durably committed, so a
    # failed upload never destroys a user's existing picture.
    _delete_stored_avatar(previous_avatar_url)

    return user
