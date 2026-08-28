"""Security-focused tests for profile avatar upload / username update.

Covers the OWASP-driven hardening in `services/profile/profile_service.py`
and `controller/profile_controller.py`:
  - real image decoding (Content-Type header alone is not trusted)
  - polyglot / mislabeled file rejection
  - oversized-dimension rejection (decompression-bomb guard)
  - size-limit enforcement
  - unguessable, non-uid-based filenames
  - old avatar file cleanup after a successful re-upload
  - path-traversal / arbitrary-filename rejection on download
  - username charset allowlist
"""

import io
import uuid

import pytest
from fastapi import HTTPException, UploadFile
from PIL import Image
from starlette.datastructures import Headers

from services.profile import profile_service
from controller import profile_controller

def _png_bytes(size=(16, 16), color="red") -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color=color).save(buf, format="PNG")
    return buf.getvalue()

def _jpeg_bytes(size=(16, 16), color="blue") -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color=color).save(buf, format="JPEG")
    return buf.getvalue()

def _upload_file(content: bytes, filename="avatar.png", content_type="image/png") -> UploadFile:
    return UploadFile(
        filename=filename,
        file=io.BytesIO(content),
        headers=Headers({"content-type": content_type}),
    )

class FakeUser:
    def __init__(self, uid, avatar_url=None, username="original"):
        self.uid = uid
        self.avatar_url = avatar_url
        self.username = username

class FakeScalarResult:
    def __init__(self, value=None):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

class FakeSession:
    def __init__(self, user, existing_username_uid=None):
        self.user = user
        self.existing_username_uid = existing_username_uid
        self.commits = 0
        self.refreshed = []
        self.commit_should_fail = False

    async def get(self, model, uid):
        return self.user if self.user and self.user.uid == uid else None

    async def execute(self, stmt):
        return FakeScalarResult(self.existing_username_uid)

    async def commit(self):
        if self.commit_should_fail:
            raise RuntimeError("db write failed")
        self.commits += 1

    async def refresh(self, obj):
        self.refreshed.append(obj)

@pytest.fixture(autouse=True)
def isolated_avatar_dir(tmp_path, monkeypatch):
    """Redirect AVATAR_DIR to a throwaway temp dir for every test in this
    module, so tests never touch (or depend on) the real `avatars/` dir."""
    avatar_dir = tmp_path / "avatars"
    avatar_dir.mkdir()
    monkeypatch.setattr(profile_service, "AVATAR_DIR", avatar_dir)
    monkeypatch.setattr(profile_controller, "AVATAR_DIR", avatar_dir)
    return avatar_dir

@pytest.mark.asyncio
async def test_update_avatar_accepts_genuine_png_regardless_of_declared_type():
    uid = uuid.uuid4()
    user = FakeUser(uid)
    session = FakeSession(user)
    file = _upload_file(_png_bytes(), content_type="image/png")

    result = await profile_service.update_avatar(session, uid, file)

    assert result.avatar_url is not None
    assert result.avatar_url.startswith("/api/profile/avatar/")
    assert session.commits == 1

@pytest.mark.asyncio
async def test_update_avatar_rejects_html_disguised_as_png():
    """A classic mislabeled-upload attack: attacker sets
    Content-Type: image/png but the body is actually an HTML/script
    payload. The old implementation trusted the header and would have
    stored this on disk; the new one must reject it because Pillow can't
    decode it as an image."""
    uid = uuid.uuid4()
    session = FakeSession(FakeUser(uid))
    malicious = b"<html><body><script>alert(document.cookie)</script></body></html>"
    file = _upload_file(malicious, filename="avatar.png", content_type="image/png")

    with pytest.raises(HTTPException) as exc_info:
        await profile_service.update_avatar(session, uid, file)

    assert exc_info.value.status_code == 400
    assert session.commits == 0

@pytest.mark.asyncio
async def test_update_avatar_rejects_polyglot_appended_payload():
    """A real PNG with extra bytes appended after the IEND chunk (a common
    polyglot trick to smuggle a second payload inside an 'image'). Pillow
    will decode the leading PNG fine on `verify()`/`open()`, but the
    re-encode step means only the genuine pixel data ever reaches disk -
    the appended bytes are dropped instead of being preserved."""
    uid = uuid.uuid4()
    session = FakeSession(FakeUser(uid))
    polyglot = _png_bytes() + b"<script>alert(1)</script>"
    file = _upload_file(polyglot, content_type="image/png")

    result = await profile_service.update_avatar(session, uid, file)

    stored_files = list(profile_service.AVATAR_DIR.glob("*.png"))
    assert len(stored_files) == 1
    stored_bytes = stored_files[0].read_bytes()
    assert b"<script>" not in stored_bytes
    assert result.avatar_url is not None

@pytest.mark.asyncio
async def test_update_avatar_rejects_unlisted_content_type_early():
    uid = uuid.uuid4()
    session = FakeSession(FakeUser(uid))
    file = _upload_file(b"whatever", content_type="application/pdf")

    with pytest.raises(HTTPException) as exc_info:
        await profile_service.update_avatar(session, uid, file)

    assert exc_info.value.status_code == 400
    assert session.commits == 0

@pytest.mark.asyncio
async def test_update_avatar_rejects_oversized_file(monkeypatch):
    uid = uuid.uuid4()
    session = FakeSession(FakeUser(uid))
    monkeypatch.setattr(profile_service, "MAX_AVATAR_SIZE", 100)
    file = _upload_file(_png_bytes(size=(64, 64)), content_type="image/png")

    with pytest.raises(HTTPException) as exc_info:
        await profile_service.update_avatar(session, uid, file)

    assert exc_info.value.status_code == 413

@pytest.mark.asyncio
async def test_update_avatar_rejects_empty_file():
    uid = uuid.uuid4()
    session = FakeSession(FakeUser(uid))
    file = _upload_file(b"", content_type="image/png")

    with pytest.raises(HTTPException) as exc_info:
        await profile_service.update_avatar(session, uid, file)

    assert exc_info.value.status_code == 400

@pytest.mark.asyncio
async def test_update_avatar_rejects_oversized_dimensions(monkeypatch):
    """Guards against decompression-bomb style images: a tiny file that
    decodes to an enormous pixel grid and blows up memory/CPU on decode."""
    uid = uuid.uuid4()
    session = FakeSession(FakeUser(uid))
    monkeypatch.setattr(profile_service, "MAX_AVATAR_DIMENSION", 32)
    monkeypatch.setattr(profile_service, "MAX_AVATAR_PIXELS", 32 * 32)
    file = _upload_file(_png_bytes(size=(64, 64)), content_type="image/png")

    with pytest.raises(HTTPException) as exc_info:
        await profile_service.update_avatar(session, uid, file)

    assert exc_info.value.status_code == 400

@pytest.mark.asyncio
async def test_avatar_filename_is_not_based_on_uid():
    uid = uuid.uuid4()
    session = FakeSession(FakeUser(uid))
    file = _upload_file(_png_bytes(), content_type="image/png")

    result = await profile_service.update_avatar(session, uid, file)

    assert str(uid) not in result.avatar_url

def test_generate_avatar_token_is_random_and_unguessable():
    tokens = {profile_service._generate_avatar_token() for _ in range(50)}
    assert len(tokens) == 50
    for token in tokens:
        assert len(token) == profile_service.AVATAR_TOKEN_BYTES * 2
        int(token, 16)

@pytest.mark.asyncio
async def test_update_avatar_deletes_old_avatar_after_success(isolated_avatar_dir):
    uid = uuid.uuid4()

    old_token = "a" * 32
    old_path = isolated_avatar_dir / f"{old_token}.png"
    old_path.write_bytes(_png_bytes())
    user = FakeUser(uid, avatar_url=f"/api/profile/avatar/{old_token}.png")
    session = FakeSession(user)

    file = _upload_file(_jpeg_bytes(), content_type="image/jpeg")
    result = await profile_service.update_avatar(session, uid, file)

    assert not old_path.exists()
    assert result.avatar_url != f"/api/profile/avatar/{old_token}.png"
    remaining = list(isolated_avatar_dir.glob("*"))
    assert len(remaining) == 1

@pytest.mark.asyncio
async def test_update_avatar_keeps_old_avatar_if_new_upload_is_invalid(isolated_avatar_dir):
    """A failed upload must never destroy the user's existing picture."""
    uid = uuid.uuid4()
    old_token = "b" * 32
    old_path = isolated_avatar_dir / f"{old_token}.png"
    old_path.write_bytes(_png_bytes())
    user = FakeUser(uid, avatar_url=f"/api/profile/avatar/{old_token}.png")
    session = FakeSession(user)

    file = _upload_file(b"not an image", content_type="image/png")
    with pytest.raises(HTTPException):
        await profile_service.update_avatar(session, uid, file)

    assert old_path.exists()

@pytest.mark.asyncio
async def test_update_avatar_cleans_up_new_file_if_db_commit_fails(isolated_avatar_dir):
    uid = uuid.uuid4()
    session = FakeSession(FakeUser(uid))
    session.commit_should_fail = True
    file = _upload_file(_png_bytes(), content_type="image/png")

    with pytest.raises(RuntimeError):
        await profile_service.update_avatar(session, uid, file)

    assert list(isolated_avatar_dir.glob("*")) == []

@pytest.mark.asyncio
async def test_download_avatar_rejects_path_traversal():
    with pytest.raises(HTTPException) as exc_info:
        await profile_controller.download_avatar_controller("../../../../etc/passwd")
    assert exc_info.value.status_code == 404

@pytest.mark.asyncio
async def test_download_avatar_rejects_names_not_matching_token_pattern():
    with pytest.raises(HTTPException) as exc_info:
        await profile_controller.download_avatar_controller("not-a-real-token.png")
    assert exc_info.value.status_code == 404

@pytest.mark.asyncio
async def test_download_avatar_rejects_tmp_scratch_files(isolated_avatar_dir):
    """The upload flow writes `{token}.tmp` scratch files mid-upload; the
    download route must never be tricked into serving one of those."""
    token = "c" * 32
    (isolated_avatar_dir / f"{token}.tmp").write_bytes(b"partial data")

    with pytest.raises(HTTPException) as exc_info:
        await profile_controller.download_avatar_controller(f"{token}.tmp")
    assert exc_info.value.status_code == 404

@pytest.mark.asyncio
async def test_download_avatar_serves_valid_token_with_nosniff_header(isolated_avatar_dir):
    token = "d" * 32
    (isolated_avatar_dir / f"{token}.png").write_bytes(_png_bytes())

    response = await profile_controller.download_avatar_controller(f"{token}.png")

    assert response.media_type == "image/png"
    assert response.headers["x-content-type-options"] == "nosniff"

@pytest.mark.asyncio
async def test_update_username_accepts_valid_username():
    uid = uuid.uuid4()
    session = FakeSession(FakeUser(uid), existing_username_uid=None)

    result = await profile_service.update_username(session, uid, "new_name-1.2")

    assert result.username == "new_name-1.2"
    assert session.commits == 1

@pytest.mark.asyncio
async def test_update_username_rejects_when_taken():
    uid = uuid.uuid4()
    other_uid = uuid.uuid4()
    session = FakeSession(FakeUser(uid), existing_username_uid=other_uid)

    with pytest.raises(HTTPException) as exc_info:
        await profile_service.update_username(session, uid, "taken_name")

    assert exc_info.value.status_code == 409

def test_username_schema_rejects_html_and_control_characters():
    from schemas.profile import UpdateProfileParams

    with pytest.raises(Exception):
        UpdateProfileParams(token="t", username="<script>alert(1)</script>")

def test_username_schema_rejects_whitespace_only_padding_tricks():
    from schemas.profile import UpdateProfileParams

    with pytest.raises(Exception):
        UpdateProfileParams(token="t", username="ab cd")

def test_username_schema_accepts_allowlisted_charset():
    from schemas.profile import UpdateProfileParams

    params = UpdateProfileParams(token="t", username="valid_user-name.123")
    assert params.username == "valid_user-name.123"
