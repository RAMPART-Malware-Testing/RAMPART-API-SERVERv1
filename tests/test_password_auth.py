"""Smoke tests for the local email+password+OTP auth flow (restored
alongside OAuth in commit 1d69804), covering
services/auth/auth_service.py::AuthService end-to-end against mocked DB
sessions. This flow previously had zero test coverage.

Key behavior under test: password auth must coexist safely with
OAuth-only accounts (`User.password IS NULL`) - login must reject those
with INVALID_CREDENTIALS rather than crash on `verify_password(None, ...)`.
"""

import uuid
from types import SimpleNamespace

import pytest

from services.auth import auth_service as auth_service_module
from services.auth.auth_service import AuthService
from utils.cypto.PasswordCreateAndVerify import get_password_hash


def make_user(uid=None, email="user@example.com", password=None, username="tester", role="user", status="active"):
    return SimpleNamespace(
        uid=uid or uuid.uuid4(),
        email=email,
        password=password,
        username=username,
        role=role,
        status=status,
        created_at=None,
        __dict__={},
    )


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

    def mappings(self):
        return self

    def one_or_none(self):
        return self._value


class FakeSession:
    """Minimal SessionLocal() async-context stand-in. `queue` is a list of
    values returned in order by successive `.execute()` calls (most
    AuthService methods only call it once per session block, but some
    open a second SessionLocal() block later - each gets its own
    FakeSession instance via fake_session_factory below)."""

    def __init__(self, value):
        self._value = value
        self.committed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def execute(self, stmt):
        return _ScalarResult(self._value)

    async def commit(self):
        self.committed = True

    def add(self, value):
        pass


def patch_session(monkeypatch, value):
    """Every AuthService method that touches the DB does
    `async with SessionLocal() as session:` fresh each time - patch the
    factory to always return a session that yields `value` from execute()."""
    monkeypatch.setattr(auth_service_module, "SessionLocal", lambda: FakeSession(value))


# ---------------------------------------------------------------------------
# login()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_rejects_unknown_email(monkeypatch):
    patch_session(monkeypatch, None)
    response = await AuthService.login(
        SimpleNamespace(email="nobody@example.com", password="whatever"), "ua", "127.0.0.1", ""
    )
    assert response["success"] is False
    assert response["status"] == "USER_NOT_FOUND"


@pytest.mark.asyncio
async def test_login_rejects_oauth_only_account_with_null_password(monkeypatch):
    """The critical coexistence case: a user who only ever signed in via
    Google/GitHub has password=None. Logging in with a password must be
    rejected cleanly, not crash inside verify_password(None, ...)."""
    user = make_user(password=None)
    patch_session(monkeypatch, user)
    response = await AuthService.login(
        SimpleNamespace(email=user.email, password="anything"), "ua", "127.0.0.1", ""
    )
    assert response["success"] is False
    assert response["status"] == "INVALID_CREDENTIALS"


@pytest.mark.asyncio
async def test_login_rejects_wrong_password(monkeypatch):
    user = make_user(password=get_password_hash("correct-horse-battery-staple"))
    patch_session(monkeypatch, user)
    response = await AuthService.login(
        SimpleNamespace(email=user.email, password="wrong-password"), "ua", "127.0.0.1", ""
    )
    assert response["success"] is False
    assert response["status"] == "INVALID_CREDENTIALS"


@pytest.mark.asyncio
async def test_login_sends_otp_on_correct_password(monkeypatch):
    plain = "correct-horse-battery-staple"
    user = make_user(password=get_password_hash(plain))
    patch_session(monkeypatch, user)

    captured = {}

    async def fake_create_otp_session(*, action, identifier, token, email):
        captured["action"] = action
        captured["identifier"] = identifier
        captured["email"] = email
        return {"success": True, "status": "OTP_SENT", "message": "sent", "data": {"token": token}}

    monkeypatch.setattr(auth_service_module.OTPService, "create_otp_session", fake_create_otp_session)

    response = await AuthService.login(SimpleNamespace(email=user.email, password=plain), "ua", "127.0.0.1", "")
    assert response["success"] is True
    assert response["status"] == "OTP_SENT"
    assert captured["action"] == "login"
    assert captured["identifier"] == str(user.uid)


@pytest.mark.asyncio
async def test_login_bypasses_otp_with_valid_trusted_device_token(monkeypatch):
    plain = "correct-horse-battery-staple"
    user = make_user(password=get_password_hash(plain))
    patch_session(monkeypatch, user)

    monkeypatch.setattr(
        auth_service_module.TokenService,
        "verify_token",
        lambda token, kind: ({"sub": str(user.uid), "type": "device"}, None),
    )

    response = await AuthService.login(
        SimpleNamespace(email=user.email, password=plain), "ua", "127.0.0.1", "trusted-device-token"
    )
    assert response["success"] is True
    assert response["data"]["bypass_otp"] is True
    assert "access_token" in response["data"]
    # Sensitive fields never leak into the response.
    assert "password" not in response["data"]["data"]


@pytest.mark.asyncio
async def test_login_falls_back_to_otp_when_device_token_invalid(monkeypatch):
    plain = "correct-horse-battery-staple"
    user = make_user(password=get_password_hash(plain))
    patch_session(monkeypatch, user)

    monkeypatch.setattr(
        auth_service_module.TokenService,
        "verify_token",
        lambda token, kind: (None, {"success": False, "status": "TOKEN_INVALID", "message": "bad"}),
    )

    async def fake_create_otp_session(*, action, identifier, token, email):
        return {"success": True, "status": "OTP_SENT", "message": "sent", "data": {"token": token}}

    monkeypatch.setattr(auth_service_module.OTPService, "create_otp_session", fake_create_otp_session)

    response = await AuthService.login(
        SimpleNamespace(email=user.email, password=plain), "ua", "127.0.0.1", "stale-or-forged-token"
    )
    assert response["status"] == "OTP_SENT"


# ---------------------------------------------------------------------------
# login_confirm()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_confirm_rejects_wrong_otp(monkeypatch):
    uid = uuid.uuid4()
    monkeypatch.setattr(
        auth_service_module.TokenService,
        "verify_token",
        lambda token, kind: ({"sub": str(uid), "type": "login"}, None),
    )
    monkeypatch.setattr(auth_service_module.OTPService, "verify_otp", lambda action, token, otp: (False, "รหัส OTP ไม่ถูกต้องหรือหมดอายุ"))

    response = await AuthService.login_confirm(SimpleNamespace(token="tok", otp="000000"), "ua", "127.0.0.1")
    assert response["success"] is False
    assert response["status"] == "OTP_INVALID"


class _MappingRow(dict):
    """RowMapping stand-in: supports both attribute access (user.uid) and
    subscript access (user["uid"]) plus .keys(), matching how
    login_confirm's `result.mappings().one_or_none()` row is used."""

    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError as exc:
            raise AttributeError(item) from exc


@pytest.mark.asyncio
async def test_login_confirm_issues_tokens_on_correct_otp(monkeypatch):
    uid = uuid.uuid4()
    user_row = _MappingRow(uid=uid, email="user@example.com", role="user", username="tester", status="active", created_at=None)

    monkeypatch.setattr(
        auth_service_module.TokenService,
        "verify_token",
        lambda token, kind: ({"sub": str(uid), "type": "login"}, None),
    )
    monkeypatch.setattr(auth_service_module.OTPService, "verify_otp", lambda action, token, otp: (True, None))
    monkeypatch.setattr(auth_service_module.OTPService, "clear_otp_session", lambda *a, **k: None)
    patch_session(monkeypatch, user_row)

    response = await AuthService.login_confirm(SimpleNamespace(token="tok", otp="123456"), "ua", "127.0.0.1")
    assert response["success"] is True
    assert response["status"] == "LOGIN_SUCCESS"
    assert "access_token" in response["data"]
    assert "refresh_token" in response["data"]


# ---------------------------------------------------------------------------
# register() / register_confirm()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_rejects_duplicate_email(monkeypatch):
    existing = make_user(email="taken@example.com")
    patch_session(monkeypatch, existing)

    response = await AuthService.register(
        SimpleNamespace(username="newuser", email="taken@example.com", password="Sup3rSecret!")
    )
    assert response["success"] is False


@pytest.mark.asyncio
async def test_register_sends_otp_for_new_email(monkeypatch):
    patch_session(monkeypatch, None)

    captured = {}

    async def fake_create_otp_session(*, action, identifier, token, email):
        captured["action"] = action
        captured["email"] = email
        return {"success": True, "status": "OTP_SENT", "message": "sent", "data": {"token": token}}

    monkeypatch.setattr(auth_service_module.OTPService, "create_otp_session", fake_create_otp_session)

    response = await AuthService.register(
        SimpleNamespace(username="newuser", email="new@example.com", password="Sup3rSecret!")
    )
    assert response["status"] == "OTP_SENT"
    assert captured["action"] == "register"
    assert captured["email"] == "new@example.com"


@pytest.mark.asyncio
async def test_register_confirm_creates_user_with_hashed_password(monkeypatch):
    added_users = []

    class RegisterSession(FakeSession):
        def add(self, value):
            added_users.append(value)

    monkeypatch.setattr(auth_service_module, "SessionLocal", lambda: RegisterSession(None))
    monkeypatch.setattr(
        auth_service_module.TokenService,
        "verify_token",
        lambda token, kind: (
            {"sub": "new@example.com", "type": "register", "username": "newuser", "password": "Sup3rSecret!"},
            None,
        ),
    )
    monkeypatch.setattr(auth_service_module.OTPService, "verify_otp", lambda action, token, otp: (True, None))
    monkeypatch.setattr(auth_service_module.OTPService, "clear_otp_session", lambda *a, **k: None)

    response = await AuthService.register_confirm(SimpleNamespace(token="tok", otp="123456", username=None))
    assert response["success"] is True
    assert response["status"] == "REGISTER_SUCCESS"

    assert len(added_users) == 1
    created = added_users[0]
    assert created.email == "new@example.com"
    assert created.role == "user"
    # Password is hashed, never stored in plaintext.
    assert created.password != "Sup3rSecret!"
    from utils.cypto.PasswordCreateAndVerify import verify_password
    assert verify_password(created.password, "Sup3rSecret!") is True


# ---------------------------------------------------------------------------
# reset() / reset_confirm()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reset_rejects_unknown_email(monkeypatch):
    patch_session(monkeypatch, None)
    response = await AuthService.reset(SimpleNamespace(email="nobody@example.com", token=None, newPasswd=None))
    assert response["success"] is False
    assert response["status"] == "USER_NOT_FOUND"


@pytest.mark.asyncio
async def test_reset_sends_otp_for_known_email(monkeypatch):
    uid = uuid.uuid4()
    row = SimpleNamespace(uid=uid, email="user@example.com")
    patch_session(monkeypatch, row)

    async def fake_create_otp_session(*, action, identifier, token, email):
        return {"success": True, "status": "OTP_SENT", "message": "sent", "data": {"token": token}}

    monkeypatch.setattr(auth_service_module.OTPService, "create_otp_session", fake_create_otp_session)

    response = await AuthService.reset(SimpleNamespace(email="user@example.com", token=None, newPasswd=None))
    assert response["status"] == "OTP_SENT"


@pytest.mark.asyncio
async def test_reset_confirm_actually_updates_password_hash(monkeypatch):
    uid = uuid.uuid4()
    user = make_user(uid=uid, password=get_password_hash("old-password"))
    patch_session(monkeypatch, user)

    monkeypatch.setattr(
        auth_service_module.TokenService,
        "verify_token",
        lambda token, kind: ({"sub": str(uid), "type": "reset-passwd"}, None),
    )
    monkeypatch.setattr(auth_service_module.OTPService, "verify_otp", lambda action, token, otp: (True, None))
    monkeypatch.setattr(auth_service_module.OTPService, "clear_otp_session", lambda *a, **k: None)

    response = await AuthService.reset_confirm(
        SimpleNamespace(token="tok", otp="123456", newPasswd="brand-new-password")
    )
    assert response["success"] is True
    assert response["status"] == "PASSWORD_RESET_SUCCESS"

    from utils.cypto.PasswordCreateAndVerify import verify_password
    assert verify_password(user.password, "brand-new-password") is True
    assert verify_password(user.password, "old-password") is False


@pytest.mark.asyncio
async def test_reset_confirm_rejects_wrong_otp(monkeypatch):
    uid = uuid.uuid4()
    monkeypatch.setattr(
        auth_service_module.TokenService,
        "verify_token",
        lambda token, kind: ({"sub": str(uid), "type": "reset-passwd"}, None),
    )
    monkeypatch.setattr(auth_service_module.OTPService, "verify_otp", lambda action, token, otp: (False, "invalid"))

    response = await AuthService.reset_confirm(
        SimpleNamespace(token="tok", otp="000000", newPasswd="brand-new-password")
    )
    assert response["success"] is False
    assert response["status"] == "OTP_INVALID"


# ---------------------------------------------------------------------------
# refresh_token()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_token_rejects_banned_or_inactive_user(monkeypatch):
    uid = uuid.uuid4()
    row = SimpleNamespace(uid=uid, status="inactive")
    monkeypatch.setattr(
        auth_service_module.TokenService,
        "verify_token",
        lambda token, kind: ({"sub": str(uid), "type": "refresh_token"}, None),
    )
    patch_session(monkeypatch, row)

    response = await AuthService.refresh_token("refresh-tok")
    assert response["success"] is False


@pytest.mark.asyncio
async def test_refresh_token_issues_new_tokens_for_active_user(monkeypatch):
    uid = uuid.uuid4()
    row = SimpleNamespace(uid=uid, status="active")
    monkeypatch.setattr(
        auth_service_module.TokenService,
        "verify_token",
        lambda token, kind: ({"sub": str(uid), "type": "refresh_token"}, None),
    )
    patch_session(monkeypatch, row)

    response = await AuthService.refresh_token("refresh-tok")
    assert response["success"] is True
    assert response["status"] == "TOKEN_REFRESH_SUCCESS"
    assert "access_token" in response["data"]
    assert "refresh_token" in response["data"]
