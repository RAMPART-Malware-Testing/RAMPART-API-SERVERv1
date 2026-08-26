import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_access_dependency_returns_uuid(monkeypatch):
    from deps import auth

    user_id = uuid.uuid4()
    monkeypatch.setattr(auth, "verify_access_token", lambda token: str(user_id))

    assert await auth.require_access_token("token") == user_id


@pytest.mark.asyncio
async def test_access_dependency_rejects_malformed_subject(monkeypatch):
    from deps import auth

    monkeypatch.setattr(auth, "verify_access_token", lambda token: "not-a-uuid")

    with pytest.raises(HTTPException) as exc:
        await auth.require_access_token("token")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_access_dependency_converts_verifier_error_to_401(monkeypatch):
    from deps import auth

    def invalid(token):
        raise ValueError("invalid token")

    monkeypatch.setattr(auth, "verify_access_token", invalid)

    with pytest.raises(HTTPException) as exc:
        await auth.require_access_token("token")
    assert exc.value.status_code == 401


def test_server_mounts_auth_and_dashboard_routes():
    import start_server

    paths = start_server.app.openapi()["paths"]
    assert "/api/auth/{provider}/login" in paths
    assert "/api/auth/{provider}/callback" in paths
    assert "/api/profile" in paths
    assert "/api/profile/avatar" in paths
    assert "/api/analy/v1/dashboard/summary" in paths
    assert "/api/analy/v1/dashboard/recent-activities" in paths


@pytest.mark.asyncio
async def test_analysis_history_passes_uuid_to_service(monkeypatch):
    from controller import analysis_controller

    user_id = uuid.uuid4()
    captured = {}
    fake_user = SimpleNamespace(uid=user_id, role="user", is_banned=False)

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return fake_user

    async def history(session, uid, body):
        captured["uid"] = uid
        return {"success": True}

    monkeypatch.setattr(analysis_controller.TokenService, "verify_token", lambda token, kind: ({"sub": str(user_id)}, None))
    monkeypatch.setattr(analysis_controller, "SessionLocal", Session)
    monkeypatch.setattr(analysis_controller, "get_analysis_history", history)

    body = SimpleNamespace(token="token")
    assert await analysis_controller.history_controller(body) == {"success": True}
    assert captured["uid"] == user_id


@pytest.mark.asyncio
async def test_analysis_report_rejects_malformed_uuid():
    from controller import analysis_controller

    with pytest.raises(HTTPException) as exc:
        await analysis_controller.analysisReport_controller("not-a-uuid", "task")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_upload_token_boundary_rejects_malformed_subject(monkeypatch):
    from controller import analysis_controller

    monkeypatch.setattr(analysis_controller.TokenService, "verify_token", lambda token, kind: ({"sub": "legacy-int"}, None))

    with pytest.raises(HTTPException) as exc:
        await analysis_controller.require_upload_token("token")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_generate_upload_token_rejects_malformed_subject(monkeypatch):
    from controller import analysis_controller

    monkeypatch.setattr(analysis_controller.TokenService, "verify_token", lambda token, kind: ({"sub": "legacy-int"}, None))

    with pytest.raises(HTTPException) as exc:
        await analysis_controller.generateToken_controller("token")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("controller_name,service_name", [
    ("dashboard_summary_controller", "get_dashboard_summary"),
    ("recent_activities_controller", "get_recent_activities"),
])
async def test_dashboard_controllers_pass_uuid(monkeypatch, controller_name, service_name):
    from controller import dashboard_controller

    user_id = uuid.uuid4()
    captured = {}
    fake_user = SimpleNamespace(uid=user_id, role="user", is_banned=False)

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return fake_user

    async def service(session, uid, role):
        captured["uid"] = uid
        return {"success": True}

    monkeypatch.setattr(dashboard_controller.TokenService, "verify_token", lambda token, kind: ({"sub": str(user_id)}, None))
    monkeypatch.setattr(dashboard_controller, "SessionLocal", Session)
    monkeypatch.setattr(dashboard_controller, service_name, service)

    result = await getattr(dashboard_controller, controller_name)(dashboard_controller.DashboardParams(token="token"))
    assert result == {"success": True}
    assert captured["uid"] == user_id


@pytest.mark.asyncio
async def test_find_or_create_user_reuses_uid_on_repeat_login(monkeypatch):
    """A second login from the same provider account must resolve to the
    exact same `uid` as the first - never create a duplicate user."""
    from services.oauth.oauth_service import OAuthProfile, find_or_create_user
    import services.oauth.oauth_service as oauth_service

    existing_uid = uuid.uuid4()
    existing_user = SimpleNamespace(uid=existing_uid, email="dev@example.com", username="dev")

    class LinkedAccountResult:
        def scalar_one_or_none(self):
            return SimpleNamespace(uid=existing_uid)

    class Session:
        async def execute(self, statement):
            return LinkedAccountResult()

        async def get(self, model, uid):
            assert uid == existing_uid
            return existing_user

    profile = OAuthProfile(
        provider="google",
        provider_uid="google-123",
        email="dev@example.com",
        email_verified=True,
        display_name="Dev",
    )

    user = await find_or_create_user(Session(), profile)
    assert user is existing_user
    assert user.uid == existing_uid


@pytest.mark.asyncio
async def test_find_or_create_user_creates_new_account_on_first_login():
    from services.oauth.oauth_service import OAuthProfile, find_or_create_user

    class EmptyResult:
        def scalar_one_or_none(self):
            return None

    class Session:
        def __init__(self):
            self.added = []

        async def execute(self, statement):
            # No linked oauth_account, no existing user by e-mail, and every
            # candidate username is free - all resolve to "not found".
            return EmptyResult()

        def add(self, obj):
            self.added.append(obj)
            if getattr(obj, "uid", None) is None:
                obj.uid = uuid.uuid4()

        async def flush(self):
            return None

        async def commit(self):
            return None

        async def refresh(self, obj):
            return None

    profile = OAuthProfile(
        provider="github",
        provider_uid="gh-456",
        email="newuser@example.com",
        email_verified=True,
        display_name="New User",
    )

    session = Session()
    user = await find_or_create_user(session, profile)
    assert user.email == "newuser@example.com"
    assert user.avatar_url is None
    assert user.username.startswith("NewUser")


@pytest.mark.asyncio
async def test_find_or_create_user_rejects_unverified_email_linking_into_existing_account(monkeypatch):
    """A NEW OAuth identity (no existing OAuthAccount row) whose e-mail
    happens to match an ALREADY-EXISTING account (e.g. one that registered
    via /api/auth/register with a password) must only be auto-linked if
    the OAuth provider actually verified that e-mail address - otherwise
    anyone could claim someone else's unverified e-mail with a rogue OAuth
    app and get silently merged into that person's account."""
    from services.oauth.oauth_service import OAuthError, OAuthProfile, find_or_create_user

    existing_user = SimpleNamespace(uid=uuid.uuid4(), email="victim@example.com", username="victim", role="user", is_banned=False)

    class NoLinkedAccountResult:
        def scalar_one_or_none(self):
            return None

    class ExistingUserByEmailResult:
        def scalar_one_or_none(self):
            return existing_user

    class Session:
        def __init__(self):
            self._call = 0

        async def execute(self, statement):
            self._call += 1
            # 1st call: OAuthAccount(provider, provider_uid) lookup -> miss.
            # 2nd call: User.email lookup -> hits the existing account.
            return NoLinkedAccountResult() if self._call == 1 else ExistingUserByEmailResult()

    profile = OAuthProfile(
        provider="github",
        provider_uid="gh-attacker-999",
        email="victim@example.com",
        email_verified=False,  # provider did NOT verify this address
        display_name="Attacker",
    )

    with pytest.raises(OAuthError):
        await find_or_create_user(Session(), profile)


@pytest.mark.asyncio
async def test_find_or_create_user_links_verified_email_into_existing_account(monkeypatch):
    """The legitimate counterpart: a verified e-mail match against an
    existing account DOES auto-link (unchanged prior behavior), so a user
    who registered with a password and later signs in with a verified
    Google account of the same address gets connected to the same uid."""
    from services.oauth.oauth_service import OAuthProfile, find_or_create_user

    existing_uid = uuid.uuid4()
    existing_user = SimpleNamespace(uid=existing_uid, email="real-user@example.com", username="realuser", role="user", is_banned=False)

    class NoLinkedAccountResult:
        def scalar_one_or_none(self):
            return None

    class ExistingUserByEmailResult:
        def scalar_one_or_none(self):
            return existing_user

    class Session:
        def __init__(self):
            self._call = 0
            self.added = []

        async def execute(self, statement):
            self._call += 1
            return NoLinkedAccountResult() if self._call == 1 else ExistingUserByEmailResult()

        def add(self, obj):
            self.added.append(obj)

        async def commit(self):
            return None

        async def refresh(self, obj):
            return None

    profile = OAuthProfile(
        provider="google",
        provider_uid="google-legit-1",
        email="real-user@example.com",
        email_verified=True,
        display_name="Real User",
    )

    session = Session()
    user = await find_or_create_user(session, profile)
    assert user is existing_user
    assert user.uid == existing_uid
    # A new OAuthAccount row was linked to the existing user.
    assert len(session.added) == 1
    assert session.added[0].uid == existing_uid
