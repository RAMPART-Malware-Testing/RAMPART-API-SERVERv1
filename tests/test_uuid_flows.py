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
    assert "/api/login" in paths
    assert "/api/reset-passwd" in paths
    assert "/api/analy/v1/dashboard/summary" in paths
    assert "/api/analy/v1/dashboard/recent-activities" in paths


@pytest.mark.asyncio
async def test_analysis_history_passes_uuid_to_service(monkeypatch):
    from controller import analysis_controller

    user_id = uuid.uuid4()
    captured = {}

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

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

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

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
async def test_login_confirm_queries_with_uuid(monkeypatch):
    from services.auth.auth_service import AuthService
    import services.auth.auth_service as auth_service

    user_id = uuid.uuid4()
    captured = {}

    class Result:
        def mappings(self):
            return self

        def one_or_none(self):
            return SimpleNamespace(uid=user_id, email="test@example.com", role="user", username="test", status="active", created_at=None)

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def execute(self, statement):
            captured["uid"] = statement.compile().params[next(key for key in statement.compile().params if key.startswith("uid_"))]
            return Result()

    monkeypatch.setattr(auth_service.TokenService, "verify_token", lambda token, kind: ({"sub": str(user_id)}, None))
    monkeypatch.setattr(auth_service.OTPService, "verify_otp", lambda *args: (True, None))
    monkeypatch.setattr(auth_service.OTPService, "clear_otp_session", lambda *args: None)
    monkeypatch.setattr(auth_service, "SessionLocal", Session)

    result = await AuthService.login_confirm(SimpleNamespace(token="token", otp="123456"), "agent", "127.0.0.1")
    assert result["success"] is True
    assert captured["uid"] == user_id


@pytest.mark.asyncio
async def test_reset_confirm_queries_with_uuid(monkeypatch):
    from services.auth.auth_service import AuthService
    import services.auth.auth_service as auth_service

    user_id = uuid.uuid4()
    captured = {}
    user = SimpleNamespace(uid=user_id, password="old")

    class Result:
        def scalar_one_or_none(self):
            return user

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def execute(self, statement):
            captured["uid"] = statement.compile().params[next(key for key in statement.compile().params if key.startswith("uid_"))]
            return Result()

        async def commit(self):
            return None

    monkeypatch.setattr(auth_service.TokenService, "verify_token", lambda token, kind: ({"sub": str(user_id)}, None))
    monkeypatch.setattr(auth_service.OTPService, "verify_otp", lambda *args: (True, None))
    monkeypatch.setattr(auth_service.OTPService, "clear_otp_session", lambda *args: None)
    monkeypatch.setattr(auth_service, "get_password_hash", lambda value: "hashed")
    monkeypatch.setattr(auth_service, "SessionLocal", Session)

    result = await AuthService.reset_confirm(SimpleNamespace(token="token", otp="123456", newPasswd="new"))
    assert result["success"] is True
    assert captured["uid"] == user_id
