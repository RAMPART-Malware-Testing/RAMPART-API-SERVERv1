import pytest
from fastapi import HTTPException
from types import SimpleNamespace

from controller import dashboard_controller
from schemas.dashboard import ReportsHistoryParams
from services.admin.authz import AuthError
from services.dashboard import dashboars_service


class FakeResult:
    def __init__(self, rows=None):
        self.rows = rows or []

    def scalar_one(self):
        return len(self.rows)

    def scalar(self):
        return len(self.rows)

    def one(self):
        return self.rows[0] if self.rows else {}

    def scalars(self):
        return self

    def unique(self):
        return self

    def all(self):
        return self.rows

    def mappings(self):
        return self

    def __iter__(self):
        return iter(self.rows)

    def first(self):
        return self.rows[0] if self.rows else None

    def one_or_none(self):
        return self.rows[0] if self.rows else None


class RecordingSession:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.statements = []
        self.captured_params = []

    async def execute(self, statement, parameters=None):
        self.statements.append(str(statement))
        try:
            self.captured_params.append(statement.compile().params)
        except Exception:
            self.captured_params.append({})
        return FakeResult(self.rows)


@pytest.mark.asyncio
async def test_public_feed_queries_only_match_rows_marked_public():
    session = RecordingSession()
    params = ReportsHistoryParams(token="token", page=1, limit=10)

    await dashboars_service._fetch_reports_history(session, params)

    privacy_queries = [q for q in session.statements if "analysis.privacy" in q]
    assert privacy_queries
    assert all("analysis.privacy IS false" in q for q in privacy_queries)


def _context(user=None):
    class Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return user

    return Context


async def _await(value):
    return value


@pytest.mark.asyncio
async def test_dashboard_reports_rejects_invalid_token(monkeypatch):
    def reject(session, token):
        raise AuthError(401, "INVALID_TOKEN", "token ไม่ถูกต้อง")

    monkeypatch.setattr(dashboard_controller, "SessionLocal", _context())
    monkeypatch.setattr(dashboard_controller, "get_current_user", reject)

    with pytest.raises(HTTPException) as raised:
        await dashboard_controller.reports_history_controller(ReportsHistoryParams(token="bad"))

    assert raised.value.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_reports_rejects_banned_user(monkeypatch):
    user = SimpleNamespace(uid="uid-1", role="user", is_banned=True)

    def banned(user_value):
        raise AuthError(403, "USER_NOT_ACTIVE", "บัญชีนี้ถูกระงับการใช้งาน")

    monkeypatch.setattr(dashboard_controller, "SessionLocal", _context(user))
    monkeypatch.setattr(dashboard_controller, "get_current_user", lambda session, token: _await(user))
    monkeypatch.setattr(dashboard_controller, "ensure_not_banned", banned)

    with pytest.raises(HTTPException) as raised:
        await dashboard_controller.reports_history_controller(ReportsHistoryParams(token="ok"))

    assert raised.value.status_code == 403


@pytest.mark.asyncio
async def test_dashboard_reports_passes_authenticated_request_to_service(monkeypatch):
    user = SimpleNamespace(uid="uid-1", role="user", is_banned=False)
    captured = {}

    async def service(session, params):
        captured["params"] = params
        return {"success": True, "data": []}

    monkeypatch.setattr(dashboard_controller, "SessionLocal", _context(user))
    monkeypatch.setattr(dashboard_controller, "get_current_user", lambda session, token: _await(user))
    monkeypatch.setattr(dashboard_controller, "get_reports_history", service)

    response = await dashboard_controller.reports_history_controller(ReportsHistoryParams(token="ok", limit=5))

    assert response == {"success": True, "data": []}
    assert captured["params"].limit == 5


@pytest.mark.asyncio
async def test_dashboard_reports_requires_token_field():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ReportsHistoryParams(page=1)


@pytest.mark.asyncio
async def test_summary_counts_every_in_flight_status():
    session = RecordingSession()

    await dashboars_service._fetch_dashboard_summary(session, "uid-1", "user")

    combined = "\n".join(str(params) for params in session.captured_params)
    for status in ("dispatching", "queued", "processing", "analyzing"):
        assert status in combined, status


@pytest.mark.asyncio
async def test_summary_user_count_excludes_banned_users():
    session = RecordingSession()

    await dashboars_service._fetch_dashboard_summary(session, "uid-1", "user")

    combined = "\n".join(session.statements)
    assert "users.is_banned IS false" in combined
    assert "users.status = 'active'" not in combined


@pytest.mark.asyncio
async def test_file_type_filter_is_contains_match():
    session = RecordingSession()
    params = ReportsHistoryParams(token="token", file_type="apk")

    await dashboars_service._fetch_reports_history(session, params)

    assert any("%apk%" in str(value) for params_set in session.captured_params for value in params_set.values())


@pytest.mark.asyncio
@pytest.mark.parametrize(("role", "scoped"), [("user", True), ("admin", False), ("master", False)])
async def test_recent_activities_scope_follows_admin_roles(role, scoped):
    session = RecordingSession()

    await dashboars_service._fetch_recent_activities(session, "uid-1", role)

    query = session.statements[0]
    assert ("analysis.uid = :uid_1" in query) is scoped


def test_invalidate_public_caches_clears_all_namespaces(monkeypatch):
    cleared = []
    monkeypatch.setattr(dashboars_service, "invalidate_cached", cleared.append)

    dashboars_service.invalidate_public_caches()

    assert cleared == [
        dashboars_service.DASHBOARD_SUMMARY_CACHE_NAMESPACE,
        dashboars_service.RECENT_ACTIVITIES_CACHE_NAMESPACE,
        dashboars_service.REPORTS_HISTORY_CACHE_NAMESPACE,
        dashboars_service.ANALYSIS_HISTORY_CACHE_NAMESPACE,
    ]
