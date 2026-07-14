import importlib
import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError


class FakeScalars:
    def __init__(self, users):
        self.users = users

    def all(self):
        return self.users


class FakeResult:
    def __init__(self, users):
        self.users = users

    def scalars(self):
        return FakeScalars(self.users)


class FakeSession:
    def __init__(self, users, fail=False):
        self.users = users
        self.fail = fail
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, statement):
        if self.fail:
            raise RuntimeError("database unavailable")
        return FakeResult(self.users)

    def add(self, user):
        self.added.append(user)
        self.users.append(user)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


class RaceSession(FakeSession):
    def __init__(self, winner):
        super().__init__([])
        self.winner = winner
        self.pending = None

    def add(self, user):
        self.added.append(user)
        self.pending = user

    async def commit(self):
        self.commits += 1
        if self.pending:
            self.pending = None
            self.users[:] = [self.winner]
            raise IntegrityError("INSERT", {}, RuntimeError("unique violation"))


class CaseInsensitiveEmailSession(FakeSession):
    async def execute(self, statement):
        if "lower(users.email)" in str(statement).lower():
            return FakeResult(self.users)
        return FakeResult([])


class SessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class FakeRedis:
    def __init__(self, fail=False):
        self.values = {}
        self.fail = fail

    def ping(self):
        if self.fail:
            raise RuntimeError("redis unavailable")
        return True

    def setex(self, key, ttl, value):
        if self.fail:
            raise RuntimeError("redis unavailable")
        self.values[key] = (ttl, value)


@pytest.fixture(autouse=True)
def prevent_live_redis(monkeypatch):
    monkeypatch.setattr("redis.Redis", lambda **kwargs: FakeRedis())


def user(username="console-user", email="console@example.com", role="test", status="active"):
    return SimpleNamespace(
        uid="bd591e22-19ef-4f83-98c9-4cf0ca00713f",
        username=username,
        email=email,
        role=role,
        status=status,
    )


def make_service(users=None, redis=None, fail_db=False):
    from services.test_mode_service import TestModeService

    session = FakeSession(users or [], fail=fail_db)
    service = TestModeService(
        session_factory=lambda: SessionContext(session),
        redis=redis or FakeRedis(),
        username="console-user",
        email="console@example.com",
    )
    return service, session


def load_app(test_mode, service=None):
    os.environ["TEST_MODE"] = test_mode
    import start_server
    from routers.test_route import get_test_mode_service

    app = importlib.reload(start_server).app
    if service:
        app.dependency_overrides[get_test_mode_service] = lambda: service
    return app


@pytest.mark.parametrize(
    ("users", "state"),
    [
        ([], "missing"),
        ([user()], "active"),
        ([user(status="inactive")], "inactive"),
        ([user(email="other@example.com")], "conflicting"),
        ([user(role="admin")], "conflicting"),
    ],
)
def test_status_reports_test_user_state(monkeypatch, users, state):
    monkeypatch.setenv("TEST_MODE", "TRUE")
    service, _ = make_service(users)
    response = TestClient(load_app("TRUE", service)).get("/test/api/status")

    assert response.status_code == 200
    assert response.json() == {
        "test_mode": True,
        "database": True,
        "redis": True,
        "user": state,
    }


def test_disabled_test_mode_returns_404_and_omits_openapi(monkeypatch):
    monkeypatch.setenv("TEST_MODE", "FALSE")
    client = TestClient(load_app("FALSE"))

    assert client.get("/test/api/status").status_code == 404
    assert not any(path.startswith("/test") for path in client.get("/openapi.json").json()["paths"])


def test_console_page_is_test_mode_gated(monkeypatch):
    monkeypatch.setenv("TEST_MODE", "FALSE")
    assert TestClient(load_app("FALSE")).get("/test").status_code == 404


def test_console_contains_complete_analysis_flow(monkeypatch):
    monkeypatch.setenv("TEST_MODE", "TRUE")
    response = TestClient(load_app("TRUE")).get("/test")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Test account" in response.text
    assert "Session tokens" in response.text
    assert "Upload sample" in response.text
    assert "Analysis progress" in response.text
    assert "/test/api/status" in response.text
    assert "/test/api/user" in response.text
    assert "/test/api/token" in response.text
    assert "/api/analy/v1/upload" in response.text
    assert "/api/analy/v1/task_id" in response.text
    assert "/api/analy/v1/report_target" in response.text
    assert "mock_token_for_testing" not in response.text
    assert "setTimeout" in response.text
    assert "setInterval" not in response.text
    assert "activePollGeneration" in response.text
    assert "sessionStorage" in response.text


def test_create_user_is_idempotent(monkeypatch):
    monkeypatch.setenv("TEST_MODE", "TRUE")
    service, session = make_service([])
    client = TestClient(load_app("TRUE", service))

    created = client.post("/test/api/user")
    reused = client.post("/test/api/user")

    assert created.status_code == 201
    assert reused.status_code == 200
    assert len(session.added) == 1
    assert created.json()["user"]["uid"] == reused.json()["user"]["uid"]
    assert created.json()["user"]["role"] == "test"


def test_create_user_reactivates_exact_test_identity(monkeypatch):
    monkeypatch.setenv("TEST_MODE", "TRUE")
    existing = user(status="inactive")
    service, session = make_service([existing])

    response = TestClient(load_app("TRUE", service)).post("/test/api/user")

    assert response.status_code == 200
    assert response.json()["state"] == "reactivated"
    assert existing.status == "active"
    assert session.commits == 1


@pytest.mark.parametrize(("status", "state"), [("active", "existing"), ("inactive", "reactivated")])
def test_create_user_recovers_from_identical_concurrent_insert(monkeypatch, status, state):
    monkeypatch.setenv("TEST_MODE", "TRUE")
    session = RaceSession(user(status=status))
    service, _ = make_service([])
    service.session_factory = lambda: SessionContext(session)

    response = TestClient(load_app("TRUE", service)).post("/test/api/user")

    assert response.status_code == 200
    assert response.json()["state"] == state
    assert response.json()["user"]["uid"] == session.winner.uid
    assert session.rollbacks == 1


def test_create_user_finds_case_insensitive_email_conflict(monkeypatch):
    monkeypatch.setenv("TEST_MODE", "TRUE")
    session = CaseInsensitiveEmailSession([user(username="other-user", email="CONSOLE@EXAMPLE.COM")])
    service, _ = make_service([])
    service.session_factory = lambda: SessionContext(session)

    response = TestClient(load_app("TRUE", service)).post("/test/api/user")

    assert response.status_code == 409
    assert response.json() == {"detail": "Configured test identity conflicts with an existing user."}
    assert not session.added


@pytest.mark.parametrize(
    "existing",
    [user(email="other@example.com"), user(username="other-user"), user(role="admin")],
)
def test_create_user_rejects_identity_conflicts(monkeypatch, existing):
    monkeypatch.setenv("TEST_MODE", "TRUE")
    service, _ = make_service([existing])

    response = TestClient(load_app("TRUE", service)).post("/test/api/user")

    assert response.status_code == 409
    assert response.json() == {"detail": "Configured test identity conflicts with an existing user."}


def test_token_issues_real_string_subject_tokens_and_redis_session(monkeypatch):
    monkeypatch.setenv("TEST_MODE", "TRUE")
    redis = FakeRedis()
    existing = user()
    service, _ = make_service([existing], redis)

    response = TestClient(load_app("TRUE", service)).post("/test/api/token")

    assert response.status_code == 200
    body = response.json()
    from utils.jwt import decode_token

    access = decode_token(body["access_token"])
    upload = decode_token(body["upload_token"])
    assert access["type"] == "access"
    assert upload["type"] == "upload"
    assert access["sub"] == existing.uid
    assert upload["sub"] == existing.uid
    assert redis.values[f"upload_session:{existing.uid}"] == (900, body["upload_token"])


@pytest.mark.parametrize(
    ("users", "status_code"),
    [([], 404), ([user(status="inactive")], 409), ([user(role="admin")], 409)],
)
def test_token_requires_active_nonconflicting_test_user(monkeypatch, users, status_code):
    monkeypatch.setenv("TEST_MODE", "TRUE")
    service, _ = make_service(users)

    response = TestClient(load_app("TRUE", service)).post("/test/api/token")

    assert response.status_code == status_code


def test_dependency_failures_return_stable_errors(monkeypatch):
    monkeypatch.setenv("TEST_MODE", "TRUE")
    database_service, _ = make_service([], fail_db=True)
    redis_service, _ = make_service([user()], FakeRedis(fail=True))

    database_response = TestClient(load_app("TRUE", database_service)).get("/test/api/status")
    redis_response = TestClient(load_app("TRUE", redis_service)).post("/test/api/token")

    assert database_response.status_code == 503
    assert database_response.json() == {"detail": "Test database is unavailable."}
    assert redis_response.status_code == 503
    assert redis_response.json() == {"detail": "Test Redis is unavailable."}
