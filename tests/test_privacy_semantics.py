import pytest
from fastapi import HTTPException
from types import SimpleNamespace

from controller import analysis_controller
from services.analy import analy_service


class FakeResult:
    def __init__(self, rows=None):
        self.rows = rows or []

    def scalar_one(self):
        return len(self.rows)

    def scalars(self):
        return self

    def unique(self):
        return self

    def all(self):
        return self.rows

    def mappings(self):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def one_or_none(self):
        return self.rows[0] if self.rows else None


class RecordingSession:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.statements = []

    async def execute(self, statement, parameters=None):
        self.statements.append(str(statement))
        return FakeResult(self.rows)


@pytest.mark.asyncio
async def test_public_report_view_only_matches_rows_marked_public():
    session = RecordingSession()

    await analy_service.get_public_analysis_with_report(session, "task-1")

    query = session.statements[0]
    assert "analysis.privacy IS false" in query
    assert "analysis.privacy = true" not in query


def _download_context(user):
    class Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return user

        async def commit(self):
            return None

    return Context


async def _await(value):
    return value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("requester_uid", "rows", "allowed"),
    [
        ("other-1", [("owner-1", False, "rid-1")], True),
        ("other-1", [("owner-1", False, None)], True),
        ("owner-1", [("owner-1", True, "rid-1")], True),
        ("owner-1", [("owner-1", True, None)], False),
        ("other-1", [("owner-1", True, "rid-1")], False),
        ("other-1", [("owner-1", None, "rid-1")], False),
    ],
)
async def test_download_requires_owner_or_public_row(monkeypatch, tmp_path, requester_uid, rows, allowed):
    report = tmp_path / f"virustotal-{'a' * 32}.json"
    report.write_text("{}", encoding="utf-8")
    user = SimpleNamespace(uid=requester_uid, role="user", is_banned=False)

    monkeypatch.setattr(analysis_controller, "BASE_REPORT_PATH", tmp_path)
    monkeypatch.setattr(analysis_controller, "SessionLocal", _download_context(user))
    monkeypatch.setattr(analysis_controller, "get_current_user", lambda session, token: _await(user))
    monkeypatch.setattr(
        analysis_controller,
        "get_analysis_access_rows_by_md5",
        lambda session, md5: _await([SimpleNamespace(uid=u, privacy=p, rid=r) for u, p, r in rows]),
    )

    if allowed:
        result = await analysis_controller.downloadReport_controller(report.name, "token")
        assert result == report.resolve()
    else:
        with pytest.raises(HTTPException) as raised:
            await analysis_controller.downloadReport_controller(report.name, "token")
        assert raised.value.status_code == 403


@pytest.mark.asyncio
async def test_admin_download_of_private_report_is_audited(monkeypatch, tmp_path):
    report = tmp_path / f"mobsf-{'a' * 32}.json"
    report.write_text("{}", encoding="utf-8")
    admin = SimpleNamespace(uid="admin-1", role="master", is_banned=False)
    audited = {}

    async def write_audit_log(session, **kwargs):
        audited.update(kwargs)

    monkeypatch.setattr(analysis_controller, "BASE_REPORT_PATH", tmp_path)
    monkeypatch.setattr(analysis_controller, "SessionLocal", _download_context(admin))
    monkeypatch.setattr(analysis_controller, "get_current_user", lambda session, token: _await(admin))
    monkeypatch.setattr(
        analysis_controller,
        "get_analysis_access_rows_by_md5",
        lambda session, md5: _await([SimpleNamespace(uid="owner-1", privacy=True, rid="rid-1")]),
    )
    monkeypatch.setattr(analysis_controller, "write_audit_log", write_audit_log)

    result = await analysis_controller.downloadReport_controller(report.name, "token")

    assert result == report.resolve()
    assert audited["action"] == "download_private_report"
    assert audited["target_uid"] == "owner-1"


@pytest.mark.asyncio
async def test_update_privacy_invalidates_public_caches(monkeypatch):
    invalidated = []
    analysis = SimpleNamespace(task_id="task-1", privacy=True, aid="aid-1")
    user = SimpleNamespace(uid="00000000-0000-4000-8000-000000000001", is_banned=False)

    class Context:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, model, uid):
            return user

        async def commit(self):
            return None

        async def refresh(self, value):
            return None

    monkeypatch.setattr(analysis_controller, "SessionLocal", Context)
    monkeypatch.setattr(
        analysis_controller.TokenService,
        "verify_token",
        lambda token, kind: ({"sub": "00000000-0000-4000-8000-000000000001"}, None),
    )
    monkeypatch.setattr(
        analysis_controller,
        "get_analysis_with_report",
        lambda session, task_id, uid: _await((analysis, None)),
    )
    monkeypatch.setattr(analysis_controller, "invalidate_public_caches", lambda: invalidated.append("caches"))

    response = await analysis_controller.update_privacy_controller(
        "task-1", "token", False
    )

    assert response["privacy"] is False
    assert invalidated == ["caches"]
