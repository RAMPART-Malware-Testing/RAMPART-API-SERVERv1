"""Tests for the admin RBAC system: services/admin/authz.py (the single
choke point for every authorization decision) and
controller/admin_controller.py (the HTTP-facing wrappers), covering every
negative case called out in docs/superpowers/specs/2026-08-25-admin-rbac-design.md.
"""

import uuid
from types import SimpleNamespace

import pytest

from controller import admin_controller
from services.admin import admin_service
from services.admin.authz import (
    ADMIN_ROLES,
    ASSIGNABLE_ROLES,
    AuthError,
    ensure_can_manage_target,
    ensure_not_banned,
    ensure_role,
    get_current_user,
)


def make_user(role="user", is_banned=False, uid=None):
    return SimpleNamespace(
        uid=uid or uuid.uuid4(),
        username=f"user-{uuid.uuid4().hex[:8]}",
        email="user@example.com",
        avatar_url=None,
        role=role,
        status="active",
        is_banned=is_banned,
        banned_at=None,
        banned_reason=None,
        banned_by=None,
        created_at=None,
    )


# ---------------------------------------------------------------------------
# ensure_not_banned
# ---------------------------------------------------------------------------


def test_ensure_not_banned_allows_active_user():
    ensure_not_banned(make_user(is_banned=False))  # no raise


def test_ensure_not_banned_rejects_banned_user():
    with pytest.raises(AuthError) as exc:
        ensure_not_banned(make_user(is_banned=True))
    assert exc.value.status_code == 403
    assert exc.value.code == "ACCOUNT_BANNED"


# ---------------------------------------------------------------------------
# ensure_role
# ---------------------------------------------------------------------------


def test_ensure_role_allows_matching_role():
    ensure_role(make_user(role="admin"), ADMIN_ROLES)  # no raise


def test_ensure_role_rejects_plain_user_from_admin_endpoints():
    with pytest.raises(AuthError) as exc:
        ensure_role(make_user(role="user"), ADMIN_ROLES)
    assert exc.value.status_code == 403
    assert exc.value.code == "INSUFFICIENT_ROLE"


# ---------------------------------------------------------------------------
# ensure_can_manage_target - the single source of truth for the
# admin-vs-admin and master-protection rules.
# ---------------------------------------------------------------------------


def test_admin_can_manage_plain_user():
    ensure_can_manage_target(make_user(role="admin"), make_user(role="user"))  # no raise


def test_admin_cannot_manage_another_admin():
    with pytest.raises(AuthError) as exc:
        ensure_can_manage_target(make_user(role="admin"), make_user(role="admin"))
    assert exc.value.code == "ADMIN_TARGET_FORBIDDEN"


def test_admin_cannot_manage_master():
    with pytest.raises(AuthError) as exc:
        ensure_can_manage_target(make_user(role="admin"), make_user(role="master"))
    # Master protection takes precedence over the generic admin-target rule.
    assert exc.value.code == "MASTER_PROTECTED"


def test_master_can_manage_admin():
    ensure_can_manage_target(make_user(role="master"), make_user(role="admin"))  # no raise


def test_master_can_manage_plain_user():
    ensure_can_manage_target(make_user(role="master"), make_user(role="user"))  # no raise


def test_master_cannot_manage_another_master():
    with pytest.raises(AuthError) as exc:
        ensure_can_manage_target(make_user(role="master"), make_user(role="master"))
    assert exc.value.code == "MASTER_PROTECTED"


def test_master_cannot_manage_self():
    same_master = make_user(role="master")
    with pytest.raises(AuthError) as exc:
        ensure_can_manage_target(same_master, same_master)
    assert exc.value.code == "MASTER_PROTECTED"


def test_plain_user_actor_is_rejected_defensively():
    with pytest.raises(AuthError) as exc:
        ensure_can_manage_target(make_user(role="user"), make_user(role="user"))
    assert exc.value.code == "INSUFFICIENT_ROLE"


# ---------------------------------------------------------------------------
# Role assignment: master can never be assigned via the API surface.
# ---------------------------------------------------------------------------


def test_master_is_not_an_assignable_role():
    assert "master" not in ASSIGNABLE_ROLES
    assert ASSIGNABLE_ROLES == {"user", "admin"}


# ---------------------------------------------------------------------------
# get_current_user - fresh-from-DB, never trusts JWT claims
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self, user):
        self._user = user
        self.commits = 0

    async def get(self, model, uid):
        return self._user

    async def commit(self):
        self.commits += 1

    async def refresh(self, value):
        return None

    def add(self, value):
        pass


@pytest.mark.asyncio
async def test_get_current_user_rejects_invalid_token(monkeypatch):
    from services.admin import authz

    monkeypatch.setattr(
        authz.TokenService, "verify_token", lambda token, kind: (None, {"status": "TOKEN_INVALID"})
    )
    with pytest.raises(AuthError) as exc:
        await get_current_user(_FakeSession(None), "bad-token")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_missing_user(monkeypatch):
    from services.admin import authz

    monkeypatch.setattr(
        authz.TokenService, "verify_token", lambda token, kind: ({"sub": str(uuid.uuid4())}, None)
    )
    with pytest.raises(AuthError) as exc:
        await get_current_user(_FakeSession(None), "token")
    assert exc.value.code == "USER_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_current_user_returns_fresh_db_row_not_jwt_claims(monkeypatch):
    """The whole point of get_current_user: even if the JWT payload claims
    a stale role, the returned object reflects whatever is in the DB
    *right now* - simulating a role/ban change taking effect on the very
    next request without needing a new token."""
    from services.admin import authz

    uid = uuid.uuid4()
    fresh_user = make_user(role="admin", is_banned=True, uid=uid)

    monkeypatch.setattr(
        authz.TokenService,
        "verify_token",
        lambda token, kind: ({"sub": str(uid), "role": "user"}, None),  # stale claim
    )

    result = await get_current_user(_FakeSession(fresh_user), "token")
    assert result.role == "admin"  # reflects fresh DB state, not the stale "user" claim
    assert result.is_banned is True


# ---------------------------------------------------------------------------
# Controller-level: every /api/admin/* endpoint rejects a plain user
# ---------------------------------------------------------------------------


class _SessionCtx:
    """Minimal SessionLocal() async-context stand-in."""

    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *args):
        return False


def _patch_current_user(monkeypatch, user):
    async def fake_get_current_user(session, token):
        return user

    monkeypatch.setattr(admin_controller, "get_current_user", fake_get_current_user)


@pytest.mark.asyncio
async def test_plain_user_cannot_list_users(monkeypatch):
    from schemas.admin import AdminListUsersParams

    session = _FakeSession(None)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="user"))

    response = await admin_controller.list_users_controller(AdminListUsersParams(token="t"))
    assert response["success"] is False
    assert response["status"] == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_banned_admin_cannot_list_users(monkeypatch):
    """An admin/master who has themselves been banned (e.g. by another
    master) loses admin-panel access too - ensure_not_banned runs before
    ensure_role for every admin endpoint."""
    from schemas.admin import AdminListUsersParams

    session = _FakeSession(None)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="admin", is_banned=True))

    response = await admin_controller.list_users_controller(AdminListUsersParams(token="t"))
    assert response["success"] is False
    assert response["status"] == "ACCOUNT_BANNED"


@pytest.mark.asyncio
async def test_admin_can_list_users(monkeypatch):
    from schemas.admin import AdminListUsersParams

    session = _FakeSession(None)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="admin"))

    async def fake_list_users(session, **kwargs):
        return {"success": True, "data": []}

    monkeypatch.setattr(admin_service, "list_users", fake_list_users)

    response = await admin_controller.list_users_controller(AdminListUsersParams(token="t"))
    assert response["success"] is True


# ---------------------------------------------------------------------------
# Ban / unban - admin-vs-admin and master-protection enforced end to end
# through the controller, not just the bare authz function.
# ---------------------------------------------------------------------------


class _BanSession(_FakeSession):
    def __init__(self, target_user):
        super().__init__(None)
        self.target_user = target_user
        self.added = []

    async def get(self, model, uid):
        return self.target_user

    def add(self, value):
        self.added.append(value)


@pytest.mark.asyncio
async def test_admin_cannot_ban_another_admin_via_controller(monkeypatch):
    from schemas.admin import AdminBanUserParams

    target_uid = uuid.uuid4()
    target = make_user(role="admin", uid=target_uid)
    session = _BanSession(target)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="admin"))

    response = await admin_controller.ban_user_controller(
        AdminBanUserParams(token="t", target_uid=str(target_uid), reason="test")
    )
    assert response["success"] is False
    assert response["status"] == "ADMIN_TARGET_FORBIDDEN"
    # No mutation happened.
    assert target.is_banned is False
    assert session.added == []


@pytest.mark.asyncio
async def test_nobody_can_ban_master_via_controller(monkeypatch):
    from schemas.admin import AdminBanUserParams

    target_uid = uuid.uuid4()
    target = make_user(role="master", uid=target_uid)
    session = _BanSession(target)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="master"))  # even another master

    response = await admin_controller.ban_user_controller(
        AdminBanUserParams(token="t", target_uid=str(target_uid), reason="test")
    )
    assert response["success"] is False
    assert response["status"] == "MASTER_PROTECTED"
    assert target.is_banned is False


@pytest.mark.asyncio
async def test_admin_can_ban_plain_user_via_controller(monkeypatch):
    from schemas.admin import AdminBanUserParams

    target_uid = uuid.uuid4()
    target = make_user(role="user", uid=target_uid)
    session = _BanSession(target)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="admin"))

    response = await admin_controller.ban_user_controller(
        AdminBanUserParams(token="t", target_uid=str(target_uid), reason="ผิดกฎ")
    )
    assert response["success"] is True
    assert target.is_banned is True
    assert target.banned_reason == "ผิดกฎ"
    # An audit_logs row was added to the session.
    assert len(session.added) == 1
    assert session.added[0].action == "ban_user"


@pytest.mark.asyncio
async def test_master_can_ban_admin_via_controller(monkeypatch):
    from schemas.admin import AdminBanUserParams

    target_uid = uuid.uuid4()
    target = make_user(role="admin", uid=target_uid)
    session = _BanSession(target)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="master"))

    response = await admin_controller.ban_user_controller(
        AdminBanUserParams(token="t", target_uid=str(target_uid), reason="abuse")
    )
    assert response["success"] is True
    assert target.is_banned is True


# ---------------------------------------------------------------------------
# Role change - master-only, and can never set "master" even if forced.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_cannot_call_role_change_endpoint(monkeypatch):
    from schemas.admin import AdminChangeRoleParams

    target_uid = uuid.uuid4()
    target = make_user(role="user", uid=target_uid)
    session = _BanSession(target)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="admin"))

    response = await admin_controller.change_role_controller(
        AdminChangeRoleParams(token="t", target_uid=str(target_uid), new_role="admin")
    )
    assert response["success"] is False
    assert response["status"] == "INSUFFICIENT_ROLE"
    assert target.role == "user"


@pytest.mark.asyncio
async def test_master_can_promote_user_to_admin(monkeypatch):
    from schemas.admin import AdminChangeRoleParams

    target_uid = uuid.uuid4()
    target = make_user(role="user", uid=target_uid)
    session = _BanSession(target)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="master"))

    response = await admin_controller.change_role_controller(
        AdminChangeRoleParams(token="t", target_uid=str(target_uid), new_role="admin")
    )
    assert response["success"] is True
    assert target.role == "admin"


@pytest.mark.asyncio
async def test_master_can_demote_admin_to_user(monkeypatch):
    from schemas.admin import AdminChangeRoleParams

    target_uid = uuid.uuid4()
    target = make_user(role="admin", uid=target_uid)
    session = _BanSession(target)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="master"))

    response = await admin_controller.change_role_controller(
        AdminChangeRoleParams(token="t", target_uid=str(target_uid), new_role="user")
    )
    assert response["success"] is True
    assert target.role == "user"


def test_role_change_schema_rejects_master_as_new_role():
    """Even a hand-crafted request body cannot set new_role="master" -
    Pydantic validation rejects it before the controller ever runs."""
    from pydantic import ValidationError

    from schemas.admin import AdminChangeRoleParams

    with pytest.raises(ValidationError):
        AdminChangeRoleParams(token="t", target_uid=str(uuid.uuid4()), new_role="master")


@pytest.mark.asyncio
async def test_master_cannot_change_own_or_another_masters_role(monkeypatch):
    from schemas.admin import AdminChangeRoleParams

    target_uid = uuid.uuid4()
    target = make_user(role="master", uid=target_uid)
    session = _BanSession(target)
    monkeypatch.setattr(admin_controller, "SessionLocal", lambda: _SessionCtx(session))
    _patch_current_user(monkeypatch, make_user(role="master"))

    response = await admin_controller.change_role_controller(
        AdminChangeRoleParams(token="t", target_uid=str(target_uid), new_role="user")
    )
    assert response["success"] is False
    assert response["status"] == "MASTER_PROTECTED"
