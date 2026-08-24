import pytest

from tools.rebuild_database_uuid import ensure_legacy_integer_schema, insert_users


class Connection:
    def __init__(self, types):
        self.types = types

    async def fetch(self, query):
        return [(table, column, data_type) for (table, column), data_type in self.types.items()]


@pytest.mark.asyncio
async def test_rebuild_rejects_already_uuid_schema():
    connection = Connection({
        ("users", "uid"): "uuid",
        ("reports", "rid"): "uuid",
        ("audit_logs", "log_id"): "uuid",
        ("analysis", "aid"): "uuid",
    })

    with pytest.raises(RuntimeError, match="already uses UUID"):
        await ensure_legacy_integer_schema(connection)


@pytest.mark.asyncio
async def test_rebuild_accepts_complete_integer_schema():
    connection = Connection({
        ("users", "uid"): "integer",
        ("reports", "rid"): "integer",
        ("audit_logs", "log_id"): "integer",
        ("analysis", "aid"): "integer",
    })

    await ensure_legacy_integer_schema(connection)


@pytest.mark.asyncio
async def test_users_restore_creator_references_after_all_users_exist():
    class RestoreConnection:
        def __init__(self):
            self.calls = []

        async def execute(self, query, *args):
            self.calls.append((query, args))

    connection = RestoreConnection()
    rows = [
        {"uid": 1, "username": "child", "email": "child@example.com", "password": "x", "role": "user", "status": "active", "created_by": 2, "created_at": None, "fcm_token": None},
        {"uid": 2, "username": "parent", "email": "parent@example.com", "password": "x", "role": "admin", "status": "active", "created_by": None, "created_at": None, "fcm_token": None},
    ]
    mappings = {"users": {"1": "00000000-0000-4000-8000-000000000001", "2": "00000000-0000-4000-8000-000000000002"}}

    await insert_users(connection, rows, mappings)

    assert len(connection.calls) == 3
    assert all(call[1][6] is None for call in connection.calls[:2])
    assert connection.calls[2][1] == (
        "00000000-0000-4000-8000-000000000002",
        "00000000-0000-4000-8000-000000000001",
    )
