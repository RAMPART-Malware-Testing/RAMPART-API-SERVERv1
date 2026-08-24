from types import SimpleNamespace

import pytest

from services.analy import analy_service


class Result:
    def __init__(self, row=None, rowcount=0):
        self.row = row
        self.rowcount = rowcount

    def first(self):
        return self.row

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row


class Session:
    def __init__(self, result=None):
        self.result = result or Result()
        self.statements = []

    async def execute(self, statement, parameters=None):
        self.statements.append((statement, parameters))
        return self.result


@pytest.mark.asyncio
async def test_hash_lock_uses_deterministic_signed_bigint():
    first = Session()
    second = Session()
    sha256 = "f" * 64

    await analy_service.acquire_analysis_hash_lock(first, sha256)
    await analy_service.acquire_analysis_hash_lock(second, sha256)

    first_sql, first_parameters = first.statements[0]
    second_sql, second_parameters = second.statements[0]
    assert "pg_advisory_xact_lock" in str(first_sql)
    assert first_parameters == second_parameters
    assert -(2**63) <= first_parameters["lock_key"] < 2**63


@pytest.mark.asyncio
async def test_task_lock_matches_sync_finalizer_expression_and_namespace():
    session = Session()

    await analy_service.acquire_analysis_task_lock(session, "shared-task")

    statement, parameters = session.statements[0]
    assert str(statement) == "SELECT pg_advisory_xact_lock(hashtextextended(:task_id, 0))"
    assert parameters == {"task_id": "shared-task"}


@pytest.mark.asyncio
async def test_update_analysis_rows_by_task_id_updates_every_attached_row():
    session = Session(Result(rowcount=2))

    count = await analy_service.update_analysis_rows_by_task_id(
        session,
        "shared-task",
        status="processing",
        rid="report-id",
    )

    statement, _ = session.statements[0]
    parameters = statement.compile().params
    assert count == 2
    assert "UPDATE analysis" in str(statement)
    assert "analysis.task_id" in str(statement)
    assert "shared-task" in parameters.values()
    assert "processing" in parameters.values()
    assert "report-id" in parameters.values()


@pytest.mark.asyncio
async def test_task_status_update_supports_task4_processing_transition():
    session = Session(Result(rowcount=2))

    count = await analy_service.update_analysis_rows_by_task_id(
        session,
        "shared-task",
        status="processing",
        from_statuses=("dispatching", "queued"),
    )

    statement, _ = session.statements[0]
    parameters = statement.compile().params
    assert count == 2
    assert "analysis.status" in str(statement)
    assert ["dispatching", "queued"] in parameters.values()
    assert "processing" in parameters.values()


@pytest.mark.asyncio
async def test_reusable_lookup_includes_committed_dispatching_jobs():
    dispatching = {"task_id": "shared-task", "status": "dispatching"}
    session = Session(Result(dispatching))

    row = await analy_service.get_file_by_hash(session, "f" * 64)

    statement, _ = session.statements[0]
    parameters = statement.compile().params
    assert row == dispatching
    assert "dispatching" in next(value for value in parameters.values() if isinstance(value, list))


@pytest.mark.asyncio
async def test_task_refresh_includes_failed_terminal_state():
    failed = {"task_id": "shared-task", "status": "failed", "rid": None}
    session = Session(Result(failed))

    row = await analy_service.get_file_by_task_id(session, "shared-task")

    statement, _ = session.statements[0]
    parameters = statement.compile().params
    assert row == failed
    assert "shared-task" in parameters.values()
    assert "failed" in next(value for value in parameters.values() if isinstance(value, list))


@pytest.mark.asyncio
async def test_attached_row_can_be_selected_by_string_user_and_shared_task():
    attached = SimpleNamespace(uid="user-b", task_id="shared-task", status="queued")
    session = Session(Result(SimpleNamespace(Analysis=attached, Reports=None)))

    row = await analy_service.get_analysis_with_report(session, "shared-task", "user-b")

    statement, _ = session.statements[0]
    parameters = statement.compile().params
    assert row == (attached, None)
    assert "shared-task" in parameters.values()
    assert "user-b" in parameters.values()
