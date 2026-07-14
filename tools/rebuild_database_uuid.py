import argparse
import asyncio
import hashlib
import json
import os
import uuid
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import asyncpg
from dotenv import load_dotenv

TABLES = ("users", "reports", "audit_logs", "analysis")
BACKUP_ROOT = Path(r"C:\Users\ubuntu24\AppData\Local\Temp\opencode")
PRIMARY_KEYS = {
    ("users", "uid"),
    ("reports", "rid"),
    ("audit_logs", "log_id"),
    ("analysis", "aid"),
}


def serialize(value):
    if isinstance(value, (datetime, date)):
        return {"type": "datetime", "value": value.isoformat()}
    if isinstance(value, Decimal):
        return {"type": "decimal", "value": str(value)}
    if isinstance(value, uuid.UUID):
        return {"type": "uuid", "value": str(value)}
    if isinstance(value, bytes):
        return {"type": "bytes", "value": value.hex()}
    raise TypeError(f"Unsupported backup value: {type(value).__name__}")


def database_config():
    load_dotenv()
    return {
        "host": os.environ["POSTGRES_HOST"],
        "port": int(os.getenv("POSTGRES_PORT", "5433")),
        "user": os.environ["POSTGRES_USER"],
        "password": os.environ["POSTGRES_PASSWORD"],
        "database": os.environ["POSTGRES_DB"],
    }


def mapped(mapping, value):
    return mapping[str(value)] if value is not None else None


async def ensure_legacy_integer_schema(connection):
    rows = await connection.fetch(
        """SELECT table_name, column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND (table_name, column_name) IN (
            ('users', 'uid'), ('reports', 'rid'),
            ('audit_logs', 'log_id'), ('analysis', 'aid')
          )"""
    )
    types = {(row[0], row[1]): row[2] for row in rows}
    if set(types) != PRIMARY_KEYS:
        raise RuntimeError("Database primary-key schema is incomplete")
    if all(data_type == "uuid" for data_type in types.values()):
        raise RuntimeError("Database already uses UUID primary keys")
    if any(data_type != "integer" for data_type in types.values()):
        raise RuntimeError(f"Unsupported mixed primary-key schema: {types}")


async def fetch_snapshot(connection):
    snapshot = {}
    for table in TABLES:
        rows = await connection.fetch(f'SELECT * FROM "{table}" ORDER BY 1')
        snapshot[table] = [dict(row) for row in rows]
    return snapshot


def validate_source(snapshot):
    users = {row["uid"] for row in snapshot["users"]}
    reports = {row["rid"] for row in snapshot["reports"]}
    checks = (
        ("users.created_by", (row["created_by"] for row in snapshot["users"]), users),
        ("analysis.uid", (row["uid"] for row in snapshot["analysis"]), users),
        ("analysis.deleted_by", (row["deleted_by"] for row in snapshot["analysis"]), users),
        ("analysis.rid", (row["rid"] for row in snapshot["analysis"]), reports),
        ("audit_logs.actor_uid", (row["actor_uid"] for row in snapshot["audit_logs"]), users),
        ("audit_logs.target_uid", (row["target_uid"] for row in snapshot["audit_logs"]), users),
    )
    for name, values, targets in checks:
        missing = sorted({value for value in values if value is not None and value not in targets})
        if missing:
            raise RuntimeError(f"Orphan references in {name}: {missing}")


def create_mappings(snapshot):
    return {
        "users": {str(row["uid"]): str(uuid.uuid4()) for row in snapshot["users"]},
        "reports": {str(row["rid"]): str(uuid.uuid4()) for row in snapshot["reports"]},
        "audit_logs": {str(row["log_id"]): str(uuid.uuid4()) for row in snapshot["audit_logs"]},
        "analysis": {str(row["aid"]): str(uuid.uuid4()) for row in snapshot["analysis"]},
    }


def write_backup(snapshot, mappings):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = BACKUP_ROOT / f"rampart-db-before-uuid-{timestamp}.json"
    payload = {
        "created_at": datetime.now().isoformat(),
        "tables": snapshot,
        "mappings": mappings,
        "row_counts": {table: len(rows) for table, rows in snapshot.items()},
    }
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, default=serialize).encode("utf-8")
    path.write_bytes(encoded)
    checksum = hashlib.sha256(encoded).hexdigest()
    checksum_path = path.with_suffix(".sha256")
    checksum_path.write_text(f"{checksum}  {path.name}\n", encoding="ascii")
    if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
        raise RuntimeError("Backup checksum verification failed")
    return path, checksum


async def insert_users(connection, rows, mappings):
    for row in rows:
        await connection.execute(
            """INSERT INTO users
            (uid, username, email, password, role, status, created_by, created_at, fcm_token)
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid, $8, $9)""",
            mappings["users"][str(row["uid"])], row["username"], row["email"], row["password"],
            row["role"], row["status"], None,
            row["created_at"], row.get("fcm_token"),
        )
    for row in rows:
        if row.get("created_by") is not None:
            await connection.execute(
                "UPDATE users SET created_by=$1::uuid WHERE uid=$2::uuid",
                mapped(mappings["users"], row["created_by"]),
                mappings["users"][str(row["uid"])],
            )


async def insert_reports(connection, rows, mappings):
    for row in rows:
        await connection.execute(
            """INSERT INTO reports
            (rid, rampart_score, package, type, score, risk_level, recommendation,
             analysis_summary, risk_indicators, file_type, virustotal_score, mobsf_score,
             cape_score, gemini_recommendation, malware_signatures, created_at)
            VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)""",
            mappings["reports"][str(row["rid"])], row.get("rampart_score"), row.get("package"),
            row.get("type"), row.get("score"), row.get("risk_level"), row.get("recommendation"),
            row.get("analysis_summary"), row.get("risk_indicators"), row.get("file_type"),
            row.get("virustotal_score"), row.get("mobsf_score"), row.get("cape_score"),
            row.get("gemini_recommendation"), row.get("malware_signatures"), row.get("created_at"),
        )


async def insert_audit_logs(connection, rows, mappings):
    for row in rows:
        await connection.execute(
            """INSERT INTO audit_logs
            (log_id, actor_uid, target_uid, action, detail, created_at)
            VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6)""",
            mappings["audit_logs"][str(row["log_id"])], mapped(mappings["users"], row["actor_uid"]),
            mapped(mappings["users"], row.get("target_uid")), row.get("action"), row.get("detail"),
            row.get("created_at"),
        )


async def insert_analysis(connection, rows, mappings):
    for row in rows:
        await connection.execute(
            """INSERT INTO analysis
            (aid, uid, rid, task_id, privacy, file_name, file_size, file_hash, file_path,
             file_type, tools, status, blocked_by, is_malicious, md5, deleted_at, deleted_by, created_at)
            VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::uuid,$18)""",
            mappings["analysis"][str(row["aid"])], mapped(mappings["users"], row["uid"]),
            mapped(mappings["reports"], row.get("rid")), row.get("task_id"), row.get("privacy"),
            row.get("file_name"), row.get("file_size"), row.get("file_hash"), row.get("file_path"),
            row.get("file_type"), row.get("tools"), row.get("status"), row.get("blocked_by"),
            row.get("is_malicious", False), row.get("md5"), row.get("deleted_at"),
            mapped(mappings["users"], row.get("deleted_by")), row.get("created_at"),
        )


async def validate_target(connection, expected_counts):
    for table, expected in expected_counts.items():
        actual = await connection.fetchval(f'SELECT count(*) FROM "{table}"')
        if actual != expected:
            raise RuntimeError(f"Row count mismatch for {table}: expected {expected}, got {actual}")
    for table, column in (("users", "uid"), ("reports", "rid"), ("audit_logs", "log_id"), ("analysis", "aid")):
        data_type = await connection.fetchval(
            """SELECT data_type FROM information_schema.columns
            WHERE table_schema='public' AND table_name=$1 AND column_name=$2""", table, column
        )
        if data_type != "uuid":
            raise RuntimeError(f"{table}.{column} is {data_type}, expected uuid")
    violations = await connection.fetchval(
        """SELECT
        (SELECT count(*) FROM analysis a LEFT JOIN users u ON u.uid=a.uid WHERE u.uid IS NULL) +
        (SELECT count(*) FROM analysis a LEFT JOIN reports r ON r.rid=a.rid WHERE a.rid IS NOT NULL AND r.rid IS NULL) +
        (SELECT count(*) FROM audit_logs l LEFT JOIN users u ON u.uid=l.actor_uid WHERE u.uid IS NULL)"""
    )
    if violations:
        raise RuntimeError(f"Foreign-key validation found {violations} orphan rows")


async def rebuild(execute):
    connection = await asyncpg.connect(**database_config())
    transaction = connection.transaction()
    await transaction.start()
    try:
        await connection.execute("LOCK TABLE analysis, audit_logs, reports, users IN ACCESS EXCLUSIVE MODE")
        await ensure_legacy_integer_schema(connection)
        snapshot = await fetch_snapshot(connection)
        validate_source(snapshot)
        mappings = create_mappings(snapshot)
        backup_path, checksum = write_backup(snapshot, mappings)
        counts = {table: len(rows) for table, rows in snapshot.items()}
        print(f"backup={backup_path}")
        print(f"sha256={checksum}")
        print(f"rows={json.dumps(counts, sort_keys=True)}")
        if not execute:
            await transaction.rollback()
            print("mode=dry-run database unchanged")
            return
        schema = Path("CREATE-SQL.sql").read_text(encoding="utf-8")
        await connection.execute("DROP TABLE analysis, audit_logs, reports, users CASCADE")
        await connection.execute(schema)
        await insert_users(connection, snapshot["users"], mappings)
        await insert_reports(connection, snapshot["reports"], mappings)
        await insert_audit_logs(connection, snapshot["audit_logs"], mappings)
        await insert_analysis(connection, snapshot["analysis"], mappings)
        await validate_target(connection, counts)
        await transaction.commit()
        print("mode=execute migration committed")
    except Exception:
        if not transaction._state.name == "ROLLEDBACK":
            await transaction.rollback()
        raise
    finally:
        await connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    asyncio.run(rebuild(args.execute))


if __name__ == "__main__":
    main()
