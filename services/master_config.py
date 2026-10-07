import json
import os
import tempfile
from pathlib import Path

MASTER_CONFIG_PATH = Path(
    os.getenv("MASTER_CONFIG_PATH")
    or (Path(__file__).resolve().parent.parent / "config" / "master_config.json")
)

_INITIAL_STATE = {"email_verified": False}


def _read() -> dict:
    try:
        raw = MASTER_CONFIG_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _write(data: dict) -> None:
    MASTER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=MASTER_CONFIG_PATH.parent,
        prefix=".master_config-",
        suffix=".tmp",
        delete=False,
    )
    try:
        with temp:
            json.dump(data, temp, ensure_ascii=False, indent=2)
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp.name, MASTER_CONFIG_PATH)
    except BaseException:
        try:
            os.unlink(temp.name)
        except OSError:
            pass
        raise


def is_master_email_verified(uid) -> bool:
    data = _read()
    return data.get("uid") == str(uid) and data.get("email_verified") is True


def _write_state(uid, email_verified: bool, email: str | None = None) -> None:
    payload = {"uid": str(uid), "email_verified": email_verified}
    if email:
        payload["email"] = email
    _write(payload)


def record_master_identity(uid, email: str | None = None) -> None:
    _write_state(uid, False, email)


def mark_master_email_verified(uid, email: str | None = None) -> None:
    _write_state(uid, True, email)


def reset_master_config() -> None:
    _write(dict(_INITIAL_STATE))


async def reset_if_installation_has_no_users() -> bool:
    from sqlalchemy import func, select

    from cores.Schema.schema_class import User
    from cores.async_pg_db import SessionLocal

    async with SessionLocal() as session:
        total = await session.execute(select(func.count()).select_from(User))
        if total.scalar_one() != 0:
            return False

    reset_master_config()
    return True
