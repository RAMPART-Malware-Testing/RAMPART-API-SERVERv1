import os

from sqlalchemy import select

from cores.Schema.schema_class import User
from cores.async_pg_db import SessionLocal
from utils.cypto.PasswordCreateAndVerify import get_password_hash, verify_password
from utils.email_normalize import normalize_email, normalized_email_expr

ROOT_EMAIL = os.getenv("ROOT_EMAIL", "").strip().lower()
ROOT_PASSWORD = os.getenv("ROOT_PASSWORD", "")
ROOT_USERNAME = os.getenv("ROOT_USERNAME", "master_admin").strip() or "master_admin"


async def _generate_unique_username(session, seed: str) -> str:
    import re
    import secrets

    sanitize_re = re.compile(r"[^a-zA-Z0-9_.-]")
    base = sanitize_re.sub("", seed.split("@")[0]).strip(".-_") or "master"
    base = base[:40] or "master"

    candidate = base
    while True:
        result = await session.execute(select(User.uid).where(User.username == candidate))
        if result.scalar_one_or_none() is None:
            return candidate
        candidate = f"{base}-{secrets.token_hex(3)}"[:50]


async def ensure_root_master_account() -> None:
    if not ROOT_EMAIL or not ROOT_PASSWORD:
        return

    normalized_root_email = normalize_email(ROOT_EMAIL)

    async with SessionLocal() as session:
        result = await session.execute(
            select(User).where(normalized_email_expr(User.email) == normalized_root_email)
        )
        user = result.scalar_one_or_none()

        if user is None:
            by_username = await session.execute(
                select(User).where(User.username == ROOT_USERNAME)
            )
            user = by_username.scalar_one_or_none()

        if user is None:
            existing_master = await session.execute(
                select(User.uid).where(User.role == "master").limit(1)
            )
            if existing_master.scalar_one_or_none() is not None:
                print(
                    f"[Bootstrap] Master account already exists (env root {ROOT_EMAIL} "
                    "was renamed or replaced) - skipping default master creation"
                )
                return

        if user is None:
            username = await _generate_unique_username(session, ROOT_USERNAME)
            user = User(
                username=username,
                email=ROOT_EMAIL,
                password=get_password_hash(ROOT_PASSWORD),
                avatar_url=None,
                role="master",
                status="active",
                must_setup=True,
            )
            session.add(user)
            await session.commit()
            print(f"[Bootstrap] Created default master admin account: {ROOT_EMAIL}")
            return

        changed = False
        if user.role != "master":
            user.role = "master"
            changed = True
        if user.is_banned:
            user.is_banned = False
            user.banned_at = None
            user.banned_reason = None
            user.banned_by = None
            changed = True
        if not user.password:
            user.password = get_password_hash(ROOT_PASSWORD)
            changed = True
        if user.password and verify_password(user.password, ROOT_PASSWORD) and not user.must_setup:
            user.must_setup = True
            changed = True

        if changed:
            await session.commit()
            print(f"[Bootstrap] Reconciled master admin account: {ROOT_EMAIL}")
