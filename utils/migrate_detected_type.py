import asyncio

from sqlalchemy import text

from cores.async_pg_db import engine

STATEMENTS = [
    "ALTER TABLE analysis ADD COLUMN IF NOT EXISTS detected_type VARCHAR(50)",
    "ALTER TABLE analysis ADD COLUMN IF NOT EXISTS detected_source VARCHAR(20)",
    "ALTER TABLE analysis ADD COLUMN IF NOT EXISTS file_type_mismatch BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE reports ADD COLUMN IF NOT EXISTS score_source VARCHAR(20)",
    "CREATE INDEX IF NOT EXISTS ix_analysis_detected_type ON analysis (detected_type)",
]


async def main() -> None:
    async with engine.begin() as connection:
        for statement in STATEMENTS:
            await connection.execute(text(statement))
            print(f"ok: {statement}")
    await engine.dispose()
    print("migration complete")


if __name__ == "__main__":
    asyncio.run(main())