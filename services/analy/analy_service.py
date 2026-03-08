from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from cores.models_class import Analysis, User, Reports

async def get_file_by_hash(
    session: AsyncSession,
    file_hash: str
) -> Analysis | None:
    result = await session.execute(
        select(
            Analysis.rid,
            Analysis.status,
            Analysis.file_path,
            Analysis.file_type,
            Analysis.file_size,
            Analysis.file_hash,
            Analysis.tools,
            Analysis.md5,
            Analysis.task_id,
        ).where(
            Analysis.file_hash == file_hash,
            Analysis.file_path.isnot(None)
        ).limit(1)
    )
    return result.mappings().one_or_none()

async def delete_table_files(
    session: AsyncSession,
    file_hash: str
) -> bool:
    # result = await session.execute(
    #     delete(Files).where(Files.file_hash == file_hash)
    # )
    # await session.commit()
    # return result.rowcount > 0
    return 0

async def get_table_uploads(
    session: AsyncSession,
    *,
    uid: int,
    fid: int,
    file_name: str
) -> Analysis | None:
    # result = await session.execute(
    #     select(Uploads).where(
    #         Uploads.uid == uid,
    #         Uploads.fid == fid,
    #         Uploads.file_name == file_name
    #     ).limit(1)
    # )
    # return result.scalars().first()
    return 0

async def touch_upload_time(
    session: AsyncSession,
    upload: Analysis
) -> Analysis:
    # upload.uploaded_at = func.now()
    # await session.commit()
    # await session.refresh(upload)
    # return upload
    return 0

async def insert_table_uploads(
    session: AsyncSession,
    *,
    uid: int,
    fid: int,
    file_name: str | None = None,
    privacy: bool = True
) -> Analysis:
    upload = Analysis(
        uid=uid,
        fid=fid,
        file_name=file_name,
        privacy=privacy
    )

    session.add(upload)
    await session.commit()
    await session.refresh(upload)

    return upload

async def insert_table_analy(
    session: AsyncSession,
    *,
    uid: int,
    rid: int | None = None,
    task_id: str | None = None,
    tools: str | None = None,
    status: str | None = None,
    file_name: str,
    file_hash: str,
    file_path: str,
    file_type: str,
    file_size: int,
    privacy: bool,
    md5: str,
) -> Analysis:
    
    stmt = select(Analysis).where(
        Analysis.uid == uid,
        Analysis.file_name == file_name,
        Analysis.file_hash == file_hash,
    )
    existing = await session.execute(stmt)
    analy = existing.scalars().first()

    if analy:
        analy.created_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(analy)
        return analy
    
    if rid:
        analy = Analysis(
            uid=uid,
            rid=rid,
            task_id=task_id,
            tools=tools,
            status=status,
            file_name=file_name,
            file_hash=file_hash,
            file_path=file_path,
            file_type=file_type,
            file_size=file_size,
            privacy=privacy,
            md5=md5,
        )
    else:
        analy = Analysis(
            uid=uid,
            file_name=file_name,
            file_hash=file_hash,
            file_path=file_path,
            file_type=file_type,
            file_size=file_size,
            privacy=privacy,
            md5=md5,
        )
    session.add(analy)
    await session.commit()
    await session.refresh(analy)
    return analy

async def get_table_analy(
    session: AsyncSession,
    fid: int
) -> Analysis | None:
    result = await session.execute(
        select(Analysis).where(Analysis.fid == fid)
    )
    return result.scalar_one_or_none()

async def get_analy_by_task_id(
    session: AsyncSession,
    task_id: str,
    uid: int
) -> Analysis | None:
    result = await session.execute(
        select(Analysis).where(Analysis.task_id == task_id, Analysis.uid == uid)
    )
    return result.scalars().first()

async def get_report(
    session: AsyncSession,
    rid: int
) -> Reports | None:
    stmt = (
        select(Reports)
        .where(Reports.rid == rid)
    )
    result = await session.execute(stmt)
    report = result.scalar_one_or_none()
    
    return report

