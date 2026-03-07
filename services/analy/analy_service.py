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

async def insert_table_analy(
    session: AsyncSession,
    *,
    uid: int,
    file_name: str,
    file_hash: str,
    file_path: str,
    file_type: str,
    file_size: int,
    privacy: bool,
    tools: str | None = None,
    md5: str | None = None,
    task_id: str | None = None,
) -> Analysis:
    analysis = Analysis(
        uid=uid,
        file_name=file_name,
        file_hash=file_hash,
        file_path=file_path,
        file_type=file_type,
        file_size=file_size,
        privacy=privacy,
        tools=tools,
        md5=md5,
        task_id=task_id,
    )
    session.add(analysis)
    await session.commit()
    await session.refresh(analysis)
    return analysis

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
    rid: int | None,
    task_id: str | None,
    tools: str | None,
    status: str | None,
    file_name: str,
    file_hash: str,
    file_path: str,
    file_type: str,
    file_size: int,
    privacy: bool,
    md5: str,
) -> Analysis:
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
    task_id: str
) -> Analysis | None:
    result = await session.execute(
        select(Analysis).where(Analysis.task_id == task_id)
    )
    return result.scalar_one_or_none()

async def get_report_by_aid(
    session: AsyncSession,
    aid: int
) -> Reports | None:
    stmt = (
        select(Reports)
        .where(Reports.aid == aid)
    )
    result = await session.execute(stmt)
    report = result.scalar_one_or_none()
    
    return report

