from typing import List, Optional
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from cores.models_class import Analysis, Files, Uploads

async def get_file_by_hash(
    session: AsyncSession,
    file_hash: str
) -> Files | None:
    result = await session.execute(
        select(Files).where(Files.file_hash == file_hash)
    )
    return result.scalar_one_or_none()

async def delete_table_files(
    session: AsyncSession,
    file_hash: str
) -> bool:
    result = await session.execute(
        delete(Files).where(Files.file_hash == file_hash)
    )
    await session.commit()
    return result.rowcount > 0

async def insert_table_files(
    session: AsyncSession,
    *,
    file_hash: str,
    file_path: str,
    file_type: str,
    file_size: int
) -> Files:
    file = Files(
        file_hash=file_hash,
        file_path=file_path,
        file_type=file_type,
        file_size=file_size
    )
    session.add(file)
    await session.commit()
    await session.refresh(file)
    return file

async def get_table_uploads(
    session: AsyncSession,
    *,
    uid: int,
    fid: int,
    file_name: str
) -> Uploads | None:
    result = await session.execute(
        select(Uploads).where(
            Uploads.uid == uid,
            Uploads.fid == fid,
            Uploads.file_name == file_name
        ).limit(1)
    )
    return result.scalars().first()


async def touch_upload_time(
    session: AsyncSession,
    upload: Uploads
) -> Uploads:
    upload.uploaded_at = func.now()
    await session.commit()
    await session.refresh(upload)
    return upload

async def insert_table_uploads(
    session: AsyncSession,
    *,
    uid: int,
    fid: int,
    file_name: str | None = None,
    privacy: bool = True
) -> Uploads:
    upload = Uploads(
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
    fid: int,
    platform: Optional[List[str]] = None
) -> Analysis:

    analy = Analysis(
        fid=fid,
        task_id=None,
        platform=platform or [],
        status="pending"
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


