
# from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy import delete, func, select

# # from cores.models_class importReports
# from sqlalchemy.orm import joinedload

async def get_report_all(
    # session: AsyncSession,
    # page = 1,
    # limit = 20
):
    return 0
    
    # offset = (page - 1) * limit

    # stmt = (
    #     select(Reports)
    #     .options(joinedload(Reports.analysis))
    #     .order_by(Reports.rid)
    #     .offset(offset)
    #     .limit(limit)
    # )

    # result = await session.execute(stmt)
    # reports = result.scalars().all()

    # count_stmt = select(func.count()).select_from(Reports)
    # total = (await session.execute(count_stmt)).scalar_one()

    # return {
    #     "data": reports,
    #     "total": total,
    #     "page": page,
    #     "limit": limit,
    #     "total_pages": (total + limit - 1) // limit
    # }
