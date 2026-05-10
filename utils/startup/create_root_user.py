from sqlalchemy import select
from cores.async_pg_db import SessionLocal
from cores.Schema.schema_class import User
from dotenv import load_dotenv
import os

from utils.cypto.PasswordCreateAndVerify import get_password_hash

load_dotenv()

ROOT_USERNAME=os.getenv('ROOT_USERNAME','rampart')
ROOT_PASSWORD=os.getenv('ROOT_PASSWORD','rampart')
ROOT_EMAIL=os.getenv('ROOT_EMAIL','rampart')

async def create_root_user():
    async with SessionLocal() as session:
        result = await session.execute(
            select(User).where(User.username == ROOT_USERNAME).where(User.role == "admin")
        )
        root_user = result.scalar_one_or_none()

        if root_user:
            print("✅ Root user already exists")
            return

        hashed_password = get_password_hash(ROOT_PASSWORD)

        new_user = User(
            username=ROOT_USERNAME,
            password=hashed_password,
            email=ROOT_EMAIL,
            role="admin"
        )

        session.add(new_user)
        await session.commit()
        print("🚀 Root user created successfully")
