from sqlalchemy import Boolean, DateTime, ForeignKey, Numeric, Text, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from datetime import datetime
from dotenv import load_dotenv
import os
from sqlalchemy import String
from sqlalchemy.dialects.postgresql import ARRAY
# ======================
# Base
# ======================
class Base(DeclarativeBase):
    pass

# ======================
# Users
# ======================
class User(Base):
    __tablename__ = "users"

    uid: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True, nullable=False)
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    password: Mapped[str] = mapped_column(nullable=False)
    role: Mapped[str] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )

    uploads = relationship(
        "Uploads",
        back_populates="user",
        cascade="all, delete-orphan"
    )

# ======================
# Files (ไฟล์กลาง)
# ======================
class Files(Base):
    __tablename__ = "files"

    fid: Mapped[int] = mapped_column(primary_key=True)
    file_hash: Mapped[str] = mapped_column(unique=True, nullable=False)
    file_path: Mapped[str] = mapped_column(nullable=False)
    file_type: Mapped[str] = mapped_column(nullable=True)
    file_size: Mapped[int] = mapped_column(nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )

    uploads = relationship(
        "Uploads",
        back_populates="file",
        cascade="all, delete-orphan"
    )

    analyses = relationship(
        "Analysis",
        back_populates="file",
        cascade="all, delete-orphan"
    )

# ======================
# Uploads (user ↔ file)
# ======================
class Uploads(Base):
    __tablename__ = "uploads"

    up_id: Mapped[int] = mapped_column(primary_key=True)

    uid: Mapped[int] = mapped_column(
        ForeignKey("users.uid", ondelete="CASCADE"),
        nullable=False
    )

    file_name: Mapped[str | None] = mapped_column(nullable=True)

    fid: Mapped[int] = mapped_column(
        ForeignKey("files.fid", ondelete="RESTRICT"),
        nullable=False
    )

    privacy: Mapped[bool] = mapped_column(
        Boolean,
        server_default=text("TRUE"),
        nullable=False
    )

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )

    user = relationship("User", back_populates="uploads")
    file = relationship("Files", back_populates="uploads")

class Analysis(Base):
    __tablename__ = "analysis"

    aid: Mapped[int] = mapped_column(primary_key=True)

    fid: Mapped[int] = mapped_column(
        ForeignKey("files.fid", ondelete="CASCADE"),
        nullable=False
    )

    task_id: Mapped[str | None] = mapped_column(nullable=True)

    status: Mapped[str] = mapped_column(
        String(50),
        server_default=text("'pending'")
    )

    platform: Mapped[list[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        default=[]
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )
    file = relationship("Files", back_populates="analyses")
    report = relationship(
        "Reports",
        back_populates="analysis",
        uselist=False,
        cascade="all, delete-orphan"
    )

class Reports(Base):
    __tablename__ = "reports"

    rid: Mapped[int] = mapped_column(primary_key=True)

    aid: Mapped[int] = mapped_column(
        ForeignKey("analysis.aid", ondelete="CASCADE"),
        unique=True,
        nullable=False
    )

    rampart_score: Mapped[float | None] = mapped_column(
        Numeric(5, 2)
    )

    package: Mapped[str | None] = mapped_column(
        Text
    )

    type: Mapped[str | None] = mapped_column(
        String(255)
    )

    score: Mapped[float | None] = mapped_column(
        Numeric(5, 2)
    )

    risk_level: Mapped[str | None] = mapped_column(
        String(128)
    )

    color: Mapped[str | None] = mapped_column(
        String(128)
    )

    recommendation: Mapped[str | None] = mapped_column(
        Text
    )

    analysis_summary: Mapped[str | None] = mapped_column(
        Text
    )

    risk_indicators: Mapped[list[str] | None] = mapped_column(
        Text
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    # ---------- Relationship ----------
    analysis = relationship(
        "Analysis",
        back_populates="report",
        lazy="joined"
    )


