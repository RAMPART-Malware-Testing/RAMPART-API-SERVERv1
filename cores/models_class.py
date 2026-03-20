from sqlalchemy import Boolean, DateTime, ForeignKey, Numeric, Text, text, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import ARRAY
from datetime import datetime
from sqlalchemy import String

class Base(DeclarativeBase):
    pass

# ======================
# Users
# ======================
class User(Base):
    __tablename__ = "users"

    uid: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(20), server_default=text("'user'"))
    status: Mapped[str] = mapped_column(String(50), server_default=text("'active'"))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.uid"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False
    )

    analyses = relationship("Analysis", foreign_keys="[Analysis.uid]", back_populates="user", cascade="all, delete-orphan")
    audit_logs_as_actor = relationship("AuditLog", foreign_keys="AuditLog.actor_uid", back_populates="actor")
    audit_logs_as_target = relationship("AuditLog", foreign_keys="AuditLog.target_uid", back_populates="target")

# ======================
# Analysis
# ======================
class Analysis(Base):
    __tablename__ = "analysis"

    aid: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[int] = mapped_column(ForeignKey("users.uid", ondelete="CASCADE"), nullable=False)
    rid: Mapped[int | None] = mapped_column(ForeignKey("reports.rid", ondelete="SET NULL"), nullable=True)
    task_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    privacy: Mapped[bool] = mapped_column(Boolean, server_default=text("TRUE"))
    file_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    tools: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str | None] = mapped_column(Text, nullable=True)
    md5: Mapped[str | None] = mapped_column(Text, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_by: Mapped[int | None] = mapped_column(ForeignKey("users.uid"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    user = relationship("User", foreign_keys=[uid], back_populates="analyses")
    report = relationship("Reports", back_populates="analyses")

# ======================
# Reports
# ======================
class Reports(Base):
    __tablename__ = "reports"

    rid: Mapped[int] = mapped_column(primary_key=True)
    rampart_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    package: Mapped[str | None] = mapped_column(Text, nullable=True)
    type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(128), nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    analysis_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_indicators: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    analyses = relationship("Analysis", foreign_keys="[Analysis.rid]", back_populates="report")

# ======================
# Audit Logs
# ======================
class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id: Mapped[int] = mapped_column(primary_key=True)
    actor_uid: Mapped[int] = mapped_column(ForeignKey("users.uid", ondelete="CASCADE"), nullable=False)
    target_uid: Mapped[int | None] = mapped_column(ForeignKey("users.uid", ondelete="SET NULL"), nullable=True)
    action: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    actor = relationship("User", foreign_keys=[actor_uid], back_populates="audit_logs_as_actor")
    target = relationship("User", foreign_keys=[target_uid], back_populates="audit_logs_as_target")

from cores.async_pg_db import engine

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Database synced and tables created!")
