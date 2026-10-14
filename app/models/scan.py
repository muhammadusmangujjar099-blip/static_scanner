from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Integer, ForeignKey, Text, JSON, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, running, completed, failed
    zip_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    zip_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    project = relationship("Project", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan", uselist=False)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), unique=True, nullable=False)

    # 1. Language detection
    languages: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    primary_language: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # 2. System / structure info
    system_info: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # 3. Secret / sensitive variables
    secrets_found: Mapped[list | None] = mapped_column(JSON, nullable=True)
    secrets_count: Mapped[int] = mapped_column(Integer, default=0)

    # 4. Static audit findings
    static_audit: Mapped[list | None] = mapped_column(JSON, nullable=True)
    audit_score: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0-100

    # Summary
    total_files: Mapped[int] = mapped_column(Integer, default=0)
    total_lines: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    scan = relationship("Scan", back_populates="results")
