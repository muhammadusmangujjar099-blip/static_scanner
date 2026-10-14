from datetime import datetime
from pydantic import BaseModel
from typing import Any


class ScanOut(BaseModel):
    id: int
    project_id: int
    status: str
    zip_filename: str | None
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanResultOut(BaseModel):
    id: int
    scan_id: int
    languages: dict | None
    primary_language: str | None
    system_info: dict | None
    secrets_found: list | None
    secrets_count: int
    static_audit: list | None
    audit_score: float | None
    total_files: int
    total_lines: int
    summary: dict | None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanDetailOut(ScanOut):
    results: ScanResultOut | None = None
