import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db, SessionLocal
from app.core.security import get_current_user
from app.core.config import get_settings
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan, ScanResult
from app.schemas.scan import ScanOut, ScanDetailOut, ScanResultOut
from app.services.scanner import run_scan_on_zip

router = APIRouter(prefix="/api/scans", tags=["Scans"])
settings = get_settings()


def _can_access_project(user: User, project: Project) -> bool:
    if user.role == "super_admin":
        return True
    return user.organization_id == project.organization_id


def _run_scan_background(scan_id: int, zip_path: str):
    """Background task: perform static scan and store results."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        try:
            result_data = run_scan_on_zip(zip_path)
            # store result
            existing = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
            if existing:
                db.delete(existing)
                db.flush()

            result = ScanResult(
                scan_id=scan_id,
                languages=result_data["languages"],
                primary_language=result_data["primary_language"],
                system_info=result_data["system_info"],
                secrets_found=result_data["secrets_found"],
                secrets_count=result_data["secrets_count"],
                static_audit=result_data["static_audit"],
                audit_score=result_data["audit_score"],
                total_files=result_data["total_files"],
                total_lines=result_data["total_lines"],
                summary=result_data["summary"],
            )
            db.add(result)
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
        except Exception as e:
            scan.status = "failed"
            scan.error_message = str(e)[:2000]
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
        # cleanup zip after scan
        try:
            if os.path.exists(zip_path):
                os.remove(zip_path)
        except Exception:
            pass


@router.post("/project/{project_id}/upload", response_model=ScanOut, status_code=201)
async def upload_and_scan(
    project_id: int,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can_access_project(current_user, project):
        raise HTTPException(status_code=403, detail="Access denied")

    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are accepted")

    # size check
    content = await file.read()
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Max {settings.MAX_UPLOAD_SIZE_MB} MB",
        )

    # save zip
    upload_root = Path(settings.UPLOAD_DIR)
    upload_root.mkdir(parents=True, exist_ok=True)
    scan = Scan(
        project_id=project_id,
        status="pending",
        zip_filename=file.filename,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    zip_path = upload_root / f"scan_{scan.id}_{file.filename}"
    with open(zip_path, "wb") as f:
        f.write(content)

    scan.zip_path = str(zip_path)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_scan_background, scan.id, str(zip_path))
    return scan


@router.get("/project/{project_id}", response_model=List[ScanOut])
def list_scans(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not _can_access_project(current_user, project):
        raise HTTPException(status_code=403, detail="Access denied")
    return (
        db.query(Scan)
        .filter(Scan.project_id == project_id)
        .order_by(Scan.id.desc())
        .all()
    )


@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    project = db.query(Project).filter(Project.id == scan.project_id).first()
    if not project or not _can_access_project(current_user, project):
        raise HTTPException(status_code=403, detail="Access denied")

    result = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    out = ScanDetailOut.model_validate(scan)
    if result:
        out.results = ScanResultOut.model_validate(result)
    return out


@router.delete("/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    project = db.query(Project).filter(Project.id == scan.project_id).first()
    if not project or not _can_access_project(current_user, project):
        raise HTTPException(status_code=403, detail="Access denied")
    if scan.zip_path and os.path.exists(scan.zip_path):
        try:
            os.remove(scan.zip_path)
        except Exception:
            pass
    db.delete(scan)
    db.commit()
    return None
