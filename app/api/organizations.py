from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.core.security import require_super_admin, get_current_user
from app.models.user import User
from app.models.organization import Organization
from app.schemas.organization import OrganizationCreate, OrganizationUpdate, OrganizationOut

router = APIRouter(prefix="/api/organizations", tags=["Organizations"])


@router.post("/", response_model=OrganizationOut, status_code=201)
def create_organization(
    body: OrganizationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Any logged-in user can create an organization and becomes its org_admin."""
    exists = db.query(Organization).filter(Organization.name == body.name).first()
    if exists:
        raise HTTPException(status_code=400, detail="Organization name already exists")
    org = Organization(name=body.name, description=body.description)
    db.add(org)
    db.flush()

    # Assign user to this org as org_admin (if not super_admin)
    if current_user.role != "super_admin":
        current_user.organization_id = org.id
        current_user.role = "org_admin"

    db.commit()
    db.refresh(org)
    return org


@router.get("/", response_model=List[OrganizationOut])
def list_organizations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role == "super_admin":
        return db.query(Organization).order_by(Organization.id).all()
    if current_user.organization_id:
        return (
            db.query(Organization)
            .filter(Organization.id == current_user.organization_id)
            .all()
        )
    return []


@router.get("/{org_id}", response_model=OrganizationOut)
def get_organization(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if current_user.role != "super_admin" and current_user.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return org


@router.patch("/{org_id}", response_model=OrganizationOut)
def update_organization(
    org_id: int,
    body: OrganizationUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_super_admin),
):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if body.name is not None:
        org.name = body.name
    if body.description is not None:
        org.description = body.description
    db.commit()
    db.refresh(org)
    return org


@router.delete("/{org_id}", status_code=204)
def delete_organization(
    org_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_super_admin),
):
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    db.delete(org)
    db.commit()
    return None
