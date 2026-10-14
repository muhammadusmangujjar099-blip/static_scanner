from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.core.security import (
    require_super_admin,
    require_org_admin_or_super,
    get_password_hash,
    get_current_user,
)
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate, UserOut

router = APIRouter(prefix="/api/users", tags=["Users"])


@router.post("/", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_org_admin_or_super),
):
    exists = db.query(User).filter(User.email == body.email).first()
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")

    # only super_admin can create another super_admin
    role = body.role
    if role == "super_admin" and current_user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Only super_admin can create super_admin")

    org_id = body.organization_id
    if current_user.role != "super_admin":
        org_id = current_user.organization_id

    user = User(
        email=body.email,
        hashed_password=get_password_hash(body.password),
        full_name=body.full_name,
        role=role,
        organization_id=org_id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/", response_model=List[UserOut])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role == "super_admin":
        return db.query(User).order_by(User.id).all()
    if current_user.organization_id:
        return (
            db.query(User)
            .filter(User.organization_id == current_user.organization_id)
            .order_by(User.id)
            .all()
        )
    return [current_user]


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if current_user.role != "super_admin":
        if user.organization_id != current_user.organization_id:
            raise HTTPException(status_code=403, detail="Access denied")
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_org_admin_or_super),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if current_user.role != "super_admin" and user.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        if body.role == "super_admin" and current_user.role != "super_admin":
            raise HTTPException(status_code=403, detail="Cannot promote to super_admin")
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.organization_id is not None and current_user.role == "super_admin":
        user.organization_id = body.organization_id
    db.commit()
    db.refresh(user)
    return user
