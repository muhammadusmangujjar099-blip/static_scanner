from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    email: EmailStr
    full_name: str | None = None
    role: str = "member"


class UserCreate(UserBase):
    password: str = Field(..., min_length=6)
    organization_id: int | None = None


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    organization_id: int | None = None


class UserOut(UserBase):
    id: int
    is_active: bool
    organization_id: int | None
    created_at: datetime

    class Config:
        from_attributes = True
