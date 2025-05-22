from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

# Base Response
class MessageResponse(BaseModel):
    message: str

# User Schemas
class UserBase(BaseModel):
    email: EmailStr
    user_name: str
    mobile_number: str
    gender: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    user_name: Optional[str] = None
    mobile_number: Optional[str] = None
    gender: Optional[str] = None
    password: Optional[str] = None

class UserResponse(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Auth Schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

# OTP Schemas
class OTPRequest(BaseModel):
    email: EmailStr

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

# Role & Permission Schemas
class RoleBase(BaseModel):
    role_name: str

class RoleCreate(RoleBase):
    expires_at: datetime

class RoleResponse(RoleBase):
    id: int
    created_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True

class PermissionBase(BaseModel):
    permission_name: str

class PermissionCreate(PermissionBase):
    expires_at: datetime

class PermissionResponse(PermissionBase):
    id: int
    created_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True

class UserRoleCreate(BaseModel):
    user_id: int
    role_id: int

class UserRoleResponse(UserRoleCreate):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

class RolePermissionCreate(BaseModel):
    role_id: int
    permission_id: int
    is_all: bool = False

class RolePermissionResponse(RolePermissionCreate):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True
