from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from app import models, schemas, auth
from fastapi import HTTPException, status

# ===== USER =====
def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_user_by_mobile_number(db: Session, mobile: str):
    return db.query(models.User).filter(models.User.mobile_number == mobile).first()

def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def create_user(db: Session, user: schemas.UserCreate):
    if get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    if get_user_by_mobile_number(db, user.mobile_number):
        raise HTTPException(status_code=400, detail="Mobile number already registered")
    
    hashed_pw = auth.get_password_hash(user.password)
    now = datetime.now(timezone.utc)
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_pw,
        user_name=user.user_name,
        mobile_number=user.mobile_number,
        gender=user.gender,
        created_at=now,
        updated_at=now
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user(db: Session, user_id: int, updates: schemas.UserUpdate):
    user = db.query(models.User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if updates.user_name: 
        user.user_name = updates.user_name
    if updates.mobile_number: 
        if get_user_by_mobile_number(db, updates.mobile_number) and get_user_by_mobile_number(db, updates.mobile_number).id != user_id:
            raise HTTPException(status_code=400, detail="Mobile number already in use")
        user.mobile_number = updates.mobile_number
    if updates.gender: 
        user.gender = updates.gender
    if updates.password: 
        user.hashed_password = auth.get_password_hash(updates.password)
    
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return user

def delete_user(db: Session, user_id: int):
    user = db.query(models.User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return user

# ===== AUTH =====
def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user or not auth.verify_password(password, user.hashed_password):
        return None
    return user

# ===== OTP =====
def create_otp(db: Session, email: str, otp: str, expires_in_seconds: int = 300):
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=expires_in_seconds)
    db_otp = models.OTP(email=email, otp=otp, created_at=now, expires_at=expires_at)
    db.add(db_otp)
    db.commit()
    return db_otp

def verify_and_delete_otp(db: Session, email: str, otp: str):
    now = datetime.now(timezone.utc)
    entry = (
        db.query(models.OTP)
        .filter(models.OTP.email == email, models.OTP.otp == otp)
        .filter(models.OTP.expires_at >= now)
        .first()
    )
    if not entry:
        return False
    db.delete(entry)
    db.commit()
    return True

def delete_expired_otps(db: Session):
    now = datetime.now(timezone.utc)
    db.query(models.OTP).filter(models.OTP.expires_at < now).delete()
    db.commit()

# ===== ROLES & PERMISSIONS =====
def create_role(db: Session, role_name: str, expires_at: datetime):
    if db.query(models.Role).filter(models.Role.role_name == role_name).first():
        raise HTTPException(status_code=400, detail="Role already exists")
    role = models.Role(role_name=role_name, created_at=datetime.now(timezone.utc), expires_at=expires_at)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role

def create_permission(db: Session, permission_name: str, expires_at: datetime):
    if db.query(models.Permission).filter(models.Permission.permission_name == permission_name).first():
        raise HTTPException(status_code=400, detail="Permission already exists")
    perm = models.Permission(permission_name=permission_name, created_at=datetime.now(timezone.utc), expires_at=expires_at)
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return perm

def assign_role_to_user(db: Session, user_id: int, role_id: int):
    if not db.query(models.User).get(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    if not db.query(models.Role).get(role_id):
        raise HTTPException(status_code=404, detail="Role not found")
    
    existing = db.query(models.UserRole).filter(models.UserRole.user_id == user_id, models.UserRole.role_id == role_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Role already assigned to user")
    
    assignment = models.UserRole(user_id=user_id, role_id=role_id, created_at=datetime.now(timezone.utc))
    db.add(assignment)
    db.commit()
    return assignment

def assign_permission_to_role(db: Session, role_id: int, permission_id: int, is_all: bool = False):
    if not db.query(models.Role).get(role_id):
        raise HTTPException(status_code=404, detail="Role not found")
    if not db.query(models.Permission).get(permission_id):
        raise HTTPException(status_code=404, detail="Permission not found")
    
    existing = db.query(models.RolePermission).filter(
        models.RolePermission.role_id == role_id, 
        models.RolePermission.permission_id == permission_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Permission already assigned to role")
    
    mapping = models.RolePermission(
        role_id=role_id, 
        permission_id=permission_id, 
        is_all=is_all,
        created_at=datetime.now(timezone.utc)
    )
    db.add(mapping)
    db.commit()
    return mapping
