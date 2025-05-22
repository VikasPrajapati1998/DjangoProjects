from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from app import models, schemas, auth

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_user_by_mobile_number(db: Session, mobile: str):
    return db.query(models.User).filter(models.User.mobile_number == mobile).first()

def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def create_user(db: Session, user: schemas.UserCreate):
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

def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if user and auth.verify_password(password, user.hashed_password):
        return user
    return None

def update_user(db: Session, user_id: int, updates: schemas.UserUpdate):
    user = db.query(models.User).get(user_id)
    if not user:
        return None
    if updates.user_name: user.user_name = updates.user_name
    if updates.mobile_number: user.mobile_number = updates.mobile_number
    if updates.gender: user.gender = updates.gender
    if updates.password: user.hashed_password = auth.get_password_hash(updates.password)
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return user

def delete_user(db: Session, user_id: int):
    user = db.query(models.User).get(user_id)
    if not user:
        return None
    db.delete(user)
    db.commit()
    return user

# OTP CRUD
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
