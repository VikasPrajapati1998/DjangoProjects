from sqlalchemy.orm import Session
from app import models, schemas, auth

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_mobile_number(db:Session, mobile_number: str):
    return db.query(models.User).filter(models.User.mobile_number == mobile_number).first()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_pw = auth.get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_pw,
        user_name=user.user_name,
        mobile_number=user.mobile_number,
        gender=user.gender
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
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    if updates.user_name is not None:
        user.user_name = updates.user_name
    if updates.mobile_number is not None:
        user.mobile_number = updates.mobile_number
    if updates.gender is not None:
        user.gender = updates.gender
    if updates.password is not None:
        user.hashed_password = auth.get_password_hash(updates.password)
    db.commit()
    db.refresh(user)
    return user

def delete_user(db: Session, user_id: int):
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    db.delete(user)
    db.commit()
    return user
