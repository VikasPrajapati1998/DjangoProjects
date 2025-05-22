from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app import schemas, crud, auth, models
from app.database import get_db
import os, random, smtplib
from email.mime.text import MIMEText
from typing import List

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Email creds
MY_EMAIL = os.getenv("MY_EMAIL")
MY_PASSWORD = os.getenv("MY_PASSWORD")

def send_email_otp(email: str, otp: str):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg['Subject'] = 'Your OTP Code'
    msg['From'] = MY_EMAIL
    msg['To'] = email
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(MY_EMAIL, MY_PASSWORD)
        server.send_message(msg)

@router.post("/send-otp", status_code=status.HTTP_202_ACCEPTED)
def send_otp(req: schemas.OTPRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # Cleanup old
    crud.delete_expired_otps(db)

    otp = f"{random.randint(0, 999999):06d}"
    crud.create_otp(db, req.email, otp)
    background_tasks.add_task(send_email_otp, req.email, otp)
    return {"message": "OTP sent"}

@router.post("/verify-otp")
def verify_otp(req: schemas.OTPVerify, db: Session = Depends(get_db)):
    crud.delete_expired_otps(db)
    if not crud.verify_and_delete_otp(db, req.email, req.otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    return {"message": "OTP verified"}

@router.post("/register", response_model=schemas.Token)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.create_user(db, user)
    token = auth.create_access_token(data={"sub": db_user.email})
    return {"access_token": token, "token_type": "bearer"}

@router.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth.create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token_data = auth.decode_access_token(token)
    user = crud.get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

@router.get("/profile", response_model=schemas.UserResponse)
def read_current_user(current_user: models.User = Depends(get_current_user)):
    return current_user

@router.put("/profile", response_model=schemas.UserResponse)
def update_profile(
    updates: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    return crud.update_user(db, current_user.id, updates)

@router.delete("/profile", response_model=schemas.MessageResponse)
def delete_profile(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    crud.delete_user(db, current_user.id)
    return {"message": "User deleted successfully"}

# Admin routes
def get_current_admin(current_user: models.User = Depends(get_current_user)):
    if not any(role.role_name == "admin" for role in current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

@router.post("/roles", response_model=schemas.RoleResponse, dependencies=[Depends(get_current_admin)])
def create_role(role: schemas.RoleCreate, db: Session = Depends(get_db)):
    return crud.create_role(db, role.role_name, role.expires_at)

@router.post("/permissions", response_model=schemas.PermissionResponse, dependencies=[Depends(get_current_admin)])
def create_permission(perm: schemas.PermissionCreate, db: Session = Depends(get_db)):
    return crud.create_permission(db, perm.permission_name, perm.expires_at)

@router.post("/assign-role", response_model=schemas.UserRoleResponse, dependencies=[Depends(get_current_admin)])
def assign_role_to_user(assignment: schemas.UserRoleCreate, db: Session = Depends(get_db)):
    return crud.assign_role_to_user(db, assignment.user_id, assignment.role_id)

@router.post("/assign-permission", response_model=schemas.RolePermissionResponse, dependencies=[Depends(get_current_admin)])
def assign_permission_to_role(assignment: schemas.RolePermissionCreate, db: Session = Depends(get_db)):
    return crud.assign_permission_to_role(db, assignment.role_id, assignment.permission_id, assignment.is_all)
