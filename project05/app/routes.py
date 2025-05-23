from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, joinedload
from app import schemas, crud, auth, models
from app.database import get_db
import os, random, smtplib
from email.mime.text import MIMEText
from typing import List

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/rbac/login")

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

# Role routes
@router.get("/roles", response_model=List[schemas.RoleResponse], dependencies=[Depends(get_current_user)])
def get_roles(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return crud.get_roles(db, skip, limit)

@router.get("/roles/{role_id}", response_model=schemas.RoleResponse, dependencies=[Depends(get_current_user)])
def get_role(role_id: int, db: Session = Depends(get_db)):
    role = crud.get_role(db, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role

@router.post("/roles", response_model=schemas.RoleResponse, dependencies=[Depends(get_current_user)])
def create_role(role: schemas.RoleCreate, db: Session = Depends(get_db)):
    return crud.create_role(db, role.role_name, role.expires_at)

@router.put("/roles/{role_id}", response_model=schemas.RoleResponse, dependencies=[Depends(get_current_user)])
def update_role(role_id: int, updates: schemas.RoleUpdate, db: Session = Depends(get_db)):
    return crud.update_role(db, role_id, updates)

@router.delete("/roles/{role_id}", response_model=schemas.MessageResponse, dependencies=[Depends(get_current_user)])
def delete_role(role_id: int, db: Session = Depends(get_db)):
    crud.delete_role(db, role_id)
    return {"message": "Role deleted successfully"}

# Permission routes
@router.get("/permissions", response_model=List[schemas.PermissionResponse], dependencies=[Depends(get_current_user)])
def get_permissions(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return crud.get_permissions(db, skip, limit)

@router.get("/permissions/{permission_id}", response_model=schemas.PermissionResponse, dependencies=[Depends(get_current_user)])
def get_permission(permission_id: int, db: Session = Depends(get_db)):
    permission = crud.get_permission(db, permission_id)
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")
    return permission

@router.post("/permissions", response_model=schemas.PermissionResponse, dependencies=[Depends(get_current_user)])
def create_permission(perm: schemas.PermissionCreate, db: Session = Depends(get_db)):
    return crud.create_permission(db, perm.permission_name, perm.expires_at)

@router.put("/permissions/{permission_id}", response_model=schemas.PermissionResponse, dependencies=[Depends(get_current_user)])
def update_permission(permission_id: int, updates: schemas.PermissionUpdate, db: Session = Depends(get_db)):
    return crud.update_permission(db, permission_id, updates)

@router.delete("/permissions/{permission_id}", response_model=schemas.MessageResponse, dependencies=[Depends(get_current_user)])
def delete_permission(permission_id: int, db: Session = Depends(get_db)):
    crud.delete_permission(db, permission_id)
    return {"message": "Permission deleted successfully"}

# User-Role routes
@router.get("/user-roles", response_model=List[schemas.UserRoleResponse], dependencies=[Depends(get_current_user)])
def get_user_roles(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    user_roles = crud.get_user_roles(db, skip, limit)
    # Add role_name to each user_role
    return [
        schemas.UserRoleResponse(
            id=ur.id,
            user_id=ur.user_id,
            role_id=ur.role_id,
            role_name=ur.role.role_name
        ) for ur in user_roles
    ]

@router.get("/user-roles/{user_role_id}", response_model=schemas.UserRoleResponse, dependencies=[Depends(get_current_user)])
def get_user_role(user_role_id: int, db: Session = Depends(get_db)):
    user_role = crud.get_user_role(db, user_role_id)
    if not user_role:
        raise HTTPException(status_code=404, detail="User role assignment not found")
    return schemas.UserRoleResponse(
        id=user_role.id,
        user_id=user_role.user_id,
        role_id=user_role.role_id,
        role_name=user_role.role.role_name
    )

@router.get("/users/{user_id}/roles", response_model=List[schemas.RoleResponse], dependencies=[Depends(get_current_user)])
def get_user_roles_by_user(user_id: int, db: Session = Depends(get_db)):
    return crud.get_user_roles_by_user(db, user_id)

@router.post("/user-roles", response_model=schemas.UserRoleResponse, dependencies=[Depends(get_current_user)])
def assign_role_to_user(assignment: schemas.UserRoleCreate, db: Session = Depends(get_db)):
    user_role = crud.assign_user_role(db, assignment.user_id, assignment.role_id)
    role = crud.get_role(db, user_role.role_id)
    return schemas.UserRoleResponse(
        id=user_role.id,
        user_id=user_role.user_id,
        role_id=user_role.role_id,
        role_name=role.role_name
    )

@router.put("/user-roles/{user_role_id}", response_model=schemas.UserRoleResponse, dependencies=[Depends(get_current_user)])
def update_user_role(user_role_id: int, updates: schemas.UserRoleUpdate, db: Session = Depends(get_db)):
    user_role = crud.update_user_role(db, user_role_id, updates)
    role = crud.get_role(db, user_role.role_id)
    return schemas.UserRoleResponse(
        id=user_role.id,
        user_id=user_role.user_id,
        role_id=user_role.role_id,
        role_name=role.role_name
    )

@router.delete("/user-roles/{user_role_id}", response_model=schemas.MessageResponse, dependencies=[Depends(get_current_user)])
def delete_user_role(user_role_id: int, db: Session = Depends(get_db)):
    crud.delete_user_role(db, user_role_id)
    return {"message": "User role assignment deleted successfully"}

# Role-Permission routes
@router.get("/role-permissions", response_model=List[schemas.RolePermissionResponse], dependencies=[Depends(get_current_user)])
def get_role_permissions(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    role_permissions = crud.get_role_permissions(db, skip, limit)
    # Add permission_name to each role_permission
    return [
        schemas.RolePermissionResponse(
            id=rp.id,
            role_id=rp.role_id,
            permission_id=rp.permission_id,
            permission_name=rp.permission.permission_name,
            is_all=rp.is_all
        ) for rp in role_permissions
    ]

@router.get("/role-permissions/{role_permission_id}", response_model=schemas.RolePermissionResponse, dependencies=[Depends(get_current_user)])
def get_role_permission(role_permission_id: int, db: Session = Depends(get_db)):
    rp = crud.get_role_permission(db, role_permission_id)
    if not rp:
        raise HTTPException(status_code=404, detail="Role permission assignment not found")
    return schemas.RolePermissionResponse(
        id=rp.id,
        role_id=rp.role_id,
        permission_id=rp.permission_id,
        permission_name=rp.permission.permission_name,
        is_all=rp.is_all
    )

@router.get("/roles/{role_id}/permissions", response_model=List[schemas.PermissionResponse], dependencies=[Depends(get_current_user)])
def get_role_permissions_by_role(role_id: int, db: Session = Depends(get_db)):
    return crud.get_role_permissions_by_role(db, role_id)

@router.post("/role-permissions", response_model=schemas.RolePermissionResponse, dependencies=[Depends(get_current_user)])
def assign_permission_to_role(assignment: schemas.RolePermissionCreate, db: Session = Depends(get_db)):
    rp = crud.assign_role_permission(db, assignment.role_id, assignment.permission_id, assignment.is_all)
    permission = crud.get_permission(db, rp.permission_id)
    return schemas.RolePermissionResponse(
        id=rp.id,
        role_id=rp.role_id,
        permission_id=rp.permission_id,
        permission_name=permission.permission_name,
        is_all=rp.is_all
    )

@router.put("/role-permissions/{role_permission_id}", response_model=schemas.RolePermissionResponse, dependencies=[Depends(get_current_user)])
def update_role_permission(role_permission_id: int, updates: schemas.RolePermissionUpdate, db: Session = Depends(get_db)):
    rp = crud.update_role_permission(db, role_permission_id, updates)
    permission = crud.get_permission(db, rp.permission_id)
    return schemas.RolePermissionResponse(
        id=rp.id,
        role_id=rp.role_id,
        permission_id=rp.permission_id,
        permission_name=permission.permission_name,
        is_all=rp.is_all
    )

@router.delete("/role-permissions/{role_permission_id}", response_model=schemas.MessageResponse, dependencies=[Depends(get_current_user)])
def delete_role_permission(role_permission_id: int, db: Session = Depends(get_db)):
    crud.delete_role_permission(db, role_permission_id)
    return {"message": "Role permission assignment deleted successfully"}
