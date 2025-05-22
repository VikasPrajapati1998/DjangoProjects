from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime, timezone

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)
    user_name = Column(String(100), nullable=False)
    mobile_number = Column(String(20), unique=True, nullable=False)
    gender = Column(String(10), nullable=True)
    created_at = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        nullable=False)
    updated_at = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc),
                        nullable=False)

    roles = relationship("UserRole", back_populates="user")


class OTP(Base):
    __tablename__ = "otps"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), index=True, nullable=False)
    otp = Column(String(6), nullable=False)
    created_at = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    users = relationship("UserRole", back_populates="role")
    permissions = relationship("RolePermission", back_populates="role")


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    permission_name = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    roles = relationship("RolePermission", back_populates="permission")


class UserRole(Base):
    __tablename__ = "user_roles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    created_at = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        nullable=False)

    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="users")


class RolePermission(Base):
    __tablename__ = "role_permissions"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    permission_id = Column(Integer, ForeignKey("permissions.id"), nullable=False)
    is_all = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        nullable=False)

    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")
