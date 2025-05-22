from sqlalchemy import Column, Integer, String
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)
    user_name = Column(String(100), nullable=False)
    mobile_number = Column(String(20), unique=True, nullable=True)
    gender = Column(String(10), nullable=True)

