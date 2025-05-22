from fastapi import FastAPI
from app import models
from app.database import engine
from app.routes import router
from fastapi.middleware.cors import CORSMiddleware

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="FastAPI Authentication System",
    description="Complete authentication system with JWT, OTP, and Role-Based Access Control",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/rbac")