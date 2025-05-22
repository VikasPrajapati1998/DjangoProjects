from fastapi import FastAPI
from app import models
from app.database import engine
from app.routes import router

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI JWT + DB-Backed OTP")

app.include_router(router)
