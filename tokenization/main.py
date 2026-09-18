"""Tokenization Service — CDE simulé, AES-256-GCM, CVV jamais stocké."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from config import get_settings
from shared.http import mount_security
from tokenization.routes import router as tokenization_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="SecurePay - Tokenization Service", version=settings.APP_VERSION, lifespan=lifespan)
mount_security(app)
app.include_router(tokenization_router, prefix="/api/v1", tags=["tokenization"])


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "tokenization"}
