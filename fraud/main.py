"""Fraud Detection Service."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from config import get_settings
from fraud.routes import router as fraud_router
from fraud.three_ds import router as three_ds_router
from shared.http import mount_security

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="SecurePay - Fraud Detection Service", version=settings.APP_VERSION, lifespan=lifespan)
mount_security(app)
app.include_router(fraud_router, prefix="/api/v1", tags=["fraud"])
app.include_router(three_ds_router, prefix="/api/v1", tags=["3ds2"])


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "fraud"}
