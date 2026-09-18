"""Payment Service."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from config import get_settings
from payment.merchants import router as merchants_router
from payment.routes import router as payment_router
from shared.http import mount_security

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="SecurePay - Payment Service", version=settings.APP_VERSION, lifespan=lifespan)
mount_security(app)
app.include_router(payment_router, prefix="/api/v1", tags=["payment"])
app.include_router(merchants_router, prefix="/api/v1/merchants", tags=["merchants"])


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "payment"}
