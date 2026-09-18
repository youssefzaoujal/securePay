"""SecurePay Gateway — point d'entrée PSP."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from gateway.middleware import RateLimitMiddleware
from gateway.routes import router as gateway_router
from shared.http import mount_security

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Passerelle de paiement simulée, inspirée PCI-DSS. "
        "Aucune donnée carte réelle n'est traitée."
    ),
    docs_url="/docs" if settings.DEBUG or settings.APP_ENV == "lab" else None,
    redoc_url="/redoc" if settings.DEBUG or settings.APP_ENV == "lab" else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.RATE_LIMIT_PER_MINUTE)
mount_security(app)
app.include_router(gateway_router, prefix="/api/v1", tags=["gateway"])


@app.get("/health", tags=["health"])
async def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "disclaimer": "simulation-only",
    }
