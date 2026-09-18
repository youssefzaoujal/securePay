# Rate limiting + enforcement SOAR (Zero Trust: deny by default si IP en blocklist).
"""Rate limiting Redis + blocage IP automatique post-détection."""

import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

import redis.asyncio as redis

from config import get_settings
from detection.soar.blocklist import is_blocked
from shared.events import emit_event
from shared.metrics import RATE_LIMIT_HITS

settings = get_settings()


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.rpm = requests_per_minute
        self.redis_client = None

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else ""
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        ip = forwarded or client_ip

        if is_blocked(ip):
            emit_event(
                {
                    "event_type": "soar_block_enforced",
                    "status": "blocked",
                    "source_ip": ip,
                    "path": str(request.url.path),
                }
            )
            return JSONResponse(
                {"detail": "IP bloquée par réponse automatique SOAR"},
                status_code=403,
            )

        if not self.redis_client:
            try:
                self.redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
            except Exception:
                return await call_next(request)

        client_id = ip
        if hasattr(request.state, "user") and isinstance(request.state.user, dict):
            client_id = request.state.user.get("sub", ip)

        key = f"rate_limit:{client_id}"
        now = int(time.time())
        window_start = now - 60

        try:
            pipe = self.redis_client.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zcard(key)
            pipe.zadd(key, {str(now): now})
            pipe.expire(key, 120)
            results = await pipe.execute()
            if results[1] >= self.rpm:
                RATE_LIMIT_HITS.inc()
                emit_event(
                    {
                        "event_type": "rate_limit_exceeded",
                        "status": "blocked",
                        "source_ip": ip,
                        "limit": self.rpm,
                    }
                )
                return JSONResponse(
                    {
                        "detail": f"Limite de débit dépassée: {self.rpm} requêtes/minute",
                    },
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
        except Exception:
            pass

        return await call_next(request)
