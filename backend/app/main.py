"""FastAPI application entrypoint.

Run:  uvicorn app.main:app --reload
       (from backend/, with a venv: python -m venv .venv && pip install -r requirements.txt)

Privacy: request logging redacts device ids to a short prefix and
never logs request bodies. No child PII is ever logged.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import db
from .config import get_settings
from .routes import routers

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

settings = get_settings()

app = FastAPI(
    title="Aegis-Kid OS Backend",
    description=(
        "Central Watchdog, AI Adjudicator & Parent Alert Backend "
        "(India Edition MVP). DPDP: no child browsing history, app usage, "
        "screenshots, search queries, or voice/text is accepted or stored."
    ),
    version="0.1.0",
)

# CORS is locked down to the configured parent/support origins only.
# An empty ALLOWED_ORIGINS means no cross-origin browser access.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# --- minimal rate-limit stub (60 requests / minute per client IP) --------
_RATE_LIMIT = 60
_WINDOW_SECONDS = 60
_hits: dict[str, list[float]] = defaultdict(list)


@app.middleware("http")
async def _rate_limit_and_redacted_log(request: Request, call_next):  # type: ignore[no-untyped-def]
    client = request.client.host if request.client else "unknown"
    now = time.time()
    window = _hits[client]
    _hits[client] = [t for t in window if now - t < _WINDOW_SECONDS]
    if len(_hits[client]) >= _RATE_LIMIT:
        return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})
    _hits[client].append(now)
    response = await call_next(request)
    # Redacted log: method + path + status only. Never log bodies or ids.
    logger.info("%s %s -> %s", request.method, request.url.path, response.status_code)
    return response


for router in routers:
    app.include_router(router)


@app.on_event("startup")
def _startup() -> None:
    db.init_db()
    db.purge_old_heartbeats(days=30)
    logger.info("Aegis-Kid OS backend started; DB at %s", db.get_db_path())


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "app": settings.app_name, "version": "0.1.0"}


@app.get("/")
def root() -> dict:
    return {"app": settings.app_name, "docs": "/docs", "health": "/health"}
