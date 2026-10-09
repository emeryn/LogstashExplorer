import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app import __version__
from app.api import admin, auth, mcp, me, projects, workspace
from app.core import syslog
from app.core.config import get_settings
from app.core.crypto import HybridCipher, init_cipher
from app.core.logging import setup_logging
from app.core.secrets import require_secret
from app.core.security import is_public_origin
from app.db.init import init_db
from app.db.session import get_engine, init_engine, sessionmaker
from app.services.settings_store import apply_logging_settings, apply_syslog_settings
from app.tasks.scheduler import start_scheduler

log = logging.getLogger("app")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@asynccontextmanager
async def lifespan(_: FastAPI):
    s = get_settings()
    setup_logging(s.log_level)
    init_cipher(
        HybridCipher.from_secrets(
            require_secret("master_key"), require_secret("kem_x25519_sk"), require_secret("kem_mlkem768_seed")
        )
    )
    init_engine()
    await init_db()
    async with sessionmaker()() as db:
        await apply_logging_settings(db)
        await apply_syslog_settings(db)
    scheduler = start_scheduler()
    log.info("backend started", extra={"ctx": {"version": __version__, "env": s.env}})
    yield
    scheduler.shutdown(wait=False)
    syslog.configure(None)  # flush queued records
    await get_engine().dispose()


settings = get_settings()
app = FastAPI(
    title="Logstash Explorer API",
    version=__version__,
    lifespan=lifespan,
    docs_url="/api/docs" if settings.env == "development" else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.env == "development" else None,
)


@app.middleware("http")
async def csrf_and_headers(request: Request, call_next):
    """CSRF: state-changing cookie-authenticated requests must carry `X-Requested-With`
    (not settable cross-origin without CORS preflight, and CORS is disabled) and, when present,
    an Origin matching the public URL. Bearer-token clients are exempt (no ambient credentials)."""
    if request.method in UNSAFE_METHODS and request.url.path.startswith("/api/"):
        bearer = request.headers.get("authorization", "").lower().startswith("bearer ")
        if not bearer:
            if request.headers.get("x-requested-with") != "XMLHttpRequest":
                return JSONResponse({"detail": "CSRF check failed"}, status_code=403)
            origin = request.headers.get("origin")
            if origin and not is_public_origin(origin):
                return JSONResponse({"detail": "CSRF origin check failed"}, status_code=403)
    response = await call_next(request)
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, exc: RequestValidationError):
    # Do not echo submitted values (may contain secrets/logs) back to the client.
    errors = [{"loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]
    return JSONResponse({"detail": errors}, status_code=422)


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    log.exception("unhandled error: %s", exc.__class__.__name__)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


@app.get("/api/health", tags=["ops"])
async def health() -> dict:
    async with sessionmaker()() as db:
        await db.execute(text("SELECT 1"))
    return {"status": "ok", "version": __version__}


app.include_router(auth.router)
app.include_router(me.router)
app.include_router(workspace.router)
app.include_router(projects.router)
app.include_router(admin.router)
app.include_router(mcp.router)
