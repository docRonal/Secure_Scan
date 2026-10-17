"""SecureScan AI MVP backend with continuous monitoring."""
from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.db import Base, engine
from app.routers import assets, scans, reports, monitoring, auth
from app.scheduler import start_scheduler, stop_scheduler
from app.seed import seed_admin_user, seed_demo_data, seed_guest_user
from app.migrate import auto_migrate_sqlite

logger = logging.getLogger("securescan.main")


def _validate_active_scanning_config() -> None:
    if settings.zap_enabled and not settings.zap_api_key:
        raise RuntimeError("ZAP_API_KEY must be set when ZAP_ENABLED=true")


Base.metadata.create_all(bind=engine)
auto_migrate_sqlite(engine, Base)
seed_admin_user()
seed_guest_user()
seed_demo_data()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.zap_enabled:
        _validate_active_scanning_config()
        from app.scanners.active.zap_client import ZAPClient, ZAPError

        zap_client = ZAPClient(settings.zap_api_url, settings.zap_api_key)
        try:
            if zap_client.is_available():
                zap_client.configure_scan_policy(
                    settings.zap_scan_policy,
                    attack_strength=settings.zap_attack_strength,
                    alert_threshold=settings.zap_alert_threshold,
                    enable_all_scanners=settings.zap_enable_all_scanners,
                )
                logger.info(
                    "Configured ZAP active scanners: strength=%s threshold=%s all_enabled=%s",
                    settings.zap_attack_strength,
                    settings.zap_alert_threshold,
                    settings.zap_enable_all_scanners,
                )
            else:
                logger.warning("ZAP API unavailable at startup; settings will be applied before the next scan")
        except ZAPError:
            logger.warning(
                "Could not configure ZAP at startup; settings will be retried before the next scan",
                exc_info=True,
            )

    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(
    title=settings.app_name,
    description=(
        "MVP backend: верификация владения активом, пассивный слой проверок "
        "(headers/TLS/fingerprint/CVE) и непрерывный мониторинг (Phase 3). "
        "Активное сканирование — см. app/scanners/active/__init__.py."
    ),
    version="0.2.0",
    lifespan=lifespan,
)

# Restrict allowed origins to the production dashboard domain when deployed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(assets.router)
app.include_router(scans.router)
app.include_router(reports.router)
app.include_router(monitoring.router)


# CSP is intentionally omitted because Swagger UI and HTML reports need a
# route-specific policy. Add one only after testing those routes explicitly.
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Log unhandled errors and return them through the CORS middleware stack."""
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.get("/", tags=["meta"])
def root():
    return {
        "name": settings.app_name,
        "status": "ok",
        "docs": "/docs",
        "note": "Only scan assets you own or are explicitly authorized to test.",
    }
