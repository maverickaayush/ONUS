from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings, validate_startup_security
from routers.scan import router as scan_router
from routers.report import router as report_router
from routers.verify import router as verify_router
from routers.auth import router as auth_router

# Refuse to boot with default secrets in a production posture (no-op warning for
# local self-hosted). Runs at import so uvicorn/gunicorn can't skip it.
validate_startup_security()

app = FastAPI(
    title="ONUS VAPT API",
    description="ONUS - Automated Vulnerability Assessment and Penetration Testing",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(report_router)
app.include_router(verify_router)
app.include_router(auth_router)
