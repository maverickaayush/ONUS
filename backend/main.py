from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers.scan import router as scan_router
from routers.report import router as report_router

app = FastAPI(
    title="VAPT Tool API",
    description="Automated Vulnerability Assessment and Penetration Testing — IIT Kanpur Computer Centre",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(report_router)
