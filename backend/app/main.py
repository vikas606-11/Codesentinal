from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import db
from app.api import explain, health, scan, scans
from app.config import get_settings

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title=f"{settings.app_name} API",
    version=settings.app_version,
    description="AI-assisted DevSecOps code security and quality platform.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GET /health (for Docker/ops) and GET /api/v1/health (for the frontend)
app.include_router(health.router)
app.include_router(health.router, prefix="/api/v1")
app.include_router(scan.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(explain.router, prefix="/api/v1")
