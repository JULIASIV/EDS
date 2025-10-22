# server/main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPBearer
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis
import logging
from contextlib import asynccontextmanager
import uvicorn

from config.settings import settings
from database.database import engine, create_db_and_tables
from server.middleware import LoggingMiddleware, SecurityHeadersMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('edr_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting EDR Server...")
    create_db_and_tables()
    
    # Initialize Redis for rate limiting
    redis_connection = redis.from_url("redis://localhost:6379", encoding="utf-8")
    await FastAPILimiter.init(redis_connection)
    
    yield
    
    # Shutdown
    logger.info("Shutting down EDR Server...")
    await FastAPILimiter.close()

app = FastAPI(
    title="Enterprise EDR System",
    description="Production Endpoint Detection and Response Platform",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Security Middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])  # Configure properly!
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(LoggingMiddleware)

# Performance Middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# CORS - Configure properly for your domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import routers
from server.routes import agents, events, dashboard, rules

# API Routes
app.include_router(agents.router, prefix="/api/v1", tags=["agents"])
app.include_router(events.router, prefix="/api/v1", tags=["events"])
app.include_router(dashboard.router, prefix="/api/v1", tags=["dashboard"])
app.include_router(rules.router, prefix="/api/v1", tags=["rules"])

@app.get("/")
async def root():
    return {"message": "Enterprise EDR System", "version": "2.0.0"}

@app.get("/health", dependencies=[Depends(RateLimiter(times=10, seconds=60))])
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }

if __name__ == "__main__":
    uvicorn.run(
        "server.main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        workers=settings.WORKER_COUNT,
        log_level="info"
    )