import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, files, shares, upload, users
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.keyvault import init_keyvault_secrets
from app.db.database import init_db
from app.middleware.auth import JWTAuthMiddleware
from app.middleware.logging import RequestLoggingMiddleware
from app.middleware.rate_limit import RateLimiterMiddleware
from app.utils.logger import setup_logging

logger = logging.getLogger("secureshare.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application Lifespan Context Manager.
    Handles startup secret hydration, database initialization, and graceful shutdown.
    """
    # 1. Initialize Structured Logging
    setup_logging()
    logger.info("Initializing SecureShare Backend Services...")

    # 2. Hydrate secrets from Azure Key Vault (with fallback to .env)
    try:
        init_keyvault_secrets(settings)
    except Exception as exc:
        logger.error(f"Error during Key Vault initialization: {exc}")

    # 3. Initialize Database Schema
    try:
        init_db()
    except Exception as exc:
        logger.warning(
            f"Database auto-migration warning: {exc}. "
            "Ensure PostgreSQL is running or run Alembic migrations."
        )

    logger.info(f"SecureShare API v{settings.VERSION} initialized and ready.")
    yield
    logger.info("SecureShare API shutting down...")


# Create FastAPI application instance with rich OpenAPI metadata
app = FastAPI(
    title="SecureShare API",
    description=(
        "**SecureShare** is an enterprise-grade cloud-based secure document sharing backend.\n\n"
        "### Security Architecture & Features\n"
        "- **Azure Key Vault**: Zero-trust credential isolation (secrets fetched dynamically with .env fallback).\n"
        "- **Azure Blob Storage**: Segregated private container ('secure-files') with randomized UUID filenames.\n"
        "- **JWT Authentication**: Encrypted tokens with sliding session refresh and constant-time password verification.\n"
        "- **Multi-Layer Validation**: Strict 25MB threshold, allowlisted extensions (.pdf, .png, .jpg, .jpeg, .docx), and deep magic byte MIME inspection.\n"
        "- **Malware Defense**: Heuristic signature analysis and ClamAV integration.\n"
        "- **Auditing & Defense**: IP-based rate limiting, OWASP secure HTTP headers, and tamper-resistant audit logs."
    ),
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# 1. Register Global Exception Handlers (400, 401, 403, 404, 409, 413, 422, 500)
register_exception_handlers(app)

# 2. Register Middleware (LIFO execution order)
# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "Content-Disposition"]
)

# JWT Context Middleware
app.add_middleware(JWTAuthMiddleware)

# Request & Security Headers Middleware
app.add_middleware(RequestLoggingMiddleware)

# Rate Limiter Middleware
app.add_middleware(RateLimiterMiddleware)


# 3. Include API Routers
# Mount direct /upload endpoint as explicitly specified in requirements
app.include_router(upload.router)

# Mount Versioned API (v1) Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(upload.router, prefix=settings.API_V1_STR)
app.include_router(files.router, prefix=settings.API_V1_STR)
app.include_router(shares.router, prefix=settings.API_V1_STR)
app.include_router(shares.documents_router, prefix=settings.API_V1_STR)
app.include_router(users.router, prefix=settings.API_V1_STR)


@app.get("/", tags=["System"])
def root():
    """System information and operational status."""
    return {
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "status": "online",
        "docs_url": "/docs"
    }


@app.get("/health", tags=["System"])
def health_check():
    """
    Comprehensive health check for container orchestration and uptime probes.
    """
    return {
        "status": "healthy",
        "keyvault_enabled": settings.AZURE_KEYVAULT_ENABLED,
        "storage_mode": "azure" if settings.AZURE_STORAGE_CONNECTION_STRING else "local_fallback",
        "timestamp": settings.VERSION
    }
