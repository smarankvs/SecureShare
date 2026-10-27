import logging

from fastapi import FastAPI

from app.api.v1 import documents
from app.core.config import settings
from app.middleware.upload_limit import UploadSizeLimitMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

app = FastAPI(
    title="SecureShare API",
    description="Secure Cloud-Based Document Sharing Platform API",
    version="0.1.0"
)

# Reject oversized uploads before multipart parsing / spooling.
app.add_middleware(
    UploadSizeLimitMiddleware,
    max_body_bytes=settings.MAX_UPLOAD_BYTES + settings.MULTIPART_OVERHEAD_BYTES,
    path_prefixes=(f"{settings.API_V1_PREFIX}/documents/upload",),
)

app.include_router(documents.router, prefix=settings.API_V1_PREFIX)


@app.get("/")
def read_root():
    return {
        "message": "Welcome to SecureShare API",
        "status": "online"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }
