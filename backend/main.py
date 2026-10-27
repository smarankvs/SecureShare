from fastapi import FastAPI
from app.api.v1.documents import router as documents_router
from app.core.config import settings
from app.middleware.upload_limit import UploadSizeLimitMiddleware

app = FastAPI(
    title="SecureShare — Storage & Inspection Service",
    description="Member 3 File Inspection, ClamAV Scanning, and Storage Pipeline",
    version="1.0.0"
)

# Enforce early 413 rejection before body parsing, allowing for multipart envelope overhead
app.add_middleware(
    UploadSizeLimitMiddleware,
    max_body_bytes=settings.MAX_UPLOAD_BYTES + settings.MULTIPART_OVERHEAD_BYTES,
    path_prefixes=("/api/v1/documents",)
)

app.include_router(documents_router, prefix="/api/v1")


@app.get("/health")
def health():
    return {"status": "ok"}
