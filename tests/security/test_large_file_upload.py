import io
import pytest
from app.core.config import settings


def test_large_file_upload_rejected_by_threshold(client, test_user_headers):
    """
    Large File Upload / Denial-of-Service Defense:
    Ensure files exceeding MAX_FILE_SIZE_BYTES (25MB) are strictly rejected with 413 Payload Too Large.
    """
    oversized_bytes = b"%PDF-1.4\n" + (b"0" * (settings.MAX_FILE_SIZE_BYTES + 1024 * 1024))

    res = client.post(
        "/api/v1/upload",
        headers=test_user_headers,
        files={"file": ("huge_file.pdf", io.BytesIO(oversized_bytes), "application/pdf")}
    )

    assert res.status_code == 413
    assert "exceed" in str(res.json()).lower()
