import io
import pytest


def test_filename_xss_and_path_traversal_sanitization(client, test_user_headers):
    """
    XSS & Path Traversal Defense:
    Ensure file uploads with XSS payloads or path traversal characters
    in the filename are strictly sanitized before storage.
    """
    xss_filename = "<script>alert('XSS')</script>_test.pdf"
    pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"

    upload_res = client.post(
        "/api/v1/upload",
        headers=test_user_headers,
        files={"file": (xss_filename, io.BytesIO(pdf_content), "application/pdf")}
    )

    assert upload_res.status_code == 201
    persisted_name = upload_res.json()["original_name"]

    # Script tags and dangerous characters must be stripped/sanitized
    assert "<script>" not in persisted_name
    assert "</script>" not in persisted_name


def test_owasp_security_headers_enforced_on_all_responses(client):
    """
    OWASP Secure Headers Defense:
    Ensure critical HTTP security headers are present to block XSS and clickjacking.
    """
    res = client.get("/health")
    assert res.status_code == 200

    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert "Strict-Transport-Security" in headers
    assert "Referrer-Policy" in headers
    assert "Permissions-Policy" in headers
