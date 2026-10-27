import io
import pytest


def test_idor_file_metadata_and_download_prevention(client):
    """
    IDOR / BOLA (Insecure Direct Object Reference / Broken Object Level Auth):
    Ensure User B cannot inspect, download, or delete User A's files.
    """
    # 1. Register and login User A
    client.post("/api/v1/auth/register", json={
        "name": "User Alpha",
        "email": "alpha@example.com",
        "password": "Password123!"
    })
    res_a = client.post("/api/v1/auth/login", json={
        "email": "alpha@example.com",
        "password": "Password123!"
    })
    token_a = res_a.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 2. Register and login User B (Attacker)
    client.post("/api/v1/auth/register", json={
        "name": "User Bravo",
        "email": "bravo@example.com",
        "password": "Password123!"
    })
    res_b = client.post("/api/v1/auth/login", json={
        "email": "bravo@example.com",
        "password": "Password123!"
    })
    token_b = res_b.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # 3. User A uploads a valid PDF document
    valid_pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
    upload_res = client.post(
        "/api/v1/upload",
        headers=headers_a,
        files={"file": ("confidential_report.pdf", io.BytesIO(valid_pdf_content), "application/pdf")}
    )
    assert upload_res.status_code == 201
    file_id = upload_res.json()["id"]
    blob_name = upload_res.json()["blob_name"]

    # 4. User A can access their own file metadata
    res_owner = client.get(f"/api/v1/files/{file_id}", headers=headers_a)
    assert res_owner.status_code == 200

    # 5. IDOR Attack: User B attempts to access User A's file metadata
    res_idor_get = client.get(f"/api/v1/files/{file_id}", headers=headers_b)
    assert res_idor_get.status_code == 403
    err_body = str(res_idor_get.json()).lower()
    assert "permission" in err_body or "forbidden" in err_body

    # 6. IDOR Attack: User B attempts to download User A's file stream
    res_idor_dl = client.get(f"/api/v1/files/download/{blob_name}", headers=headers_b)
    assert res_idor_dl.status_code == 403

    # 7. IDOR Attack: User B attempts to delete User A's file
    res_idor_del = client.delete(f"/api/v1/files/{file_id}", headers=headers_b)
    assert res_idor_del.status_code == 403
