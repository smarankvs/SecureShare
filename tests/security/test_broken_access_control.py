import pytest


def test_vertical_privilege_escalation_blocked(client):
    """
    Vertical Privilege Escalation:
    Ensure non-admin users cannot grant themselves or others administrative roles.
    """
    # 1. Register and login regular User
    client.post("/api/v1/auth/register", json={
        "name": "Regular User",
        "email": "standard@example.com",
        "password": "Password123!"
    })
    res = client.post("/api/v1/auth/login", json={
        "email": "standard@example.com",
        "password": "Password123!"
    })
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    me_res = client.get("/api/v1/users/me", headers=headers)
    assert me_res.status_code == 200
    user_id = me_res.json()["id"]
    assert me_res.json()["role"] == "user"

    # 2. Attempt unauthorized role upgrade to 'admin'
    escalate_res = client.patch(
        f"/api/v1/users/{user_id}/role",
        headers=headers,
        json={"role": "admin"}
    )
    assert escalate_res.status_code == 403
    err_body = str(escalate_res.json()).lower()
    assert "administrator" in err_body or "forbidden" in err_body

    # 3. Verify role was NOT modified
    verify_res = client.get("/api/v1/users/me", headers=headers)
    assert verify_res.json()["role"] == "user"


def test_horizontal_user_isolation(client):
    """
    Horizontal Access Control:
    Ensure User B cannot inspect User A's profile.
    """
    # Register User A
    reg_a = client.post("/api/v1/auth/register", json={
        "name": "Target User",
        "email": "target@example.com",
        "password": "Password123!"
    })
    user_a_id = reg_a.json()["id"]

    # Register and login User B
    client.post("/api/v1/auth/register", json={
        "name": "Curious User",
        "email": "curious@example.com",
        "password": "Password123!"
    })
    res_b = client.post("/api/v1/auth/login", json={
        "email": "curious@example.com",
        "password": "Password123!"
    })
    headers_b = {"Authorization": f"Bearer {res_b.json()['access_token']}"}

    # User B attempts to inspect User A's profile
    res_unauth = client.get(f"/api/v1/users/{user_a_id}", headers=headers_b)
    assert res_unauth.status_code == 403
