"""HTTP tests for authenticated self-service MFA management."""

import pyotp
from conftest import WEB_CLIENT_ID

MFA_ROOT = "/api/v1/profile/mfa"


def _auth_headers(client, username: str, password: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password, "client_id": WEB_CLIENT_ID},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_mfa_management_requires_authentication(client):
    response = client.get(MFA_ROOT)

    assert response.status_code == 401


def test_setup_enable_and_read_mfa_status(client, make_user):
    user = make_user(username="mfa-user", password="Str0ng!Pass")
    headers = _auth_headers(client, user.username, "Str0ng!Pass")

    initial_status = client.get(MFA_ROOT, headers=headers)
    assert initial_status.status_code == 200
    assert initial_status.json() == {"mfa_enabled": False}

    setup = client.post(f"{MFA_ROOT}/setup", headers=headers)
    assert setup.status_code == 200
    assert setup.headers["cache-control"] == "no-store"
    secret = setup.json()["secret"]

    enabled = client.post(
        f"{MFA_ROOT}/enable",
        headers=headers,
        json={"current_password": "Str0ng!Pass", "mfa_code": pyotp.TOTP(secret).now()},
    )
    assert enabled.status_code == 200
    assert enabled.headers["cache-control"] == "no-store"
    assert enabled.json()["message"] == "MFA enabled successfully"
    assert enabled.json()["backup_codes"]

    current_status = client.get(MFA_ROOT, headers=headers)
    assert current_status.status_code == 200
    assert current_status.json() == {"mfa_enabled": True}

    backup_status = client.get(f"{MFA_ROOT}/backup-codes", headers=headers)
    assert backup_status.status_code == 200
    assert backup_status.json()["unused"] == len(enabled.json()["backup_codes"])

    verified = client.post(
        f"{MFA_ROOT}/verify",
        headers=headers,
        json={"mfa_code": enabled.json()["backup_codes"][0]},
    )
    assert verified.status_code == 200

    regenerated = client.post(
        f"{MFA_ROOT}/backup-codes",
        headers=headers,
        json={
            "current_password": "Str0ng!Pass",
            "mfa_code": enabled.json()["backup_codes"][1],
        },
    )
    assert regenerated.status_code == 201
    assert regenerated.headers["cache-control"] == "no-store"
    assert regenerated.json()["codes"]

    disabled = client.post(
        f"{MFA_ROOT}/disable",
        headers=headers,
        json={
            "current_password": "Str0ng!Pass",
            "mfa_code": regenerated.json()["codes"][0],
        },
    )
    assert disabled.status_code == 200
    assert client.get(MFA_ROOT, headers=headers).json() == {"mfa_enabled": False}
    assert client.get(f"{MFA_ROOT}/backup-codes", headers=headers).json()["has_codes"] is False
