"""End-to-end HTTP tests through the mounted JAFAAL router (FastAPI TestClient).

Covers the login → refresh → logout lifecycle, the MFA-required branch, and the
object-level authorization guard on the session endpoints.
"""

import pyotp
import pytest

import jafaal
import jafaal.exceptions as exc
import jafaal.mfa.crud as mfa_crud
import jafaal.orm as jafaal_orm
from jafaal import scopes as scopes_mod
from jafaal._core import crypto
from jafaal._internal.internal_dependencies import ClientType, get_client_type

WEB = {"X-Client-Type": "web"}


def _login(client, username="alice", password="Str0ng!Pass"):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
        headers=WEB,
    )


def _enable_mfa(user_id, secret):
    session = jafaal_orm.get_sessionmaker()()
    try:
        with jafaal_orm.unit_of_work(session):
            mfa_crud.update_user_mfa(user_id, session, encrypted_secret=crypto.encrypt_token_fernet(secret))
    finally:
        session.close()


def test_login_success_web(client, make_user):
    make_user(username="alice")
    resp = _login(client)
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["csrf_token"]  # web clients get a CSRF token in the body
    assert body["token_type"] == "bearer"
    # Refresh token delivered as an httpOnly cookie, not in the body.
    assert "refresh_token" not in body
    assert "jafaal_refresh_token" in resp.cookies


def test_login_wrong_password_401(client, make_user):
    make_user(username="alice")
    resp = _login(client, password="Wr0ng!Pass")
    assert resp.status_code == 401


def test_login_unknown_user_401(client):
    resp = _login(client, username="ghost")
    assert resp.status_code == 401


def test_login_ip_lockout_blocks_spray_across_usernames(client, make_user):
    from jafaal._internal.security_stores import get_failed_login_attempts

    store = get_failed_login_attempts()
    # Pre-load 49 sprayed failures from this source IP (just under the 50 threshold).
    for _ in range(49):
        store.record_ip_failure("testclient")

    # One real failed login via HTTP crosses the threshold (the handler records
    # the IP failure) and trips the per-IP backoff.
    first = client.post(
        "/api/v1/auth/login",
        data={"username": "u-50", "password": "whatever"},
        headers=WEB,
    )
    assert first.status_code == 401  # auth failed; the IP is now locked

    # A login for a DIFFERENT, never-seen account is refused with 429 — proving
    # the IP backoff bounds cross-account spray independently of per-account state.
    blocked = client.post(
        "/api/v1/auth/login",
        data={"username": "u-51", "password": "whatever"},
        headers=WEB,
    )
    assert blocked.status_code == 429
    assert "network" in blocked.json()["detail"].lower()


def test_successful_login_resets_ip_backoff(client, make_user):
    from jafaal._internal.security_stores import get_failed_login_attempts

    make_user(username="victim", password="Str0ng!Pass")
    store = get_failed_login_attempts()
    for _ in range(49):
        store.record_ip_failure("testclient")

    # A successful login from this IP clears the per-IP failure counter...
    assert _login(client, username="victim").status_code == 200

    # ...so it takes a fresh 49 failures again to approach the lock (not 98).
    for _ in range(49):
        store.record_ip_failure("testclient")
    assert store.is_ip_locked_out("testclient") is False


def test_login_missing_client_type_header_rejected(client, make_user):
    make_user(username="alice")
    resp = client.post("/api/v1/auth/login", data={"username": "alice", "password": "Str0ng!Pass"})
    assert resp.status_code in (401, 403)


def test_login_invalid_client_type_header_rejected(client, make_user):
    # A present-but-unrecognised X-Client-Type is rejected at the boundary (400),
    # not silently treated as mobile or stopped only by a downstream guard.
    make_user(username="alice")
    resp = client.post(
        "/api/v1/auth/login",
        data={"username": "alice", "password": "Str0ng!Pass"},
        headers={"X-Client-Type": "desktop"},
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "invalid_request"


def test_login_invalid_client_type_rejected_before_mfa(client, make_user):
    # An MFA-enabled account with an invalid client type is rejected at the
    # boundary before any handler logic runs, closing the old fall-through where
    # an unrecognised client type slipped past the MFA branch to complete_login.
    user = make_user(username="mfauser")
    _enable_mfa(user.id, pyotp.random_base32())
    resp = client.post(
        "/api/v1/auth/login",
        data={"username": "mfauser", "password": "Str0ng!Pass"},
        headers={"X-Client-Type": "Web"},  # wrong case -> invalid, not "web"
    )
    assert resp.status_code == 400
    assert "access_token" not in resp.json()


def test_get_client_type_dependency_validates():
    # web/mobile map to the enum; anything else (incl. wrong case / whitespace)
    # is rejected. A StrEnum, so members still compare as their string value.
    assert get_client_type("web") is ClientType.WEB
    assert get_client_type("mobile") is ClientType.MOBILE
    assert ClientType.WEB == "web"
    for bad in ("desktop", "Web", "MOBILE", "", "web "):
        with pytest.raises(exc.InvalidRequestError):
            get_client_type(bad)


def test_refresh_rotates_tokens(client, make_user):
    make_user(username="alice")
    first = _login(client).json()
    resp = client.post("/api/v1/auth/refresh", headers=WEB)
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["csrf_token"]
    # A fresh access token is issued.
    assert body["access_token"] != first["access_token"]


def test_logout(client, make_user):
    make_user(username="alice")
    _login(client)
    resp = client.post("/api/v1/auth/logout", headers=WEB)
    assert resp.status_code == 200


def test_login_mfa_required_returns_202(client, make_user):
    user = make_user(username="mfauser")
    _enable_mfa(user.id, pyotp.random_base32())
    resp = _login(client, username="mfauser")
    assert resp.status_code == 202
    body = resp.json()
    assert body["mfa_required"] is True
    assert body["username"] == "mfauser"


def _grant_regular_session_scopes():
    """Extend the catalog so regular users carry the session scopes."""
    jafaal.configure_scopes(
        scopes_mod.DEFAULT_SCOPE_CATALOG.extend(
            regular=("sessions:read", "sessions:write"),
            admin=(),
            descriptions={},
        )
    )


def test_object_level_auth_blocks_cross_user_access(client, make_user):
    _grant_regular_session_scopes()
    alice = make_user(username="alice")
    bob = make_user(username="bob")

    access = _login(client, username="alice").json()["access_token"]
    auth = {"Authorization": f"Bearer {access}", **WEB}

    # Alice may read her own sessions.
    own = client.get(f"/api/v1/auth/sessions/user/{alice.id}", headers=auth)
    assert own.status_code == 200

    # Alice may NOT read Bob's sessions (object-level guard).
    other = client.get(f"/api/v1/auth/sessions/user/{bob.id}", headers=auth)
    assert other.status_code == 403


def test_superuser_bypasses_object_level_guard(client, make_user):
    _grant_regular_session_scopes()
    make_user(username="root", is_superuser=True)
    victim = make_user(username="victim")

    access = _login(client, username="root").json()["access_token"]
    auth = {"Authorization": f"Bearer {access}", **WEB}

    resp = client.get(f"/api/v1/auth/sessions/user/{victim.id}", headers=auth)
    assert resp.status_code == 200


def test_missing_scope_forbidden(client, make_user):
    # Without the extended catalog, a regular user lacks sessions:read entirely.
    alice = make_user(username="alice")
    access = _login(client, username="alice").json()["access_token"]
    auth = {"Authorization": f"Bearer {access}", **WEB}
    resp = client.get(f"/api/v1/auth/sessions/user/{alice.id}", headers=auth)
    assert resp.status_code == 403
