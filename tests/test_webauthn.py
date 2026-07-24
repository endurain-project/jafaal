"""Tests for the WebAuthn / passkey ceremonies.

``py_webauthn`` is server-side only (no authenticator simulator), so the tests
mock the two verification calls (``verify_registration_response`` /
``verify_authentication_response``) at the boundary and exercise all of JAFAAL's
plumbing for real: challenge lifecycle, credential persistence, token issuance,
sign-count updates, the second-factor login branch, error handling, config
resolution, and the optional-dependency guard.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest
from webauthn.helpers import bytes_to_base64url

import jafaal
import jafaal.orm as jafaal_orm
import jafaal.webauthn.crud as webauthn_crud
import jafaal.webauthn.service as webauthn_service
from jafaal._core.optional_deps import MissingDependencyError

WEB = {"X-Client-Type": "web"}

REG_BEGIN = "/api/v1/auth/webauthn/register/begin"
REG_COMPLETE = "/api/v1/auth/webauthn/register/complete"
CREDENTIALS = "/api/v1/auth/webauthn/credentials"
MFA_BEGIN = "/api/v1/auth/webauthn/mfa/begin"
MFA_COMPLETE = "/api/v1/auth/webauthn/mfa/complete"
AUTH_BEGIN = "/api/v1/public/webauthn/authenticate/begin"
AUTH_COMPLETE = "/api/v1/public/webauthn/authenticate/complete"


# --------------------------------------------------------------------------- #
# Helpers / fixtures
# --------------------------------------------------------------------------- #


def _login(client, username="alice", password="Str0ng!Pass"):
    return client.post("/api/v1/auth/login", data={"username": username, "password": password}, headers=WEB)


def _auth_headers(client, username="alice", password="Str0ng!Pass"):
    access = _login(client, username, password).json()["access_token"]
    return {"X-Client-Type": "web", "Authorization": f"Bearer {access}"}


@contextmanager
def override_settings(**overrides):
    """Temporarily replace the installed settings, restoring them afterwards."""
    original = jafaal.get_settings()
    jafaal.configure(replace(original, **overrides))
    try:
        yield
    finally:
        jafaal.configure(original)


def _fake_registration(
    *,
    credential_id=b"cred-1",
    public_key=b"cose-public-key",
    sign_count=0,
    aaguid="00000000-0000-0000-0000-000000000000",
    device_type="multi_device",
    backed_up=True,
):
    return SimpleNamespace(
        credential_id=credential_id,
        credential_public_key=public_key,
        sign_count=sign_count,
        aaguid=aaguid,
        fmt="none",
        credential_type="public-key",
        user_verified=True,
        credential_device_type=SimpleNamespace(value=device_type),
        credential_backed_up=backed_up,
    )


def _fake_authentication(*, credential_id=b"cred-1", new_sign_count=1):
    return SimpleNamespace(
        credential_id=credential_id,
        new_sign_count=new_sign_count,
        credential_device_type=SimpleNamespace(value="multi_device"),
        credential_backed_up=True,
        user_verified=True,
    )


@pytest.fixture
def mock_verify(monkeypatch):
    """Mock the two ``py_webauthn`` verification calls at the boundary.

    Returns a mutable dict so a test can swap in a different verified result
    (e.g. a specific ``new_sign_count`` or ``credential_id``) before completing.
    """
    state = {"registration": _fake_registration(), "authentication": _fake_authentication()}
    monkeypatch.setattr(webauthn_service._webauthn, "verify_registration_response", lambda **kw: state["registration"])
    monkeypatch.setattr(
        webauthn_service._webauthn, "verify_authentication_response", lambda **kw: state["authentication"]
    )
    return state


def _register_credential(user_id, *, raw_id=b"cred-1", sign_count=0, label="My Key"):
    """Persist a passkey directly (bypassing the ceremony) for auth/2FA tests."""
    session = jafaal_orm.get_sessionmaker()()
    try:
        return webauthn_crud.create_credential(
            user_id=user_id,
            credential_id=bytes_to_base64url(raw_id),
            public_key=base64.b64encode(b"cose-public-key").decode("ascii"),
            sign_count=sign_count,
            transports="internal",
            aaguid=None,
            label=label,
            backup_eligible=True,
            backup_state=True,
            db=session,
        )
    finally:
        session.close()


def _assertion_credential(raw_id=b"cred-1", *, transports=None):
    encoded = bytes_to_base64url(raw_id)
    response = {
        "clientDataJSON": "e30",
        "authenticatorData": "e30",
        "signature": "e30",
        "userHandle": None,
    }
    if transports is not None:
        response["transports"] = transports
    return {
        "id": encoded,
        "rawId": encoded,
        "type": "public-key",
        "response": response,
    }


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


def test_register_begin_returns_creation_options(client, make_user):
    make_user(username="alice")
    resp = client.post(REG_BEGIN, headers=_auth_headers(client))
    assert resp.status_code == 200
    options = resp.json()
    assert options["challenge"]
    assert options["rp"]["id"] == "app.test"
    assert options["user"]["name"] == "alice"
    assert options["pubKeyCredParams"]


def test_register_begin_requires_auth(client, make_user):
    make_user(username="alice")
    resp = client.post(REG_BEGIN, headers=WEB)
    assert resp.status_code in (401, 403)


def test_register_complete_persists_credential(client, make_user, mock_verify, db):
    make_user(username="alice")
    headers = _auth_headers(client)
    client.post(REG_BEGIN, headers=headers)

    resp = client.post(
        REG_COMPLETE,
        json={"credential": _assertion_credential(transports=["internal", "hybrid"]), "label": "Yubikey 5"},
        headers=headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["label"] == "Yubikey 5"
    assert body["backup_eligible"] is True

    stored = webauthn_crud.get_credential_by_credential_id(bytes_to_base64url(b"cred-1"), db)
    assert stored is not None
    assert stored.transports == "internal,hybrid"
    assert stored.sign_count == 0


def test_register_complete_without_begin_is_rejected(client, make_user, mock_verify):
    make_user(username="alice")
    resp = client.post(
        REG_COMPLETE,
        json={"credential": _assertion_credential(), "label": "No Begin"},
        headers=_auth_headers(client),
    )
    # No challenge was stored → the ceremony cannot be completed.
    assert resp.status_code == 400


def test_register_duplicate_credential_conflicts(client, make_user, mock_verify):
    make_user(username="alice")
    headers = _auth_headers(client)

    client.post(REG_BEGIN, headers=headers)
    first = client.post(REG_COMPLETE, json={"credential": _assertion_credential()}, headers=headers)
    assert first.status_code == 201

    client.post(REG_BEGIN, headers=headers)
    second = client.post(REG_COMPLETE, json={"credential": _assertion_credential()}, headers=headers)
    assert second.status_code == 409


# --------------------------------------------------------------------------- #
# Credential management
# --------------------------------------------------------------------------- #


def test_list_credentials(client, make_user):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-a", label="Phone")
    _register_credential(user.id, raw_id=b"cred-b", label="Laptop")

    resp = client.get(CREDENTIALS, headers=_auth_headers(client))
    assert resp.status_code == 200
    labels = {c["label"] for c in resp.json()}
    assert labels == {"Phone", "Laptop"}


def test_delete_credential(client, make_user, db):
    user = make_user(username="alice")
    cred = _register_credential(user.id)

    resp = client.delete(f"{CREDENTIALS}/{cred.id}", headers=_auth_headers(client))
    assert resp.status_code == 204
    assert webauthn_crud.get_credentials_by_user_id(user.id, db) == []


def test_delete_missing_credential_404(client, make_user):
    make_user(username="alice")
    resp = client.delete(f"{CREDENTIALS}/9999", headers=_auth_headers(client))
    assert resp.status_code == 404


def test_cannot_delete_another_users_credential(client, make_user, db):
    alice = make_user(username="alice")
    make_user(username="bob")
    alice_cred = _register_credential(alice.id, raw_id=b"alice-key")

    # Bob authenticates and tries to delete Alice's credential by its pk.
    resp = client.delete(f"{CREDENTIALS}/{alice_cred.id}", headers=_auth_headers(client, "bob"))
    assert resp.status_code == 404
    # Alice's credential is untouched.
    assert webauthn_crud.get_credential_by_pk(alice_cred.id, alice.id, db) is not None


# --------------------------------------------------------------------------- #
# Passwordless authentication
# --------------------------------------------------------------------------- #


def test_passwordless_authentication_issues_tokens(client, make_user, mock_verify, db):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1", sign_count=0)
    mock_verify["authentication"] = _fake_authentication(new_sign_count=7)

    begin = client.post(AUTH_BEGIN, json={"username": "alice"})
    assert begin.status_code == 200
    challenge_id = begin.json()["challenge_id"]
    assert begin.json()["options"]["challenge"]

    resp = client.post(
        AUTH_COMPLETE,
        json={"challenge_id": challenge_id, "credential": _assertion_credential()},
        headers=WEB,
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]
    assert "jafaal_refresh_token" in resp.cookies

    # The signature counter advanced to the authenticator's reported value.
    stored = webauthn_crud.get_credential_by_credential_id(bytes_to_base64url(b"cred-1"), db)
    assert stored.sign_count == 7
    assert stored.last_used_at is not None


def test_passwordless_usernameless_flow(client, make_user, mock_verify):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")

    # No username → discoverable-credential ceremony (empty allow-list).
    begin = client.post(AUTH_BEGIN, json={})
    assert begin.status_code == 200
    assert begin.json()["options"].get("allowCredentials") in (None, [])

    resp = client.post(
        AUTH_COMPLETE,
        json={"challenge_id": begin.json()["challenge_id"], "credential": _assertion_credential()},
        headers=WEB,
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_passwordless_unknown_credential_rejected(client, make_user, mock_verify):
    make_user(username="alice")  # no passkey registered
    begin = client.post(AUTH_BEGIN, json={"username": "alice"})
    resp = client.post(
        AUTH_COMPLETE,
        json={"challenge_id": begin.json()["challenge_id"], "credential": _assertion_credential(b"unknown")},
        headers=WEB,
    )
    assert resp.status_code == 401


def test_passwordless_challenge_is_single_use(client, make_user, mock_verify):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")
    begin = client.post(AUTH_BEGIN, json={"username": "alice"})
    challenge_id = begin.json()["challenge_id"]
    payload = {"challenge_id": challenge_id, "credential": _assertion_credential()}

    first = client.post(AUTH_COMPLETE, json=payload, headers=WEB)
    assert first.status_code == 200
    # The challenge was consumed; replaying the same handle fails.
    second = client.post(AUTH_COMPLETE, json=payload, headers=WEB)
    assert second.status_code == 401


def test_passwordless_inactive_user_rejected(client, make_user, mock_verify):
    user = make_user(username="alice", is_active=False)
    _register_credential(user.id, raw_id=b"cred-1")
    begin = client.post(AUTH_BEGIN, json={"username": "alice"})
    resp = client.post(
        AUTH_COMPLETE,
        json={"challenge_id": begin.json()["challenge_id"], "credential": _assertion_credential()},
        headers=WEB,
    )
    assert resp.status_code in (401, 403)


# --------------------------------------------------------------------------- #
# Second factor (password + passkey)
# --------------------------------------------------------------------------- #


def test_login_requires_second_factor_when_enabled(client, make_user):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")
    with override_settings(webauthn_second_factor_enabled=True):
        resp = _login(client)
    assert resp.status_code == 202
    body = resp.json()
    assert body["mfa_required"] is True
    assert body["username"] == "alice"


def test_login_no_second_factor_when_disabled(client, make_user):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")
    # Default: passkeys do not gate the password path.
    resp = _login(client)
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_second_factor_completes_login(client, make_user, mock_verify):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")

    with override_settings(webauthn_second_factor_enabled=True):
        assert _login(client).status_code == 202

        begin = client.post(MFA_BEGIN, json={"username": "alice"})
        assert begin.status_code == 200
        assert begin.json()["challenge"]

        resp = client.post(
            MFA_COMPLETE,
            json={"username": "alice", "credential": _assertion_credential()},
            headers=WEB,
        )
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_second_factor_rejects_foreign_credential(client, make_user):
    alice = make_user(username="alice")
    bob = make_user(username="bob")
    _register_credential(alice.id, raw_id=b"alice-key")
    bob_cred = _register_credential(bob.id, raw_id=b"bob-key")

    with override_settings(webauthn_second_factor_enabled=True):
        assert _login(client, "alice").status_code == 202
        client.post(MFA_BEGIN, json={"username": "alice"})
        # Present Bob's credential to satisfy Alice's pending second factor.
        resp = client.post(
            MFA_COMPLETE,
            json={"username": "alice", "credential": _assertion_credential(b"bob-key")},
            headers=WEB,
        )
    assert resp.status_code == 401
    assert bob_cred is not None


def test_second_factor_complete_without_pending_login_rejected(client, make_user, mock_verify):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")
    with override_settings(webauthn_second_factor_enabled=True):
        # No prior password login → no pending second factor.
        client.post(MFA_BEGIN, json={"username": "alice"})
        resp = client.post(
            MFA_COMPLETE,
            json={"username": "alice", "credential": _assertion_credential()},
            headers=WEB,
        )
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# Configuration & optional-dependency guards
# --------------------------------------------------------------------------- #


def test_ceremony_requires_configuration(client, make_user):
    make_user(username="alice")
    # The anonymous passwordless ceremony needs no token, so clearing base_url
    # (and the explicit RP settings) isolates the "WebAuthn not configured" path.
    with override_settings(base_url="", webauthn_rp_id="", webauthn_origins=()):
        resp = client.post(AUTH_BEGIN, json={"username": "alice"})
    assert resp.status_code == 503


def test_explicit_rp_id_and_origins_are_used(client, make_user):
    make_user(username="alice")
    headers = _auth_headers(client)
    with override_settings(webauthn_rp_id="passkeys.example", webauthn_origins=("https://passkeys.example",)):
        resp = client.post(REG_BEGIN, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["rp"]["id"] == "passkeys.example"


def test_missing_dependency_guard(monkeypatch, make_user, db):
    user = make_user(username="alice")
    monkeypatch.setattr(webauthn_service, "_webauthn", None)
    with pytest.raises(MissingDependencyError, match="WebAuthn"):
        webauthn_service.begin_registration(user, db)


# --------------------------------------------------------------------------- #
# Settings validation
# --------------------------------------------------------------------------- #


def test_settings_reject_invalid_user_verification():
    with pytest.raises(ValueError, match="webauthn_user_verification"):
        jafaal.AuthSettings(
            secret_key="s" * 32,
            fernet_key=_a_fernet_key(),
            webauthn_user_verification="sometimes",
        )


def test_settings_reject_invalid_attestation():
    with pytest.raises(ValueError, match="webauthn_attestation"):
        jafaal.AuthSettings(
            secret_key="s" * 32,
            fernet_key=_a_fernet_key(),
            webauthn_attestation="indirect",
        )


def _a_fernet_key() -> str:
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()
