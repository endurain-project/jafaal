"""Tests for the WebAuthn / passkey ceremonies.

Most tests mock the two verification calls
(``verify_registration_response`` / ``verify_authentication_response``) at the
boundary and exercise all of JAFAAL's plumbing for real: challenge lifecycle,
credential persistence, token issuance, sign-count updates, the second-factor
login branch, error handling, config resolution, and the optional-dependency
guard.

The final section goes further and drives the passwordless ceremony with a
**real software authenticator** (a genuine ES256 key signing a real assertion),
so ``py_webauthn`` performs actual signature verification and sign-count clone
detection with nothing mocked.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from contextlib import contextmanager
from types import SimpleNamespace

import cbor2
import pytest
from conftest import WEB_CLIENT_ID, replace_settings
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

import jafaal
import jafaal.orm as jafaal_orm
import jafaal.webauthn.crud as webauthn_crud
import jafaal.webauthn.service as webauthn_service
from jafaal._core.optional_deps import MissingDependencyError

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
    return client.post(
        "/api/v1/auth/login", data={"username": username, "password": password, "client_id": WEB_CLIENT_ID}
    )


def _auth_headers(client, username="alice", password="Str0ng!Pass"):
    access = _login(client, username, password).json()["access_token"]
    return {"Authorization": f"Bearer {access}"}


@contextmanager
def override_settings(**overrides):
    """Temporarily replace the installed settings, restoring them afterwards."""
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, **overrides))
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


def _register_credential(user_id, *, raw_id=b"cred-1", sign_count=0, label="My Key", public_key=b"cose-public-key"):
    """Persist a passkey directly (bypassing the ceremony) for auth/2FA tests."""
    session = jafaal_orm.get_sessionmaker()()
    try:
        with jafaal_orm.unit_of_work(session):
            return webauthn_crud.create_credential(
                user_id=user_id,
                credential_id=bytes_to_base64url(raw_id),
                public_key=base64.b64encode(public_key).decode("ascii"),
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


def test_register_begin_uses_opaque_user_handle(client, make_user):
    user = make_user(username="alice")
    headers = _auth_headers(client)
    opts1 = client.post(REG_BEGIN, headers=headers).json()
    opts2 = client.post(REG_BEGIN, headers=headers).json()
    handle = opts1["user"]["id"]
    # The handle must not be the raw (often sequential / PII) user id.
    assert handle != bytes_to_base64url(str(user.id).encode("utf-8"))
    # Opaque 32-byte handle, stable across ceremonies (same passkey account).
    assert len(base64url_to_bytes(handle)) == 32
    assert opts2["user"]["id"] == handle


def test_user_handle_is_opaque_stable_and_per_user(make_user):
    alice = make_user(username="alice")
    bob = make_user(username="bob")
    handle = webauthn_service._user_handle(alice)
    # Deterministic / stable for the same user (all their passkeys share it).
    assert webauthn_service._user_handle(alice) == handle
    # Opaque 32-byte value, never the raw user id.
    assert len(handle) == 32
    assert handle != str(alice.id).encode("utf-8")
    # Distinct per user.
    assert webauthn_service._user_handle(bob) != handle


def test_register_begin_requires_auth(client, make_user):
    make_user(username="alice")
    resp = client.post(REG_BEGIN)
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
        json={"challenge_id": challenge_id, "credential": _assertion_credential(), "client_id": WEB_CLIENT_ID},
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
        json={
            "challenge_id": begin.json()["challenge_id"],
            "credential": _assertion_credential(),
            "client_id": WEB_CLIENT_ID,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_passwordless_unknown_credential_rejected(client, make_user, mock_verify):
    make_user(username="alice")  # no passkey registered
    begin = client.post(AUTH_BEGIN, json={"username": "alice"})
    resp = client.post(
        AUTH_COMPLETE,
        json={
            "challenge_id": begin.json()["challenge_id"],
            "credential": _assertion_credential(b"unknown"),
            "client_id": WEB_CLIENT_ID,
        },
    )
    assert resp.status_code == 401


def test_passwordless_challenge_is_single_use(client, make_user, mock_verify):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")
    begin = client.post(AUTH_BEGIN, json={"username": "alice"})
    challenge_id = begin.json()["challenge_id"]
    payload = {"challenge_id": challenge_id, "credential": _assertion_credential(), "client_id": WEB_CLIENT_ID}

    first = client.post(AUTH_COMPLETE, json=payload)
    assert first.status_code == 200
    # The challenge was consumed; replaying the same handle fails.
    second = client.post(AUTH_COMPLETE, json=payload)
    assert second.status_code == 401


def test_passwordless_inactive_user_rejected(client, make_user, mock_verify):
    user = make_user(username="alice", is_active=False)
    _register_credential(user.id, raw_id=b"cred-1")
    begin = client.post(AUTH_BEGIN, json={"username": "alice"})
    resp = client.post(
        AUTH_COMPLETE,
        json={
            "challenge_id": begin.json()["challenge_id"],
            "credential": _assertion_credential(),
            "client_id": WEB_CLIENT_ID,
        },
    )
    assert resp.status_code in (401, 403)


def test_passwordless_begin_requires_user_verification(client, make_user):
    # Passwordless login forces UV=required regardless of the (default
    # "preferred") global setting, so the passkey is a genuine factor rather than
    # mere possession.
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")
    begin = client.post(AUTH_BEGIN, json={"username": "alice"})
    assert begin.status_code == 200
    assert begin.json()["options"]["userVerification"] == "required"


def test_passwordless_complete_enforces_user_verification(client, make_user, monkeypatch):
    # The passwordless completion verifies the assertion with
    # require_user_verification=True, independent of the global setting.
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")
    captured: dict = {}

    def _capture(**kw):
        captured.update(kw)
        return _fake_authentication()

    monkeypatch.setattr(webauthn_service._webauthn, "verify_authentication_response", _capture)

    begin = client.post(AUTH_BEGIN, json={"username": "alice"})
    resp = client.post(
        AUTH_COMPLETE,
        json={
            "challenge_id": begin.json()["challenge_id"],
            "credential": _assertion_credential(),
            "client_id": WEB_CLIENT_ID,
        },
    )
    assert resp.status_code == 200
    assert captured["require_user_verification"] is True


# --------------------------------------------------------------------------- #
# Second factor (password + passkey)
# --------------------------------------------------------------------------- #


def test_login_requires_second_factor_when_enabled(client, make_user):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")
    with override_settings(second_factor_enabled=True):
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

    with override_settings(second_factor_enabled=True):
        challenge = _login(client)
        assert challenge.status_code == 202
        mfa_token = challenge.json()["mfa_token"]

        begin = client.post(MFA_BEGIN, json={"mfa_token": mfa_token})
        assert begin.status_code == 200
        assert begin.json()["challenge"]

        resp = client.post(
            MFA_COMPLETE,
            json={"mfa_token": mfa_token, "credential": _assertion_credential(), "client_id": WEB_CLIENT_ID},
        )
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_second_factor_uses_configured_user_verification(client, make_user, monkeypatch):
    # The second-factor path (the password already provided the first factor)
    # keeps UV governed by AuthSettings.webauthn_user_verification, unlike the
    # forced-UV passwordless path.
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")
    captured: dict = {}

    def _capture(**kw):
        captured.update(kw)
        return _fake_authentication()

    monkeypatch.setattr(webauthn_service._webauthn, "verify_authentication_response", _capture)

    with override_settings(second_factor_enabled=True, user_verification="discouraged"):
        challenge = _login(client)
        assert challenge.status_code == 202
        mfa_token = challenge.json()["mfa_token"]
        begin = client.post(MFA_BEGIN, json={"mfa_token": mfa_token})
        assert begin.status_code == 200
        # The second-factor ceremony advertises the configured (non-forced) UV level.
        assert begin.json()["userVerification"] == "discouraged"
        resp = client.post(
            MFA_COMPLETE,
            json={"mfa_token": mfa_token, "credential": _assertion_credential(), "client_id": WEB_CLIENT_ID},
        )
    assert resp.status_code == 200
    assert captured["require_user_verification"] is False


def test_second_factor_rejects_foreign_credential(client, make_user):
    alice = make_user(username="alice")
    bob = make_user(username="bob")
    _register_credential(alice.id, raw_id=b"alice-key")
    bob_cred = _register_credential(bob.id, raw_id=b"bob-key")

    with override_settings(second_factor_enabled=True):
        challenge = _login(client, "alice")
        assert challenge.status_code == 202
        mfa_token = challenge.json()["mfa_token"]
        client.post(MFA_BEGIN, json={"mfa_token": mfa_token})
        # Present Bob's credential to satisfy Alice's pending second factor.
        resp = client.post(
            MFA_COMPLETE,
            json={"mfa_token": mfa_token, "credential": _assertion_credential(b"bob-key"), "client_id": WEB_CLIENT_ID},
        )
    assert resp.status_code == 401
    assert bob_cred is not None


def test_second_factor_complete_without_pending_login_rejected(client, make_user, mock_verify):
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")
    with override_settings(second_factor_enabled=True):
        # No prior password login → no pending second factor.
        client.post(MFA_BEGIN, json={"mfa_token": "not-a-real-ticket"})
        resp = client.post(
            MFA_COMPLETE,
            json={"mfa_token": "not-a-real-ticket", "credential": _assertion_credential(), "client_id": WEB_CLIENT_ID},
        )
    assert resp.status_code == 400


def test_second_factor_rejects_a_passkey_assertion_without_the_ticket(client, make_user, mock_verify):
    """Knowing the username must not let a caller finish someone else's login.

    The WebAuthn second factor is addressed by the same opaque ticket as the
    TOTP path, so an attacker who can produce an assertion but never passed the
    password step has nothing to present.
    """
    user = make_user(username="alice")
    _register_credential(user.id, raw_id=b"cred-1")

    with override_settings(second_factor_enabled=True):
        # The victim performs the password step, opening the window.
        assert _login(client).status_code == 202

        # The attacker guesses the username — the old address for this ceremony.
        resp = client.post(
            MFA_COMPLETE,
            json={"mfa_token": "alice", "credential": _assertion_credential(), "client_id": WEB_CLIENT_ID},
        )
        assert resp.status_code == 400

        # And the legacy username field is no longer accepted at all.
        legacy = client.post(
            MFA_COMPLETE,
            json={"username": "alice", "credential": _assertion_credential()},
        )
        assert legacy.status_code == 422


# --------------------------------------------------------------------------- #
# Configuration & optional-dependency guards
# --------------------------------------------------------------------------- #


def test_ceremony_requires_configuration(client, make_user):
    make_user(username="alice")
    # The anonymous passwordless ceremony needs no token, so clearing base_url
    # (and the explicit RP settings) isolates the "WebAuthn not configured" path.
    with override_settings(base_url="", rp_id="", origins=()):
        resp = client.post(AUTH_BEGIN, json={"username": "alice"})
    assert resp.status_code == 503


def test_explicit_rp_id_and_origins_are_used(client, make_user):
    make_user(username="alice")
    headers = _auth_headers(client)
    with override_settings(rp_id="passkeys.example", origins=("https://passkeys.example",)):
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
    with pytest.raises(ValueError, match="user_verification"):
        jafaal.WebAuthnSettings(user_verification="sometimes")


def test_settings_reject_invalid_attestation():
    with pytest.raises(ValueError, match="attestation"):
        jafaal.WebAuthnSettings(attestation="indirect")


def _a_fernet_key() -> str:
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


# --------------------------------------------------------------------------- #
# REAL-CRYPTO ceremonies (nothing mocked)
#
# A software authenticator holding a genuine ES256 key signs real assertions, so
# ``py_webauthn`` runs actual signature verification and sign-count clone
# detection against the key JAFAAL persisted at registration. This closes the
# fidelity gap left by the mocked verification above: the stored public key, the
# stored sign count, and the challenge all have to be correct end-to-end or the
# assertion simply will not verify.
# --------------------------------------------------------------------------- #

RP_ID = "app.test"
ORIGIN = "https://app.test"


class SoftAuthenticator:
    """A minimal software WebAuthn authenticator (real ES256 key, real signatures)."""

    def __init__(self, credential_id=b"real-cred"):
        self.credential_id = credential_id
        self._key = ec.generate_private_key(ec.SECP256R1())

    @property
    def cose_public_key(self) -> bytes:
        """COSE_Key encoding of the public key, as an authenticator would report it."""
        numbers = self._key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def assert_(self, challenge_b64: str, *, sign_count: int, user_handle=b"handle") -> dict:
        """Produce a real, signed authentication assertion for ``challenge_b64``."""
        # rp_id_hash || flags(UP|UV) || signCount
        authenticator_data = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x05]) + struct.pack(">I", sign_count)
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": challenge_b64, "origin": ORIGIN},
            separators=(",", ":"),
        ).encode()
        signature = self._key.sign(
            authenticator_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(crypto_hashes.SHA256()),
        )
        encoded_id = bytes_to_base64url(self.credential_id)
        return {
            "id": encoded_id,
            "rawId": encoded_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(authenticator_data),
                "signature": bytes_to_base64url(signature),
                "userHandle": bytes_to_base64url(user_handle),
            },
        }


def _begin_passwordless(client, username="alice"):
    """Start a passwordless ceremony; return (challenge_id, challenge_b64)."""
    begin = client.post(AUTH_BEGIN, json={"username": username})
    assert begin.status_code == 200
    body = begin.json()
    return body["challenge_id"], body["options"]["challenge"]


def test_real_assertion_authenticates_and_advances_sign_count(client, make_user, db):
    # Full passwordless login with a real signature verified by py_webauthn.
    authenticator = SoftAuthenticator()
    user = make_user(username="alice")
    _register_credential(
        user.id,
        raw_id=authenticator.credential_id,
        sign_count=4,
        public_key=authenticator.cose_public_key,
    )

    challenge_id, challenge = _begin_passwordless(client)
    resp = client.post(
        AUTH_COMPLETE,
        json={
            "challenge_id": challenge_id,
            "credential": authenticator.assert_(challenge, sign_count=5),
            "client_id": WEB_CLIENT_ID,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]

    stored = webauthn_crud.get_credential_by_credential_id(bytes_to_base64url(authenticator.credential_id), db)
    assert stored.sign_count == 5


def test_real_assertion_with_regressed_sign_count_is_rejected_as_clone(client, make_user, db):
    # Clone detection: an authenticator whose counter goes *backwards* signals a
    # duplicated credential. The signature is valid, so only the sign-count check
    # can reject this - and the stored counter must not move.
    authenticator = SoftAuthenticator()
    user = make_user(username="alice")
    _register_credential(
        user.id,
        raw_id=authenticator.credential_id,
        sign_count=9,
        public_key=authenticator.cose_public_key,
    )

    challenge_id, challenge = _begin_passwordless(client)
    resp = client.post(
        AUTH_COMPLETE,
        json={
            "challenge_id": challenge_id,
            "credential": authenticator.assert_(challenge, sign_count=3),
            "client_id": WEB_CLIENT_ID,
        },
    )
    assert resp.status_code == 401

    stored = webauthn_crud.get_credential_by_credential_id(bytes_to_base64url(authenticator.credential_id), db)
    assert stored.sign_count == 9  # unchanged - the clone did not advance it


def test_real_assertion_replayed_sign_count_is_rejected_as_clone(client, make_user):
    # An exactly-equal counter is also a clone signal (it must strictly increase),
    # which is what catches a replayed assertion from a duplicated authenticator.
    authenticator = SoftAuthenticator()
    user = make_user(username="alice")
    _register_credential(
        user.id,
        raw_id=authenticator.credential_id,
        sign_count=6,
        public_key=authenticator.cose_public_key,
    )

    challenge_id, challenge = _begin_passwordless(client)
    resp = client.post(
        AUTH_COMPLETE,
        json={
            "challenge_id": challenge_id,
            "credential": authenticator.assert_(challenge, sign_count=6),
            "client_id": WEB_CLIENT_ID,
        },
    )
    assert resp.status_code == 401


def test_real_assertion_from_a_different_key_is_rejected(client, make_user):
    # The signature must verify against the *stored* public key: an attacker who
    # knows the credential id but not the private key cannot authenticate.
    legitimate = SoftAuthenticator()
    attacker = SoftAuthenticator(credential_id=legitimate.credential_id)
    user = make_user(username="alice")
    _register_credential(
        user.id,
        raw_id=legitimate.credential_id,
        sign_count=0,
        public_key=legitimate.cose_public_key,
    )

    challenge_id, challenge = _begin_passwordless(client)
    resp = client.post(
        AUTH_COMPLETE,
        json={
            "challenge_id": challenge_id,
            "credential": attacker.assert_(challenge, sign_count=1),
            "client_id": WEB_CLIENT_ID,
        },
    )
    assert resp.status_code == 401


def test_real_assertion_for_another_challenge_is_rejected(client, make_user):
    # The assertion is bound to the server-issued challenge, so one signed for a
    # different challenge (a captured/replayed ceremony) cannot be substituted.
    authenticator = SoftAuthenticator()
    user = make_user(username="alice")
    _register_credential(
        user.id,
        raw_id=authenticator.credential_id,
        sign_count=0,
        public_key=authenticator.cose_public_key,
    )

    challenge_id, _ = _begin_passwordless(client)
    foreign_challenge = bytes_to_base64url(b"\x02" * 32)
    resp = client.post(
        AUTH_COMPLETE,
        json={
            "challenge_id": challenge_id,
            "credential": authenticator.assert_(foreign_challenge, sign_count=1),
            "client_id": WEB_CLIENT_ID,
        },
    )
    assert resp.status_code == 401
