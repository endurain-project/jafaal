"""End-to-end HTTP tests for the password-reset, sign-up, and MFA-verify flows."""

import secrets
import time
from contextlib import contextmanager

import pyotp
import pytest
from conftest import NATIVE_CLIENT_ID, NATIVE_REDIRECT_URI, WEB_CLIENT_ID

import jafaal
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.schema as idp_schema
import jafaal.mfa.crud as mfa_crud
import jafaal.orm as jafaal_orm
import jafaal.ports as ports
from jafaal._core import crypto


class _SignupProvider:
    """A SettingsProvider with configurable sign-up toggles."""

    def __init__(self, *, enabled=True, verify=False, approve=False):
        self._config = jafaal.SignupConfig(
            enabled=enabled, require_email_verification=verify, require_admin_approval=approve
        )
        self._policy = jafaal.PasswordPolicy(min_length_regular=8, min_length_admin=12, password_type="strict")

    def get_password_policy(self):
        return self._policy

    def get_signup_config(self):
        return self._config


@contextmanager
def _signup(**kwargs):
    original = ports.get_settings_provider()
    jafaal.configure_settings_provider(_SignupProvider(**kwargs))
    try:
        yield
    finally:
        jafaal.configure_settings_provider(original)


def _enable_mfa(user_id, secret):
    session = jafaal_orm.get_sessionmaker()()
    try:
        with jafaal_orm.unit_of_work(session):
            mfa_crud.update_user_mfa(user_id, session, encrypted_secret=crypto.encrypt_token_fernet(secret))
    finally:
        session.close()


def _login(client, username, password):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password, "client_id": WEB_CLIENT_ID},
    )


def _auth_headers(client, username, password):
    access = _login(client, username, password).json()["access_token"]
    return {"Authorization": f"Bearer {access}"}


def _create_linked_idp(user_id, *, slug, link=True):
    session = jafaal_orm.get_sessionmaker()()
    try:
        with jafaal_orm.unit_of_work(session):
            idp = idp_crud.create_identity_provider(
                idp_schema.IdentityProviderCreate(
                    name=f"IdP {slug}",
                    slug=slug,
                    client_id="cid",
                    client_secret="secret",
                    enabled=True,
                    authorization_endpoint="https://idp.example/authorize",
                ),
                session,
            )
            if link:
                links_crud.create_user_identity_provider(user_id, idp.id, f"sub-{slug}", session)
        return idp.id
    finally:
        session.close()


def test_step_up_reauth_initiate_returns_authorization_url(client, make_user):
    # An authenticated user linked to an IdP gets an authorization URL that
    # forces a fresh sign-in (prompt=login) with the configured max_age.
    user = make_user(username="ssoinit", password="Str0ng!Pass")
    idp_id = _create_linked_idp(user.id, slug="reauth")
    r = client.post(
        f"/api/v1/auth/idp/step-up/reauth/{idp_id}",
        json={"client_id": NATIVE_CLIENT_ID, "redirect_uri": NATIVE_REDIRECT_URI},
        headers=_auth_headers(client, "ssoinit", "Str0ng!Pass"),
    )
    assert r.status_code == 200
    url = r.json()["authorization_url"]
    assert url.startswith("https://idp.example/authorize")
    assert "prompt=login" in url
    assert "max_age=300" in url


def test_step_up_reauth_initiate_requires_a_registered_redirect_uri(client, make_user):
    # A step-up round trip ends in a browser redirect, so it gets the same
    # exact-match gate as /auth/authorize. There is no weaker rule for
    # "internal" redirects.
    user = make_user(username="ssoopen", password="Str0ng!Pass")
    idp_id = _create_linked_idp(user.id, slug="openredir")
    r = client.post(
        f"/api/v1/auth/idp/step-up/reauth/{idp_id}",
        json={"client_id": NATIVE_CLIENT_ID, "redirect_uri": "https://evil.test/steal"},
        headers=_auth_headers(client, "ssoopen", "Str0ng!Pass"),
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"


def test_step_up_reauth_initiate_requires_link(client, make_user):
    # You can only re-authenticate an identity provider you are linked to.
    user = make_user(username="nolink", password="Str0ng!Pass")
    idp_id = _create_linked_idp(user.id, slug="unlinked", link=False)
    r = client.post(
        f"/api/v1/auth/idp/step-up/reauth/{idp_id}",
        json={"client_id": NATIVE_CLIENT_ID, "redirect_uri": NATIVE_REDIRECT_URI},
        headers=_auth_headers(client, "nolink", "Str0ng!Pass"),
    )
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Password reset
# --------------------------------------------------------------------------- #


def test_password_reset_http_flow(client, make_user, event_sink):
    user = make_user(username="alice", password="Old1!Pass")

    r = client.post("/api/v1/auth/password-reset/request", json={"email": user.email})
    assert r.status_code == 200
    assert len(event_sink.events) == 1
    token = event_sink.events[0].token

    confirm = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "New1!Passw"},
    )
    assert confirm.status_code == 200

    # Old password no longer works; the new one does.
    assert _login(client, "alice", "Old1!Pass").status_code == 401
    assert _login(client, "alice", "New1!Passw").status_code == 200


def test_password_reset_request_is_enumeration_safe(client, event_sink):
    # A syntactically valid address that matches no account.
    r = client.post("/api/v1/auth/password-reset/request", json={"email": "ghost@absent.dev"})
    assert r.status_code == 200  # same generic response as a real account
    assert event_sink.events == []


def test_password_reset_confirm_rejects_bad_token(client):
    r = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": "bogus-token", "new_password": "New1!Passw"},
    )
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Sign-up
# --------------------------------------------------------------------------- #


def test_signup_http_happy_path(client):
    r = client.post(
        "/api/v1/auth/sign-up/request",
        json={"username": "newbie", "email": "newbie@test.dev", "password": "Str0ng!Pass"},
    )
    assert r.status_code == 201
    # No verification/approval required → can log in immediately.
    assert _login(client, "newbie", "Str0ng!Pass").status_code == 200


def test_signup_disabled_returns_403(client):
    with _signup(enabled=False):
        r = client.post(
            "/api/v1/auth/sign-up/request",
            json={"username": "x", "email": "x@test.dev", "password": "Str0ng!Pass"},
        )
    assert r.status_code == 403


def test_signup_email_verification_flow(client, event_sink):
    with _signup(enabled=True, verify=True):
        signup_payload = {"username": "ver", "email": "ver@test.dev", "password": "Str0ng!Pass"}
        r = client.post(
            "/api/v1/auth/sign-up/request",
            json=signup_payload,
        )
        assert r.status_code == 201
        signup_handle = r.json()["signup_handle"]
        assert isinstance(signup_handle, str)
        assert len(signup_handle) >= 32

        duplicate = client.post("/api/v1/auth/sign-up/request", json=signup_payload)
        assert duplicate.status_code == 201
        decoy_handle = duplicate.json()["signup_handle"]
        assert isinstance(decoy_handle, str)
        assert len(decoy_handle) >= 32
        assert decoy_handle != signup_handle

        assert len(event_sink.events) == 1
        token = event_sink.events[0].token

        pending = client.get("/api/v1/auth/sign-up/status", params={"handle": signup_handle})
        assert pending.status_code == 200
        assert pending.json() == {"confirmed": False}
        assert pending.headers["Cache-Control"] == "no-store"
        assert client.get("/api/v1/auth/sign-up/status", params={"handle": decoy_handle}).json() == {"confirmed": False}
        assert client.get("/api/v1/auth/sign-up/status", params={"handle": "unknown"}).status_code == 404

        # Account is inactive until verified → login is forbidden.
        assert _login(client, "ver", "Str0ng!Pass").status_code == 401

        confirm = client.post("/api/v1/auth/sign-up/confirm", json={"token": token})
        assert confirm.status_code == 200

        assert client.get("/api/v1/auth/sign-up/status", params={"handle": signup_handle}).json() == {"confirmed": True}
        assert client.get("/api/v1/auth/sign-up/status", params={"handle": decoy_handle}).json() == {"confirmed": False}

        # Now the account is active.
        assert _login(client, "ver", "Str0ng!Pass").status_code == 200


# --------------------------------------------------------------------------- #
# MFA verify (login → 202 → verify)
# --------------------------------------------------------------------------- #


def test_mfa_verify_login_flow(client, make_user):
    user = make_user(username="mfauser", password="Str0ng!Pass")
    secret = pyotp.random_base32()
    _enable_mfa(user.id, secret)

    challenge = _login(client, "mfauser", "Str0ng!Pass")
    assert challenge.status_code == 202
    mfa_token = challenge.json()["mfa_token"]

    code = pyotp.TOTP(secret).now()
    verify = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": mfa_token, "mfa_code": code, "client_id": WEB_CLIENT_ID},
    )
    assert verify.status_code == 200
    assert verify.json()["access_token"]


def test_mfa_verify_rejects_wrong_code(client, make_user):
    user = make_user(username="mfauser", password="Str0ng!Pass")
    secret = pyotp.random_base32()
    _enable_mfa(user.id, secret)
    mfa_token = _login(client, "mfauser", "Str0ng!Pass").json()["mfa_token"]

    wrong = pyotp.TOTP(secret).at(int(time.time()) - 300)
    verify = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": mfa_token, "mfa_code": wrong, "client_id": WEB_CLIENT_ID},
    )
    assert verify.status_code == 400


def test_mfa_verify_rejects_a_valid_code_without_the_ticket(client, make_user):
    """A valid OTP alone must not complete a login somebody else's password opened.

    This is the second-factor invariant: the password step hands its ticket only
    to the caller that passed it. An attacker who knows the username and holds a
    currently-valid TOTP code (phished, shoulder-surfed, or read off a shared
    authenticator) must still be unable to finish the login.
    """
    user = make_user(username="victim", password="Str0ng!Pass")
    secret = pyotp.random_base32()
    _enable_mfa(user.id, secret)

    # The victim performs the password step, opening the MFA window.
    assert _login(client, "victim", "Str0ng!Pass").status_code == 202

    code = pyotp.TOTP(secret).now()
    # The attacker knows the username and has a valid code, but no ticket.
    for guess in ("victim", "", "not-a-real-ticket", secrets.token_urlsafe(32)):
        attacker = client.post(
            "/api/v1/auth/mfa/verify",
            json={"mfa_token": guess, "mfa_code": code, "client_id": WEB_CLIENT_ID},
        )
        assert attacker.status_code in (400, 422)
        assert "access_token" not in attacker.json()

    # Sending the username under its old field name is rejected outright.
    legacy = client.post(
        "/api/v1/auth/mfa/verify",
        json={"username": "victim", "mfa_code": code},
    )
    assert legacy.status_code == 422


def test_mfa_ticket_is_single_use(client, make_user):
    user = make_user(username="onceuser", password="Str0ng!Pass")
    secret = pyotp.random_base32()
    _enable_mfa(user.id, secret)
    mfa_token = _login(client, "onceuser", "Str0ng!Pass").json()["mfa_token"]

    payload = {"mfa_token": mfa_token, "mfa_code": pyotp.TOTP(secret).now(), "client_id": WEB_CLIENT_ID}
    assert client.post("/api/v1/auth/mfa/verify", json=payload).status_code == 200
    # The ticket was consumed: one password step authorises exactly one login.
    assert client.post("/api/v1/auth/mfa/verify", json=payload).status_code == 400


def test_mfa_tickets_are_not_interchangeable_between_users(client, make_user):
    """One user's ticket must not complete another user's pending login."""
    alice = make_user(username="alice-mfa", password="Str0ng!Pass")
    bob = make_user(username="bob-mfa", password="Str0ng!Pass")
    alice_secret = pyotp.random_base32()
    bob_secret = pyotp.random_base32()
    _enable_mfa(alice.id, alice_secret)
    _enable_mfa(bob.id, bob_secret)

    alice_ticket = _login(client, "alice-mfa", "Str0ng!Pass").json()["mfa_token"]
    _login(client, "bob-mfa", "Str0ng!Pass")

    # Alice's ticket with Bob's code resolves to Alice, whose TOTP rejects it.
    crossed = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": alice_ticket, "mfa_code": pyotp.TOTP(bob_secret).now(), "client_id": WEB_CLIENT_ID},
    )
    assert crossed.status_code == 400


def test_mfa_verify_login_flow_with_zero_user_id(client, make_user, engine):
    """A user whose integer id is the falsy value ``0`` can still complete MFA login.

    Regression for the ``if not user_id`` check (now ``if pending is None``):
    the resolved pending login carries ``0``, which a truthiness test would
    wrongly treat as "no pending login".
    """
    if engine.dialect.name == "mysql":
        pytest.skip("MySQL AUTO_INCREMENT reserves 0 unless NO_AUTO_VALUE_ON_ZERO is enabled")

    user = make_user(username="zerouser", user_id=0, password="Str0ng!Pass")
    assert user.id == 0

    secret = pyotp.random_base32()
    _enable_mfa(user.id, secret)

    challenge = _login(client, "zerouser", "Str0ng!Pass")
    assert challenge.status_code == 202
    mfa_token = challenge.json()["mfa_token"]

    code = pyotp.TOTP(secret).now()
    verify = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": mfa_token, "mfa_code": code, "client_id": WEB_CLIENT_ID},
    )
    assert verify.status_code == 200
    assert verify.json()["access_token"]


# --------------------------------------------------------------------------- #
# Security events (event sink)
# --------------------------------------------------------------------------- #


def test_new_device_login_emits_event(client, make_user, event_sink):
    from jafaal.ports import NewDeviceLogin

    make_user(username="alice", password="Str0ng!Pass")

    # First login is from a device with no prior session → new-device event.
    assert _login(client, "alice", "Str0ng!Pass").status_code == 200
    new_device = [e for e in event_sink.events if isinstance(e, NewDeviceLogin)]
    assert len(new_device) == 1
    assert new_device[0].username == "alice"

    # A second login from the same client/device does not re-emit.
    event_sink.events.clear()
    assert _login(client, "alice", "Str0ng!Pass").status_code == 200
    assert not [e for e in event_sink.events if isinstance(e, NewDeviceLogin)]


def test_account_lockout_emits_event(client, make_user, event_sink):
    from jafaal.ports import AccountLocked

    make_user(username="alice", password="Str0ng!Pass")

    # Five failed logins trip the first per-username lockout tier.
    for _ in range(5):
        _login(client, "alice", "WrongPass1")

    locked = [e for e in event_sink.events if isinstance(e, AccountLocked)]
    assert locked
    assert any(e.subject_kind == "username" and e.subject == "alice" for e in locked)
