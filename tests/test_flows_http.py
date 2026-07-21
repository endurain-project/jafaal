"""End-to-end HTTP tests for the password-reset, sign-up, and MFA-verify flows."""

import time
from contextlib import contextmanager

import pyotp

import jafaal
import jafaal.mfa.crud as mfa_crud
import jafaal.orm as jafaal_orm
import jafaal.ports as ports
from jafaal._core import crypto

WEB = {"X-Client-Type": "web"}


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
        mfa_crud.update_user_mfa(user_id, session, encrypted_secret=crypto.encrypt_token_fernet(secret))
    finally:
        session.close()


def _login(client, username, password):
    return client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
        headers=WEB,
    )


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
        r = client.post(
            "/api/v1/auth/sign-up/request",
            json={"username": "ver", "email": "ver@test.dev", "password": "Str0ng!Pass"},
        )
        assert r.status_code == 201
        assert len(event_sink.events) == 1
        token = event_sink.events[0].token

        # Account is inactive until verified → login is forbidden.
        assert _login(client, "ver", "Str0ng!Pass").status_code == 403

        confirm = client.post("/api/v1/auth/sign-up/confirm", json={"token": token})
        assert confirm.status_code == 200

        # Now the account is active.
        assert _login(client, "ver", "Str0ng!Pass").status_code == 200


# --------------------------------------------------------------------------- #
# MFA verify (login → 202 → verify)
# --------------------------------------------------------------------------- #


def test_mfa_verify_login_flow(client, make_user):
    user = make_user(username="mfauser", password="Str0ng!Pass")
    secret = pyotp.random_base32()
    _enable_mfa(user.id, secret)

    assert _login(client, "mfauser", "Str0ng!Pass").status_code == 202

    code = pyotp.TOTP(secret).now()
    verify = client.post(
        "/api/v1/auth/mfa/verify",
        json={"username": "mfauser", "mfa_code": code},
        headers=WEB,
    )
    assert verify.status_code == 200
    assert verify.json()["access_token"]


def test_mfa_verify_rejects_wrong_code(client, make_user):
    user = make_user(username="mfauser", password="Str0ng!Pass")
    secret = pyotp.random_base32()
    _enable_mfa(user.id, secret)
    _login(client, "mfauser", "Str0ng!Pass")

    wrong = pyotp.TOTP(secret).at(int(time.time()) - 300)
    verify = client.post(
        "/api/v1/auth/mfa/verify",
        json={"username": "mfauser", "mfa_code": wrong},
        headers=WEB,
    )
    assert verify.status_code == 400
