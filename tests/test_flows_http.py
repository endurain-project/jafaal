"""End-to-end HTTP tests for the password-reset, sign-up, and MFA-verify flows."""

import time
from contextlib import contextmanager

import pyotp

import jafaal
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.schema as idp_schema
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


def _auth_headers(client, username, password):
    access = _login(client, username, password).json()["access_token"]
    return {"X-Client-Type": "web", "Authorization": f"Bearer {access}"}


def _create_linked_idp(user_id, *, slug, link=True):
    session = jafaal_orm.get_sessionmaker()()
    try:
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
        session.commit()
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
        headers=_auth_headers(client, "ssoinit", "Str0ng!Pass"),
    )
    assert r.status_code == 200
    url = r.json()["authorization_url"]
    assert url.startswith("https://idp.example/authorize")
    assert "prompt=login" in url
    assert "max_age=300" in url


def test_step_up_reauth_initiate_requires_link(client, make_user):
    # You can only re-authenticate an identity provider you are linked to.
    user = make_user(username="nolink", password="Str0ng!Pass")
    idp_id = _create_linked_idp(user.id, slug="unlinked", link=False)
    r = client.post(
        f"/api/v1/auth/idp/step-up/reauth/{idp_id}",
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


def test_mfa_verify_login_flow_with_zero_user_id(client, make_user):
    """A user whose integer id is the falsy value ``0`` can still complete MFA login.

    Regression for the ``if not user_id`` check (now ``if user_id is None``):
    ``get_pending_login`` returns ``0`` for such a user, which the old truthiness
    test wrongly treated as "no pending login".
    """
    user = make_user(username="zerouser", user_id=0, password="Str0ng!Pass")
    assert user.id == 0

    secret = pyotp.random_base32()
    _enable_mfa(user.id, secret)

    assert _login(client, "zerouser", "Str0ng!Pass").status_code == 202

    code = pyotp.TOTP(secret).now()
    verify = client.post(
        "/api/v1/auth/mfa/verify",
        json={"username": "zerouser", "mfa_code": code},
        headers=WEB,
    )
    assert verify.status_code == 200
    assert verify.json()["access_token"]
