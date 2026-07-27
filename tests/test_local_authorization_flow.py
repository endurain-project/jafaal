"""The local (no-``idp``) authorization-code flow.

``/auth/authorize`` has two ways to authenticate the user. The SSO half is
covered in ``test_authorization_code_flow.py``; this file covers the half that
uses JAFAAL's *own* credentials, where the browser is sent to the host's login
page and that page posts back to ``/auth/login`` with an ``auth_request`` handle.

The property under test throughout is that the login page cannot alter the terms
of the grant it is completing: the client, redirect URI, PKCE challenge and scope
all come from the parked request, never from the login form.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlsplit

import pyotp
import pytest
from conftest import replace_settings

import jafaal
import jafaal.mfa.crud as mfa_crud
import jafaal.orm as jafaal_orm
from jafaal import scopes as scopes_mod
from jafaal._core import crypto

AUTHORIZE = "/api/v1/auth/authorize"
LOGIN = "/api/v1/auth/login"
TOKEN = "/api/v1/auth/token"
MFA_VERIFY = "/api/v1/auth/mfa/verify"

CLIENT_ID = "com.example.local"
REDIRECT_URI = "com.example.local://oauth/callback"
LOGIN_UI = "https://app.test/sign-in"
PASSWORD = "Str0ng!Pass"


@pytest.fixture(autouse=True)
def _local_login_deployment():
    """A registered client plus a configured host login page."""
    original = jafaal.get_settings()
    jafaal.configure(
        replace_settings(
            original,
            login_ui_url=LOGIN_UI,
            oauth_clients=(
                jafaal.OAuthClient(
                    client_id=CLIENT_ID,
                    redirect_uris=(REDIRECT_URI,),
                    name="Local App",
                ),
            ),
        )
    )
    yield
    jafaal.configure(original)


def _pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
    return verifier, challenge


def _query(url: str) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


def _authorize(client, *, challenge, **overrides):
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "opaque-state",
    }
    params.update(overrides)
    return client.get(AUTHORIZE, params=params, follow_redirects=False)


def _start(client, **overrides):
    """Run /authorize and return ``(verifier, auth_request)``."""
    verifier, challenge = _pkce()
    started = _authorize(client, challenge=challenge, **overrides)
    assert started.status_code == 302
    location = started.headers["location"]
    assert location.startswith(LOGIN_UI), location
    return verifier, _query(location)["auth_request"]


def _login(client, auth_request, *, username="alice", password=PASSWORD, client_id=CLIENT_ID):
    return client.post(
        LOGIN,
        data={
            "username": username,
            "password": password,
            "client_id": client_id,
            "auth_request": auth_request,
        },
    )


def _redeem(client, *, code, verifier):
    return client.post(
        TOKEN,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
        },
    )


def _enable_mfa(user_id, secret):
    session = jafaal_orm.get_sessionmaker()()
    try:
        with jafaal_orm.unit_of_work(session):
            mfa_crud.update_user_mfa(user_id, session, encrypted_secret=crypto.encrypt_token_fernet(secret))
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_local_authorization_code_flow_issues_tokens(client, make_user):
    # The flow a native app should use even though /auth/login exists: the
    # password is entered in a browser the app does not control (RFC 8252 §8.1).
    make_user(username="alice")
    verifier, auth_request = _start(client)

    completed = _login(client, auth_request)
    assert completed.status_code == 200
    target = completed.json()["redirect_to"]
    assert target.startswith(REDIRECT_URI)

    params = _query(target)
    assert params["code"]
    assert params["state"] == "opaque-state"  # returned unmodified, per §4.1.2
    assert params["iss"] == jafaal.get_settings().resolved_issuer  # RFC 9207

    body = _redeem(client, code=params["code"], verifier=verifier).json()
    assert body["access_token"]
    assert body["refresh_token"]


def test_no_token_reaches_the_browser(client, make_user):
    # The whole point of the code flow: the redirect carries a single-use code
    # and nothing bearer-ish, so nothing lands in history, logs or a Referer.
    make_user(username="alice")
    _verifier, auth_request = _start(client)

    completed = _login(client, auth_request)
    params = _query(completed.json()["redirect_to"])

    assert set(params) <= {"code", "state", "iss"}
    assert completed.headers["cache-control"] == "no-store"
    assert "jafaal_refresh_token" not in completed.cookies


def test_the_login_response_carries_no_tokens_of_its_own(client, make_user):
    make_user(username="alice")
    _verifier, auth_request = _start(client)

    body = _login(client, auth_request).json()
    assert "access_token" not in body
    assert "refresh_token" not in body
    assert "csrf_token" not in body


# --------------------------------------------------------------------------- #
# The login page cannot alter the terms of the grant
# --------------------------------------------------------------------------- #


def test_scope_comes_from_the_parked_request_not_the_login_form(client, make_user):
    # The client asked at /authorize. If the login form could restate the scope,
    # a compromised login page could widen every grant it completes.
    make_user(username="alice", is_superuser=True)
    verifier, auth_request = _start(client, scope=scopes_mod.PROFILE)

    completed = client.post(
        LOGIN,
        data={
            "username": "alice",
            "password": PASSWORD,
            "client_id": CLIENT_ID,
            "auth_request": auth_request,
            "scope": " ".join(scopes_mod.get_scope_catalog().admin),
        },
    )
    code = _query(completed.json()["redirect_to"])["code"]
    assert _redeem(client, code=code, verifier=verifier).json()["scope"] == scopes_mod.PROFILE


def test_another_client_cannot_complete_the_request(client, make_user):
    make_user(username="alice")
    _verifier, auth_request = _start(client)

    original = jafaal.get_settings()
    jafaal.configure(
        replace_settings(
            original,
            oauth_clients=(
                *original.oauth_clients,
                jafaal.OAuthClient(client_id="com.other.app", redirect_uris=("com.other.app://cb",)),
            ),
        )
    )
    try:
        resp = _login(client, auth_request, client_id="com.other.app")
        assert resp.status_code == 400
    finally:
        jafaal.configure(original)


def test_the_request_is_single_use(client, make_user):
    make_user(username="alice")
    _verifier, auth_request = _start(client)

    assert _login(client, auth_request).status_code == 200
    assert _login(client, auth_request).status_code == 400


def test_an_unknown_auth_request_is_refused(client, make_user):
    make_user(username="alice")
    assert _login(client, "not-a-real-handle").status_code == 400


def test_an_sso_state_cannot_be_completed_by_password(client, make_user):
    # A state minted for an IdP round trip belongs to that provider's callback.
    # Redeeming it here would skip the provider entirely.
    import jafaal.identity_providers.crud as idp_crud
    import jafaal.identity_providers.schema as idp_schema

    make_user(username="alice")
    session = jafaal_orm.get_sessionmaker()()
    try:
        with jafaal_orm.unit_of_work(session):
            idp_crud.create_identity_provider(
                idp_schema.IdentityProviderCreate(
                    name="IdP",
                    slug="oidc",
                    client_id="cid",
                    client_secret="secret",
                    enabled=True,
                    authorization_endpoint="https://idp.example/authorize",
                ),
                session,
            )
    finally:
        session.close()

    _verifier, challenge = _pkce()
    started = _authorize(client, challenge=challenge, idp="oidc")
    assert started.status_code == 302
    upstream_state = _query(started.headers["location"])["state"]

    assert _login(client, upstream_state).status_code == 400


# --------------------------------------------------------------------------- #
# Second factors finish the same request
# --------------------------------------------------------------------------- #


def test_mfa_completes_the_authorization_request(client, make_user):
    # A flow begun at /authorize must finish as an authorization response no
    # matter which factor ended it — otherwise enabling MFA silently changes the
    # shape of the response a client gets.
    user = make_user(username="mfauser")
    secret = pyotp.random_base32()
    _enable_mfa(user.id, secret)

    verifier, auth_request = _start(client)

    challenge = _login(client, auth_request, username="mfauser")
    assert challenge.json()["mfa_required"] is True

    completed = client.post(
        MFA_VERIFY,
        json={
            "mfa_token": challenge.json()["mfa_token"],
            "mfa_code": pyotp.TOTP(secret).now(),
            "client_id": CLIENT_ID,
        },
    )
    assert completed.status_code == 200
    body = completed.json()
    assert "access_token" not in body

    params = _query(body["redirect_to"])
    assert _redeem(client, code=params["code"], verifier=verifier).json()["access_token"]


def test_mfa_cannot_redirect_the_request_elsewhere(client, make_user):
    # The handle is carried on the pending-MFA ticket, never re-supplied at step
    # two, so the second factor cannot swap in a different authorization request.
    # The request schema forbids unknown fields, so an attempt is refused
    # outright rather than silently ignored.
    user = make_user(username="mfauser")
    secret = pyotp.random_base32()
    _enable_mfa(user.id, secret)

    _verifier, first = _start(client)
    _verifier2, second = _start(client)

    challenge = _login(client, first, username="mfauser")
    completed = client.post(
        MFA_VERIFY,
        json={
            "mfa_token": challenge.json()["mfa_token"],
            "mfa_code": pyotp.TOTP(secret).now(),
            "client_id": CLIENT_ID,
            "auth_request": second,
        },
    )
    assert completed.status_code == 422

    # The second request is untouched and still usable on its own.
    assert _login(client, second, username="mfauser").json()["mfa_required"] is True


# --------------------------------------------------------------------------- #
# Deployment configuration
# --------------------------------------------------------------------------- #


def test_local_login_is_refused_when_no_login_page_is_configured(client):
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, login_ui_url=""))
    try:
        _verifier, challenge = _pkce()
        resp = _authorize(client, challenge=challenge)
        # Reported by redirect: the redirect URI has validated, so the waiting
        # client should learn the deployment cannot serve local login.
        assert resp.status_code == 302
        params = _query(resp.headers["location"])
        assert params["error"] == "server_error"
        assert params["state"] == "opaque-state"
    finally:
        jafaal.configure(original)


def test_pkce_is_still_mandatory_without_an_idp(client):
    resp = _authorize(client, challenge="", code_challenge_method="")
    assert resp.status_code == 302
    assert _query(resp.headers["location"])["error"] == "invalid_request"


def test_an_unregistered_redirect_uri_is_still_refused(client):
    # RFC 6749 §4.1.2.1: reported to the user agent, never redirected — an
    # unvalidated redirect target is exactly the open redirect that leaks codes.
    _verifier, challenge = _pkce()
    resp = _authorize(client, challenge=challenge, redirect_uri="com.example.local://evil")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
