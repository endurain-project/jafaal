"""End-to-end tests for the RFC 6749 authorization-code flow with PKCE.

These drive the flow the way a stock OAuth client library would:

    GET  /auth/authorize?response_type=code&client_id=…&redirect_uri=…
                        &code_challenge=…&code_challenge_method=S256&state=…
      → 307 to the identity provider
    (IdP → /public/idp/callback/{slug})
      → 307 to the client's registered redirect_uri?code=…&state=…
    POST /auth/token  grant_type=authorization_code&code=…&code_verifier=…
                      &redirect_uri=…&client_id=…
      → {access_token, refresh_token, …}

The upstream leg (JAFAAL ↔ the identity provider) is stubbed, because it is
covered in depth by ``test_idp_service``; what is exercised here is JAFAAL's own
authorization server behaviour and, above all, the four bindings that make a
code safe to hand to a browser: PKCE, ``client_id``, exact ``redirect_uri``, and
single use.
"""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import replace_settings

import jafaal
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.schema as idp_schema
import jafaal.identity_providers.service as idp_service
import jafaal.orm as jafaal_orm

AUTHORIZE = "/api/v1/auth/authorize"
TOKEN = "/api/v1/auth/token"
CALLBACK = "/api/v1/public/idp/callback"

CLIENT_ID = "com.example.app"
REDIRECT_URI = "com.example.app://oauth/callback"
OTHER_REDIRECT_URI = "com.example.app://oauth/other"


@pytest.fixture(autouse=True)
def _registered_client():
    """Register a public client for the duration of each test."""
    original = jafaal.get_settings()
    jafaal.configure(
        replace_settings(
            original,
            oauth_clients=(
                jafaal.OAuthClient(
                    client_id=CLIENT_ID,
                    redirect_uris=(REDIRECT_URI, OTHER_REDIRECT_URI),
                    name="Example App",
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


def _create_idp(slug="oidc"):
    session = jafaal_orm.get_sessionmaker()()
    try:
        with jafaal_orm.unit_of_work(session):
            idp = idp_crud.create_identity_provider(
                idp_schema.IdentityProviderCreate(
                    name=f"IdP {slug}",
                    slug=slug,
                    client_id="upstream-cid",
                    client_secret="upstream-secret",
                    enabled=True,
                    authorization_endpoint="https://idp.example/authorize",
                ),
                session,
            )
        session.expunge(idp)
        return idp
    finally:
        session.close()


def _authorize(client, *, challenge, state="opaque-state", **overrides):
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "idp": "oidc",
    }
    if state is not None:
        params["state"] = state
    params.update(overrides)
    return client.get(AUTHORIZE, params=params, follow_redirects=False)


def _stub_callback(monkeypatch, user):
    """Make the IdP callback resolve to ``user`` without touching the network."""

    async def _handle_callback(idp, code, state, request, password_hasher, db, oauth_state):
        return {
            "user": user,
            "token_data": {},
            "userinfo": {"sub": "idp-subject"},
            "redirect_path": oauth_state.redirect_path,
            "client_type": oauth_state.client_type,
        }

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", _handle_callback)


def _complete_authorization(client, monkeypatch, make_user, *, state="opaque-state"):
    """Run /authorize → callback and return ``(verifier, code, echoed_state)``."""
    user = make_user(username="ada")
    _create_idp()
    _stub_callback(monkeypatch, user)

    verifier, challenge = _pkce()
    started = _authorize(client, challenge=challenge, state=state)
    assert started.status_code == 307
    upstream_state = parse_qs(urlsplit(started.headers["location"]).query)["state"][0]

    landed = client.get(
        f"{CALLBACK}/oidc",
        params={"code": "upstream-code", "state": upstream_state},
        follow_redirects=False,
    )
    assert landed.status_code == 307
    target = urlsplit(landed.headers["location"])
    query = parse_qs(target.query)

    # The code is delivered to the client's *registered* URI, not to JAFAAL's
    # own frontend.
    assert f"{target.scheme}://{target.netloc}{target.path}" == REDIRECT_URI
    return verifier, query["code"][0], query.get("state", [None])[0]


def _redeem(client, *, code, verifier, **overrides):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
    }
    data.update(overrides)
    return client.post(TOKEN, data=data)


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_full_authorization_code_flow_issues_tokens(client, monkeypatch, make_user):
    verifier, code, echoed_state = _complete_authorization(client, monkeypatch, make_user)

    assert echoed_state == "opaque-state", "the client's state must come back unmodified"

    response = _redeem(client, code=code, verifier=verifier)

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    # A registered client redeems over HTTP and gets the refresh token in the
    # body — it never receives it as a browser cookie.
    assert body["refresh_token"]
    assert body["expires_in"] > 0
    assert "csrf_token" not in body or body.get("csrf_token") is None


def test_state_is_omitted_when_the_client_sent_none(client, monkeypatch, make_user):
    _, _code, echoed_state = _complete_authorization(client, monkeypatch, make_user, state=None)
    assert echoed_state is None


def test_issued_tokens_authenticate_a_request(client, monkeypatch, make_user):
    verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)
    access = _redeem(client, code=code, verifier=verifier).json()["access_token"]

    me = client.get(
        "/api/v1/auth/sessions/user/1",
        headers={"Authorization": f"Bearer {access}", "X-Client-Type": "mobile"},
    )
    # 200 or 403 both prove the token authenticated; 401 would mean it did not.
    assert me.status_code != 401


# --------------------------------------------------------------------------- #
# The authorization request itself
# --------------------------------------------------------------------------- #


def test_unregistered_client_is_refused_without_redirecting(client, monkeypatch, make_user):
    """An unknown client must be reported to the user agent, never redirected.

    RFC 6749 §4.1.2.1: redirecting to an unvalidated URI is the open redirect
    that leaks the code, so the error is rendered instead.
    """
    _create_idp()
    _, challenge = _pkce()
    response = _authorize(client, challenge=challenge, client_id="not.registered")

    assert response.status_code == 400
    assert "location" not in response.headers


def test_unregistered_redirect_uri_is_refused(client, make_user):
    _create_idp()
    _, challenge = _pkce()
    response = _authorize(client, challenge=challenge, redirect_uri="com.attacker.app://steal")

    assert response.status_code == 400
    assert "location" not in response.headers


def test_redirect_uri_matching_is_exact_not_prefix(client):
    """A registered URI must not authorise its own sub-paths or query variants.

    Prefix matching is how authorization codes get exfiltrated to an attacker
    path on an otherwise legitimate client, so RFC 9700 §4.1.3 mandates exact
    comparison.
    """
    _create_idp()
    _, challenge = _pkce()
    for near_miss in (
        f"{REDIRECT_URI}/extra",
        f"{REDIRECT_URI}?next=https://evil.test",
        REDIRECT_URI.rstrip("k"),
        f"{REDIRECT_URI} ",
    ):
        response = _authorize(client, challenge=challenge, redirect_uri=near_miss)
        assert response.status_code == 400, near_miss


def test_implicit_and_hybrid_response_types_are_refused(client):
    _create_idp()
    _, challenge = _pkce()
    for response_type in ("token", "id_token", "code token", "code id_token"):
        response = _authorize(client, challenge=challenge, response_type=response_type)
        assert response.status_code == 400, response_type


def test_pkce_is_mandatory_and_plain_is_refused(client):
    _create_idp()
    _, challenge = _pkce()

    assert _authorize(client, challenge=challenge, code_challenge_method="plain").status_code == 400
    assert _authorize(client, challenge="short").status_code == 400


# --------------------------------------------------------------------------- #
# Redemption bindings
# --------------------------------------------------------------------------- #


def test_wrong_code_verifier_is_refused(client, monkeypatch, make_user):
    _verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)
    other_verifier, _ = _pkce()

    assert _redeem(client, code=code, verifier=other_verifier).status_code == 400


def test_code_cannot_be_redeemed_by_another_client(client, monkeypatch, make_user):
    """A stolen code is useless to a client it was not issued to."""
    verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)

    response = _redeem(client, code=code, verifier=verifier, client_id="com.other.app")

    assert response.status_code == 400
    # And the code survives for its rightful owner — a failed probe must not
    # burn it.
    assert _redeem(client, code=code, verifier=verifier).status_code == 200


def test_code_cannot_be_redeemed_against_a_different_registered_uri(client, monkeypatch, make_user):
    """RFC 6749 §4.1.3: the redirect_uri must match the authorization request.

    ``OTHER_REDIRECT_URI`` is registered for this same client, so only the
    per-code binding — not the registry — can reject this.
    """
    verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)

    response = _redeem(client, code=code, verifier=verifier, redirect_uri=OTHER_REDIRECT_URI)

    assert response.status_code == 400


def test_authorization_code_is_single_use(client, monkeypatch, make_user):
    verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)

    assert _redeem(client, code=code, verifier=verifier).status_code == 200
    replay = _redeem(client, code=code, verifier=verifier)
    assert replay.status_code in (400, 409)


def test_unknown_code_is_refused(client):
    assert _redeem(client, code=secrets.token_urlsafe(32), verifier=_pkce()[0]).status_code == 400


def test_missing_parameters_are_reported(client):
    complete = {
        "grant_type": "authorization_code",
        "code": "x" * 43,
        "code_verifier": "y" * 43,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
    }
    for omitted in ("code", "code_verifier", "redirect_uri", "client_id"):
        response = client.post(TOKEN, data={**complete, omitted: ""})
        assert response.status_code == 400, omitted
        assert omitted in response.json()["detail"]


def test_the_code_is_not_stored_in_plaintext(client, monkeypatch, make_user):
    """Database read access alone must not yield a redeemable code."""
    import jafaal.oauth_state.models as oauth_state_models

    _verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)

    with jafaal_orm.get_sessionmaker()() as session:
        stored = [
            row.authorization_code_hash
            for row in session.query(oauth_state_models.OAuthState).all()
            if row.authorization_code_hash
        ]
    assert stored, "no code digest was persisted"
    assert code not in stored


# --------------------------------------------------------------------------- #
# Interaction with the native flow
# --------------------------------------------------------------------------- #


def test_a_code_flow_session_cannot_be_redeemed_by_session_id(client, monkeypatch, make_user):
    """The native exchange must not be a second, weaker door into a code flow.

    ``/session/{id}/tokens`` checks PKCE but knows nothing about ``client_id`` or
    ``redirect_uri``, so honouring it here would silently drop two of the four
    bindings the authorization-code flow relies on.
    """
    import jafaal.sessions.models as sessions_models

    verifier, _code, _ = _complete_authorization(client, monkeypatch, make_user)

    with jafaal_orm.get_sessionmaker()() as session:
        pending = session.query(sessions_models.UsersSessions).all()
        session_id = pending[0].id

    response = client.post(
        f"/api/v1/public/idp/session/{session_id}/tokens",
        json={"code_verifier": verifier},
        headers={"X-Client-Type": "mobile"},
    )
    assert response.status_code == 400


def test_refresh_grant_still_works_on_the_token_endpoint(client, monkeypatch, make_user):
    """One token endpoint, both grants — a standard client uses only this URL."""
    verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)
    issued = _redeem(client, code=code, verifier=verifier).json()

    refreshed = client.post(
        TOKEN,
        data={"grant_type": "refresh_token", "refresh_token": issued["refresh_token"]},
    )

    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"]
    assert refreshed.json()["refresh_token"] != issued["refresh_token"], "refresh must rotate"


def test_unsupported_grant_type_is_rejected(client):
    response = client.post(TOKEN, data={"grant_type": "password", "username": "a", "password": "b"})
    assert response.status_code == 400
    assert "unsupported_grant_type" in response.json()["detail"]


def test_refresh_grant_without_a_token_is_a_bad_request(client):
    response = client.post(TOKEN, data={"grant_type": "refresh_token"})
    assert response.status_code == 400


def test_a_failed_callback_reports_the_error_to_the_clients_redirect_uri(client, monkeypatch, make_user):
    """RFC 6749 §4.1.2.1: report failures at the validated redirect_uri.

    Falling back to JAFAAL's own error page instead would leave a native app
    waiting on its callback listener with no way to distinguish a denial from a
    crash.
    """
    make_user(username="ada")
    _create_idp()

    async def _explode(*_args, **_kwargs):
        raise RuntimeError("the identity provider fell over")

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", _explode)

    _verifier, challenge = _pkce()
    started = _authorize(client, challenge=challenge, state="round-trip")
    upstream_state = parse_qs(urlsplit(started.headers["location"]).query)["state"][0]

    landed = client.get(
        f"{CALLBACK}/oidc",
        params={"code": "upstream-code", "state": upstream_state},
        follow_redirects=False,
    )

    assert landed.status_code == 307
    target = urlsplit(landed.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == REDIRECT_URI
    query = parse_qs(target.query)
    assert query["error"] == ["server_error"]
    assert query["state"] == ["round-trip"]
