"""HTTP tests for the public SSO router (list / initiate / callback / token exchange).

The service layer is mocked where it performs network I/O (``handle_callback``);
``initiate_login`` runs for real against an IdP with a manual authorization
endpoint (no discovery). DB setup uses short-lived sessions so it never holds
the shared SQLite connection open across a TestClient request.
"""

import base64
import hashlib
import secrets

from starlette.requests import Request

import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.schema as idp_schema
import jafaal.identity_providers.service as idp_service
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.oauth_state.utils as oauth_state_utils
import jafaal.orm as jafaal_orm
import jafaal.sessions.utils as session_utils

BASE = "/api/v1/public/idp"


def _session():
    return jafaal_orm.get_sessionmaker()()


def _fake_request():
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [(b"user-agent", b"Mozilla/5.0")],
        "client": ("1.2.3.4", 1),
        "scheme": "https",
        "server": ("app.test", 443),
    }
    return Request(scope)


def _pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
    return verifier, challenge


def _create_idp(slug="oidc", *, enabled=True, **kwargs):
    session = _session()
    try:
        idp = idp_crud.create_identity_provider(
            idp_schema.IdentityProviderCreate(
                name=f"IdP {slug}", slug=slug, client_id="cid", client_secret="secret", enabled=enabled, **kwargs
            ),
            session,
        )
        session.expunge(idp)
        return idp
    finally:
        session.close()


def _create_oauth_state(idp_id, *, client_type="web", user_id=None, code_challenge=None):
    session = _session()
    try:
        state_id, nonce = oauth_state_utils.create_state_id_and_nonce()
        oauth_state_crud.create_oauth_state(
            db=session,
            state_id=state_id,
            nonce=nonce,
            client_type=client_type,
            ip_address=None,
            idp_id=idp_id,
            user_id=user_id,
            code_challenge=code_challenge,
            code_challenge_method="S256" if code_challenge else None,
        )
        return state_id
    finally:
        session.close()


def _create_session_linked(user, state_id, session_id="sess-1"):
    session = _session()
    try:
        session_utils.create_session(session_id, user, _fake_request(), None, session, oauth_state_id=state_id)
        return session_id
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# GET "" — list enabled providers
# --------------------------------------------------------------------------- #


def test_list_enabled_providers(client):
    _create_idp(slug="visible", enabled=True)
    _create_idp(slug="hidden", enabled=False)
    resp = client.get(BASE)
    assert resp.status_code == 200
    assert {p["slug"] for p in resp.json()} == {"visible"}


# --------------------------------------------------------------------------- #
# GET /login/{slug} — initiate
# --------------------------------------------------------------------------- #


def test_initiate_login_redirects_to_authorization_url(client):
    _create_idp(slug="goog", authorization_endpoint="https://idp.example/authorize")
    _verifier, challenge = _pkce()
    resp = client.get(
        f"{BASE}/login/goog?code_challenge={challenge}&code_challenge_method=S256",
        follow_redirects=False,
    )
    assert resp.status_code == 307
    assert resp.headers["location"].startswith("https://idp.example/authorize")
    assert "state=" in resp.headers["location"]


def test_initiate_login_unknown_idp(client):
    _verifier, challenge = _pkce()
    resp = client.get(
        f"{BASE}/login/nope?code_challenge={challenge}&code_challenge_method=S256",
        follow_redirects=False,
    )
    assert resp.status_code == 404


def test_initiate_login_rejects_bad_pkce(client):
    _create_idp(slug="goog", authorization_endpoint="https://idp.example/authorize")
    resp = client.get(
        f"{BASE}/login/goog?code_challenge=short&code_challenge_method=S256",
        follow_redirects=False,
    )
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# GET /callback/{slug}
# --------------------------------------------------------------------------- #


def test_callback_login_creates_session_and_redirects(client, make_user, monkeypatch):
    user = make_user(username="ssouser")
    idp = _create_idp(slug="goog")
    state_id = _create_oauth_state(idp.id, client_type="web")

    async def fake_handle(*args, **kwargs):
        return {"user": user, "token_data": {}, "userinfo": {}, "redirect_path": None, "client_type": "web"}

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", fake_handle)

    resp = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert resp.status_code == 307
    location = resp.headers["location"]
    assert "sso=success" in location
    assert "session_id=" in location


def test_callback_link_mode_redirects(client, make_user, monkeypatch):
    user = make_user()
    idp = _create_idp(slug="goog")
    state_id = _create_oauth_state(idp.id, client_type="web", user_id=user.id)

    async def fake_handle(*args, **kwargs):
        return {"user": user, "mode": "link", "token_data": {}, "userinfo": {}}

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", fake_handle)

    resp = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert resp.status_code == 307
    assert "idp_link=success" in resp.headers["location"]


def test_callback_invalid_state_is_400(client):
    _create_idp(slug="goog")
    resp = client.get(f"{BASE}/callback/goog?code=abc&state=does-not-exist", follow_redirects=False)
    assert resp.status_code == 400


def test_callback_unexpected_error_redirects_to_error(client, monkeypatch):
    idp = _create_idp(slug="goog")
    state_id = _create_oauth_state(idp.id, client_type="web")

    async def boom(*args, **kwargs):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", boom)

    resp = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert resp.status_code == 307
    assert "error=sso_failed" in resp.headers["location"]


# --------------------------------------------------------------------------- #
# POST /session/{id}/tokens — PKCE exchange
# --------------------------------------------------------------------------- #


def test_token_exchange_mobile(client, make_user):
    user = make_user()
    verifier, challenge = _pkce()
    state_id = _create_oauth_state(None, client_type="mobile", code_challenge=challenge)
    session_id = _create_session_linked(user, state_id)

    resp = client.post(
        f"{BASE}/session/{session_id}/tokens",
        json={"code_verifier": verifier},
        headers={"X-Client-Type": "mobile"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["refresh_token"]  # mobile → refresh token in body


def test_token_exchange_rejects_bad_verifier(client, make_user):
    user = make_user()
    _verifier, challenge = _pkce()
    other_verifier, _other_challenge = _pkce()
    state_id = _create_oauth_state(None, client_type="mobile", code_challenge=challenge)
    session_id = _create_session_linked(user, state_id)

    resp = client.post(
        f"{BASE}/session/{session_id}/tokens",
        json={"code_verifier": other_verifier},
        headers={"X-Client-Type": "mobile"},
    )
    assert resp.status_code == 400


def test_token_exchange_replay_after_success(client, make_user):
    user = make_user()
    verifier, challenge = _pkce()
    state_id = _create_oauth_state(None, client_type="mobile", code_challenge=challenge)
    session_id = _create_session_linked(user, state_id)

    first = client.post(
        f"{BASE}/session/{session_id}/tokens",
        json={"code_verifier": verifier},
        headers={"X-Client-Type": "mobile"},
    )
    assert first.status_code == 200
    # A successful exchange unlinks + deletes the one-shot OAuth state, so the
    # session is no longer eligible for another exchange.
    second = client.post(
        f"{BASE}/session/{session_id}/tokens",
        json={"code_verifier": verifier},
        headers={"X-Client-Type": "mobile"},
    )
    assert second.status_code == 404


def test_token_exchange_session_not_found(client):
    verifier, _challenge = _pkce()
    resp = client.post(
        f"{BASE}/session/nope/tokens",
        json={"code_verifier": verifier},
        headers={"X-Client-Type": "mobile"},
    )
    assert resp.status_code == 404
