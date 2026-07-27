"""HTTP tests for the public SSO router (list providers, provider callback).

The service layer is mocked where it performs network I/O (``handle_callback``).
DB setup uses short-lived sessions so it never holds the shared SQLite connection
open across a TestClient request.

The through-line of these tests is a single rule: **every browser redirect this
router emits targets a registered ``redirect_uri``**. There is no configured
frontend path to fall back to, so a flow whose state carries no validated target
cannot redirect at all — it must render.
"""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlsplit

from conftest import NATIVE_CLIENT_ID, NATIVE_REDIRECT_URI
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


def _query(location: str) -> dict[str, str]:
    """Return the redirect target's query parameters, one value each."""
    return {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}


def _create_idp(slug="oidc", *, enabled=True, **kwargs):
    session = _session()
    try:
        with jafaal_orm.unit_of_work(session):
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


def _create_oauth_state(
    idp_id,
    *,
    user_id=None,
    code_challenge=None,
    purpose="login",
    client_id=NATIVE_CLIENT_ID,
    redirect_uri=NATIVE_REDIRECT_URI,
    client_state=None,
):
    session = _session()
    try:
        state_id, nonce = oauth_state_utils.create_state_id_and_nonce()
        with jafaal_orm.unit_of_work(session):
            oauth_state_crud.create_oauth_state(
                db=session,
                state_id=state_id,
                nonce=nonce,
                ip_address=None,
                idp_id=idp_id,
                user_id=user_id,
                purpose=purpose,
                code_challenge=code_challenge,
                code_challenge_method="S256" if code_challenge else None,
                client_id=client_id,
                redirect_uri=redirect_uri,
                client_state=client_state,
            )
        return state_id
    finally:
        session.close()


def _create_session_linked(user, state_id, session_id="sess-1"):
    session = _session()
    try:
        with jafaal_orm.unit_of_work(session):
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
# GET /callback/{slug} — login mode
# --------------------------------------------------------------------------- #


def test_callback_login_delivers_an_authorization_code_to_the_client(client, make_user, monkeypatch):
    # The RFC 6749 §4.1.2 authorization response: a code at the registered
    # redirect_uri. No tokens travel through the browser.
    user = make_user(username="ssouser")
    idp = _create_idp(slug="goog")
    _verifier, challenge = _pkce()
    state_id = _create_oauth_state(idp.id, code_challenge=challenge, client_state="opaque-123")

    async def fake_handle(*args, **kwargs):
        return {"user": user, "token_data": {}, "userinfo": {}}

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", fake_handle)

    resp = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(NATIVE_REDIRECT_URI)
    params = _query(location)
    assert params["code"]
    # §4.1.2 requires state to be returned exactly as sent, so the client can
    # match the response to its request (and detect CSRF).
    assert params["state"] == "opaque-123"
    assert "access_token" not in params
    assert "session_id" not in params


def test_callback_login_omits_state_when_the_client_sent_none(client, make_user, monkeypatch):
    user = make_user(username="ssouser")
    idp = _create_idp(slug="goog")
    _verifier, challenge = _pkce()
    state_id = _create_oauth_state(idp.id, code_challenge=challenge)

    async def fake_handle(*args, **kwargs):
        return {"user": user, "token_data": {}, "userinfo": {}}

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", fake_handle)

    resp = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert resp.status_code == 302
    assert "state" not in _query(resp.headers["location"])


# --------------------------------------------------------------------------- #
# GET /callback/{slug} — link and step-up modes
# --------------------------------------------------------------------------- #


def test_callback_link_mode_returns_to_the_registered_uri(client, make_user, monkeypatch):
    user = make_user()
    idp = _create_idp(slug="goog")
    state_id = _create_oauth_state(idp.id, user_id=user.id, purpose="link")

    async def fake_handle(*args, **kwargs):
        return {"user": user, "mode": "link", "token_data": {}, "userinfo": {}}

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", fake_handle)

    resp = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(NATIVE_REDIRECT_URI)
    assert _query(location)["idp_link"] == "success"


def test_callback_step_up_returns_to_the_registered_uri(client, make_user, monkeypatch):
    user = make_user()
    idp = _create_idp(slug="goog")
    state_id = _create_oauth_state(idp.id, user_id=user.id, purpose="stepup")

    async def fake_handle(*args, **kwargs):
        return {"user": user, "mode": "stepup", "token_data": {}, "userinfo": {}}

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", fake_handle)

    resp = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert resp.status_code == 302
    assert _query(resp.headers["location"])["step_up"] == "success"


# --------------------------------------------------------------------------- #
# GET /callback/{slug} — failures
# --------------------------------------------------------------------------- #


def test_callback_with_an_unresolvable_state_renders_rather_than_redirects(client):
    # No state means no validated redirect target. RFC 6749 §4.1.2.1 is explicit
    # that an unvalidated URI must never be used, so the error is rendered.
    _create_idp(slug="goog")
    resp = client.get(f"{BASE}/callback/goog?code=abc&state=does-not-exist", follow_redirects=False)
    assert resp.status_code == 400


def test_callback_failure_after_validation_redirects_with_an_error(client, monkeypatch):
    # Once the redirect target is known-good the failure goes to the client:
    # otherwise a native app sits on its callback listener until it times out.
    idp = _create_idp(slug="goog")
    state_id = _create_oauth_state(idp.id, client_state="opaque-123")

    async def boom(*args, **kwargs):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", boom)

    resp = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert resp.status_code == 302
    params = _query(resp.headers["location"])
    assert params["error"] == "server_error"
    assert params["state"] == "opaque-123"


def test_callback_jafaal_failure_after_validation_redirects_with_access_denied(client, make_user, monkeypatch):
    import jafaal.exceptions as jafaal_exceptions

    user = make_user()
    idp = _create_idp(slug="goog")
    state_id = _create_oauth_state(idp.id)

    async def denied(*args, **kwargs):
        raise jafaal_exceptions.AuthenticationError("The provider rejected the sign-in")

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", denied)

    resp = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert resp.status_code == 302
    assert _query(resp.headers["location"])["error"] == "access_denied"
    assert user  # the account is untouched by a failed callback


def test_callback_state_bound_to_another_provider_is_rejected(client, make_user, monkeypatch):
    # A state minted for one provider must not be redeemable at another's
    # callback, even where two IdP rows share an authorization server. The state
    # itself resolves, so its validated redirect_uri exists and the rejection is
    # reported there rather than rendered — but no code is issued.
    user = make_user()
    idp_a = _create_idp(slug="alpha")
    _create_idp(slug="beta")
    state_id = _create_oauth_state(idp_a.id)

    async def fake_handle(*args, **kwargs):
        raise AssertionError("the provider mismatch must be caught before the callback is processed")

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", fake_handle)

    resp = client.get(f"{BASE}/callback/beta?code=abc&state={state_id}", follow_redirects=False)
    assert resp.status_code == 302
    params = _query(resp.headers["location"])
    assert params["error"] == "access_denied"
    assert "code" not in params
    assert user  # no session was created for anyone


def test_callback_state_is_single_use(client, make_user, monkeypatch):
    user = make_user(username="ssouser")
    idp = _create_idp(slug="goog")
    state_id = _create_oauth_state(idp.id)

    async def fake_handle(*args, **kwargs):
        return {"user": user, "token_data": {}, "userinfo": {}}

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", fake_handle)

    first = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert first.status_code == 302
    replay = client.get(f"{BASE}/callback/goog?code=abc&state={state_id}", follow_redirects=False)
    assert replay.status_code == 400


def test_native_login_and_token_exchange_endpoints_are_gone(client, make_user):
    # The two JAFAAL-specific SSO endpoints are deleted, not deprecated. A
    # second way to obtain tokens is a second attack surface, and this one
    # bypassed the client_id and redirect_uri bindings entirely.
    user = make_user()
    _create_idp(slug="goog", authorization_endpoint="https://idp.example/authorize")
    _verifier, challenge = _pkce()
    state_id = _create_oauth_state(None, code_challenge=challenge)
    session_id = _create_session_linked(user, state_id)

    assert client.get(f"{BASE}/login/goog?code_challenge={challenge}&code_challenge_method=S256").status_code == 404
    assert client.post(f"{BASE}/session/{session_id}/tokens", json={"code_verifier": _verifier}).status_code == 404
