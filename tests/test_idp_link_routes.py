"""HTTP tests for the identity-provider link routes (owner and administrator)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import LIMITED_CLIENT_ID, NATIVE_CLIENT_ID, NATIVE_REDIRECT_URI, RecordingEventSink

import jafaal
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.schema as idp_schema
import jafaal.identity_providers.service as idp_service
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.oauth_state.models as oauth_state_models
import jafaal.orm as jafaal_orm
import jafaal.ports as jafaal_ports
from jafaal._internal.security_stores import grant_step_up_reauth

PASSWORD = "Str0ng!Pass"
PROFILE = "/api/v1/profile"
USERS = "/api/v1/users"
PUBLIC_IDP = "/api/v1/public/idp"


class LinkEventSink(RecordingEventSink):
    async def on_idp_account_linked(self, event):
        self.events.append(event)

    async def on_idp_account_unlinked(self, event):
        self.events.append(event)


@pytest.fixture
def sink():
    recorder = LinkEventSink()
    jafaal.configure_event_sink(recorder)
    yield recorder
    jafaal.configure_event_sink(jafaal.NullAuthEventSink())


def _session():
    return jafaal_orm.get_sessionmaker()()


def _create_idp(slug="oidc", *, enabled=True):
    session = _session()
    try:
        with jafaal_orm.unit_of_work(session):
            idp = idp_crud.create_identity_provider(
                idp_schema.IdentityProviderCreate(
                    name=f"IdP {slug}",
                    slug=slug,
                    client_id="cid",
                    client_secret="secret",
                    enabled=enabled,
                    authorization_endpoint=f"https://{slug}.example/authorize",
                ),
                session,
            )
        return idp.id
    finally:
        session.close()


def _link(user_id, idp_id, subject=None):
    session = _session()
    try:
        with jafaal_orm.unit_of_work(session):
            links_crud.create_user_identity_provider(user_id, idp_id, subject or f"sub-{user_id}-{idp_id}", session)
    finally:
        session.close()


def _is_linked(user_id, idp_id):
    session = _session()
    try:
        return links_crud.get_user_identity_provider_by_user_id_and_idp_id(user_id, idp_id, session) is not None
    finally:
        session.close()


def _bearer(client, username, *, client_id=NATIVE_CLIENT_ID, password=PASSWORD):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password, "client_id": client_id},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _start(client, headers, idp_id, *, client_id=NATIVE_CLIENT_ID, redirect_uri=NATIVE_REDIRECT_URI, **body):
    body = {"client_id": client_id, "redirect_uri": redirect_uri, "state": "s1", **body}
    return client.post(f"{PROFILE}/idp/{idp_id}/link", json=body, headers=headers)


def _state_id(response):
    return parse_qs(urlsplit(response.json()["authorization_url"]).query)["state"][0]


def _callback(client, state_id):
    return client.get(f"{PUBLIC_IDP}/callback/oidc?code=abc&state={state_id}", follow_redirects=False)


# --------------------------------------------------------------------------- #
# Listing
# --------------------------------------------------------------------------- #


def test_the_caller_lists_only_their_own_links_without_secrets(client, make_user):
    alice, bob = make_user(username="alice"), make_user(username="bob")
    one, two = _create_idp("one"), _create_idp("two")
    _link(alice.id, one)
    _link(bob.id, two)

    body = client.get(f"{PROFILE}/idp", headers=_bearer(client, "alice")).json()

    assert [link["idp_slug"] for link in body] == ["one"]
    assert set(body[0]) == {"idp_id", "idp_name", "idp_slug", "linked_at", "last_login"}


def test_listing_needs_a_token_and_the_read_scope(client, make_user):
    make_user(username="alice")
    assert client.get(f"{PROFILE}/idp").status_code == 401
    narrow = _bearer(client, "alice", client_id=LIMITED_CLIENT_ID)  # carries only `profile`
    assert client.get(f"{PROFILE}/idp", headers=narrow).status_code == 403


# --------------------------------------------------------------------------- #
# Starting a link
# --------------------------------------------------------------------------- #


def test_starting_a_link_requires_step_up(client, make_user):
    make_user(username="alice")
    idp = _create_idp()
    headers = _bearer(client, "alice")

    assert _start(client, headers, idp).status_code == 401
    assert _start(client, headers, idp, current_password="wrong-password").status_code == 401
    ok = _start(client, headers, idp, current_password=PASSWORD)
    assert ok.status_code == 200
    assert set(ok.json()) == {"authorization_url"}
    assert "no-store" in ok.headers["cache-control"]


def test_starting_a_link_needs_a_bearer(client):
    assert client.post(f"{PROFILE}/idp/1/link", json={}).status_code == 401


def test_starting_refuses_a_missing_disabled_or_already_linked_provider(client, make_user):
    alice = make_user(username="alice")
    headers = _bearer(client, "alice")
    disabled, linked = _create_idp("off", enabled=False), _create_idp("on")
    _link(alice.id, linked)

    assert _start(client, headers, 9999, current_password=PASSWORD).status_code == 404
    assert _start(client, headers, disabled, current_password=PASSWORD).status_code == 404
    assert _start(client, headers, linked, current_password=PASSWORD).status_code == 409


def test_starting_a_link_returns_the_provider_url_and_binds_the_user(client, make_user):
    alice = make_user(username="alice")
    idp = _create_idp()

    response = _start(client, _bearer(client, "alice"), idp, current_password=PASSWORD)

    location = urlsplit(response.json()["authorization_url"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == "https://oidc.example/authorize"
    session = _session()
    try:
        state = oauth_state_crud.get_oauth_state_by_id(_state_id(response), session)
        assert (state.purpose, state.user_id, state.idp_id) == ("link", alice.id, idp)
        assert (state.client_id, state.redirect_uri, state.client_state) == (
            NATIVE_CLIENT_ID,
            NATIVE_REDIRECT_URI,
            "s1",
        )
    finally:
        session.close()


def test_an_unregistered_redirect_is_refused_before_any_state_is_parked(client, make_user):
    make_user(username="alice")
    idp = _create_idp()

    refused = _start(
        client,
        _bearer(client, "alice"),
        idp,
        redirect_uri="https://attacker.example/cb",
        current_password=PASSWORD,
    )

    assert refused.status_code in (400, 401)
    session = _session()
    try:
        assert session.query(oauth_state_models.OAuthState).count() == 0
    finally:
        session.close()


def test_the_link_round_trip_completes_through_the_callback_and_notifies(client, make_user, monkeypatch, sink):
    alice = make_user(username="alice")
    idp = _create_idp()
    state_id = _state_id(_start(client, _bearer(client, "alice"), idp, current_password=PASSWORD))
    _complete_link_in_callback(monkeypatch)

    callback = _callback(client, state_id)

    assert callback.status_code == 302
    assert parse_qs(urlsplit(callback.headers["location"]).query)["idp_link"] == ["success"]
    assert _is_linked(alice.id, idp)
    jafaal_ports.wait_for_pending_events(5.0)
    linked = [e for e in sink.events if isinstance(e, jafaal.IdpAccountLinked)]
    assert [(e.user_id, e.idp_slug) for e in linked] == [(alice.id, "oidc")]


def _complete_link_in_callback(monkeypatch):
    """Stand in for the provider round trip: the callback links ``provider-subject``."""

    async def complete(idp_row, code, state, request, password_hasher, db, oauth_state):
        identity = idp_service._CallbackIdentity(subject="provider-subject", userinfo={}, token_response={})
        return idp_service.idp_service._complete_link_callback(idp_row, oauth_state.user_id, identity, db)

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", complete)


# --------------------------------------------------------------------------- #
# Unlink
# --------------------------------------------------------------------------- #


@pytest.fixture
def revoked(monkeypatch):
    """Record upstream revocations instead of calling a provider."""
    calls = []

    async def fake_revoke(user_id, idp_id, db):
        calls.append((user_id, idp_id))
        return True

    monkeypatch.setattr(idp_service.idp_service, "revoke_idp_token", fake_revoke)
    return calls


def _unlink(client, headers, idp_id, **body):
    return client.post(f"{PROFILE}/idp/{idp_id}/unlink", json=body, headers=headers)


def test_unlink_requires_step_up(client, make_user, revoked):
    alice = make_user(username="alice")
    idp = _create_idp()
    _link(alice.id, idp)
    headers = _bearer(client, "alice")

    assert _unlink(client, headers, idp).status_code == 401
    assert _unlink(client, headers, idp, current_password="wrong-password").status_code == 401
    assert _is_linked(alice.id, idp)
    assert revoked == []


def test_unlink_with_step_up_removes_the_link_revokes_upstream_and_notifies(client, make_user, revoked, sink):
    alice = make_user(username="alice")
    idp = _create_idp()
    _link(alice.id, idp)

    response = _unlink(client, _bearer(client, "alice"), idp, current_password=PASSWORD)

    assert response.status_code == 204
    assert not _is_linked(alice.id, idp)
    assert revoked == [(alice.id, idp)]
    jafaal_ports.wait_for_pending_events(5.0)
    unlinked = [e for e in sink.events if isinstance(e, jafaal.IdpAccountUnlinked)]
    assert [(e.user_id, e.idp_slug, e.by_admin) for e in unlinked] == [(alice.id, "oidc", False)]


def test_unlinking_a_provider_that_is_not_linked_is_a_404(client, make_user, revoked):
    make_user(username="alice")
    assert _unlink(client, _bearer(client, "alice"), _create_idp(), current_password=PASSWORD).status_code == 404


def test_the_last_sign_in_method_cannot_be_unlinked(client, make_user, revoked):
    sso_only = make_user(username="sso", password=None)
    idp = _create_idp()
    _link(sso_only.id, idp)
    headers = {"Authorization": f"Bearer {_sso_token(sso_only)}"}

    grant_step_up_reauth(sso_only.id, idp_id=idp, ttl_seconds=120)
    refused = _unlink(client, headers, idp)

    assert refused.status_code == 400
    assert refused.json()["code"] == "last_sign_in_method"
    assert _is_linked(sso_only.id, idp)
    assert revoked == []


def test_a_second_link_makes_the_first_removable(client, make_user, revoked):
    sso_only = make_user(username="sso", password=None)
    first, second = _create_idp("one"), _create_idp("two")
    _link(sso_only.id, first)
    _link(sso_only.id, second)
    headers = {"Authorization": f"Bearer {_sso_token(sso_only)}"}

    grant_step_up_reauth(sso_only.id, idp_id=first, ttl_seconds=120)
    assert _unlink(client, headers, first).status_code == 204


def _sso_token(user):
    """An access token for an account that has no password to log in with."""
    from jafaal._internal.token_manager import TokenType, get_token_manager

    _, token = get_token_manager().create_token(
        "sid-sso", user, TokenType.ACCESS, client=jafaal.get_settings().oauth_client(NATIVE_CLIENT_ID)
    )
    return token


# --------------------------------------------------------------------------- #
# Administrator routes
# --------------------------------------------------------------------------- #


def test_an_administrator_lists_and_unlinks_another_users_providers(client, make_user, revoked, sink):
    make_user(username="admin", is_superuser=True)
    alice = make_user(username="alice")
    idp = _create_idp()
    _link(alice.id, idp)
    admin = _bearer(client, "admin")

    listing = client.get(f"{USERS}/{alice.id}/identity-providers", headers=admin)
    assert [link["idp_slug"] for link in listing.json()] == ["oidc"]

    removed = client.delete(f"{USERS}/{alice.id}/identity-providers/{idp}", headers=admin)
    assert removed.status_code == 204
    assert not _is_linked(alice.id, idp)
    assert revoked == [(alice.id, idp)]
    jafaal_ports.wait_for_pending_events(5.0)
    unlinked = [e for e in sink.events if isinstance(e, jafaal.IdpAccountUnlinked)]
    assert [e.by_admin for e in unlinked] == [True]


def test_a_regular_user_cannot_reach_another_users_links(client, make_user, revoked):
    make_user(username="mallory")
    alice = make_user(username="alice")
    idp = _create_idp()
    _link(alice.id, idp)
    mallory = _bearer(client, "mallory")

    assert client.get(f"{USERS}/{alice.id}/identity-providers", headers=mallory).status_code == 403
    assert client.delete(f"{USERS}/{alice.id}/identity-providers/{idp}", headers=mallory).status_code == 403
    assert _is_linked(alice.id, idp)


def test_a_regular_user_may_read_their_own_links_here_but_not_delete(client, make_user, revoked):
    alice = make_user(username="alice")
    idp = _create_idp()
    _link(alice.id, idp)
    headers = _bearer(client, "alice")

    assert client.get(f"{USERS}/{alice.id}/identity-providers", headers=headers).status_code == 200
    # Deleting needs `identity_providers:write`, an administrator scope; a user
    # unlinks their own through the step-up-gated route instead.
    assert client.delete(f"{USERS}/{alice.id}/identity-providers/{idp}", headers=headers).status_code == 403


def test_the_administrator_routes_need_authentication(client, make_user):
    alice = make_user(username="alice")
    assert client.get(f"{USERS}/{alice.id}/identity-providers").status_code == 401
    assert client.delete(f"{USERS}/{alice.id}/identity-providers/1").status_code == 401


def test_an_administrator_needs_force_to_remove_the_last_sign_in_method(client, make_user, revoked):
    make_user(username="admin", is_superuser=True)
    sso_only = make_user(username="sso", password=None)
    idp = _create_idp()
    _link(sso_only.id, idp)
    admin = _bearer(client, "admin")
    url = f"{USERS}/{sso_only.id}/identity-providers/{idp}"

    refused = client.delete(url, headers=admin)
    assert refused.status_code == 400
    assert refused.json()["code"] == "last_sign_in_method"
    assert _is_linked(sso_only.id, idp)

    assert client.delete(url, params={"force": "true"}, headers=admin).status_code == 204
    assert not _is_linked(sso_only.id, idp)


def test_the_administrator_gets_a_404_for_a_link_that_does_not_exist(client, make_user, revoked):
    make_user(username="admin", is_superuser=True)
    alice = make_user(username="alice")
    idp = _create_idp()
    assert (
        client.delete(f"{USERS}/{alice.id}/identity-providers/{idp}", headers=_bearer(client, "admin")).status_code
        == 404
    )


# --------------------------------------------------------------------------- #
# Sinks
# --------------------------------------------------------------------------- #


def test_a_composite_sink_skips_a_sink_that_predates_the_event(caplog):
    import asyncio

    from jafaal.adapters import CompositeAuthEventSink

    class Old:
        pass

    new = LinkEventSink()
    event = jafaal.IdpAccountUnlinked(user_id=1, username="a", idp_name="IdP", idp_slug="idp", by_admin=False)
    asyncio.run(CompositeAuthEventSink([Old(), new]).on_idp_account_unlinked(event))

    assert new.events == [event]
    assert not caplog.records


# --------------------------------------------------------------------------- #
# Browser binding (forced-linking protection)
# --------------------------------------------------------------------------- #


def _fresh_client():
    """A second browser: same app, empty cookie jar."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(jafaal.create_auth_router(app=app), prefix="/api/v1")
    return TestClient(app)


def test_a_victims_browser_cannot_finish_an_attackers_link(client, make_user, monkeypatch):
    attacker = make_user(username="attacker")
    idp = _create_idp()
    state_id = _state_id(_start(client, _bearer(client, "attacker"), idp, current_password=PASSWORD))
    _complete_link_in_callback(monkeypatch)

    refused = _callback(_fresh_client(), state_id)

    assert refused.status_code == 400
    assert not _is_linked(attacker.id, idp)
    # Refusing did not spend the state: the attacker's own browser still finishes it.
    assert _callback(client, state_id).status_code == 302
    assert _is_linked(attacker.id, idp)


def test_a_cookie_for_another_state_does_not_bind(client, make_user, monkeypatch):
    make_user(username="alice")
    idp = _create_idp()
    headers = _bearer(client, "alice")
    first = _state_id(_start(client, headers, idp, current_password=PASSWORD))
    second = _state_id(_start(client, headers, idp, current_password=PASSWORD))
    _complete_link_in_callback(monkeypatch)

    # The jar now holds the second state's cookie.
    assert _callback(client, first).status_code == 400
    assert _callback(client, second).status_code == 302


def test_the_binding_cookie_is_lax_and_http_only(client, make_user):
    make_user(username="alice")
    idp = _create_idp()

    cookie = _start(client, _bearer(client, "alice"), idp, current_password=PASSWORD).headers["set-cookie"].lower()

    assert "httponly" in cookie
    # The provider's redirect is a cross-site navigation, which a Strict cookie would not survive.
    assert "samesite=lax" in cookie
    assert "max-age=600" in cookie


def test_login_states_are_not_bound_to_a_cookie(client, make_user, monkeypatch):
    make_user(username="alice")
    idp = _create_idp()
    session = _session()
    try:
        with jafaal_orm.unit_of_work(session):
            oauth_state_crud.create_oauth_state(
                db=session,
                state_id="login-state",
                idp_id=idp,
                nonce="n",
                ip_address=None,
                client_id=NATIVE_CLIENT_ID,
                redirect_uri=NATIVE_REDIRECT_URI,
            )
    finally:
        session.close()

    async def refuse(*args, **kwargs):
        raise jafaal.InvalidRequestError("reached the service")

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", refuse)

    # Past the binding check, so the failure comes from the service rather than the state gate.
    location = _callback(_fresh_client(), "login-state").headers["location"]
    assert parse_qs(urlsplit(location).query)["error_description"] == ["reached the service"]


def test_binding_can_be_switched_off_for_clients_that_cannot_hold_a_cookie(client, make_user, monkeypatch):
    alice = make_user(username="alice")
    idp = _create_idp()
    original = jafaal.get_settings()
    from conftest import replace_settings

    jafaal.configure(replace_settings(original, idp_link_browser_binding=False))
    try:
        started = _start(client, _bearer(client, "alice"), idp, current_password=PASSWORD)
        assert "set-cookie" not in started.headers
        _complete_link_in_callback(monkeypatch)
        assert _callback(_fresh_client(), _state_id(started)).status_code == 302
        assert _is_linked(alice.id, idp)
    finally:
        jafaal.configure(original)
