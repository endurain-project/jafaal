"""HTTP tests for the identity-provider link routes (owner and administrator)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import LIMITED_CLIENT_ID, NATIVE_CLIENT_ID, NATIVE_REDIRECT_URI, RecordingEventSink

import jafaal
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.link_tokens.models as link_token_models
import jafaal.identity_providers.links.crud as links_crud
import jafaal.identity_providers.schema as idp_schema
import jafaal.identity_providers.service as idp_service
import jafaal.oauth_state.crud as oauth_state_crud
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


def _mint(client, headers, idp_id, **body):
    return client.post(f"{PROFILE}/idp/{idp_id}/link/token", json=body, headers=headers)


def _claim(client, token, idp_id, **overrides):
    params = {"token": token, "client_id": NATIVE_CLIENT_ID, "redirect_uri": NATIVE_REDIRECT_URI, "state": "s1"}
    params.update(overrides)
    return client.get(f"{PROFILE}/idp/{idp_id}/link", params=params, follow_redirects=False)


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
# Link token handoff
# --------------------------------------------------------------------------- #


def test_minting_a_link_token_requires_step_up(client, make_user):
    make_user(username="alice")
    idp = _create_idp()
    headers = _bearer(client, "alice")

    assert _mint(client, headers, idp).status_code == 401
    assert _mint(client, headers, idp, current_password="wrong-password").status_code == 401
    ok = _mint(client, headers, idp, current_password=PASSWORD)
    assert ok.status_code == 200
    assert ok.json()["token"]
    assert "no-store" in ok.headers["cache-control"]


def test_minting_refuses_a_missing_disabled_or_already_linked_provider(client, make_user):
    alice = make_user(username="alice")
    headers = _bearer(client, "alice")
    disabled, linked = _create_idp("off", enabled=False), _create_idp("on")
    _link(alice.id, linked)

    assert _mint(client, headers, 9999, current_password=PASSWORD).status_code == 404
    assert _mint(client, headers, disabled, current_password=PASSWORD).status_code == 404
    assert _mint(client, headers, linked, current_password=PASSWORD).status_code == 409


def test_a_link_token_redirects_to_the_provider_and_binds_the_user(client, make_user):
    alice = make_user(username="alice")
    idp = _create_idp()
    token = _mint(client, _bearer(client, "alice"), idp, current_password=PASSWORD).json()["token"]

    # The browser navigation carries no bearer at all: the token is the credential.
    response = _claim(client, token, idp)

    assert response.status_code == 302
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    location = urlsplit(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == "https://oidc.example/authorize"
    state_id = parse_qs(location.query)["state"][0]
    session = _session()
    try:
        state = oauth_state_crud.get_oauth_state_by_id(state_id, session)
        assert (state.purpose, state.user_id, state.idp_id) == ("link", alice.id, idp)
        assert (state.client_id, state.redirect_uri, state.client_state) == (
            NATIVE_CLIENT_ID,
            NATIVE_REDIRECT_URI,
            "s1",
        )
    finally:
        session.close()


def test_a_link_token_is_single_use(client, make_user):
    make_user(username="alice")
    idp = _create_idp()
    token = _mint(client, _bearer(client, "alice"), idp, current_password=PASSWORD).json()["token"]

    assert _claim(client, token, idp).status_code == 302
    assert _claim(client, token, idp).status_code in (400, 401)


def test_an_expired_link_token_is_refused(client, make_user):
    make_user(username="alice")
    idp = _create_idp()
    token = _mint(client, _bearer(client, "alice"), idp, current_password=PASSWORD).json()["token"]
    session = _session()
    try:
        with jafaal_orm.unit_of_work(session):
            for row in session.query(link_token_models.IdpLinkToken).all():
                row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    finally:
        session.close()

    assert _claim(client, token, idp).status_code == 401


def test_a_link_token_is_only_good_for_the_provider_it_was_minted_for(client, make_user):
    make_user(username="alice")
    first, second = _create_idp("one"), _create_idp("two")
    token = _mint(client, _bearer(client, "alice"), first, current_password=PASSWORD).json()["token"]

    assert _claim(client, token, second).status_code == 401
    assert _claim(client, token, first).status_code == 302  # the refusal did not burn it


def test_a_guessed_token_is_refused(client, make_user):
    make_user(username="alice")
    assert _claim(client, "not-a-real-token", _create_idp()).status_code == 401


def test_an_unregistered_redirect_is_refused_before_the_token_is_spent(client, make_user):
    make_user(username="alice")
    idp = _create_idp()
    token = _mint(client, _bearer(client, "alice"), idp, current_password=PASSWORD).json()["token"]

    assert _claim(client, token, idp, redirect_uri="https://attacker.example/cb").status_code in (400, 401)
    assert _claim(client, token, idp).status_code == 302


def test_a_token_minted_by_one_user_links_that_user_whoever_navigates(client, make_user):
    alice, bob = make_user(username="alice"), make_user(username="bob")
    idp = _create_idp()
    token = _mint(client, _bearer(client, "alice"), idp, current_password=PASSWORD).json()["token"]

    # Even carrying bob's bearer, the navigation links the token's owner.
    response = client.get(
        f"{PROFILE}/idp/{idp}/link",
        params={"token": token, "client_id": NATIVE_CLIENT_ID, "redirect_uri": NATIVE_REDIRECT_URI},
        headers=_bearer(client, "bob"),
        follow_redirects=False,
    )
    state_id = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
    session = _session()
    try:
        assert oauth_state_crud.get_oauth_state_by_id(state_id, session).user_id == alice.id
    finally:
        session.close()
    assert bob.id != alice.id


def test_the_link_round_trip_completes_through_the_callback_and_notifies(client, make_user, monkeypatch, sink):
    alice = make_user(username="alice")
    idp = _create_idp()
    token = _mint(client, _bearer(client, "alice"), idp, current_password=PASSWORD).json()["token"]
    location = _claim(client, token, idp).headers["location"]
    state_id = parse_qs(urlsplit(location).query)["state"][0]

    async def complete(idp_row, code, state, request, password_hasher, db, oauth_state):
        identity = idp_service._CallbackIdentity(subject="provider-subject", userinfo={}, token_response={})
        return idp_service.idp_service._complete_link_callback(idp_row, oauth_state.user_id, identity, db)

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", complete)
    callback = client.get(f"{PUBLIC_IDP}/callback/oidc?code=abc&state={state_id}", follow_redirects=False)

    assert callback.status_code == 302
    assert parse_qs(urlsplit(callback.headers["location"]).query)["idp_link"] == ["success"]
    assert _is_linked(alice.id, idp)
    jafaal_ports.wait_for_pending_events(5.0)
    linked = [e for e in sink.events if isinstance(e, jafaal.IdpAccountLinked)]
    assert [(e.user_id, e.idp_slug) for e in linked] == [(alice.id, "oidc")]


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
