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
from urllib.parse import parse_qs, urlencode, urlsplit

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

#: A second *registered* client, so "the code belongs to someone else" can be
#: tested without also tripping the unregistered-client check.
SECOND_CLIENT_ID = "com.other.app"


@pytest.fixture(autouse=True)
def _registered_client():
    """Register two public clients for the duration of each test."""
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
                jafaal.OAuthClient(
                    client_id=SECOND_CLIENT_ID,
                    redirect_uris=("com.other.app://oauth/callback",),
                    name="Other App",
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
        }

    monkeypatch.setattr(idp_service.idp_service, "handle_callback", _handle_callback)


def _complete_authorization(client, monkeypatch, make_user, *, state="opaque-state", scope=None, superuser=False):
    """Run /authorize → callback and return ``(verifier, code, echoed_state)``."""
    user = make_user(username="ada", is_superuser=superuser)
    _create_idp()
    _stub_callback(monkeypatch, user)

    verifier, challenge = _pkce()
    extra = {"scope": scope} if scope is not None else {}
    started = _authorize(client, challenge=challenge, state=state, **extra)
    assert started.status_code == 302
    upstream_state = parse_qs(urlsplit(started.headers["location"]).query)["state"][0]

    landed = client.get(
        f"{CALLBACK}/oidc",
        params={"code": "upstream-code", "state": upstream_state},
        follow_redirects=False,
    )
    assert landed.status_code == 302
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
    assert body["token_type"] == "Bearer"
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
        headers={"Authorization": f"Bearer {access}"},
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

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    assert "location" not in response.headers


def test_unregistered_redirect_uri_is_refused(client, make_user):
    _create_idp()
    _, challenge = _pkce()
    response = _authorize(client, challenge=challenge, redirect_uri="com.attacker.app://steal")

    assert response.status_code == 400
    assert "location" not in response.headers


def test_missing_client_or_redirect_is_never_redirected(client):
    _, challenge = _pkce()
    complete = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "opaque-state",
    }

    for invalid in ("client_id", "redirect_uri"):
        for params in (
            {name: value for name, value in complete.items() if name != invalid},
            {**complete, invalid: ""},
        ):
            response = client.get(AUTHORIZE, params=params, follow_redirects=False)

            assert response.status_code == 400, invalid
            assert set(response.json()) == {"error", "error_description"}, invalid
            assert response.json()["error"] == "invalid_request", invalid
            assert invalid in response.json()["error_description"], invalid
            assert "location" not in response.headers, invalid


def test_missing_authorization_fields_use_the_validated_redirect(client):
    _, challenge = _pkce()
    complete = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "opaque-state",
    }

    for invalid in ("response_type", "code_challenge", "code_challenge_method"):
        for params in (
            {name: value for name, value in complete.items() if name != invalid},
            {**complete, invalid: ""},
        ):
            response = client.get(AUTHORIZE, params=params, follow_redirects=False)

            assert response.status_code == 302, invalid
            query = parse_qs(urlsplit(response.headers["location"]).query)
            assert query["error"] == ["invalid_request"], invalid
            assert query["error_description"], invalid
            assert query["state"] == ["opaque-state"], invalid
            assert query["iss"] == [jafaal.get_settings().resolved_issuer], invalid


def test_duplicate_client_or_redirect_is_never_redirected(client):
    _, challenge = _pkce()
    complete = [
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", "opaque-state"),
    ]

    for name, second_value in (
        ("client_id", SECOND_CLIENT_ID),
        ("redirect_uri", "com.attacker.app://steal"),
    ):
        response = client.get(
            f"{AUTHORIZE}?{urlencode([*complete, (name, second_value)])}",
            follow_redirects=False,
        )

        assert response.status_code == 400, name
        assert response.json()["error"] == "invalid_request", name
        assert name in response.json()["error_description"], name
        assert "location" not in response.headers, name


def test_duplicate_authorization_parameters_use_the_validated_redirect(client):
    _, challenge = _pkce()
    complete = [
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", "opaque-state"),
        ("scope", "profile"),
        ("idp", "oidc"),
    ]

    for name in ("response_type", "code_challenge", "code_challenge_method", "state", "scope", "idp"):
        original = next(value for parameter, value in complete if parameter == name)
        response = client.get(
            f"{AUTHORIZE}?{urlencode([*complete, (name, original)])}",
            follow_redirects=False,
        )

        assert response.status_code == 302, name
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["error"] == ["invalid_request"], name
        assert query["iss"] == [jafaal.get_settings().resolved_issuer], name
        if name == "state":
            assert "state" not in query
        else:
            assert query["state"] == ["opaque-state"], name


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
    # Reported by redirect: the client and redirect URI already validated, so
    # RFC 6749 §4.1.2.1 requires the error to reach the waiting client.
    _create_idp()
    _, challenge = _pkce()
    for response_type in ("token", "id_token", "code token", "code id_token"):
        response = _authorize(client, challenge=challenge, response_type=response_type)
        assert response.status_code == 302, response_type
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["error"] == ["unsupported_response_type"], response_type
        assert query["state"] == ["opaque-state"], response_type


def test_pkce_is_mandatory_and_plain_is_refused(client):
    _create_idp()
    _, challenge = _pkce()

    plain = _authorize(client, challenge=challenge, code_challenge_method="plain")
    assert plain.status_code == 302
    assert parse_qs(urlsplit(plain.headers["location"]).query)["error"] == ["invalid_request"]

    short = _authorize(client, challenge="short")
    assert short.status_code == 302
    assert parse_qs(urlsplit(short.headers["location"]).query)["error"] == ["invalid_request"]


def test_an_unknown_idp_is_reported_by_redirect(client):
    # There is no OAuth error code for "your idp parameter is wrong", but the
    # client still has to learn the flow failed rather than hang on its
    # callback listener.
    _create_idp()
    _, challenge = _pkce()
    response = _authorize(client, challenge=challenge, idp="does-not-exist")

    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["error"] == ["invalid_request"]
    assert query["state"] == ["opaque-state"]


def test_a_scope_outside_the_catalog_is_refused(client):
    _create_idp()
    _, challenge = _pkce()
    response = _authorize(client, challenge=challenge, scope="not:a:real:scope")

    assert response.status_code == 302
    assert parse_qs(urlsplit(response.headers["location"]).query)["error"] == ["invalid_scope"]


def test_requested_scope_survives_the_browser_round_trip(client, monkeypatch, make_user):
    # The authorization request and the token exchange are separated by a
    # redirect to the IdP and back, so a scope that is not parked on the state
    # row is a scope that silently reverts to "everything" at redemption.
    verifier, code, _ = _complete_authorization(
        client, monkeypatch, make_user, scope=jafaal.scopes.PROFILE, superuser=True
    )
    body = _redeem(client, code=code, verifier=verifier).json()

    assert body["scope"] == jafaal.scopes.PROFILE


def test_an_omitted_scope_still_grants_the_full_set(client, monkeypatch, make_user):
    verifier, code, _ = _complete_authorization(client, monkeypatch, make_user, superuser=True)
    body = _redeem(client, code=code, verifier=verifier).json()

    assert set(body["scope"].split()) == set(jafaal.scopes.get_scope_catalog().admin)


# --------------------------------------------------------------------------- #
# Redemption bindings
# --------------------------------------------------------------------------- #


def test_wrong_code_verifier_is_refused(client, monkeypatch, make_user):
    _verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)
    other_verifier, _ = _pkce()

    response = _redeem(client, code=code, verifier=other_verifier)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_every_redemption_failure_returns_the_same_error(client, monkeypatch, make_user):
    """Distinguishing failures would make the token endpoint a probing oracle.

    "Unknown code", "issued to a different *registered* client", "wrong
    redirect_uri", and "wrong verifier" all answer ``invalid_grant`` with the
    same description, so an attacker learns nothing about which codes exist or
    who they belong to. (An *unregistered* client is a different case — RFC 6749
    §5.2 gives it ``invalid_client``, and it reveals only what the caller already
    told us.)
    """
    verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)
    other_verifier, _ = _pkce()

    bodies = [
        _redeem(client, code=secrets.token_urlsafe(32), verifier=verifier).json(),
        _redeem(client, code=code, verifier=verifier, client_id=SECOND_CLIENT_ID).json(),
        _redeem(client, code=code, verifier=verifier, redirect_uri=OTHER_REDIRECT_URI).json(),
        _redeem(client, code=code, verifier=other_verifier).json(),
    ]
    assert {b["error"] for b in bodies} == {"invalid_grant"}
    assert len({b["error_description"] for b in bodies}) == 1


def test_code_cannot_be_redeemed_by_another_client(client, monkeypatch, make_user):
    """A stolen code is useless to a client it was not issued to."""
    verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)

    response = _redeem(client, code=code, verifier=verifier, client_id=SECOND_CLIENT_ID)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    # And the code survives for its rightful owner — a failed probe must not
    # burn it.
    assert _redeem(client, code=code, verifier=verifier).status_code == 200


def test_an_unregistered_client_is_invalid_client_not_invalid_grant(client):
    response = _redeem(client, code="x" * 43, verifier="y" * 43, client_id="not.registered")
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


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
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"


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
        for data in (
            {name: value for name, value in complete.items() if name != omitted},
            {**complete, omitted: ""},
        ):
            response = client.post(TOKEN, data=data)
            assert response.status_code == 400, omitted
            body = response.json()
            assert set(body) == {"error", "error_description"}, omitted
            assert body["error"] == "invalid_request", omitted
            assert omitted in body["error_description"], omitted


def test_missing_grant_type_is_an_oauth_invalid_request(client):
    for data in ({}, {"grant_type": ""}):
        response = client.post(TOKEN, data=data)

        assert response.status_code == 400
        assert response.json() == {
            "error": "invalid_request",
            "error_description": "'grant_type' is required.",
        }


def test_refresh_grant_requires_a_non_empty_refresh_token(client):
    for data in (
        {"grant_type": "refresh_token"},
        {"grant_type": "refresh_token", "refresh_token": ""},
    ):
        response = client.post(TOKEN, data=data)

        assert response.status_code == 400
        assert set(response.json()) == {"error", "error_description"}
        assert response.json()["error"] == "invalid_request"
        assert "refresh_token" in response.json()["error_description"]


def test_duplicate_token_form_fields_are_invalid_requests(client):
    authorization_code = {
        "grant_type": "authorization_code",
        "code": "x" * 43,
        "code_verifier": "y" * 43,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
    }
    requests = [(authorization_code, name) for name in authorization_code] + [
        ({"grant_type": "refresh_token", "refresh_token": "not-a-token"}, "refresh_token"),
        ({"grant_type": "password", "extension": "value"}, "extension"),
    ]

    for data, repeated_name in requests:
        pairs = [*data.items(), (repeated_name, data[repeated_name])]
        response = client.post(
            TOKEN,
            content=urlencode(pairs),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        assert response.status_code == 400, repeated_name
        assert set(response.json()) == {"error", "error_description"}, repeated_name
        assert response.json()["error"] == "invalid_request", repeated_name
        assert repeated_name in response.json()["error_description"], repeated_name


def test_token_endpoint_rejects_non_form_malformed_or_non_text_input(client):
    responses = [
        client.post(TOKEN, json={"grant_type": "authorization_code"}),
        client.post(
            TOKEN,
            content=b"not-a-multipart-body",
            headers={"Content-Type": "multipart/form-data"},
        ),
        client.post(TOKEN, files={"grant_type": ("grant.txt", b"authorization_code")}),
    ]

    for response in responses:
        assert response.status_code == 400
        assert set(response.json()) == {"error", "error_description"}
        assert response.json()["error"] == "invalid_request"


def test_malformed_refresh_grant_is_an_oauth_invalid_grant(client):
    response = client.post(
        TOKEN,
        data={"grant_type": "refresh_token", "refresh_token": "not-a-jwt"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_grant",
        "error_description": "The refresh token is invalid, expired, or was revoked.",
    }


def test_token_endpoint_errors_are_not_cacheable(client):
    # RFC 6749 §5.1: token responses carry Cache-Control: no-store, so no
    # intermediary retains an authorization outcome.
    response = client.post(TOKEN, data={"grant_type": "password"})
    assert response.headers["cache-control"] == "no-store"


def test_openapi_keeps_the_manually_parsed_oauth_request_contract(client):
    document = client.get("/openapi.json").json()

    authorization = document["paths"][AUTHORIZE]["get"]
    query = {parameter["name"]: parameter for parameter in authorization["parameters"]}
    assert set(query) == {
        "response_type",
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_challenge_method",
        "idp",
        "state",
        "scope",
    }
    assert all(query[name]["required"] for name in ("response_type", "client_id", "redirect_uri"))
    assert all(query[name]["required"] for name in ("code_challenge", "code_challenge_method"))
    assert all(not query[name]["required"] for name in ("idp", "state", "scope"))

    expected_forms = {
        TOKEN: ({"grant_type"}, {"grant_type", "code", "code_verifier", "redirect_uri", "client_id", "refresh_token"}),
        "/api/v1/auth/introspect": ({"token"}, {"token", "token_type_hint"}),
        "/api/v1/auth/revoke": ({"token", "client_id"}, {"token", "client_id", "token_type_hint"}),
    }
    for path, (required, properties) in expected_forms.items():
        request_body = document["paths"][path]["post"]["requestBody"]
        schema = request_body["content"]["application/x-www-form-urlencoded"]["schema"]
        assert set(schema["required"]) == required, path
        assert set(schema["properties"]) == properties, path


def test_successful_token_responses_are_not_cacheable(client, make_user):
    """RFC 6749 §5.1 requires no-store on *any* response carrying tokens.

    The error path alone is not enough: it is the success path that hands out an
    access token (and, under body delivery, a refresh token) which a proxy,
    CDN, or browser cache could otherwise retain and serve to someone else.
    """
    make_user(username="cacheuser", password="Str0ng!Pass")

    login = client.post(
        "/api/v1/auth/login",
        data={"username": "cacheuser", "password": "Str0ng!Pass", "client_id": CLIENT_ID},
    )
    assert login.status_code == 200
    assert login.json()["access_token"]
    assert login.headers["cache-control"] == "no-store"
    assert login.headers["pragma"] == "no-cache"

    refreshed = client.post(
        "/api/v1/auth/refresh",
        headers={"Authorization": f"Bearer {login.json()['refresh_token']}"},
    )
    assert refreshed.status_code == 200
    assert refreshed.headers["cache-control"] == "no-store"
    assert refreshed.headers["pragma"] == "no-cache"


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
# One flow, no side doors
# --------------------------------------------------------------------------- #


def test_there_is_no_session_id_exchange_endpoint(client, monkeypatch, make_user):
    """The native exchange is deleted, not merely refused for code flows.

    It checked PKCE but knew nothing about ``client_id`` or ``redirect_uri``, so
    it was a second door that silently dropped two of the four bindings. A
    refusal would still be a code path to get wrong; removal is not.
    """
    import jafaal.sessions.models as sessions_models

    verifier, _code, _ = _complete_authorization(client, monkeypatch, make_user)

    with jafaal_orm.get_sessionmaker()() as session:
        pending = session.query(sessions_models.UsersSessions).all()
        session_id = pending[0].id

    response = client.post(
        f"/api/v1/public/idp/session/{session_id}/tokens",
        json={"code_verifier": verifier},
    )
    assert response.status_code == 404


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


def test_the_refreshed_token_keeps_the_original_clients_delivery_mode(client, monkeypatch, make_user):
    """The client is fixed at issuance and read from the token, not the request.

    Otherwise a caller holding a body-delivery refresh token could ask for the
    cookie shape (or vice versa) and change where the next refresh token lands.
    """
    verifier, code, _ = _complete_authorization(client, monkeypatch, make_user)
    issued = _redeem(client, code=code, verifier=verifier).json()

    refreshed = client.post(
        TOKEN,
        data={"grant_type": "refresh_token", "refresh_token": issued["refresh_token"]},
    )

    assert refreshed.json()["refresh_token"]
    assert "csrf_token" not in refreshed.json()
    assert "jafaal_refresh_token" not in refreshed.cookies


def test_unsupported_grant_type_is_rejected(client):
    response = client.post(TOKEN, data={"grant_type": "password", "username": "a", "password": "b"})
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


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

    assert landed.status_code == 302
    target = urlsplit(landed.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == REDIRECT_URI
    query = parse_qs(target.query)
    assert query["error"] == ["server_error"]
    assert query["state"] == ["round-trip"]
