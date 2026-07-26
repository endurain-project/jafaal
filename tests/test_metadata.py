"""Tests for the RFC 8414 authorization-server metadata document."""

from __future__ import annotations

import dataclasses

import pytest

import jafaal
import jafaal.metadata as metadata
import jafaal.scopes as jafaal_scopes

METADATA_URL = "/api/v1/.well-known/oauth-authorization-server"


@pytest.fixture
def doc(client):
    """The served metadata document."""
    response = client.get(METADATA_URL)
    assert response.status_code == 200
    return response.json()


def test_metadata_is_served_beside_jwks(client, doc):
    # The document must point at the JWKS route that is actually mounted, not a
    # guessed one — a wrong ``jwks_uri`` silently breaks every verifier.
    assert doc["jwks_uri"] == "https://app.test/api/v1/.well-known/jwks.json"
    assert client.get("/api/v1/.well-known/jwks.json").status_code == 200


def test_issuer_matches_the_iss_claim_jafaal_mints(doc):
    # RFC 8414 §2: the advertised issuer is what a verifier will compare ``iss``
    # against, so drift here rejects every token.
    assert doc["issuer"] == jafaal.get_settings().resolved_issuer


def test_advertised_endpoints_exist(client, doc):
    for key in ("token_endpoint", "introspection_endpoint", "revocation_endpoint"):
        path = doc[key].removeprefix("https://app.test")
        # 405 would mean the path resolves but rejects GET; 404 means the URL is
        # a lie. Anything but 404 proves the route is mounted where advertised.
        assert client.get(path).status_code != 404, key


def test_endpoint_urls_follow_custom_router_prefixes():
    prefixes = jafaal.RouterPrefixes(auth="/identity")
    document = metadata.get_authorization_server_metadata(
        api_root="https://app.test/api/v2",
        auth_prefix=prefixes.auth,
    )
    assert document["token_endpoint"] == "https://app.test/api/v2/identity/refresh"
    assert document["revocation_endpoint"] == "https://app.test/api/v2/identity/revoke"
    assert document["jwks_uri"] == "https://app.test/api/v2/.well-known/jwks.json"


def test_client_auth_is_declared_so_the_spec_default_does_not_apply(doc):
    # Omitting this member means ``client_secret_basic`` per RFC 8414 §2, which
    # would send clients hunting for a secret JAFAAL never issues.
    assert doc["token_endpoint_auth_methods_supported"] == ["none"]
    assert doc["grant_types_supported"] == ["refresh_token"]
    # RFC 8414 §2 requires ``authorization_endpoint`` only when a supported grant
    # uses one; ``refresh_token`` does not, so omitting it stays conformant.
    assert "authorization_endpoint" not in doc


def test_password_grant_is_never_advertised(doc):
    # The resource-owner password-credentials grant is removed in OAuth 2.1 and
    # discouraged by RFC 9700 §2.4. JAFAAL authenticates first-party users
    # directly, which is a different thing — advertising it as an OAuth grant
    # would invite third-party clients to send it user passwords.
    assert "password" not in doc["grant_types_supported"]


def test_login_endpoint_is_not_advertised_as_a_token_endpoint(doc):
    # /auth/login returns JAFAAL's own session tokens (and may return a 202 MFA
    # challenge). Advertising it would tell a stock OAuth client to treat it as
    # an RFC 6749 token endpoint, which it is not.
    assert not doc["token_endpoint"].endswith("/login")
    assert "/login" not in " ".join(value for value in doc.values() if isinstance(value, str))


def test_scopes_supported_tracks_the_installed_catalog(client):
    jafaal.configure_scopes(
        jafaal_scopes.DEFAULT_SCOPE_CATALOG.extend(
            regular=("activities:read",),
            admin=("activities:read", "activities:write"),
            descriptions={"activities:read": "Read activities", "activities:write": "Write activities"},
        )
    )
    scopes = client.get(METADATA_URL).json()["scopes_supported"]
    assert "activities:write" in scopes
    assert scopes == sorted(scopes)


def test_origin_ignores_a_forged_host_header(client):
    # The document is built from the configured ``base_url``, so a spoofed Host
    # cannot make JAFAAL advertise an attacker-controlled token endpoint.
    document = client.get(METADATA_URL, headers={"Host": "evil.test"}).json()
    assert document["token_endpoint"].startswith("https://app.test/")


def test_origin_falls_back_to_the_request_when_base_url_is_unset(client):
    original = jafaal.get_settings()
    jafaal.configure(dataclasses.replace(original, base_url="", issuer="https://issuer.test"))
    try:
        document = client.get(METADATA_URL).json()
        assert document["token_endpoint"] == "http://testserver/api/v1/auth/refresh"
    finally:
        jafaal.configure(original)


def test_document_is_cacheable(client):
    response = client.get(METADATA_URL)
    assert response.headers["cache-control"] == "public, max-age=300"
