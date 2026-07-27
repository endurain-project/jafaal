"""Snapshot tests pinning the exact JWT wire format JAFAAL emits.

JAFAAL publishes a JWKS so third-party resource servers can verify its access
tokens statelessly with a stock JWT library. That makes the claim names, their
JSON types, and the JOSE header part of the public contract — a change to any of
them silently breaks every resource server. These tests pin that contract so
such a change can never be accidental.
"""

from __future__ import annotations

import base64
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from conftest import replace_settings
from joserfc import jwt as joserfc_jwt
from joserfc.errors import MissingClaimError
from joserfc.jwk import OctKey

import jafaal.settings as settings_mod
from jafaal._internal.token_manager import (
    TokenManager,
    TokenType,
    get_token_manager,
    scopes_from_claims,
    token_use,
)
from jafaal.exceptions import InvalidTokenError


def _user(user_id=7, *, is_superuser=False):
    return SimpleNamespace(id=user_id, is_superuser=is_superuser)


def _b64url_json(segment: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def _header(token: str) -> dict:
    return _b64url_json(token.split(".")[0])


def _payload(token: str) -> dict:
    return _b64url_json(token.split(".")[1])


@contextmanager
def _settings(**overrides):
    """Temporarily reconfigure JAFAAL, yielding a token manager built from it."""
    original = settings_mod.get_settings()
    settings_mod.configure(replace_settings(original, **overrides))
    try:
        yield get_token_manager()
    finally:
        settings_mod.configure(original)


def test_access_token_header_declares_the_rfc9068_media_type():
    _, token = get_token_manager().create_token("sid-1", _user(), TokenType.ACCESS)
    # RFC 9068 §2.1: the media type lets a resource server reject a token minted
    # for a different purpose before parsing any claim.
    assert _header(token)["typ"] == "at+jwt"
    assert _header(token)["alg"] == "HS256"


def test_refresh_token_header_declares_its_own_media_type():
    _, token = get_token_manager().create_token("sid-1", _user(), TokenType.REFRESH)
    assert _header(token)["typ"] == "rt+jwt"


def test_access_token_claim_names_are_exactly_the_documented_set():
    _, token = get_token_manager().create_token("sid-1", _user(), TokenType.ACCESS)
    assert set(_payload(token)) == {
        "sid",
        "iss",
        "aud",
        "sub",
        "scope",
        "client_id",
        "iat",
        "nbf",
        "exp",
        "jti",
        "token_use",
    }


def test_access_token_claim_json_types_are_standards_conformant():
    _, token = get_token_manager().create_token("sid-1", _user(7), TokenType.ACCESS)
    claims = _payload(token)

    # RFC 7519 §4.1.2: ``sub`` is StringOrURI — a string, never a JSON number.
    assert isinstance(claims["sub"], str)
    assert claims["sub"] == "7"
    # RFC 6749 §3.3 / RFC 9068 §2.2: ``scope`` is a space-delimited string.
    assert isinstance(claims["scope"], str)
    assert " " in claims["scope"]
    # RFC 9068 §2.2: ``client_id`` is required.
    assert isinstance(claims["client_id"], str)
    # Time claims are NumericDate (seconds since epoch).
    for claim in ("iat", "nbf", "exp"):
        assert isinstance(claims[claim], int)
    # ``jti`` and ``sid`` are strings.
    assert isinstance(claims["jti"], str)
    assert isinstance(claims["sid"], str)


def test_the_colliding_typ_payload_claim_is_never_emitted():
    # ``typ`` is a registered JOSE *header* parameter, so the payload must not
    # also carry a claim of that name.
    _, token = get_token_manager().create_token("sid-1", _user(), TokenType.ACCESS)
    assert "typ" not in _payload(token)


def test_nbf_is_backdated_so_a_slightly_slow_verifier_still_accepts():
    # A resource server runs on someone else's clock and has no access to this
    # deployment's ``leeway_seconds``. With ``nbf == iat`` a sub-second
    # difference rejects a token minted moments earlier; RFC 7519 §4.1.5
    # anticipates the small leeway, applied here at issuance so the token is
    # portable without asking every verifier to configure one.
    _, token = get_token_manager().create_token("sid-1", _user(), TokenType.ACCESS)
    claims = _payload(token)
    assert claims["nbf"] < claims["iat"]
    # Bounded: this absorbs skew, it must not extend the credential's life.
    assert claims["iat"] - claims["nbf"] <= 60
    assert claims["nbf"] < claims["exp"]


def test_client_id_defaults_to_the_audience_and_can_be_overridden():
    settings = settings_mod.get_settings()
    _, token = get_token_manager().create_token("sid-1", _user(), TokenType.ACCESS)
    assert _payload(token)["client_id"] == settings.resolved_audience

    with _settings(client_id="my-spa") as tm:
        _, explicit = tm.create_token("sid-1", _user(), TokenType.ACCESS)
        assert _payload(explicit)["client_id"] == "my-spa"


def test_a_stock_jwt_library_can_read_the_scope_claim():
    # The interop check that motivated the profile: splitting on whitespace is
    # what every OAuth resource server does with ``scope``.
    _, token = get_token_manager().create_token("sid-1", _user(is_superuser=True), TokenType.ACCESS)
    scopes = _payload(token)["scope"].split()
    assert "profile" in scopes
    assert "users:write" in scopes


# --------------------------------------------------------------------------- #
# Claim readers
# --------------------------------------------------------------------------- #


def test_claim_readers_round_trip_a_minted_token():
    tm = get_token_manager()
    _, token = tm.create_token("sid-1", _user(is_superuser=True), TokenType.ACCESS)
    claims = tm.decode_token(token).claims

    assert token_use(claims) == "access"
    scopes = scopes_from_claims(claims)
    assert scopes is not None and "users:write" in scopes


def test_scopes_from_claims_rejects_malformed_shapes():
    assert scopes_from_claims({}) is None
    assert scopes_from_claims({"scope": 42}) is None
    # A JSON array is not the RFC 6749 §3.3 form and is not accepted.
    assert scopes_from_claims({"scope": ["a", "b"]}) is None
    assert scopes_from_claims({"scope": "a b"}) == ["a", "b"]


def test_token_use_rejects_a_non_string_claim():
    assert token_use({}) is None
    assert token_use({"token_use": 7}) is None
    assert token_use({"token_use": "access"}) == "access"


def test_the_legacy_typ_claim_is_not_honoured():
    # A token carrying only the pre-1.0 ``typ`` claim names no usable token use,
    # so it cannot be presented as either an access or a refresh token.
    assert token_use({"typ": "access"}) is None


def test_token_type_confusion_is_rejected():
    tm = get_token_manager()
    _, refresh = tm.create_token("sid-1", _user(), TokenType.REFRESH)
    # A refresh token must never be accepted where an access token is due.
    with pytest.raises(InvalidTokenError):
        tm.validate_token_expiration(refresh, TokenType.ACCESS)


def test_a_token_with_no_token_use_claim_is_rejected():
    tm = get_token_manager()
    _, token = tm.create_token("sid-1", _user(), TokenType.ACCESS)
    claims = tm.decode_token(token).claims
    claims.pop("token_use")

    stripped = joserfc_jwt.encode(
        {"alg": "HS256"},
        claims,
        OctKey.import_key(settings_mod.get_settings().secrets.secret_key),
    )
    with pytest.raises(InvalidTokenError) as excinfo:
        tm.validate_token_expiration(stripped, TokenType.ACCESS)
    # The MissingClaimError cause is load-bearing: the refresh dependency uses
    # it to detect an unusable cookie and clear it rather than looping.
    assert isinstance(excinfo.value.__cause__, MissingClaimError)


def test_direct_token_manager_construction_emits_the_rfc9068_shape():
    tm = TokenManager("k" * 32, "HS256", issuer="i", audience="a")
    _, token = tm.create_token("sid", _user(), TokenType.ACCESS)
    assert _header(token)["typ"] == "at+jwt"
    assert isinstance(_payload(token)["scope"], str)
