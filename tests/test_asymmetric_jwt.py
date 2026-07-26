"""Tests for asymmetric JWT signing (RS256/ES256) and the JWKS endpoint.

Exercises the capability unlock: signing with a private key, publishing the
public key(s) via JWKS, and a resource server verifying JAFAAL's access tokens
statelessly with the public key only (no shared secret), plus key rotation.
"""

from __future__ import annotations

import base64
import dataclasses
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from joserfc import jwt
from joserfc.jwk import ECKey, KeySet, RSAKey

import jafaal
import jafaal.exceptions as exc
from jafaal._internal.token_manager import TokenType, get_token_manager


def _user(user_id=7, is_superuser=False):
    return SimpleNamespace(id=user_id, is_superuser=is_superuser)


def _key_class(alg):
    return RSAKey if alg[:2] in ("RS", "PS") else ECKey


def _keypair(alg):
    key = RSAKey.generate_key(2048) if alg[:2] in ("RS", "PS") else ECKey.generate_key("P-256")
    return key, key.as_pem(private=True).decode()


@contextmanager
def _asymmetric(alg, private_key, **extra):
    original = jafaal.get_settings()
    jafaal.configure(dataclasses.replace(original, algorithm=alg, private_key=private_key, **extra))
    try:
        yield
    finally:
        jafaal.configure(original)


def _header(token):
    head = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_sign_validate_roundtrip_with_kid(alg):
    key, pem = _keypair(alg)
    with _asymmetric(alg, pem):
        tm = get_token_manager()
        _exp, token = tm.create_token("sid-1", _user(), TokenType.ACCESS)
        tm.validate_token_expiration(token, TokenType.ACCESS)  # no raise
        assert tm.get_token_claim(token, "sub") == "7"
        header = _header(token)
        assert header["alg"] == alg
        assert header["kid"] == key.thumbprint()  # RFC 7638 thumbprint


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_resource_server_verifies_with_public_key_only(alg):
    _key, pem = _keypair(alg)
    with _asymmetric(alg, pem):
        token = get_token_manager().create_token("sid-1", _user(), TokenType.ACCESS)[1]
        jwks = jafaal.get_jwks()

    assert len(jwks["keys"]) == 1
    entry = jwks["keys"][0]
    assert entry["use"] == "sig" and entry["alg"] == alg
    assert "d" not in entry and "p" not in entry  # no private component published

    # A resource server rebuilds the key set from JWKS and verifies statelessly.
    keyset = KeySet([_key_class(alg).import_key(k) for k in jwks["keys"]])
    claims = jwt.decode(token, keyset, algorithms=[alg]).claims
    assert claims["sub"] == "7"


def test_hs256_jwks_is_empty():
    # The default symmetric mode has no public key to publish.
    assert jafaal.get_jwks() == {"keys": []}


def test_key_rotation_publishes_both_and_verifies_old_tokens():
    old_key, old_pem = _keypair("RS256")
    new_key, new_pem = _keypair("RS256")

    with _asymmetric("RS256", old_pem):
        old_token = get_token_manager().create_token("s", _user(), TokenType.ACCESS)[1]

    # Rotate: new key signs; old key stays as a verify-only fallback in the JWKS.
    with _asymmetric("RS256", new_pem, private_key_fallbacks=(old_pem,)):
        tm = get_token_manager()
        tm.validate_token_expiration(old_token, TokenType.ACCESS)  # old token still valid
        new_token = tm.create_token("s", _user(), TokenType.ACCESS)[1]
        tm.validate_token_expiration(new_token, TokenType.ACCESS)
        assert _header(new_token)["kid"] == new_key.thumbprint()  # new tokens use the new key
        jwks = jafaal.get_jwks()

    assert {k["kid"] for k in jwks["keys"]} == {old_key.thumbprint(), new_key.thumbprint()}


def test_token_signed_by_unknown_key_is_rejected():
    _key, pem = _keypair("RS256")
    forger, _forger_pem = _keypair("RS256")
    with _asymmetric("RS256", pem):
        tm = get_token_manager()
        forged = jwt.encode(
            {"alg": "RS256", "kid": forger.thumbprint()},
            {"sub": 1},
            forger,
            algorithms=["RS256"],
        )
        with pytest.raises(exc.JafaalError):
            tm.decode_token(forged)


def test_algorithm_confusion_rejected():
    # A token signed with one algorithm must not validate under another.
    _key, pem = _keypair("ES256")
    with _asymmetric("ES256", pem):
        es_token = get_token_manager().create_token("s", _user(), TokenType.ACCESS)[1]
    _rsa_key, rsa_pem = _keypair("RS256")
    with _asymmetric("RS256", rsa_pem):
        tm = get_token_manager()
        with pytest.raises(exc.JafaalError):
            tm.decode_token(es_token)


def test_jwks_endpoint_served_over_http(client):
    key, pem = _keypair("RS256")
    with _asymmetric("RS256", pem):
        resp = client.get("/api/v1/.well-known/jwks.json")
    assert resp.status_code == 200
    body = resp.json()
    assert [k["kid"] for k in body["keys"]] == [key.thumbprint()]
    assert "max-age" in resp.headers.get("cache-control", "")
