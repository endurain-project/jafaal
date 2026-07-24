"""Tests for TokenManager: issuance, validation, type confusion, and tampering."""

import base64
import json
from types import SimpleNamespace

import pytest

import jafaal.exceptions as exc
from jafaal._internal.token_manager import TokenManager, TokenType, get_token_manager


def _user(user_id=1, is_superuser=False):
    return SimpleNamespace(id=user_id, is_superuser=is_superuser)


def test_algorithm_allow_list_enforced():
    with pytest.raises(ValueError, match="allow-list"):
        TokenManager("k" * 32, "none")
    with pytest.raises(ValueError, match="allow-list"):
        TokenManager("k" * 32, "RS256")


def test_access_token_roundtrip_and_claims():
    tm = get_token_manager()
    _exp, token = tm.create_token("sid-1", _user(7), TokenType.ACCESS)
    tm.validate_token_expiration(token, TokenType.ACCESS)  # does not raise
    assert tm.get_token_claim(token, "sub") == 7
    assert tm.get_token_claim(token, "sid") == "sid-1"
    assert tm.get_token_claim(token, "typ") == "access"
    assert isinstance(tm.get_token_claim(token, "scope"), list)


def test_superuser_gets_admin_scope():
    tm = get_token_manager()
    _, admin_token = tm.create_token("s", _user(1, is_superuser=True), TokenType.ACCESS)
    _, regular_token = tm.create_token("s", _user(2, is_superuser=False), TokenType.ACCESS)
    admin_scopes = set(tm.get_token_claim(admin_token, "scope"))
    regular_scopes = set(tm.get_token_claim(regular_token, "scope"))
    assert regular_scopes.issubset(admin_scopes)
    assert admin_scopes - regular_scopes  # admin has strictly more


def test_type_confusion_rejected():
    tm = get_token_manager()
    _, access = tm.create_token("s", _user(), TokenType.ACCESS)
    # An access token must not validate as a refresh token (typ mismatch).
    with pytest.raises(exc.InvalidTokenError):
        tm.validate_token_expiration(access, TokenType.REFRESH)


def test_expired_token_raises_token_expired():
    tm = TokenManager(
        "k" * 32,
        "HS256",
        access_token_expire_minutes=-1,  # exp lands in the past
        refresh_token_expire_days=7,
        issuer="iss",
        audience="aud",
    )
    _, token = tm.create_token("s", _user(), TokenType.ACCESS)
    with pytest.raises(exc.TokenExpiredError):
        tm.validate_token_expiration(token, TokenType.ACCESS)


def test_leeway_tolerates_recently_expired_token():
    # With a leeway wider than the token's overshoot, a just-expired token still
    # validates; strict validation (leeway 0) rejects the same token.
    lenient = TokenManager(
        "k" * 32,
        "HS256",
        access_token_expire_minutes=-1,  # exp ~60s in the past
        issuer="iss",
        audience="aud",
        leeway_seconds=120,
    )
    _, token = lenient.create_token("s", _user(), TokenType.ACCESS)
    lenient.validate_token_expiration(token, TokenType.ACCESS)  # within leeway → no raise

    strict = TokenManager("k" * 32, "HS256", access_token_expire_minutes=-1, issuer="iss", audience="aud")
    _, strict_token = strict.create_token("s", _user(), TokenType.ACCESS)
    with pytest.raises(exc.TokenExpiredError):
        strict.validate_token_expiration(strict_token, TokenType.ACCESS)


def test_tampered_signature_rejected():
    tm = get_token_manager()
    _, token = tm.create_token("s", _user(), TokenType.ACCESS)
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload}.{signature[:-2]}xx"
    with pytest.raises(exc.InvalidTokenError):
        tm.decode_token(tampered)


def test_wrong_key_rejected():
    tm = get_token_manager()
    _, token = tm.create_token("s", _user(), TokenType.ACCESS)
    other = TokenManager("d" * 32, "HS256", issuer=tm.issuer, audience=tm.audience)
    with pytest.raises(exc.InvalidTokenError):
        other.decode_token(token)


def test_missing_claim_raises_invalid_token():
    tm = get_token_manager()
    _, token = tm.create_token("s", _user(), TokenType.ACCESS)
    with pytest.raises(exc.InvalidTokenError):
        tm.get_token_claim(token, "nonexistent_claim")


def test_csrf_token_is_random_and_urlsafe():
    a = TokenManager.create_csrf_token()
    b = TokenManager.create_csrf_token()
    assert a != b
    assert len(a) >= 32


def _unsigned_token(alg: str) -> str:
    """Craft a header.payload. token with a chosen ``alg`` and an empty signature."""

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": 1}).encode())
    return f"{header}.{payload}."


def test_alg_none_token_rejected():
    # An ``alg: none`` token must never be accepted: the decode allow-list is
    # pinned to HS256, so joserfc rejects it before any signature check.
    tm = get_token_manager()
    with pytest.raises(exc.InvalidTokenError):
        tm.decode_token(_unsigned_token("none"))


def test_disallowed_algorithm_header_rejected():
    # A token advertising an algorithm outside the allow-list (HS512 here) is
    # rejected at decode, closing the algorithm-substitution vector.
    tm = get_token_manager()
    with pytest.raises(exc.InvalidTokenError):
        tm.decode_token(_unsigned_token("HS512"))


def test_wrong_issuer_rejected():
    # Same signing key (signature verifies) but a different issuer must fail the
    # essential ``iss`` claim check.
    signer = TokenManager("k" * 32, "HS256", issuer="issuer-a", audience="aud")
    _, token = signer.create_token("s", _user(), TokenType.ACCESS)
    verifier = TokenManager("k" * 32, "HS256", issuer="issuer-b", audience="aud")
    with pytest.raises(exc.InvalidTokenError):
        verifier.validate_token_expiration(token, TokenType.ACCESS)


def test_wrong_audience_rejected():
    signer = TokenManager("k" * 32, "HS256", issuer="iss", audience="aud-a")
    _, token = signer.create_token("s", _user(), TokenType.ACCESS)
    verifier = TokenManager("k" * 32, "HS256", issuer="iss", audience="aud-b")
    with pytest.raises(exc.InvalidTokenError):
        verifier.validate_token_expiration(token, TokenType.ACCESS)
