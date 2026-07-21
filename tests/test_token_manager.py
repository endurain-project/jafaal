"""Tests for TokenManager: issuance, validation, type confusion, and tampering."""

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
