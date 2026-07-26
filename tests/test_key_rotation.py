"""Tests for at-rest key rotation: JWT signing keys and Fernet encryption keys."""

from __future__ import annotations

import dataclasses
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from starlette.requests import Request

import jafaal
import jafaal.exceptions as exc
import jafaal.sessions.utils as sessions_utils
import jafaal.token_hashing as token_hashing
from jafaal._core import crypto
from jafaal._internal.token_manager import TokenManager, TokenType


def _user(user_id=1, is_superuser=False):
    return SimpleNamespace(id=user_id, is_superuser=is_superuser)


def _request(client_host="203.0.113.7"):
    """A minimal real Starlette request (audit logging reads client + path)."""
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/api/v1/whatever",
            "query_string": b"",
            "headers": [],
            "client": (client_host, 12345),
            "server": ("test", 80),
            "scheme": "http",
        }
    )


# --------------------------------------------------------------------------- #
# JWT signing-key rotation
# --------------------------------------------------------------------------- #


def test_token_signed_with_previous_key_still_validates():
    old = "o" * 32
    new = "n" * 32
    tm_old = TokenManager(old, "HS256", issuer="iss", audience="aud")
    _, token = tm_old.create_token("sid", _user(7), TokenType.ACCESS)

    # After rotation the primary key is ``new``; ``old`` is kept as a fallback.
    tm_new = TokenManager(new, "HS256", issuer="iss", audience="aud", secret_key_fallbacks=(old,))
    tm_new.validate_token_expiration(token, TokenType.ACCESS)  # does not raise
    assert tm_new.get_token_claim(token, "sub") == "7"


def test_new_tokens_are_signed_with_primary_key_only():
    old = "o" * 32
    new = "n" * 32
    tm_new = TokenManager(new, "HS256", issuer="iss", audience="aud", secret_key_fallbacks=(old,))
    _, token = tm_new.create_token("sid", _user(1), TokenType.ACCESS)
    # A verifier holding only the OLD key must reject a token signed with NEW,
    # proving signing uses the primary key (never a fallback).
    tm_old_only = TokenManager(old, "HS256", issuer="iss", audience="aud")
    with pytest.raises(exc.InvalidTokenError):
        tm_old_only.decode_token(token)


def test_token_signed_with_unknown_key_is_rejected():
    tm = TokenManager("n" * 32, "HS256", issuer="iss", audience="aud", secret_key_fallbacks=("o" * 32,))
    stranger = TokenManager("z" * 32, "HS256", issuer="iss", audience="aud")
    _, token = stranger.create_token("sid", _user(1), TokenType.ACCESS)
    with pytest.raises(exc.InvalidTokenError):
        tm.decode_token(token)


# --------------------------------------------------------------------------- #
# Fernet encryption-key rotation
# --------------------------------------------------------------------------- #


def test_fernet_decrypts_data_written_with_previous_key():
    key_old = Fernet.generate_key().decode()
    key_new = Fernet.generate_key().decode()
    original = jafaal.get_settings()
    try:
        # Encrypt while ``key_old`` is the primary key.
        jafaal.configure(dataclasses.replace(original, fernet_key=key_old, fernet_key_fallbacks=()))
        ciphertext = crypto.encrypt_token_fernet("s3cret")

        # Rotate: ``key_new`` primary, ``key_old`` kept as a decrypt fallback.
        jafaal.configure(dataclasses.replace(original, fernet_key=key_new, fernet_key_fallbacks=(key_old,)))
        assert crypto.decrypt_token_fernet(ciphertext) == "s3cret"

        # New writes use the new key and still round-trip.
        new_ct = crypto.encrypt_token_fernet("again")
        assert crypto.decrypt_token_fernet(new_ct) == "again"
    finally:
        jafaal.configure(original)


def test_fernet_ciphertext_unreadable_once_old_key_fully_dropped():
    key_old = Fernet.generate_key().decode()
    key_new = Fernet.generate_key().decode()
    original = jafaal.get_settings()
    try:
        jafaal.configure(dataclasses.replace(original, fernet_key=key_old, fernet_key_fallbacks=()))
        ciphertext = crypto.encrypt_token_fernet("s3cret")
        # Rotation finished: old key removed entirely → old ciphertext no longer
        # decryptable (surfaced as a 500 InternalError).
        jafaal.configure(dataclasses.replace(original, fernet_key=key_new, fernet_key_fallbacks=()))
        with pytest.raises(exc.InternalError):
            crypto.decrypt_token_fernet(ciphertext)
    finally:
        jafaal.configure(original)


# --------------------------------------------------------------------------- #
# Keyed-digest rotation
#
# Every stored token digest (sessions, API keys, CSRF, password-reset, sign-up,
# IdP-link, rotated refresh tokens) is an HMAC keyed by a subkey derived from
# ``secret_key``. Rotating that key must NOT orphan them: the read side accepts
# the fallback subkeys too, otherwise a rotation would log every session out and
# permanently kill every API key.
# --------------------------------------------------------------------------- #


@contextmanager
def _rotated(primary, fallbacks=()):
    """Reconfigure with a different ``secret_key`` for the duration of the block."""
    original = jafaal.get_settings()
    jafaal.configure(dataclasses.replace(original, secret_key=primary, secret_key_fallbacks=tuple(fallbacks)))
    try:
        yield
    finally:
        jafaal.configure(original)


@pytest.mark.parametrize("purpose", list(token_hashing.KeyPurpose))
def test_digest_written_before_rotation_still_verifies(purpose):
    old = "o" * 32
    new = "n" * 32
    with _rotated(old):
        stored = token_hashing.hmac_sha256("tok3n", purpose)

    with _rotated(new, (old,)):
        # The live primary digest no longer equals the stored one...
        assert token_hashing.hmac_sha256("tok3n", purpose) != stored
        # ...but verification accepts the fallback subkey.
        assert token_hashing.verify_hmac("tok3n", purpose, stored) is True
        # And the stored digest is offered as a lookup candidate.
        assert stored in token_hashing.digest_candidates("tok3n", purpose)


def test_digest_candidates_are_primary_first():
    old = "o" * 32
    new = "n" * 32
    with _rotated(new, (old,)):
        candidates = token_hashing.digest_candidates("tok3n", token_hashing.KeyPurpose.API_KEY)
        assert len(candidates) == 2
        assert candidates[0] == token_hashing.hmac_sha256("tok3n", token_hashing.KeyPurpose.API_KEY)


def test_digest_unverifiable_once_old_key_fully_dropped():
    old = "o" * 32
    new = "n" * 32
    with _rotated(old):
        stored = token_hashing.hmac_sha256("tok3n", token_hashing.KeyPurpose.API_KEY)
    # Rotation finished: the old key is gone, so the old digest no longer matches.
    with _rotated(new):
        assert token_hashing.verify_hmac("tok3n", token_hashing.KeyPurpose.API_KEY, stored) is False


def test_wrong_value_never_verifies_under_any_key():
    old = "o" * 32
    new = "n" * 32
    with _rotated(old):
        stored = token_hashing.hmac_sha256("tok3n", token_hashing.KeyPurpose.API_KEY)
    with _rotated(new, (old,)):
        assert token_hashing.verify_hmac("wrong", token_hashing.KeyPurpose.API_KEY, stored) is False


def test_digest_purposes_stay_separated_across_rotation():
    old = "o" * 32
    new = "n" * 32
    with _rotated(old):
        stored = token_hashing.hmac_sha256("tok3n", token_hashing.KeyPurpose.API_KEY)
    with _rotated(new, (old,)):
        # A fallback subkey must not let a digest cross purposes.
        assert token_hashing.verify_hmac("tok3n", token_hashing.KeyPurpose.CSRF, stored) is False


def test_session_refresh_token_survives_rotation():
    old = "o" * 32
    new = "n" * 32
    with _rotated(old):
        stored = sessions_utils.hash_refresh_token("refresh-jwt")
    with _rotated(new, (old,)):
        assert sessions_utils.verify_refresh_token("refresh-jwt", stored) is True
        assert sessions_utils.verify_refresh_token("other-jwt", stored) is False


def test_csrf_token_survives_rotation():
    old = "o" * 32
    new = "n" * 32
    with _rotated(old):
        stored = sessions_utils._hash_csrf_token("csrf")
    with _rotated(new, (old,)):
        assert sessions_utils.verify_csrf_token("csrf", stored) is True


def test_api_key_issued_before_rotation_still_authenticates_and_is_rekeyed(db, make_user):
    """The unrecoverable case: an API-key row is never rewritten on its own."""
    import jafaal.api_keys.crud as api_keys_crud
    import jafaal.api_keys.schema as api_keys_schema
    import jafaal.api_keys.utils as api_keys_utils
    from jafaal._internal.password_hasher import get_password_hasher
    from jafaal._internal.token_manager import get_token_manager
    from jafaal.identity_service import DefaultIdentityService

    old = "o" * 32
    new = "n" * 32
    user = make_user(username="rotator")
    jafaal.configure_api_key_scopes(["reports:read"])

    with _rotated(old):
        row, raw_key = api_keys_crud.create_api_key(
            user.id,
            api_keys_schema.UsersApiKeyCreate(name="k", scopes=["reports:read"]),
            db,
        )
        key_id = row.id
        old_digest = row.key_hash

    with _rotated(new, (old,)):
        service = DefaultIdentityService(db, get_token_manager(), get_password_hasher())
        principal = service.resolve_from_api_key(raw_key, _request())
        assert principal.user_id == user.id

        # Located via the fallback → the row is re-keyed to the primary digest,
        # so the key keeps working once the old secret is dropped.
        db.expire_all()
        refreshed = api_keys_crud.get_api_key_by_id(key_id, user.id, db)
        assert refreshed.key_hash != old_digest
        assert refreshed.key_hash == api_keys_utils.hash_api_key(raw_key)

    # Old key fully dropped: still authenticates, because it was re-keyed.
    with _rotated(new):
        service = DefaultIdentityService(db, get_token_manager(), get_password_hasher())
        assert service.resolve_from_api_key(raw_key, _request()).user_id == user.id


# --------------------------------------------------------------------------- #
# Rotation-key validation
# --------------------------------------------------------------------------- #


def test_invalid_fernet_fallback_rejected():
    with pytest.raises(ValueError, match="fernet_key_fallbacks"):
        jafaal.AuthSettings(
            secret_key="s" * 32,
            fernet_key=Fernet.generate_key().decode(),
            fernet_key_fallbacks=("not-a-valid-fernet-key",),
        )


def test_short_secret_key_fallback_rejected():
    with pytest.raises(ValueError, match="secret_key_fallbacks"):
        jafaal.AuthSettings(
            secret_key="s" * 32,
            fernet_key=Fernet.generate_key().decode(),
            secret_key_fallbacks=("too-short",),
        )
