"""Tests for at-rest key rotation: JWT signing keys and Fernet encryption keys."""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

import jafaal
import jafaal.exceptions as exc
from jafaal._core import crypto
from jafaal._internal.token_manager import TokenManager, TokenType


def _user(user_id=1, is_superuser=False):
    return SimpleNamespace(id=user_id, is_superuser=is_superuser)


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
