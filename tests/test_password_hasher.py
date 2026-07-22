"""Tests for PasswordHasher: hashing, verification, policy, and dummy verify."""

import dataclasses

import pytest

import jafaal
from jafaal._internal.password_hasher import PasswordHasher, get_password_hasher
from jafaal.exceptions import PasswordPolicyError


def test_get_password_hasher_uses_settings_argon2_cost():
    # The Argon2 cost from AuthSettings must flow into the hasher: the produced
    # hash string encodes the memory/time/parallelism parameters, so we assert
    # they match the configured (distinctive, cheap) values.
    original = jafaal.get_settings()
    jafaal.configure(dataclasses.replace(original, argon2_memory_cost=8192, argon2_time_cost=1, argon2_parallelism=1))
    try:
        digest = get_password_hasher().hash_password("Str0ng!Pass")
        assert digest.startswith("$argon2")
        assert "m=8192" in digest
        assert "t=1" in digest
        assert "p=1" in digest
    finally:
        jafaal.configure(original)


def test_hash_and_verify_roundtrip():
    hasher = get_password_hasher()
    hashed = hasher.hash_password("Str0ng!Pass")
    assert hashed != "Str0ng!Pass"
    assert hasher.verify_password("Str0ng!Pass", hashed) is True
    assert hasher.verify_password("wrong", hashed) is False


def test_verify_and_update_returns_bool_and_optional_hash():
    hasher = get_password_hasher()
    hashed = hasher.hash_password("Str0ng!Pass")
    ok, updated = hasher.verify_and_update("Str0ng!Pass", hashed)
    assert ok is True
    # No rehash needed for a hash produced by the same configuration.
    assert updated is None


def test_validate_password_strict_requirements():
    with pytest.raises(PasswordPolicyError, match="too short"):
        PasswordHasher.validate_password("aA1!", min_length=8)
    with pytest.raises(PasswordPolicyError, match="uppercase"):
        PasswordHasher.validate_password("lowercase1!", min_length=8)
    with pytest.raises(PasswordPolicyError, match="lowercase"):
        PasswordHasher.validate_password("UPPERCASE1!", min_length=8)
    with pytest.raises(PasswordPolicyError, match="digit"):
        PasswordHasher.validate_password("NoDigits!!", min_length=8)
    with pytest.raises(PasswordPolicyError, match="special"):
        PasswordHasher.validate_password("NoSpecial1", min_length=8)
    # A compliant password does not raise.
    PasswordHasher.validate_password("Str0ng!Pass", min_length=8)


def test_validate_password_length_only():
    PasswordHasher.validate_password("abcdefgh", min_length=8, policy_type="length_only")
    with pytest.raises(PasswordPolicyError, match="too short"):
        PasswordHasher.validate_password("abc", min_length=8, policy_type="length_only")


def test_validate_password_unknown_policy():
    with pytest.raises(PasswordPolicyError, match="Unknown password policy"):
        PasswordHasher.validate_password("Str0ng!Pass", min_length=8, policy_type="bogus")


def test_is_valid_password():
    assert PasswordHasher.is_valid_password("Str0ng!Pass") is True
    assert PasswordHasher.is_valid_password("weak") is False


def test_generate_password_meets_policy():
    pw = PasswordHasher.generate_password(16)
    assert len(pw) == 16
    PasswordHasher.validate_password(pw, min_length=16)  # generated pw is compliant


def test_generate_password_rejects_short_length():
    with pytest.raises(PasswordPolicyError, match="too short"):
        PasswordHasher.generate_password(4)


def test_dummy_verify_runs_without_error():
    hasher = PasswordHasher()
    # Should perform a full verify against a throwaway hash and return None.
    assert hasher.dummy_verify() is None
    # Second call reuses the cached dummy hash.
    assert hasher.dummy_verify() is None


def test_unsupported_hasher_type_raises():
    with pytest.raises(TypeError):
        PasswordHasher(hasher=object())
