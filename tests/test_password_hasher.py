"""Tests for PasswordHasher: hashing, verification, policy, and dummy verify."""

import pytest
from conftest import replace_settings
from pwdlib.hashers.argon2 import Argon2Hasher

import jafaal
from jafaal._internal.password_hasher import (
    PasswordHasher,
    get_password_hasher,
    normalize_password,
)
from jafaal.exceptions import PasswordPolicyError

# A composed/decomposed pair that NFKC folds together: "pässw0rd!" written with
# U+00E4, and with "a" + U+0308 COMBINING DIAERESIS.
COMPOSED_PASSWORD = "p\u00e4ssw0rd!"
DECOMPOSED_PASSWORD = "pa\u0308ssw0rd!"


def test_a_very_long_password_verifies_without_raising():
    """Argon2 takes the password whole, so length is bounded by policy alone.

    Any hasher with a hard input limit turns a long password into a 500 for some
    accounts and a 401 for others — an unauthenticated oracle for which hash an
    account carries.
    """
    hasher = PasswordHasher(hasher=Argon2Hasher())
    hashed = hasher.hash_password("a" * 200)

    assert hasher.verify_password("a" * 200, hashed) is True
    # Not truncated: a prefix is not the password.
    assert hasher.verify_password("a" * 72, hashed) is False
    assert hasher.verify_and_update("b" * 200, hashed) == (False, None)


def test_password_is_nfkc_normalized_before_hashing():
    """NIST SP 800-63B §5.1.1.2: normalize so one passphrase works everywhere."""
    assert normalize_password(DECOMPOSED_PASSWORD) == COMPOSED_PASSWORD
    # ASCII is untouched.
    assert normalize_password("Str0ng!Pass") == "Str0ng!Pass"

    hasher = get_password_hasher()
    hashed = hasher.hash_password(DECOMPOSED_PASSWORD)
    # Enrolled on a decomposing platform, typed on a composing one.
    assert hasher.verify_password(COMPOSED_PASSWORD, hashed) is True
    assert hasher.verify_password(DECOMPOSED_PASSWORD, hashed) is True
    # Both spellings also survive the verify_and_update path.
    assert hasher.verify_and_update(COMPOSED_PASSWORD, hashed)[0] is True


def test_get_password_hasher_uses_settings_argon2_cost():
    # The Argon2 cost from AuthSettings must flow into the hasher: the produced
    # hash string encodes the memory/time/parallelism parameters, so we assert
    # they match the configured (distinctive, cheap) values.
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, argon2_memory_cost=8192, argon2_time_cost=1, argon2_parallelism=1))
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


def test_validate_password_max_length():
    # Both policies reject a password over the maximum (checked before hashing).
    with pytest.raises(PasswordPolicyError, match="too long"):
        PasswordHasher.validate_password("a" * 40, min_length=8, policy_type="length_only", max_length=32)
    with pytest.raises(PasswordPolicyError, match="too long"):
        PasswordHasher.validate_password("Str0ng!" + "a" * 40, min_length=8, max_length=32)
    # Within the bound is accepted; None (the default) means no maximum.
    PasswordHasher.validate_password("abcdefgh", min_length=8, policy_type="length_only", max_length=32)
    PasswordHasher.validate_password("a" * 500, min_length=8, policy_type="length_only")


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
    # Second call reuses the pre-warmed dummy hash.
    assert hasher.dummy_verify() is None


def test_dummy_hash_is_prewarmed_at_construction():
    # The dummy hash is built in __init__, so dummy_verify()'s first call costs a
    # single verify (not hash + verify) — keeping the first "user not found"
    # login response the same latency as steady state (no enumeration signal).
    hasher = PasswordHasher()
    assert hasher._dummy_hash  # a real, non-empty hash is ready before first use


def test_unsupported_hasher_type_raises():
    with pytest.raises(TypeError):
        PasswordHasher(hasher=object())
