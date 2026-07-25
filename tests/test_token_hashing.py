"""Tests for the shared token-hashing helpers."""

import dataclasses

import pytest

import jafaal.settings as settings_mod
import jafaal.token_hashing as token_hashing
from jafaal.token_hashing import KeyPurpose


def test_sha256_hex_is_deterministic_and_64_hex():
    d = token_hashing.sha256_hex("hello")
    assert d == token_hashing.sha256_hex("hello")
    assert len(d) == 64
    assert all(c in "0123456789abcdef" for c in d)


def test_hmac_differs_from_plain_sha256():
    value = "some-token-value"
    keyed = token_hashing.hmac_sha256(value, KeyPurpose.CSRF)
    assert keyed != token_hashing.sha256_hex(value)
    assert keyed == token_hashing.hmac_sha256(value, KeyPurpose.CSRF)
    assert len(keyed) == 64


def test_every_purpose_yields_a_distinct_digest():
    # Domain separation: hashing one value under two purposes must never produce
    # the same digest, so a digest computed for one job can never be replayed as
    # another.
    value = "the-same-token-value"
    digests = {purpose: token_hashing.hmac_sha256(value, purpose) for purpose in KeyPurpose}
    assert len(set(digests.values())) == len(KeyPurpose)


@pytest.mark.parametrize("purpose", list(KeyPurpose))
def test_subkey_is_32_bytes_and_not_the_raw_secret(purpose):
    subkey = token_hashing._subkey(purpose)
    assert len(subkey) == 32
    assert subkey != settings_mod.get_settings().secret_key.encode()


def test_subkeys_rebuild_after_reconfigure():
    original = settings_mod.get_settings()
    before = token_hashing.hmac_sha256("value", KeyPurpose.CSRF)
    try:
        settings_mod.configure(dataclasses.replace(original, secret_key="d" * 32))
        # A rotated signing secret must produce different digests, not stale
        # ones served from the subkey cache.
        assert token_hashing.hmac_sha256("value", KeyPurpose.CSRF) != before
    finally:
        settings_mod.configure(original)
    assert token_hashing.hmac_sha256("value", KeyPurpose.CSRF) == before


def test_generate_token_and_hash_roundtrip():
    token, token_hash = token_hashing.generate_token_and_hash(KeyPurpose.PASSWORD_RESET)
    assert token_hashing.hmac_sha256(token, KeyPurpose.PASSWORD_RESET) == token_hash
    # High entropy: two calls never collide.
    token2, hash2 = token_hashing.generate_token_and_hash(KeyPurpose.PASSWORD_RESET)
    assert token != token2
    assert token_hash != hash2


def test_legacy_lookup_digests_returns_keyed_and_unkeyed():
    # Rows written before keyed hashing hold the unkeyed digest; a lookup must
    # accept either form so those credentials survive the upgrade.
    token = "a-token"
    keyed, legacy = token_hashing.legacy_lookup_digests(token, KeyPurpose.API_KEY)
    assert keyed == token_hashing.hmac_sha256(token, KeyPurpose.API_KEY)
    assert legacy == token_hashing.sha256_hex(token)
    assert keyed != legacy
