"""Tests for the shared token-hashing helpers."""

import jafaal.token_hashing as token_hashing


def test_sha256_hex_is_deterministic_and_64_hex():
    d = token_hashing.sha256_hex("hello")
    assert d == token_hashing.sha256_hex("hello")
    assert len(d) == 64
    assert all(c in "0123456789abcdef" for c in d)


def test_hmac_differs_from_plain_sha256():
    value = "some-token-value"
    assert token_hashing.hmac_sha256(value) != token_hashing.sha256_hex(value)
    assert token_hashing.hmac_sha256(value) == token_hashing.hmac_sha256(value)
    assert len(token_hashing.hmac_sha256(value)) == 64


def test_generate_token_and_hash_roundtrip():
    token, token_hash = token_hashing.generate_token_and_hash()
    assert token_hashing.sha256_hex(token) == token_hash
    # High entropy: two calls never collide.
    token2, hash2 = token_hashing.generate_token_and_hash()
    assert token != token2
    assert token_hash != hash2
