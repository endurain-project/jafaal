"""Tests for identity-provider pure utilities: URL building + PKCE validation."""

import base64
import hashlib
import secrets

import pytest

import jafaal.exceptions as exc
import jafaal.identity_providers.utils as idp_utils


def _pkce_pair():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
    return verifier, challenge


# --------------------------------------------------------------------------- #
# Redirect URL building
# --------------------------------------------------------------------------- #


def test_append_query_params_preserves_the_existing_query():
    url = idp_utils.append_query_params("com.example.app://cb?a=1", {"code": "xyz"})
    assert url == "com.example.app://cb?a=1&code=xyz"


def test_append_query_params_percent_encodes_values():
    # Concatenating instead would let a value smuggle extra parameters into the
    # URL the receiving client parses.
    url = idp_utils.append_query_params("com.example.app://cb", {"state": "a&code=stolen"})
    assert "a%26code%3Dstolen" in url
    assert url.count("code=") == 0


def test_append_query_params_preserves_the_fragment():
    url = idp_utils.append_query_params("https://app.test/cb#frag", {"code": "xyz"})
    assert url == "https://app.test/cb?code=xyz#frag"


# --------------------------------------------------------------------------- #
# PKCE (RFC 7636)
# --------------------------------------------------------------------------- #


def test_validate_pkce_challenge_ok():
    _verifier, challenge = _pkce_pair()
    idp_utils.validate_pkce_challenge(challenge, "S256")  # no raise


def test_validate_pkce_challenge_rejects_wrong_method():
    _verifier, challenge = _pkce_pair()
    with pytest.raises(exc.InvalidRequestError):
        idp_utils.validate_pkce_challenge(challenge, "plain")


def test_validate_pkce_challenge_rejects_bad_length_and_chars():
    with pytest.raises(exc.InvalidRequestError):
        idp_utils.validate_pkce_challenge("too-short", "S256")
    with pytest.raises(exc.InvalidRequestError):
        idp_utils.validate_pkce_challenge("!" * 50, "S256")


def test_validate_pkce_verifier_roundtrip():
    verifier, challenge = _pkce_pair()
    idp_utils.validate_pkce_verifier(verifier, challenge, "S256")  # no raise


def test_validate_pkce_verifier_mismatch():
    verifier, _challenge = _pkce_pair()
    _other_verifier, other_challenge = _pkce_pair()
    with pytest.raises(exc.InvalidRequestError):
        idp_utils.validate_pkce_verifier(verifier, other_challenge, "S256")


def test_secure_compare():
    assert idp_utils._secure_compare("abc", "abc") is True
    assert idp_utils._secure_compare("abc", "abd") is False
    assert idp_utils._secure_compare("abc", "abcd") is False
