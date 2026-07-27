"""Tests for identity-provider pure utilities: redirect + PKCE validation."""

import base64
import hashlib
import secrets
from contextlib import contextmanager

import pytest
from conftest import replace_settings

import jafaal
import jafaal.exceptions as exc
import jafaal.identity_providers.utils as idp_utils


@contextmanager
def _settings(**overrides):
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, **overrides))
    try:
        yield
    finally:
        jafaal.configure(original)


def _pkce_pair():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
    return verifier, challenge


# --------------------------------------------------------------------------- #
# Redirect validation (open-redirect prevention)
# --------------------------------------------------------------------------- #


def test_validate_redirect_allows_none_and_relative():
    idp_utils.validate_redirect_url(None)
    idp_utils.validate_redirect_url("")
    idp_utils.validate_redirect_url("/dashboard")


def test_validate_redirect_rejects_external_http():
    with pytest.raises(exc.InvalidRequestError):
        idp_utils.validate_redirect_url("http://evil.example")
    with pytest.raises(exc.InvalidRequestError):
        idp_utils.validate_redirect_url("https://evil.example")


def test_validate_redirect_rejects_unconfigured_scheme():
    with pytest.raises(exc.InvalidRequestError):
        idp_utils.validate_redirect_url("gadgetbridge://callback")


def test_validate_redirect_allows_configured_custom_scheme():
    with _settings(allowed_redirect_schemes=("myapp",)):
        idp_utils.validate_redirect_url("myapp://callback")  # no raise


def test_validate_redirect_rejects_bare_relative_and_traversal():
    with pytest.raises(exc.InvalidRequestError):
        idp_utils.validate_redirect_url("no-leading-slash")
    with pytest.raises(exc.InvalidRequestError):
        idp_utils.validate_redirect_url("/a/../../etc/passwd")
    with pytest.raises(exc.InvalidRequestError):
        idp_utils.validate_redirect_url("//evil.example")


def test_is_custom_scheme_redirect():
    assert idp_utils.is_custom_scheme_redirect("myapp://cb") is True
    assert idp_utils.is_custom_scheme_redirect("/path") is False
    assert idp_utils.is_custom_scheme_redirect("https://x") is False
    assert idp_utils.is_custom_scheme_redirect(None) is False


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
