"""Tests for API-key helpers and the host-configurable scope allow-list."""

import pytest

import jafaal
import jafaal.api_keys.utils as api_keys_utils
import jafaal.settings as settings_mod


def test_generate_api_key_format():
    key = api_keys_utils.generate_api_key()
    prefix = settings_mod.get_settings().api_key_prefix
    assert key.startswith(f"{prefix}_")
    # prefix + "_" + 43-char base64url token
    assert len(key.split("_", 1)[1]) >= 43


def test_hash_api_key_is_sha256():
    raw = "jafaal_abc"
    assert api_keys_utils.hash_api_key(raw) == api_keys_utils.token_hashing.sha256_hex(raw)


def test_scope_allow_list_is_empty_by_default():
    assert api_keys_utils.get_api_key_scopes() == frozenset()
    # With no configured scopes, everything is rejected.
    with pytest.raises(ValueError):
        api_keys_utils.validate_api_key_scopes(["anything"])


def test_configure_and_validate_scopes():
    jafaal.configure_api_key_scopes(["reports:read", "reports:write"])
    assert api_keys_utils.get_api_key_scopes() == frozenset({"reports:read", "reports:write"})
    # Supported scopes pass.
    api_keys_utils.validate_api_key_scopes(["reports:read"])
    # Unsupported scope rejected.
    with pytest.raises(ValueError, match="Unsupported API key scopes"):
        api_keys_utils.validate_api_key_scopes(["reports:delete"])
    # Empty request rejected.
    with pytest.raises(ValueError):
        api_keys_utils.validate_api_key_scopes([])


def test_reset_scopes():
    jafaal.configure_api_key_scopes(["reports:read"])
    jafaal.reset_api_key_scopes()
    assert api_keys_utils.get_api_key_scopes() == frozenset()


def test_scopes_json_roundtrip():
    scopes = ["reports:read", "reports:write"]
    encoded = api_keys_utils.scopes_to_json(scopes)
    assert api_keys_utils.json_to_scopes(encoded) == scopes
