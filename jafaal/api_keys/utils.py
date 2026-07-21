"""User API key utility functions."""

import json
import secrets
from collections.abc import Iterable

import jafaal.settings as jafaal_settings
import jafaal.token_hashing as token_hashing
from jafaal._core.registry import ConfigSlot

# Host-configurable allow-list of scopes an API key may carry. JAFAAL ships no
# application scopes of its own, so the default is empty: a host that offers API
# keys installs the scopes it supports via :func:`configure_api_key_scopes`
# (typically a curated subset of its :class:`~jafaal.scopes.ScopeCatalog`).
# Until then, API-key creation rejects every requested scope. Keeping this
# allow-list separate from the full JWT scope set means API keys never silently
# gain access when new endpoints/scopes are added later.
_supported_api_key_scopes: ConfigSlot[frozenset[str]] = ConfigSlot(default_factory=frozenset)


def configure_api_key_scopes(scopes: Iterable[str]) -> None:
    """Install the scopes an API key is allowed to grant.

    Call once at startup, before serving requests.

    Args:
        scopes: The scope strings API keys may carry.
    """
    _supported_api_key_scopes.configure(frozenset(scopes))


def get_api_key_scopes() -> frozenset[str]:
    """Return the configured API-key scope allow-list (empty until configured)."""
    return _supported_api_key_scopes.get()


def reset_api_key_scopes() -> None:
    """Reset the API-key scope allow-list to empty. Intended for tests."""
    _supported_api_key_scopes.reset()


def generate_api_key() -> str:
    """
    Generate a new raw API key.

    Keys have the format ``<prefix>_<token>`` where ``<prefix>`` is
    ``AuthSettings.api_key_prefix`` and ``<token>`` is 32 cryptographically
    random bytes encoded as base64url (43 characters). Total entropy is
    256 bits.

    Returns:
        A new raw API key string.
    """
    return f"{jafaal_settings.get_settings().api_key_prefix}_{secrets.token_urlsafe(32)}"


def hash_api_key(raw_key: str) -> str:
    """
    Compute the SHA-256 hex digest of a raw API key.

    High-entropy secrets do not require a slow KDF
    (Argon2/bcrypt). SHA-256 is the industry standard
    for hashing tokens of this entropy level.

    Args:
        raw_key: The plain-text API key to hash.

    Returns:
        Lowercase hex-encoded SHA-256 digest (64 chars).
    """
    return token_hashing.sha256_hex(raw_key)


def validate_api_key_scopes(
    requested_scopes: list[str],
) -> None:
    """
    Validate requested scopes against the host-configured API-key allow-list.

    The set of scopes an API key may carry is installed by the host via
    :func:`configure_api_key_scopes` (empty by default). A request for any
    scope outside that allow-list — or an empty request — is rejected.

    Args:
        requested_scopes: List of scopes the caller wants
            to assign to the new API key.

    Raises:
        ValueError: If any requested scope is not supported, or none is given.
    """
    supported = get_api_key_scopes()
    unsupported = set(requested_scopes) - supported
    if unsupported or not requested_scopes:
        offending = unsupported or set(requested_scopes)
        raise ValueError(f"Unsupported API key scopes: {sorted(offending)}. Valid scopes: {sorted(supported)}")


def scopes_to_json(scopes: list[str]) -> str:
    """
    Serialize a list of scope strings to a JSON string.

    Args:
        scopes: List of scope strings.

    Returns:
        JSON-encoded string representation.
    """
    return json.dumps(scopes)


def json_to_scopes(scopes_json: str) -> list[str]:
    """
    Deserialize a JSON string to a list of scope strings.

    Args:
        scopes_json: JSON-encoded scope list.

    Returns:
        List of scope strings.
    """
    return json.loads(scopes_json)
