"""User API key utility functions."""

import json
import secrets
from collections.abc import Iterable

import jafaal.exceptions as jafaal_exceptions
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
    return f"{jafaal_settings.get_settings().api_keys.prefix}_{secrets.token_urlsafe(32)}"


def hash_api_key(raw_key: str) -> str:
    """
    Compute the stored digest of a raw API key.

    A keyed HMAC-SHA256 under the API-key subkey derived from
    ``AuthSettings.secret_key``. High-entropy secrets do not need a slow KDF
    (Argon2), but keying the digest means database read access alone does
    not let an attacker verify a stolen key offline, and an API-key digest can
    never collide with a digest computed for another purpose.

    This is the **write** side (always the primary subkey). Authentication looks
    a key up through :func:`api_key_digests` so keys minted before a
    ``secret_key`` rotation keep working.

    Args:
        raw_key: The plain-text API key to hash.

    Returns:
        Lowercase hex-encoded HMAC-SHA256 digest (64 chars).
    """
    return token_hashing.hmac_sha256(raw_key, token_hashing.KeyPurpose.API_KEY)


def api_key_digests(raw_key: str) -> tuple[str, ...]:
    """Return every digest an API key could be stored as, primary first.

    An API key is long-lived and its row is never rewritten on its own, so a
    ``secret_key`` rotation would otherwise invalidate every existing key —
    permanently, and with no signal to the owner. Authentication therefore tries
    each candidate and re-keys the row to the primary digest on a fallback match.

    Args:
        raw_key: The plain-text API key presented by the caller.

    Returns:
        Candidate digests, primary subkey first.
    """
    return token_hashing.digest_candidates(raw_key, token_hashing.KeyPurpose.API_KEY)


def scopes_outside_allow_list(requested_scopes: Iterable[str]) -> set[str]:
    """Return the requested scopes that are not in the API-key allow-list.

    The shared half of the two-layer check: the request schema uses it to reject
    an unsupported scope at parse time (as a Pydantic ``ValueError``, so it
    surfaces as a 422 field error) and :func:`validate_api_key_scopes` uses it
    for the authoritative check, so the rule lives in one place.

    Args:
        requested_scopes: Scopes the caller wants the key to carry.

    Returns:
        The offending scopes; empty when all are allow-listed.
    """
    return set(requested_scopes) - get_api_key_scopes()


def validate_api_key_scopes(
    requested_scopes: list[str],
    *,
    granted_scopes: Iterable[str],
) -> None:
    """
    Validate requested scopes against the allow-list **and** the caller's own.

    Two independent bounds, because either alone is insufficient:

    * the host-configured allow-list (:func:`configure_api_key_scopes`, empty by
      default) caps what an API key may *ever* carry, so keys do not silently
      gain access when new endpoints and scopes are added later; and
    * ``granted_scopes`` — the scopes the requesting principal actually holds —
      caps what *this* caller may delegate. Without it any authenticated user
      could mint a key carrying an allow-listed admin scope they do not hold and
      then authenticate with it, turning API-key creation into a privilege
      escalation. A credential can never delegate authority its creator lacks.

    Args:
        requested_scopes: List of scopes the caller wants to assign to the new
            API key.
        granted_scopes: Scopes held by the principal creating the key.

    Raises:
        InvalidRequestError: If no scope is requested, or any requested scope is
            outside the allow-list or not held by the caller.
    """
    if not requested_scopes:
        raise jafaal_exceptions.InvalidRequestError(
            f"No API key scopes requested. Valid scopes: {sorted(get_api_key_scopes())}"
        )

    unsupported = scopes_outside_allow_list(requested_scopes)
    if unsupported:
        raise jafaal_exceptions.InvalidRequestError(
            f"Unsupported API key scopes: {sorted(unsupported)}. Valid scopes: {sorted(get_api_key_scopes())}"
        )

    # Reported separately from ``unsupported``: "the deployment does not offer
    # this scope" and "you do not hold this scope" are different problems, and
    # conflating them would tell a caller that an admin scope exists but hide why
    # it was refused.
    not_granted = set(requested_scopes) - set(granted_scopes)
    if not_granted:
        raise jafaal_exceptions.InvalidRequestError(
            f"Cannot grant API key scopes you do not hold: {sorted(not_granted)}. "
            "An API key may only carry scopes the requesting account has."
        )


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
