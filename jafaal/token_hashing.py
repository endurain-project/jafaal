"""Shared hashing helpers for opaque auth tokens.

Every stored token digest is a keyed HMAC-SHA256 under a **per-purpose subkey**
derived from the configured signing secret (``AuthSettings.secret_key``): the
session refresh-token digest, refresh-token reuse detection, CSRF tokens, API
keys, password-reset / sign-up / IdP-link tokens, and the WebAuthn user handle.

The keyed MAC adds defense-in-depth — even with database read access an attacker
cannot verify stolen tokens without the server secret — while costing
microseconds. These are all server-minted, high-entropy values rather than
user-chosen secrets, so a password KDF would add no strength, only latency.

Domain separation
-----------------
``secret_key`` is a single value doing several jobs (it also signs HS256 JWTs).
Rather than MAC different kinds of data under one key, each purpose gets its own
32-byte subkey via HKDF-SHA256 (RFC 5869) with a distinct ``info`` label. Two
different kinds of token can therefore never produce the same digest, and a
digest computed for one purpose can never be replayed as another. Callers pass a
:class:`KeyPurpose`; they never touch the raw secret.

Digests are lowercase hex and deterministic, enabling indexed equality lookups.

Key rotation
------------
A digest is keyed by whichever ``secret_key`` was primary when it was written, so
rotating that key would orphan every stored digest — logging out every session
and permanently invalidating every API key — unless the read side also accepts
the previous key. New digests are therefore always written with the primary
subkey (:func:`hmac_sha256`), while the read side goes through
:func:`verify_hmac` (direct comparison) or :func:`digest_candidates` (indexed
lookup), both of which additionally accept the subkeys derived from
``AuthSettings.secret_key_fallbacks``.
"""

import hashlib
import hmac
import secrets
from enum import StrEnum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import jafaal.settings as jafaal_settings


class KeyPurpose(StrEnum):
    """The distinct jobs :attr:`AuthSettings.secret_key` is stretched into.

    Each member is the HKDF ``info`` label for its subkey, so adding a purpose is
    a one-line change and can never collide with an existing one. Values are
    versioned (``v1``) so a future derivation change can be rolled out
    side-by-side.
    """

    #: Digest of the refresh token stored on a session row.
    REFRESH_SESSION = "jafaal/v1/refresh-session"
    #: Digest of a rotated refresh token, for reuse/theft detection.
    REFRESH_ROTATED = "jafaal/v1/refresh-rotated"
    #: Digest of a session's CSRF token.
    CSRF = "jafaal/v1/csrf"
    #: Digest of an API key.
    API_KEY = "jafaal/v1/api-key"
    #: Digest of a password-reset token.
    PASSWORD_RESET = "jafaal/v1/password-reset"
    #: Digest of a sign-up / email-verification token.
    SIGN_UP = "jafaal/v1/sign-up"
    #: Digest of a caller-held sign-up status polling handle.
    SIGN_UP_STATUS = "jafaal/v1/sign-up-status"
    #: Digest of an identity-provider account-link token.
    IDP_LINK = "jafaal/v1/idp-link"
    #: Digest of an RFC 6749 authorization code.
    AUTHORIZATION_CODE = "jafaal/v1/authorization-code"
    #: Opaque WebAuthn user handle.
    WEBAUTHN_USER_HANDLE = "jafaal/v1/webauthn-user-handle"


# Derived subkeys, cached per settings generation so a reconfigure rebuilds them
# (mirroring the token manager and password hasher). The value is the tuple of
# subkeys for one purpose: the primary (index 0, always used to *write*) followed
# by one per ``AuthSettings.secret_key_fallbacks`` entry (verify-only).
_subkeys: dict[str, tuple[bytes, ...]] = {}
_subkeys_generation: int = -1


def _derive(secret_key: str, purpose: KeyPurpose) -> bytes:
    """Derive the 32-byte subkey for ``purpose`` from one signing secret."""
    # No salt: the input keying material is already a high-entropy secret
    # (>= 32 chars, enforced at construction), so HKDF is used purely for
    # domain separation via ``info`` — which is exactly what RFC 5869 §3.1
    # describes as acceptable.
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=purpose.value.encode(),
    ).derive(secret_key.encode())


def _subkeys_for(purpose: KeyPurpose) -> tuple[bytes, ...]:
    """Return the subkeys for ``purpose``: primary first, then rotation fallbacks.

    Args:
        purpose: The job the keys will be used for.

    Returns:
        A non-empty tuple of 32-byte subkeys. Index 0 is derived from
        ``AuthSettings.secret_key`` and is the only one used to produce new
        digests; the rest come from ``AuthSettings.secret_key_fallbacks`` and are
        accepted on verification only.

    Raises:
        RuntimeError: If JAFAAL has not been configured.
    """
    global _subkeys, _subkeys_generation
    generation = jafaal_settings.settings_generation()
    if _subkeys_generation != generation:
        _subkeys = {}
        _subkeys_generation = generation
    cached = _subkeys.get(purpose.value)
    if cached is None:
        settings = jafaal_settings.get_settings()
        cached = (
            _derive(settings.secrets.secret_key, purpose),
            *(_derive(fallback, purpose) for fallback in settings.secrets.secret_key_fallbacks),
        )
        _subkeys[purpose.value] = cached
    return cached


def _subkey(purpose: KeyPurpose) -> bytes:
    """Return the primary HKDF-SHA256 subkey for ``purpose``.

    Args:
        purpose: The job the key will be used for.

    Returns:
        A 32-byte subkey derived from ``AuthSettings.secret_key``.

    Raises:
        RuntimeError: If JAFAAL has not been configured.
    """
    return _subkeys_for(purpose)[0]


def hmac_sha256(value: str, purpose: KeyPurpose) -> str:
    """Return the keyed HMAC-SHA256 hex digest of ``value`` for ``purpose``.

    The key is the *primary* per-purpose subkey derived from
    ``AuthSettings.secret_key``, so the digest is unforgeable without the server
    secret and cannot be replayed across purposes — while remaining
    microseconds-fast (unlike Argon2, which is designed for password storage).

    This is the **write** side: new digests are always produced under the primary
    key. To match a *stored* digest use :func:`digest_candidates` (for an indexed
    lookup) or :func:`verify_hmac` (for a direct comparison), both of which also
    accept digests written before a ``secret_key`` rotation.

    Args:
        value: The plaintext token to hash.
        purpose: The job this digest is for; selects the subkey.

    Returns:
        Lowercase hex-encoded HMAC-SHA256 digest (64 chars).

    Raises:
        RuntimeError: If JAFAAL has not been configured.
    """
    return hmac.new(_subkey(purpose), value.encode(), hashlib.sha256).hexdigest()


def digest_candidates(value: str, purpose: KeyPurpose) -> tuple[str, ...]:
    """Return every digest ``value`` could have been stored as, primary first.

    A stored digest is keyed by the ``secret_key`` that was primary when it was
    written, so after a rotation the live digest of a still-valid token no longer
    equals the one in the database. Callers that locate a row **by** its digest
    (API keys, password-reset / sign-up / IdP-link tokens, rotated refresh
    tokens) must therefore try each candidate — primary first, then one per
    ``AuthSettings.secret_key_fallbacks`` entry — instead of a single equality
    lookup, or a ``secret_key`` rotation would silently invalidate every one of
    those tokens.

    Args:
        value: The plaintext token to hash.
        purpose: The job the digest is for; selects the subkeys.

    Returns:
        Lowercase hex digests, ordered primary-first. Always at least one entry.

    Raises:
        RuntimeError: If JAFAAL has not been configured.
    """
    return tuple(hmac.new(key, value.encode(), hashlib.sha256).hexdigest() for key in _subkeys_for(purpose))


def verify_hmac(value: str, purpose: KeyPurpose, stored_digest: str) -> bool:
    """Verify ``value`` against a stored digest, accepting rotation fallbacks.

    Compares in constant time against the primary digest and then each
    rotation-fallback digest, so a token whose digest was written before a
    ``secret_key`` rotation keeps verifying during the overlap window. Every
    candidate is compared (no early exit on the first mismatch) so the number of
    comparisons does not depend on which key matched.

    Args:
        value: The plaintext token presented by the caller.
        purpose: The job the digest is for; selects the subkeys.
        stored_digest: The digest persisted alongside the record.

    Returns:
        True when ``value`` matches ``stored_digest`` under any active key.

    Raises:
        RuntimeError: If JAFAAL has not been configured.
    """
    matched = False
    for candidate in digest_candidates(value, purpose):
        matched |= hmac.compare_digest(candidate, stored_digest)
    return matched


def generate_token_and_hash(purpose: KeyPurpose) -> tuple[str, str]:
    """Generate a high-entropy opaque token and its keyed lookup digest.

    Used to mint single-purpose tokens (password-reset, sign-up). Only the digest
    is persisted; the plaintext token is delivered to the user and never stored.

    Args:
        purpose: The job the digest is for; selects the subkey.

    Returns:
        Tuple ``(token, token_hash)``: a 256-bit ``secrets.token_urlsafe(32)``
        plaintext token and its :func:`hmac_sha256` digest.
    """
    token = secrets.token_urlsafe(32)
    return token, hmac_sha256(token, purpose)
