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
    #: Digest of an identity-provider account-link token.
    IDP_LINK = "jafaal/v1/idp-link"
    #: Opaque WebAuthn user handle.
    WEBAUTHN_USER_HANDLE = "jafaal/v1/webauthn-user-handle"


# Derived subkeys, cached per settings generation so a reconfigure rebuilds them
# (mirroring the token manager and password hasher).
_subkeys: dict[str, bytes] = {}
_subkeys_generation: int = -1


def _subkey(purpose: KeyPurpose) -> bytes:
    """Return the HKDF-SHA256 subkey for ``purpose``.

    Args:
        purpose: The job the key will be used for.

    Returns:
        A 32-byte subkey derived from ``AuthSettings.secret_key``.

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
        # No salt: the input keying material is already a high-entropy secret
        # (>= 32 chars, enforced at construction), so HKDF is used purely for
        # domain separation via ``info`` — which is exactly what RFC 5869 §3.1
        # describes as acceptable.
        cached = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=purpose.value.encode(),
        ).derive(jafaal_settings.get_settings().secret_key.encode())
        _subkeys[purpose.value] = cached
    return cached


def hmac_sha256(value: str, purpose: KeyPurpose) -> str:
    """Return the keyed HMAC-SHA256 hex digest of ``value`` for ``purpose``.

    The key is a per-purpose subkey derived from ``AuthSettings.secret_key``, so
    the digest is unforgeable without the server secret and cannot be replayed
    across purposes — while remaining microseconds-fast (unlike Argon2, which is
    designed for password storage).

    Args:
        value: The plaintext token to hash.
        purpose: The job this digest is for; selects the subkey.

    Returns:
        Lowercase hex-encoded HMAC-SHA256 digest (64 chars).

    Raises:
        RuntimeError: If JAFAAL has not been configured.
    """
    return hmac.new(_subkey(purpose), value.encode(), hashlib.sha256).hexdigest()


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
