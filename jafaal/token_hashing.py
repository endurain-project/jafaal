"""Shared hashing helpers for opaque auth tokens.

Centralizes the two token-hashing strategies used across the auth token
modules so the choice is made in one place and cannot drift:

- :func:`sha256_hex` — plain SHA-256 hex digest. Used for high-entropy,
  single-purpose opaque tokens (API keys, password-reset, sign-up, and IdP
  link tokens). These are 256-bit ``secrets.token_urlsafe(32)`` values, so a
  slow KDF (Argon2/bcrypt) is unnecessary; SHA-256 is the standard choice for
  hashing tokens of this entropy level.
- :func:`hmac_sha256` — keyed HMAC-SHA256 using the configured signing secret
  (``AuthSettings.secret_key``).
  Used for refresh-token reuse detection and CSRF tokens, where a keyed MAC
  adds defense-in-depth: even with database read access an attacker cannot
  verify stolen tokens without the server secret.

Both return a lowercase hex digest and are deterministic, enabling indexed
equality lookups.
"""

import hashlib
import hmac
import secrets

import jafaal.settings as jafaal_settings
from jafaal._core import hashing


def sha256_hex(value: str) -> str:
    """Return the SHA-256 hex digest of ``value``.

    Args:
        value: The plaintext token to hash.

    Returns:
        Lowercase hex-encoded SHA-256 digest (64 chars).
    """
    return hashing.sha256_hex(value)


def hmac_sha256(value: str) -> str:
    """Return the keyed HMAC-SHA256 hex digest of ``value``.

    Uses the configured signing secret (``AuthSettings.secret_key``) as the
    HMAC key so the digest is unforgeable without the server secret, while
    remaining microseconds-fast (unlike Argon2, which is designed for password
    storage).

    Args:
        value: The plaintext token to hash.

    Returns:
        Lowercase hex-encoded HMAC-SHA256 digest (64 chars).

    Raises:
        RuntimeError: If JAFAAL has not been configured.
    """
    secret_key = jafaal_settings.get_settings().secret_key
    return hmac.new(
        secret_key.encode(),
        value.encode(),
        hashlib.sha256,
    ).hexdigest()


def generate_token_and_hash() -> tuple[str, str]:
    """Generate a high-entropy opaque token and its SHA-256 lookup hash.

    Used to mint single-purpose tokens (password-reset, sign-up). Only the hash
    is persisted; the plaintext token is delivered to the user and never stored.

    Returns:
        Tuple ``(token, token_hash)``: a 256-bit ``secrets.token_urlsafe(32)``
        plaintext token and its :func:`sha256_hex` digest.
    """
    token = secrets.token_urlsafe(32)
    return token, sha256_hex(token)
