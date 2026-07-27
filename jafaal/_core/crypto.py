"""Fernet symmetric encryption for at-rest auth secrets.

Encrypts and decrypts IdP client id/secret, MFA secrets, and rotated
refresh tokens using the Fernet key supplied through
:class:`jafaal.settings.AuthSettings`. The library never reads the key from the
environment itself.
"""

from __future__ import annotations

import logging

from cryptography.fernet import Fernet, MultiFernet

import jafaal.exceptions as jafaal_exceptions
import jafaal.settings as jafaal_settings

logger = logging.getLogger(__name__)


def _create_cipher() -> MultiFernet:
    """Build a MultiFernet from the primary key plus any rotation fallbacks.

    Encryption always uses the primary ``fernet_key`` (the first key); decryption
    tries the primary and then each ``AuthSettings.fernet_key_fallbacks`` entry in
    order. That is what makes key rotation possible: put a freshly generated key
    first and keep the previous key as a fallback, and secrets written under
    either key still decrypt — no bulk re-encrypt required.

    Returns:
        A MultiFernet cipher over ``[fernet_key, *fernet_key_fallbacks]``.

    Raises:
        InternalError: 500 if a key is missing or malformed.
    """
    try:
        settings = jafaal_settings.get_settings()
        keys = [Fernet(settings.secrets.fernet_key.encode())]
        keys.extend(Fernet(fallback.encode()) for fallback in settings.secrets.fernet_key_fallbacks)
        return MultiFernet(keys)
    except Exception as err:
        logger.error(f"Error in _create_cipher: {type(err).__name__}", exc_info=err)
        raise jafaal_exceptions.InternalError() from err


def encrypt_token_fernet(token: object | None) -> str | None:
    """Encrypt a token with Fernet symmetric encryption.

    Args:
        token: Token value to encrypt, or None.

    Returns:
        Encrypted token string, or None when input is None.

    Raises:
        InternalError: 500 if encryption fails.
    """
    try:
        if token is None:
            return None

        cipher = _create_cipher()

        if not isinstance(token, str):
            token = str(token)

        return cipher.encrypt(token.encode()).decode()
    except Exception as err:
        logger.error(f"Error in encrypt_token_fernet: {type(err).__name__}", exc_info=err)
        raise jafaal_exceptions.InternalError() from err


def decrypt_token_fernet(encrypted_token: str | None) -> str | None:
    """Decrypt a Fernet-encrypted token.

    Args:
        encrypted_token: Encrypted token string, or None.

    Returns:
        Decrypted token string, or None when input is None.

    Raises:
        InternalError: 500 if decryption fails.
    """
    try:
        if encrypted_token is None:
            return None

        cipher = _create_cipher()

        return cipher.decrypt(encrypted_token.encode()).decode()
    except Exception as err:
        logger.error(f"Error in decrypt_token_fernet: {type(err).__name__}", exc_info=err)
        raise jafaal_exceptions.InternalError() from err
