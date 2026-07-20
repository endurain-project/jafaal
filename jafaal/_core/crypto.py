"""Fernet symmetric encryption for at-rest auth secrets.

Encrypts and decrypts IdP client id/secret, MFA secrets, and rotated
refresh tokens using the Fernet key supplied through
:class:`jafaal.settings.AuthSettings`. The library never reads the key from the
environment itself.
"""

from __future__ import annotations

import logging

from cryptography.fernet import Fernet
from fastapi import HTTPException, status

import jafaal.settings as jafaal_settings

logger = logging.getLogger(__name__)


def _create_cipher() -> Fernet:
    """Build a Fernet cipher from the configured key.

    Returns:
        A Fernet cipher initialised with ``AuthSettings.fernet_key``.

    Raises:
        HTTPException: 500 if the key is missing or malformed.
    """
    try:
        key = jafaal_settings.get_settings().fernet_key
        return Fernet(key.encode())
    except Exception as err:
        logger.error(f"Error in _create_cipher: {type(err).__name__}", exc_info=err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        ) from err


def encrypt_token_fernet(token: object | None) -> str | None:
    """Encrypt a token with Fernet symmetric encryption.

    Args:
        token: Token value to encrypt, or None.

    Returns:
        Encrypted token string, or None when input is None.

    Raises:
        HTTPException: 500 if encryption fails.
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        ) from err


def decrypt_token_fernet(encrypted_token: str | None) -> str | None:
    """Decrypt a Fernet-encrypted token.

    Args:
        encrypted_token: Encrypted token string, or None.

    Returns:
        Decrypted token string, or None when input is None.

    Raises:
        HTTPException: 500 if decryption fails.
    """
    try:
        if encrypted_token is None:
            return None

        cipher = _create_cipher()

        return cipher.decrypt(encrypted_token.encode()).decode()
    except Exception as err:
        logger.error(f"Error in decrypt_token_fernet: {type(err).__name__}", exc_info=err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        ) from err
