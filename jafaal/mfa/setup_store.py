"""Temporary MFA setup secret storage with TTL, backed by the configured state store.

The plaintext TOTP secret is Fernet-encrypted in this module and only the
ciphertext is handed to the configured :class:`~jafaal.state_store.StateStore`
(an in-process dict by default, a distributed backend when the host configures
one); this module no longer knows which backend is used.
"""

import logging
from typing import NoReturn

import jafaal.settings as jafaal_settings
from jafaal._core import crypto, hashing
from jafaal.exceptions import StoreUnavailableError
from jafaal.orm import UserId
from jafaal.state_store import (
    StateStore,
    StateStoreUnavailableError,
    get_state_store,
    raise_store_unavailable,
)

logger = logging.getLogger(__name__)

_DEFAULT_TTL_SECONDS: int = 300


def _mfa_secret_key_prefix() -> str:
    """Return the namespace prefix for MFA setup-secret store keys."""
    return f"{jafaal_settings.get_settings().store_key_prefix}:mfa:setup_secret"


class MFASecretStoreUnavailableError(StoreUnavailableError):
    """
    Raised when MFA secret storage cannot be reached.

    Attributes:
        None.
    """


def _raise_store_unavailable(operation: str, err: StateStoreUnavailableError) -> NoReturn:
    """
    Log a storage outage and re-raise it as an MFA-store error.

    Args:
        operation: Storage operation that failed.
        err: The provider outage error.

    Raises:
        MFASecretStoreUnavailableError: Always raised.
    """
    raise_store_unavailable(
        err,
        error_cls=MFASecretStoreUnavailableError,
        label="MFA secret storage failed",
        message="MFA secret storage is unavailable",
        operation=operation,
        logger=logger,
    )


def _user_id_digest(user_id: UserId) -> str:
    """
    Hash a user ID for storage key names.

    Args:
        user_id: User ID to hash.

    Returns:
        SHA-256 digest for use in the storage key.

    Raises:
        None.
    """
    return hashing.sha256_hex(str(user_id))


def _encrypt_secret(secret: str) -> str:
    """
    Encrypt a plaintext MFA secret.

    Args:
        secret: Plaintext MFA setup secret.

    Returns:
        Fernet-encrypted secret.

    Raises:
        ValueError: When encryption returns no value.
        JafaalError: When Fernet encryption fails.
    """
    encrypted_secret = crypto.encrypt_token_fernet(secret)
    if not encrypted_secret:
        raise ValueError("Failed to encrypt MFA secret")
    return encrypted_secret


def _decrypt_secret(encrypted_secret: str, user_id: UserId) -> str | None:
    """
    Decrypt an encrypted MFA secret.

    Args:
        encrypted_secret: Fernet-encrypted MFA setup secret.
        user_id: User ID used for sanitized logging.

    Returns:
        Decrypted MFA setup secret, or None on failure.

    Raises:
        None.
    """
    try:
        return crypto.decrypt_token_fernet(encrypted_secret)
    except Exception as err:
        logger.error(f"Failed to decrypt MFA secret for user {user_id}: {type(err).__name__}", exc_info=err)
        return None


def _log_secret_stored(user_id: UserId, ttl_seconds: int) -> None:
    """
    Log MFA secret storage without exposing the secret.

    Args:
        user_id: User ID associated with the setup secret.
        ttl_seconds: Secret time-to-live in seconds.

    Returns:
        None.

    Raises:
        None.
    """
    logger.debug(f"Securely stored MFA secret for user {user_id} (expires in {ttl_seconds}s)")


class MFASecretStore:
    """
    Temporary encrypted MFA setup-secret storage backed by the platform state.

    Attributes:
        DEFAULT_TTL_SECONDS: Default secret lifetime in seconds.
        _state_override: Explicit provider (tests); ``None`` resolves the
            process-wide provider lazily at call time.
        _ttl_seconds: Secret lifetime in seconds.
    """

    DEFAULT_TTL_SECONDS: int = _DEFAULT_TTL_SECONDS

    def __init__(self, state: StateStore | None = None, ttl_seconds: int = _DEFAULT_TTL_SECONDS) -> None:
        """
        Initialize the MFA secret store.

        Args:
            state: Optional explicit state store (defaults to the configured one).
            ttl_seconds: Time-to-live for secrets in seconds.
        """
        self._state_override = state
        self._ttl_seconds = ttl_seconds

    @property
    def _state(self) -> StateStore:
        return self._state_override if self._state_override is not None else get_state_store()

    def _key(self, user_id: UserId) -> str:
        """Build the storage key for a user's pending MFA secret."""
        return f"{_mfa_secret_key_prefix()}:{_user_id_digest(user_id)}"

    def add_secret(self, user_id: UserId, secret: str) -> None:
        """
        Encrypt and store an MFA setup secret with TTL.

        Args:
            user_id: User ID to associate with the secret.
            secret: Plaintext MFA secret to encrypt and store.

        Raises:
            MFASecretStoreUnavailableError: When storage is unavailable.
            ValueError: If encryption fails.
            JafaalError: If Fernet encryption fails.
        """
        encrypted_secret = _encrypt_secret(secret)
        try:
            self._state.set(self._key(user_id), encrypted_secret.encode(), ttl_seconds=self._ttl_seconds)
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("add MFA setup secret", err)
        _log_secret_stored(user_id, self._ttl_seconds)

    def get_secret(self, user_id: UserId) -> str | None:
        """
        Retrieve and decrypt an MFA secret if present.

        Args:
            user_id: User ID to retrieve the secret for.

        Returns:
            Decrypted MFA secret, or None when missing or invalid.

        Raises:
            MFASecretStoreUnavailableError: When storage is unavailable.
        """
        try:
            encrypted_secret = self._state.get(self._key(user_id))
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("get MFA setup secret", err)
        if encrypted_secret is None:
            return None
        return _decrypt_secret(encrypted_secret.decode(), user_id)

    def delete_secret(self, user_id: UserId) -> None:
        """
        Remove an MFA secret from storage.

        Failures are swallowed because the entry expires via TTL anyway.

        Args:
            user_id: User ID whose secret should be removed.

        Returns:
            None.
        """
        try:
            self._state.delete(self._key(user_id))
        except StateStoreUnavailableError as err:
            logger.warning("Failed to delete MFA setup secret; entry will expire naturally via TTL", exc_info=err)

    def has_secret(self, user_id: UserId) -> bool:
        """
        Check if a non-expired secret exists for a user.

        Args:
            user_id: User ID to check.

        Returns:
            True if a secret exists, False otherwise.

        Raises:
            MFASecretStoreUnavailableError: When storage is unavailable.
        """
        try:
            return self._state.get(self._key(user_id)) is not None
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("check MFA setup secret", err)

    def clear_all(self) -> None:
        """
        Remove all MFA setup secrets from storage.

        Returns:
            None.

        Raises:
            MFASecretStoreUnavailableError: When storage is unavailable.
        """
        try:
            self._state.delete_prefix(f"{_mfa_secret_key_prefix()}:")
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("clear MFA setup secrets", err)


mfa_secret_store = MFASecretStore()


def get_mfa_secret_store() -> MFASecretStore:
    """
    Get the module-level MFA secret store instance.

    Returns:
        The global MFA secret store instance.

    Raises:
        None.
    """
    return mfa_secret_store
