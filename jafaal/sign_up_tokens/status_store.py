"""Opaque polling handles for pending email-verification status."""

import logging
from typing import NoReturn

import jafaal.settings as jafaal_settings
import jafaal.token_hashing as token_hashing
from jafaal.exceptions import StoreUnavailableError
from jafaal.state_store import (
    StateStore,
    StateStoreUnavailableError,
    get_state_store,
    raise_store_unavailable,
)

logger = logging.getLogger(__name__)

_DECOY_VALUE = b"decoy"
_TOKEN_VALUE_PREFIX = b"token:"


def _key_prefix() -> str:
    return f"{jafaal_settings.get_settings().store_key_prefix}:signup:status"


class SignUpStatusStoreUnavailableError(StoreUnavailableError):
    """Raised when sign-up status storage cannot be reached."""


def _raise_store_unavailable(operation: str, err: StateStoreUnavailableError) -> NoReturn:
    raise_store_unavailable(
        err,
        error_cls=SignUpStatusStoreUnavailableError,
        label="Sign-up status storage failed",
        message="Sign-up status storage is unavailable",
        operation=operation,
        logger=logger,
    )


class SignUpStatusStore:
    """Short-lived sign-up status handles backed by the configured state store."""

    def __init__(self, state: StateStore | None = None) -> None:
        self._state_override = state

    @property
    def _state(self) -> StateStore:
        return self._state_override if self._state_override is not None else get_state_store()

    @staticmethod
    def _key(handle_digest: str) -> str:
        return f"{_key_prefix()}:{handle_digest}"

    def create(self, token_id: str | None, *, ttl_seconds: int) -> str:
        """Create a real or decoy status handle with the supplied lifetime."""
        handle, handle_digest = token_hashing.generate_token_and_hash(token_hashing.KeyPurpose.SIGN_UP_STATUS)
        value = _DECOY_VALUE if token_id is None else _TOKEN_VALUE_PREFIX + token_id.encode()
        try:
            self._state.set(self._key(handle_digest), value, ttl_seconds=ttl_seconds)
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("create sign-up status handle", err)
        return handle

    def resolve(self, handle: str) -> tuple[bool, str | None]:
        """Resolve a handle to ``(found, token_id)``; decoys have no token ID."""
        try:
            value = next(
                (
                    candidate
                    for digest in token_hashing.digest_candidates(handle, token_hashing.KeyPurpose.SIGN_UP_STATUS)
                    if (candidate := self._state.get(self._key(digest))) is not None
                ),
                None,
            )
        except StateStoreUnavailableError as err:
            _raise_store_unavailable("read sign-up status handle", err)

        if value is None:
            return False, None
        if value == _DECOY_VALUE:
            return True, None
        if not value.startswith(_TOKEN_VALUE_PREFIX):
            logger.warning("Ignoring malformed sign-up status state")
            return False, None
        try:
            token_id = value.removeprefix(_TOKEN_VALUE_PREFIX).decode()
        except UnicodeDecodeError:
            logger.warning("Ignoring malformed sign-up status token reference")
            return False, None
        return (True, token_id) if token_id else (False, None)


sign_up_status_store = SignUpStatusStore()


def get_sign_up_status_store() -> SignUpStatusStore:
    """Return the module-level sign-up status store."""
    return sign_up_status_store
