"""
API key management module.

This module provides API key lifecycle management including
creation, validation, revocation, and deletion.
"""

from .crud import (
    create_api_key,
    delete_api_key,
    get_api_key_by_hash,
    get_api_key_by_id,
    get_api_keys_by_user_id,
    revoke_api_key,
    update_last_used,
)
from .models import UsersApiKeys as UsersApiKeysModel
from .schema import (
    UsersApiKeyCreate,
    UsersApiKeyCreated,
    UsersApiKeyRead,
)
from .utils import (
    configure_api_key_scopes,
    generate_api_key,
    get_api_key_scopes,
    hash_api_key,
    reset_api_key_scopes,
    validate_api_key_scopes,
)

__all__ = [
    "UsersApiKeyCreate",
    "UsersApiKeyCreated",
    "UsersApiKeyRead",
    "UsersApiKeysModel",
    "configure_api_key_scopes",
    "create_api_key",
    "delete_api_key",
    "generate_api_key",
    "get_api_key_by_hash",
    "get_api_key_by_id",
    "get_api_key_scopes",
    "get_api_keys_by_user_id",
    "hash_api_key",
    "reset_api_key_scopes",
    "revoke_api_key",
    "update_last_used",
    "validate_api_key_scopes",
]
