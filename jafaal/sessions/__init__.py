"""
Session management module.

This module provides session management including CRUD operations,
device detection, timeout validation, and token rotation.
"""

from .crud import (
    claim_session_for_rotation,
    create_session,
    delete_idle_sessions,
    delete_session,
    delete_sessions_by_family,
    get_session_by_id,
    get_session_by_id_not_expired,
    get_session_with_oauth_state,
    get_user_sessions,
    mark_tokens_exchanged,
)
from .models import UsersSessions as UsersSessionsModel
from .schema import (
    UsersSessionsBase,
    UsersSessionsInternal,
    UsersSessionsRead,
)
from .utils import (
    DeviceInfo,
    DeviceType,
    cleanup_idle_sessions,
    create_session_object,
    edit_session_object,
    get_user_agent,
    parse_user_agent,
    rotate_session,
    session_absolute_deadline,
    session_expires_at,
    validate_session_timeout,
)

__all__ = [
    "DeviceInfo",
    "DeviceType",
    "UsersSessionsBase",
    "UsersSessionsInternal",
    "UsersSessionsModel",
    "UsersSessionsRead",
    "claim_session_for_rotation",
    "cleanup_idle_sessions",
    "create_session",
    "create_session_object",
    "delete_idle_sessions",
    "delete_session",
    "delete_sessions_by_family",
    "edit_session_object",
    "get_session_by_id",
    "get_session_by_id_not_expired",
    "get_session_with_oauth_state",
    "get_user_agent",
    "get_user_sessions",
    "mark_tokens_exchanged",
    "parse_user_agent",
    "rotate_session",
    "session_absolute_deadline",
    "session_expires_at",
    "validate_session_timeout",
]
