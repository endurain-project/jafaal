"""Public authentication dependencies for non-auth modules.

This module is the supported boundary for routers outside ``auth`` that
need identity, scope checks, or mixed JWT/API-key authentication. The
implementations delegate credential resolution to ``IdentityService`` so
callers do not import ``jafaal._internal.internal_dependencies`` directly.

``AuthContext``, the shared OAuth2/API-key schemes
(``oauth2_scheme``, ``header_client_type_scheme``, ``header_api_key_scheme``),
the principal caching helper ``_resolve_and_cache_principal``, and functions
whose implementations are identical in ``jafaal._internal.internal_dependencies`` are
re-exported from that module.  Only functions with a different FastAPI
dependency signature (using ``IdentityService`` instead of ``TokenManager``),
plus the unified ``check_auth_scopes``, are defined here.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import SecurityScopes

import jafaal._internal.security_stores as jafaal_security_stores
import jafaal.audit as jafaal_audit
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_service as jafaal_identity_service
from jafaal._internal.internal_dependencies import (
    AuthContext,
    _resolve_and_cache_principal,
    get_access_token,
    get_sid_from_access_token,
    get_sub_from_access_token,
    get_user_id_from_auth,
    validate_access_token_or_api_key,
)
from jafaal.principal import Principal


def get_current_principal(
    request: Request,
    access_token: Annotated[str, Depends(get_access_token)],
    identity_service: Annotated[
        jafaal_identity_service.IdentityService,
        Depends(jafaal_identity_service.get_identity_service),
    ],
) -> Principal:
    """Resolve (and cache) the authenticated :class:`~jafaal.principal.Principal`.

    Use this on endpoints that must apply object-level authorization (e.g.
    comparing the caller to a ``user_id`` path parameter) in addition to a
    scope check. Shares the per-request principal cache with the scope
    dependencies, so it adds no extra DB lookup.

    Args:
        request: Current HTTP request (used for caching).
        access_token: Raw JWT access token.
        identity_service: Per-request IdentityService.

    Returns:
        The resolved principal.

    Raises:
        AuthenticationError: 401 if the token is invalid or the user is
            not found/active.
    """
    return _resolve_and_cache_principal(access_token, request, identity_service)


def validate_access_token(
    request: Request,
    access_token: Annotated[str, Depends(get_access_token)],
    identity_service: Annotated[
        jafaal_identity_service.IdentityService,
        Depends(jafaal_identity_service.get_identity_service),
    ],
) -> None:
    """Validate an access token through IdentityService.

    Args:
        request: Current HTTP request.
        access_token: Raw JWT access token.
        identity_service: Per-request IdentityService.

    Raises:
        AuthenticationError: 401 if the token is invalid.
    """
    _resolve_and_cache_principal(access_token, request, identity_service)


def check_scopes(
    request: Request,
    access_token: Annotated[str, Depends(get_access_token)],
    identity_service: Annotated[
        jafaal_identity_service.IdentityService,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    security_scopes: SecurityScopes,
) -> None:
    """Validate required scopes through IdentityService.

    Args:
        request: Current HTTP request.
        access_token: Raw JWT access token.
        identity_service: Per-request IdentityService.
        security_scopes: Required scopes for the endpoint.

    Raises:
        MissingScopeError: 403 if required scopes are missing.
    """
    principal = _resolve_and_cache_principal(access_token, request, identity_service)
    identity_service.check_scope(principal, frozenset(security_scopes.scopes))


def check_auth_scopes(
    auth: Annotated[
        AuthContext,
        Depends(validate_access_token_or_api_key),
    ],
    security_scopes: SecurityScopes,
) -> None:
    """Validate scopes from a unified AuthContext.

    Use this in place of :func:`check_scopes` on endpoints that accept both
    JWT and API key auth. The underlying ``AuthContext`` is resolved by
    :func:`validate_access_token_or_api_key`, which goes through
    ``IdentityService`` (asserting the user exists and is active).

    Args:
        auth: Resolved AuthContext from validate_access_token_or_api_key.
        security_scopes: Required scopes for the endpoint.

    Raises:
        MissingScopeError: 403 if any required scope is missing from the
            AuthContext.
    """
    missing = set(security_scopes.scopes) - set(auth.scopes)
    if missing:
        jafaal_audit.record(
            jafaal_audit.Event.SCOPE_DENIED,
            outcome=jafaal_audit.Outcome.BLOCKED,
            level=logging.WARNING,
            user_id=auth.user_id,
            auth_type=auth.auth_type,
            missing=sorted(missing),
            required=sorted(security_scopes.scopes),
        )
        raise jafaal_exceptions.MissingScopeError(
            f"Unauthorized Access - Missing permissions: {' '.join(sorted(missing))}",
            missing=missing,
            required=set(security_scopes.scopes),
        )


__all__ = [
    "AuthContext",
    "StepUpStore",
    "check_auth_scopes",
    "check_scopes",
    "get_access_token",
    "get_current_principal",
    "get_sid_from_access_token",
    "get_step_up_attempts",
    "get_sub_from_access_token",
    "get_user_id_from_auth",
    "validate_access_token",
    "validate_access_token_or_api_key",
]

# Re-export step-up store type and dep getter for non-auth modules
StepUpStore = jafaal_security_stores.StepUpStore
get_step_up_attempts = jafaal_security_stores.get_step_up_attempts
