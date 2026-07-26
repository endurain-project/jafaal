"""Auth-owned identity-provider link workflows exposed to profile routes."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import Request
from sqlalchemy.orm import Session

import jafaal._internal.security_stores as jafaal_security_stores
import jafaal._internal.services.step_up_service as step_up_service
import jafaal.audit as jafaal_audit
import jafaal.credentials.crud as jafaal_credentials_crud
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.link_tokens.crud as idp_link_token_crud
import jafaal.identity_providers.link_tokens.schema as idp_link_token_schema
import jafaal.identity_providers.link_tokens.utils as idp_link_token_utils
import jafaal.identity_providers.links.crud as jafaal_identity_links_crud
import jafaal.identity_providers.links.schema as jafaal_identity_links_schema
import jafaal.identity_providers.links.utils as jafaal_identity_links_utils
import jafaal.schema as jafaal_schema
from jafaal._core import network
from jafaal.orm import UserId

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from jafaal.identity_service import IdentityService


def generate_link_token(
    idp_id: int,
    link_request: idp_link_token_schema.IdpLinkTokenRequest,
    request: Request,
    token_user_id: UserId,
    identity_service: IdentityService,
    step_up_store: jafaal_security_stores.StepUpStore,
    db: Session,
) -> idp_link_token_schema.IdpLinkTokenResponse:
    """Generate a one-time IdP link token after step-up verification."""
    step_up_service.verify_step_up_credentials(
        token_user_id,
        link_request.current_password,
        link_request.mfa_code,
        identity_service,
        step_up_store,
        db,
    )

    idp = idp_crud.get_identity_provider(idp_id, db)
    if not idp or not idp.enabled:
        raise jafaal_exceptions.NotFoundError("Identity provider not found or disabled")

    existing_link = jafaal_identity_links_crud.get_user_identity_provider_by_user_id_and_idp_id(
        token_user_id,
        idp_id,
        db,
    )
    if existing_link:
        raise jafaal_exceptions.ConflictError(f"Identity provider {idp.name} is already linked to your account")

    ip_address = network.get_ip_address(request)
    link_token = idp_link_token_utils.generate_idp_link_token(
        user_id=token_user_id,
        idp_id=idp_id,
        ip_address=ip_address,
        db=db,
    )

    logger.debug(f"Generated link token for user {token_user_id}, idp_id={idp_id} ({idp.name})")

    return link_token


def delete_identity_provider_link(
    idp_id: int,
    step_up: jafaal_schema.StepUpVerification,
    token_user_id: UserId,
    identity_service: IdentityService,
    step_up_store: jafaal_security_stores.StepUpStore,
    db: Session,
) -> None:
    """Unlink an IdP while enforcing anti-lockout checks."""
    step_up_service.verify_step_up_credentials(
        token_user_id,
        step_up.current_password,
        step_up.mfa_code,
        identity_service,
        step_up_store,
        db,
    )

    idp = idp_crud.get_identity_provider(idp_id, db)
    if idp is None:
        raise jafaal_exceptions.NotFoundError(f"Identity provider with id {idp_id} not found")

    link = jafaal_identity_links_crud.get_user_identity_provider_by_user_id_and_idp_id(
        token_user_id,
        idp_id,
        db,
    )
    if not link:
        raise jafaal_exceptions.NotFoundError(f"Identity provider {idp.name} is not linked to your account")

    all_idp_links = jafaal_identity_links_crud.get_user_identity_providers_by_user_id(
        token_user_id,
        db,
    )
    remaining_idp_count = len(all_idp_links) - 1

    if not identity_service.has_local_password(token_user_id) and remaining_idp_count == 0:
        raise jafaal_exceptions.InvalidRequestError(
            "Cannot unlink last authentication method. Please set a password first."
        )

    success = jafaal_identity_links_crud.delete_user_identity_provider(
        token_user_id,
        idp_id,
        db,
    )

    if not success:
        raise jafaal_exceptions.InternalError("Failed to unlink identity provider")

    logger.info(f"User {token_user_id} unlinked IdP: idp_id={idp_id} ({idp.name})")
    jafaal_audit.record(
        jafaal_audit.Event.IDP_LINK_REMOVED,
        level=logging.WARNING,
        user_id=token_user_id,
        idp_id=idp_id,
        idp=idp.name,
        actor="self",
    )


def admin_delete_identity_provider_link(
    user_id: UserId,
    idp_id: int,
    db: Session,
) -> None:
    """Unlink an IdP from a user as an administrator.

    Unlike :func:`delete_identity_provider_link`, this is an
    administrative action against another user's account: it does not
    require step-up verification from the caller (authorization is
    enforced by the ``users:write`` scope on the route).

    Args:
        user_id: ID of the user to unlink the IdP from.
        idp_id: ID of the identity provider to unlink.
        db: Database session.

    Returns:
        None.

    Raises:
        JafaalError: 404 if the IdP or the user-IdP link does not
            exist, 400 if unlinking would remove the user's last
            authentication method, 500 if the deletion fails at the
            database level.
    """
    idp = idp_crud.get_identity_provider(idp_id, db)
    if idp is None:
        raise jafaal_exceptions.NotFoundError(f"Identity provider with id {idp_id} not found")

    link = jafaal_identity_links_crud.get_user_identity_provider_by_user_id_and_idp_id(
        user_id,
        idp_id,
        db,
    )
    if not link:
        raise jafaal_exceptions.NotFoundError(f"Identity provider {idp.name} is not linked to this user")

    all_idp_links = jafaal_identity_links_crud.get_user_identity_providers_by_user_id(
        user_id,
        db,
    )
    remaining_idp_count = len(all_idp_links) - 1

    has_local_password = jafaal_credentials_crud.get_credential(user_id, db) is not None
    if not has_local_password and remaining_idp_count == 0:
        raise jafaal_exceptions.InvalidRequestError(
            "Cannot unlink last authentication method. User has no password set."
        )

    success = jafaal_identity_links_crud.delete_user_identity_provider(user_id, idp_id, db)
    if not success:
        raise jafaal_exceptions.InternalError("Failed to unlink identity provider")

    logger.info(f"Admin unlinked IdP for user {user_id}: idp_id={idp_id} ({idp.name})")
    jafaal_audit.record(
        jafaal_audit.Event.IDP_LINK_REMOVED,
        level=logging.WARNING,
        user_id=user_id,
        idp_id=idp_id,
        idp=idp.name,
        actor="admin",
    )


def get_user_identity_provider_links(
    user_id: UserId,
    db: Session,
) -> list[jafaal_identity_links_schema.UsersIdentityProviderResponse]:
    """Return enriched identity provider links for the authenticated user."""
    idp_links = jafaal_identity_links_crud.get_user_identity_providers_by_user_id(user_id, db)
    return jafaal_identity_links_utils.enrich_user_identity_providers(idp_links, user_id, db)


def validate_and_claim_browser_link_token(
    link_token: str,
    idp_id: int,
    client_ip: str | None,
    db: Session,
) -> UserId:
    """Validate, IP-check, and atomically claim a browser-redirect link token.

    Encapsulates all auth-owned CRUD operations (idp_link_token_crud and
    jafaal_identity_links_crud) so that the browser redirect router does not import
    low-level auth persistence modules directly.

    Args:
        link_token: Plaintext one-time link token from query parameter.
        idp_id: The identity provider ID expected in the token.
        client_ip: Caller IP address for soft IP-match check.
        db: SQLAlchemy database session.

    Returns:
        The user ID encoded in the token.

    Raises:
        JafaalError: 401 if token is invalid, expired, or IdP mismatch.
        JafaalError: 400 if token was already used (race/replay).
        JafaalError: 409 if the IdP is already linked to the user.
    """
    # Try each candidate digest (primary key first, then any
    # secret_key_fallbacks) so a token minted just before a signing-key rotation
    # is still redeemable. The matched digest is reused for mark_token_as_used so
    # the claim targets the same row that was found.
    link_token_hash: str | None = None
    db_token = None
    for candidate in idp_link_token_utils.idp_link_token_digests(link_token):
        db_token = idp_link_token_crud.get_idp_link_token_by_hash(candidate, db)
        if db_token is not None:
            link_token_hash = candidate
            break
    if not db_token or link_token_hash is None:
        raise jafaal_exceptions.InvalidTokenError("Invalid or expired link token")

    if db_token.idp_id != idp_id:
        logger.warning(f"Link token IdP mismatch: token idp_id={db_token.idp_id}, requested idp_id={idp_id}")
        raise jafaal_exceptions.InvalidTokenError("Invalid link token for this identity provider")

    if db_token.ip_address and client_ip and db_token.ip_address != client_ip:
        logger.warning(f"Link token IP mismatch: token ip={db_token.ip_address}, request ip={client_ip}")
        # Soft check — log but don't fail (NAT, proxies, etc.)

    token_user_id = db_token.user_id
    existing_link = jafaal_identity_links_crud.get_user_identity_provider_by_user_id_and_idp_id(
        token_user_id, idp_id, db
    )
    if existing_link:
        idp = idp_crud.get_identity_provider(idp_id, db)
        idp_name = idp.name if idp else f"ID {idp_id}"
        raise jafaal_exceptions.ConflictError(f"Identity provider {idp_name} is already linked to your account")

    if not idp_link_token_crud.mark_token_as_used(link_token_hash, db):
        logger.warning(f"IdP link token replay/race rejected for user {token_user_id}: token row {db_token.id}")
        raise jafaal_exceptions.InvalidRequestError("Invalid or expired link token")

    return token_user_id


def get_identity_link_counts_for_users(
    user_ids: list[int],
    db: Session,
) -> dict[int, int]:
    """Return identity link count per user ID in a single grouped query.

    Args:
        user_ids: List of user IDs to query.
        db: SQLAlchemy database session.

    Returns:
        Dict mapping user_id to link count.
        Users with no links are absent (callers should use .get(id, 0)).
    """
    return jafaal_identity_links_crud.get_identity_link_counts_for_users(user_ids, db)
