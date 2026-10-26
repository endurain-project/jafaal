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
import jafaal.identity_providers.models as idp_models
import jafaal.ports as jafaal_ports
import jafaal.schema as jafaal_schema
import jafaal.webauthn.crud as jafaal_webauthn_crud
from jafaal._core import network
from jafaal.orm import UserId

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from jafaal.identity_service import LocalCredentialStore


def generate_link_token(
    idp_id: int,
    link_request: idp_link_token_schema.IdpLinkTokenRequest,
    request: Request,
    token_user_id: UserId,
    identity_service: LocalCredentialStore,
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


def _has_other_sign_in_method(user_id: UserId, idp_id: int, db: Session) -> bool:
    """Return whether the account could still sign in without this link.

    True when it has a local password, a registered passkey, or another
    identity-provider link. What the account *can* use is counted, not what
    :class:`~jafaal.ports.LoginMethods` allows right now: that policy changes
    at runtime and must not decide whether an account is stranded.
    """
    if jafaal_credentials_crud.get_credential(user_id, db) is not None:
        return True
    if jafaal_webauthn_crud.user_has_credentials(user_id, db):
        return True
    links = jafaal_identity_links_crud.get_user_identity_providers_by_user_id(user_id, db)
    return any(link.idp_id != idp_id for link in links)


def _require_link(user_id: UserId, idp_id: int, db: Session, *, whose: str) -> idp_models.IdentityProvider:
    """Return the provider, asserting the user is linked to it (404 otherwise)."""
    idp = idp_crud.get_identity_provider(idp_id, db)
    if idp is None:
        raise jafaal_exceptions.NotFoundError(f"Identity provider with id {idp_id} not found")
    if not jafaal_identity_links_crud.get_user_identity_provider_by_user_id_and_idp_id(user_id, idp_id, db):
        raise jafaal_exceptions.NotFoundError(f"Identity provider {idp.name} is not linked to {whose}")
    return idp


def prepare_identity_provider_unlink(
    idp_id: int,
    step_up: jafaal_schema.StepUpVerification,
    token_user_id: UserId,
    identity_service: LocalCredentialStore,
    step_up_store: jafaal_security_stores.StepUpStore,
    db: Session,
) -> None:
    """Run every check an owner's unlink must pass, changing nothing.

    Step-up verification, then that the link exists, then the last-sign-in-method
    rule. Split from :func:`finalize_identity_provider_unlink` so the route can
    revoke the provider's tokens (a network call) between the two, and only once
    the unlink is certain to go ahead.

    Raises:
        JafaalError: Step-up errors; 404 if the provider or link does not exist;
            :class:`~jafaal.exceptions.LastSignInMethodError` if it is the
            account's only way to sign in.
    """
    step_up_service.verify_step_up_credentials(
        token_user_id,
        step_up.current_password,
        step_up.mfa_code,
        identity_service,
        step_up_store,
        db,
    )
    _require_link(token_user_id, idp_id, db, whose="your account")
    if not _has_other_sign_in_method(token_user_id, idp_id, db):
        raise jafaal_exceptions.LastSignInMethodError(
            "Cannot unlink your last sign-in method. Set a password or register a passkey first."
        )


def check_admin_identity_provider_unlink(user_id: UserId, idp_id: int, db: Session, *, force: bool = False) -> None:
    """Run the checks for an administrator's unlink, changing nothing.

    Raises:
        JafaalError: 404 if the provider or link does not exist;
            :class:`~jafaal.exceptions.LastSignInMethodError` if it is the
            account's only way to sign in and ``force`` is not set.
    """
    _require_link(user_id, idp_id, db, whose="this user")
    if not force and not _has_other_sign_in_method(user_id, idp_id, db):
        raise jafaal_exceptions.LastSignInMethodError(
            "Cannot unlink the user's last sign-in method (no password, no passkey, no other link). "
            "Pass force=true to remove it anyway and leave the account unable to sign in."
        )


def finalize_identity_provider_unlink(
    user_id: UserId,
    idp_id: int,
    db: Session,
    *,
    by_admin: bool,
    actor_user_id: UserId | None = None,
    forced: bool = False,
) -> None:
    """Delete the link, audit it, and tell the account owner.

    Local only: the link's stored provider tokens are cleared with it, but
    revoking them *at the provider* is a network call the route makes first (see
    :meth:`~jafaal.identity_providers.service.IdentityProviderService.revoke_idp_token`).

    Raises:
        JafaalError: 404 if the link does not exist; 500 if the delete fails.
    """
    idp = _require_link(user_id, idp_id, db, whose="this user")
    user = jafaal_ports.get_user_repository().get_by_id(user_id, db)

    if not jafaal_identity_links_crud.delete_user_identity_provider(user_id, idp_id, db):
        raise jafaal_exceptions.InternalError("Failed to unlink identity provider")

    logger.info(f"IdP unlinked for user {user_id}: idp_id={idp_id} ({idp.name}) by_admin={by_admin}")
    jafaal_audit.record(
        jafaal_audit.Event.IDP_LINK_REMOVED,
        level=logging.WARNING,
        user_id=user_id,
        idp_id=idp_id,
        idp=idp.name,
        actor="admin" if by_admin else "self",
        actor_user_id=actor_user_id,
        forced=forced,
    )
    jafaal_ports.dispatch_event(
        "on_idp_account_unlinked",
        jafaal_ports.IdpAccountUnlinked(
            user_id=user_id,
            username=user.username if user is not None else "",
            idp_name=idp.name,
            idp_slug=idp.slug,
            by_admin=by_admin,
        ),
    )


def delete_identity_provider_link(
    idp_id: int,
    step_up: jafaal_schema.StepUpVerification,
    token_user_id: UserId,
    identity_service: LocalCredentialStore,
    step_up_store: jafaal_security_stores.StepUpStore,
    db: Session,
) -> None:
    """Unlink an IdP for its owner: step-up, anti-lockout check, then delete.

    Local only; it does not revoke the provider's tokens at the provider. The
    unlink route does, between :func:`prepare_identity_provider_unlink` and
    :func:`finalize_identity_provider_unlink`.
    """
    prepare_identity_provider_unlink(idp_id, step_up, token_user_id, identity_service, step_up_store, db)
    finalize_identity_provider_unlink(token_user_id, idp_id, db, by_admin=False, actor_user_id=token_user_id)


def admin_delete_identity_provider_link(
    user_id: UserId,
    idp_id: int,
    db: Session,
    *,
    force: bool = False,
    actor_user_id: UserId | None = None,
) -> None:
    """Unlink an IdP from a user as an administrator.

    Unlike :func:`delete_identity_provider_link` this acts on another user's
    account and requires no step-up from the caller: the route's
    ``identity_providers:write`` scope and the object-level access check are the
    authorization.

    Args:
        user_id: ID of the user to unlink the IdP from.
        idp_id: ID of the identity provider to unlink.
        db: Database session.
        force: Remove the link even when it is the account's last sign-in
            method. The account is then unable to sign in until a password is
            set by reset or an administrator.
        actor_user_id: The administrator, for the audit record.

    Raises:
        JafaalError: 404 if the IdP or the link does not exist;
            :class:`~jafaal.exceptions.LastSignInMethodError` if it is the
            account's last sign-in method and ``force`` is not set; 500 if the
            deletion fails.
    """
    check_admin_identity_provider_unlink(user_id, idp_id, db, force=force)
    finalize_identity_provider_unlink(
        user_id,
        idp_id,
        db,
        by_admin=True,
        actor_user_id=actor_user_id,
        forced=force,
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
