"""Service layer for identity provider OAuth2/OIDC flows."""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets as secrets_module
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, cast

import httpx
from fastapi import Request
from sqlalchemy.orm import Session

import jafaal._internal.password_hasher as jafaal_password_hasher
import jafaal._internal.security_stores as jafaal_security_stores
import jafaal.audit as jafaal_audit
import jafaal.exceptions as jafaal_exceptions
import jafaal.identity_providers.crud as idp_crud
import jafaal.identity_providers.discovery as idp_discovery
import jafaal.identity_providers.id_token as id_token_verify
import jafaal.identity_providers.links.crud as jafaal_identity_links_crud
import jafaal.identity_providers.links.models as jafaal_identity_links_models
import jafaal.identity_providers.links.utils as jafaal_identity_links_utils
import jafaal.identity_providers.models as idp_models
import jafaal.oauth_state.crud as oauth_state_crud
import jafaal.oauth_state.models as oauth_state_models
import jafaal.ports as jafaal_ports
import jafaal.settings as jafaal_settings
from jafaal._core import crypto, network, optional_deps, timeutils
from jafaal.orm import UserId

# Single sign-on relies on authlib's OAuth2 client, shipped as the optional
# ``jafaal[sso]`` extra. Import defensively so ``import jafaal`` works without it;
# _oauth_client_cls() fails fast (with an install hint) when an SSO flow runs.
try:
    from authlib.integrations.httpx_client import AsyncOAuth2Client
except ImportError:  # pragma: no cover - exercised via the missing-dep guard
    AsyncOAuth2Client = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# Constants for token rotation policy
MAX_IDP_TOKEN_AGE_DAYS = 90
TOKEN_EXPIRY_THRESHOLD_MINUTES = 5
TOKEN_REFRESH_RATE_LIMIT_MINUTES = 1
DEFAULT_TOKEN_EXPIRY_SECONDS = 300

# Clock-skew tolerance (seconds) allowed when checking the IdP-asserted
# ``auth_time`` for step-up re-authentication freshness (auth_time slightly
# ahead of the local clock is tolerated up to this bound).
_REAUTH_CLOCK_SKEW_LEEWAY_SECONDS = 30


def _oauth_client_cls() -> Any:
    """Return authlib's ``AsyncOAuth2Client``, or fail fast if ``jafaal[sso]`` is missing."""
    return optional_deps.require(AsyncOAuth2Client, package="authlib", extra="sso", feature="Single sign-on (OIDC)")


def _idp_require_https() -> bool:
    """Whether identity-provider endpoints must use https (``idp_require_https``)."""
    return jafaal_settings.get_settings().sso.idp_require_https


def _generate_pkce_verifier() -> str:
    """Generate a high-entropy PKCE ``code_verifier`` (RFC 7636).

    Returns a url-safe token of ~86 unreserved characters ([A-Za-z0-9-_]),
    comfortably within the RFC's 43-128 character range.
    """
    return secrets_module.token_urlsafe(64)


def _pkce_challenge_s256(code_verifier: str) -> str:
    """Compute the S256 PKCE ``code_challenge`` for ``code_verifier`` (RFC 7636)."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class TokenAction(Enum):
    """
    Actions to take for an IdP token based on policy evaluation.

    Attributes:
        SKIP: Token is valid, no action needed
        REFRESH: Token is close to expiry, should be refreshed
        CLEAR: Token is too old or invalid, should be cleared
    """

    SKIP = "skip"
    REFRESH = "refresh"
    CLEAR = "clear"


class IdentityProviderService:
    """Orchestrates the identity-provider login, link, and step-up flows.

    Owns the request-scoped work: building authorization URLs, redeeming the
    provider's code, mapping claims, provisioning users, and keeping stored IdP
    tokens fresh. Everything it needs to know *about* a provider — its
    ``.well-known`` document, its key set, whether an ID token is genuine — comes
    from the :class:`~jafaal.identity_providers.discovery.OidcDiscovery`
    collaborator, which owns the caches and the pooled HTTP client that work
    requires.
    """

    def __init__(self):
        """Build the service and its discovery collaborator."""
        self.discovery = idp_discovery.OidcDiscovery()

    async def aclose(self) -> None:
        """Release the pooled HTTP client and cached discovery data.

        Call from the host's ASGI lifespan shutdown (see :func:`jafaal.shutdown`).
        Delegates to the discovery collaborator, which owns the client.
        """
        await self.discovery.aclose()

    async def get_oidc_configuration(self, idp: idp_models.IdentityProvider) -> dict[str, Any] | None:
        """Return the provider's cached OIDC discovery document, or ``None``.

        Kept on the service because callers outside this module (the link and
        login routers) reach for it; the work happens in
        :class:`~jafaal.identity_providers.discovery.OidcDiscovery`.
        """
        return await self.discovery.get_oidc_configuration(idp)

    def _get_redirect_uri(self, idp_slug: str) -> str:
        """
        Generates the redirect URI for a given identity provider slug.

        Args:
            idp_slug (str): The slug identifier for the identity provider.

        Returns:
            str: The complete redirect URI for the specified identity provider.
        """
        base_url = jafaal_settings.get_settings().base_url
        return f"{base_url}/api/v1/public/idp/callback/{idp_slug}"

    def _decrypt_client_id(self, idp: idp_models.IdentityProvider) -> str:
        """
        Decrypts the client ID of the given identity provider.

        Attempts to decrypt the `client_id` attribute of the provided `IdentityProvider` instance
        using Fernet symmetric encryption. If decryption fails or returns an empty value, logs the error
        and raises an HTTP 500 exception indicating a configuration error.

        Args:
            idp (idp_models.IdentityProvider): The identity provider instance containing the encrypted client ID.

        Returns:
            str: The decrypted client ID.

        Raises:
            JafaalError: If decryption fails or returns an empty value, an HTTP 500 error is raised.
        """
        try:
            client_id = crypto.decrypt_token_fernet(idp.client_id)
            if not client_id:
                raise ValueError("Decryption returned empty value")
            return client_id
        except Exception as err:
            logger.error(f"Failed to decrypt client ID for IdP {idp.name}: {err}", exc_info=err)
            raise jafaal_exceptions.InternalError(
                f"Identity provider {idp.name} configuration error. Please contact administrator."
            ) from err

    def _decrypt_client_secret(self, idp: idp_models.IdentityProvider) -> str:
        """
        Decrypt the IdP client secret using Fernet encryption.

        This helper method centralizes client secret decryption logic to avoid code duplication
        and ensure consistent error handling across all OAuth flows.

        Args:
            idp (idp_models.IdentityProvider): The identity provider with encrypted client secret.

        Returns:
            str: The decrypted client secret.

        Raises:
            JafaalError: If decryption fails or returns empty value (500 Internal Server Error).

        Security Note:
            - Decrypted secret only exists in function scope (not logged)
            - Raises JafaalError to prevent OAuth flows with invalid credentials
        """
        try:
            client_secret = crypto.decrypt_token_fernet(idp.client_secret)
            if not client_secret:
                raise ValueError("Decryption returned empty value")
            return client_secret
        except Exception as err:
            logger.error(f"Failed to decrypt client secret for IdP {idp.name}: {err}", exc_info=err)
            raise jafaal_exceptions.InternalError(
                f"Identity provider {idp.name} configuration error. Please contact administrator."
            ) from err

    def _create_oauth_client(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str | None = None,
    ) -> AsyncOAuth2Client:
        """
        Create an OAuth2 client for communicating with IdP token endpoints.

        This helper method centralizes OAuth client creation to ensure consistent
        configuration across all OAuth flows.

        Args:
            client_id (str): The OAuth2 client ID.
            client_secret (str): The OAuth2 client secret (decrypted).
            redirect_uri (str | None): The redirect URI (required for authorization code flow).

        Returns:
            AsyncOAuth2Client: Configured OAuth2 client instance.

        Note:
            - For authorization code flow: provide redirect_uri
            - For refresh token flow: redirect_uri can be None
        """
        return _oauth_client_cls()(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            # Pin outbound token/userinfo connections to a validated public IP
            # (these carry client credentials and bearer tokens), closing the
            # DNS-rebinding TOCTOU that the pre-flight reject_private_url leaves.
            transport=network.build_ssrf_guard_transport(),
            # Token/userinfo requests carry client credentials and/or bearer
            # tokens; never follow a redirect that could replay them to an
            # attacker-controlled or internal target (also authlib's default).
            follow_redirects=False,
        )

    async def initiate_login(
        self,
        idp: idp_models.IdentityProvider,
        request: Request,
        db: Session,
        oauth_state_id: str | None = None,
    ) -> str:
        """
        Initiates the OAuth2/OIDC login process for the given identity provider.

        This method prepares the authorization URL for the user to authenticate with the specified
        identity provider (IdP). It handles endpoint discovery and authorization URL construction.


        Args:
            idp (idp_models.IdentityProvider): The identity provider instance containing configuration details.
            request (Request): The current HTTP request object.
            db (Session): The database session.
            oauth_state_id (str | None): Database OAuth state ID (from PKCE flow).

        Returns:
            str: The authorization URL to which the user should be redirected to initiate login.

        Raises:
            JafaalError: If the identity provider is not properly configured or if an error occurs during initiation.
        """
        try:
            client_id = self._decrypt_client_id(idp)

            # Get endpoints
            authorization_endpoint = idp.authorization_endpoint

            # Try OIDC discovery if issuer URL is provided
            if not authorization_endpoint and idp.issuer_url:
                config = await self.get_oidc_configuration(idp)
                if config:
                    authorization_endpoint = config.get("authorization_endpoint")

            if not authorization_endpoint:
                raise jafaal_exceptions.IdentityProviderError(
                    f"Identity provider {idp.name} authorization "
                    "endpoint could not be resolved. Verify the "
                    "issuer URL is reachable; if it is on a "
                    "private network, add its host or CIDR to "
                    "SSRF_ALLOWED_HOSTS."
                )

            # Retrieve database-backed OAuth state (mandatory for all clients)
            if not oauth_state_id:
                raise jafaal_exceptions.InternalError("OAuth state ID is required (PKCE mandatory)")

            oauth_state_obj = oauth_state_crud.get_oauth_state_by_id_and_not_used(oauth_state_id, db)
            if not oauth_state_obj:
                raise jafaal_exceptions.InternalError("OAuth state not found")

            state = oauth_state_id
            nonce = oauth_state_obj.nonce

            # Enforce encrypted transport for the browser-facing authorization
            # endpoint when idp_require_https is on (the redirect carries the
            # state, nonce and PKCE challenge to the IdP).
            if _idp_require_https():
                network.require_https_url(authorization_endpoint)

            # Build authorization URL
            redirect_uri = self._get_redirect_uri(idp.slug)
            scopes = idp.scopes or "openid profile email"

            # Upstream PKCE (RFC 7636): bind this authorization request to a
            # secret code_verifier so an intercepted authorization code cannot
            # be redeemed without it. The verifier is stored (encrypted) against
            # the OAuth state and replayed on the token exchange in handle_callback.
            code_verifier = _generate_pkce_verifier()
            oauth_state_crud.set_upstream_code_verifier(state, crypto.encrypt_token_fernet(code_verifier), db)
            code_challenge = _pkce_challenge_s256(code_verifier)

            client = _oauth_client_cls()(client_id=client_id, redirect_uri=redirect_uri, scope=scopes)

            authorization_url, _ = client.create_authorization_url(
                authorization_endpoint,
                state=state,
                nonce=nonce,
                code_challenge=code_challenge,
                code_challenge_method="S256",
            )

            return authorization_url

        except jafaal_exceptions.JafaalError:
            raise
        except Exception as err:
            logger.error(f"Error initiating OAuth login for IdP {idp.name}: {err}", exc_info=err)
            raise jafaal_exceptions.InternalError("Failed to initiate SSO login") from err

    async def initiate_link(
        self,
        idp: idp_models.IdentityProvider,
        request: Request,
        user_id: UserId,
        db: Session,
        oauth_state_id: str | None = None,
        *,
        authorize_extra_params: dict[str, str] | None = None,
    ) -> str:
        """
        Initiates an authenticated OAuth/OIDC authorization flow for an existing user account.

        Used both for linking a new identity provider and for step-up
        re-authentication (which passes ``authorize_extra_params={"prompt":
        "login", "max_age": ...}`` to force a fresh IdP sign-in). This method
        generates the authorization URL that redirects the user to the identity
        provider's login page. Uses database-backed OAuth state for security and
        replay protection.

        Args:
            idp (idp_models.IdentityProvider): The identity provider configuration object containing
                client credentials, endpoints, and other OAuth/OIDC settings.
            request (Request): The FastAPI request object used to access and store session data.
            user_id (int): The ID of the authenticated user who is linking their account to the
                identity provider.
            db (Session): The database session for database operations.
            oauth_state_id (str | None): Database OAuth state ID (required for secure linking).
            authorize_extra_params (dict[str, str] | None): Extra query parameters appended to the
                authorization request (e.g. ``prompt=login`` and ``max_age`` for step-up
                re-authentication).

        Returns:
            str: The authorization URL to redirect the user to for identity provider authentication.

        Raises:
            JafaalError:
                - 500 status code if the identity provider is not properly configured (missing
                  authorization endpoint).
                - 500 status code if OAuth state ID is missing or invalid.
                - 500 status code if any unexpected error occurs during the OAuth flow initiation.

        Note:
            - If authorization_endpoint is not directly configured, the method attempts OIDC
              discovery using the issuer_url.
            - OAuth state is stored in database with user_id to indicate link mode.
        """
        try:
            client_id = self._decrypt_client_id(idp)

            # Get endpoints
            authorization_endpoint = idp.authorization_endpoint

            # Try OIDC discovery if issuer URL is provided
            if not authorization_endpoint and idp.issuer_url:
                config = await self.get_oidc_configuration(idp)
                if config:
                    authorization_endpoint = config.get("authorization_endpoint")

            if not authorization_endpoint:
                raise jafaal_exceptions.IdentityProviderError(
                    f"Identity provider {idp.name} authorization "
                    "endpoint could not be resolved. Verify the "
                    "issuer URL is reachable; if it is on a "
                    "private network, add its host or CIDR to "
                    "SSRF_ALLOWED_HOSTS."
                )

            # Retrieve database-backed OAuth state (required for link mode)
            if not oauth_state_id:
                raise jafaal_exceptions.InternalError("OAuth state ID is required for secure linking")

            oauth_state_obj = oauth_state_crud.get_oauth_state_by_id_and_not_used(oauth_state_id, db)
            if not oauth_state_obj:
                raise jafaal_exceptions.InternalError("OAuth state not found")

            # Validate user_id matches (security check for link mode)
            if oauth_state_obj.user_id != user_id:
                raise jafaal_exceptions.InternalError("OAuth state user mismatch")

            state = oauth_state_id
            nonce = oauth_state_obj.nonce

            # Enforce encrypted transport for the browser-facing authorization
            # endpoint when idp_require_https is on (the redirect carries the
            # state, nonce and PKCE challenge to the IdP).
            if _idp_require_https():
                network.require_https_url(authorization_endpoint)

            # Build authorization URL
            redirect_uri = self._get_redirect_uri(idp.slug)
            scopes = idp.scopes or "openid profile email"

            # Upstream PKCE (RFC 7636): bind this authorization request to a
            # secret code_verifier so an intercepted authorization code cannot
            # be redeemed without it. The verifier is stored (encrypted) against
            # the OAuth state and replayed on the token exchange in handle_callback.
            code_verifier = _generate_pkce_verifier()
            oauth_state_crud.set_upstream_code_verifier(state, crypto.encrypt_token_fernet(code_verifier), db)
            code_challenge = _pkce_challenge_s256(code_verifier)

            client = _oauth_client_cls()(client_id=client_id, redirect_uri=redirect_uri, scope=scopes)

            authorization_url, _ = client.create_authorization_url(
                authorization_endpoint,
                state=state,
                nonce=nonce,
                code_challenge=code_challenge,
                code_challenge_method="S256",
                **(authorize_extra_params or {}),
            )

            return authorization_url

        except jafaal_exceptions.JafaalError:
            raise
        except Exception as err:
            logger.error(f"Error initiating OAuth link for IdP {idp.name}, user {user_id}: {err}", exc_info=err)
            raise jafaal_exceptions.InternalError("Failed to initiate identity provider linking") from err

    async def handle_callback(
        self,
        idp: idp_models.IdentityProvider,
        code: str,
        state: str,
        request: Request,
        password_hasher: jafaal_password_hasher.PasswordHasher,
        db: Session,
        oauth_state: oauth_state_models.OAuthState,
    ) -> dict[str, Any]:
        """
        Handle the OAuth2/OIDC callback from an identity provider.
        This method processes the authorization code received from an identity provider,
        validates the state parameter, exchanges the code for tokens, retrieves user
        information, and either creates/updates a user session (login mode) or links
        the identity provider to an existing user account (link mode).
        Args:
            idp (idp_models.IdentityProvider): The identity provider configuration object.
            code (str): The authorization code returned by the identity provider.
            state (str): The state parameter for CSRF protection (database state ID).
            request (Request): The FastAPI/Starlette request object.
            password_hasher (jafaal_password_hasher.PasswordHasher): Password hasher instance
                for user authentication operations.
            db (Session): SQLAlchemy database session.
            oauth_state (oauth_state_models.OAuthState): Database OAuth state object.

        Returns:
            dict[str, Any]: A dictionary containing:
                - user: The authenticated or linked user object
                - token_data: OAuth2 token response (access_token, refresh_token, etc.)
                - userinfo: User information claims from the identity provider
                - mode (optional): "link" if this was a link operation (not present for login)

        Raises:
            JafaalError: With appropriate status codes for various error conditions:
                - 400 BAD_REQUEST: Invalid/expired state, missing parameters, user ID mismatch
                - 404 NOT_FOUND: User not found during link mode
                - 409 CONFLICT: IdP account already linked to a user
                - 500 INTERNAL_SERVER_ERROR: Unexpected errors during authentication
                - 502 BAD_GATEWAY: IdP communication errors, invalid responses
                - 504 GATEWAY_TIMEOUT: IdP not responding

        Notes:
            - State parameter must be valid and not older than 10 minutes (CSRF protection)
            - In link mode, validates that the IdP account is not already linked to any user
            - In login mode, creates new user accounts if they don't exist (SSO provisioning)
            - Stores IdP tokens securely for future session renewal
            - Performs ID token verification if JWKS URI is available
            - Cleans up OAuth state from database after successful completion
        """
        try:
            logger.debug(f"Using database OAuth state for IdP {idp.name} (client={oauth_state.client_id})")

            # Detect the flow purpose. A user_id on the state marks an
            # authenticated flow (link or step-up re-auth); ``purpose``
            # discriminates them (both carry user_id).
            link_user_id = oauth_state.user_id
            is_step_up_mode = oauth_state.purpose == "stepup" and link_user_id is not None
            is_link_mode = link_user_id is not None and not is_step_up_mode

            if is_link_mode:
                # Link mode: OAuth state was created during authenticated linking request
                # The user_id in oauth_state proves the user initiated this link
                logger.debug(f"Link mode detected for IdP {idp.name}, user_id={link_user_id}")
            elif is_step_up_mode:
                logger.debug(f"Step-up re-auth mode detected for IdP {idp.name}, user_id={link_user_id}")

            # Decrypt credentials and resolve endpoints using helper methods
            client_id = self._decrypt_client_id(idp)
            client_secret = self._decrypt_client_secret(idp)
            token_endpoint = await self.discovery.resolve_token_endpoint(idp)

            # Get OIDC configuration (for userinfo, jwks_uri, issuer)
            userinfo_endpoint = idp.userinfo_endpoint
            jwks_uri = None
            expected_issuer = None

            if idp.issuer_url:
                try:
                    config = await self.get_oidc_configuration(idp)
                    if config:
                        # Get userinfo endpoint if not manually configured
                        if not userinfo_endpoint:
                            userinfo_endpoint = config.get("userinfo_endpoint")

                        # Get JWKS URI for ID token verification
                        jwks_uri = config.get("jwks_uri")
                        expected_issuer = config.get("issuer")

                        logger.debug(
                            f"OIDC discovery complete for {idp.name}: "
                            f"userinfo={bool(userinfo_endpoint)}, "
                            f"jwks_uri={bool(jwks_uri)}, "
                            f"issuer={bool(expected_issuer)}"
                        )
                except Exception as err:
                    # Fail closed. The IdP declares an ``issuer_url``, so this
                    # flow is OIDC and the ID token is meant to be verified
                    # against the discovered JWKS. Continuing without it would
                    # silently skip signature, issuer and nonce validation and
                    # fall back to trusting the userinfo response alone — the
                    # exact downgrade an attacker able to disrupt discovery would
                    # want. A transient outage becomes a failed login, not an
                    # unverified one.
                    logger.error(f"OIDC discovery failed for IdP {idp.name}: {err}", exc_info=err)
                    jafaal_audit.record(
                        jafaal_audit.Event.IDP_DISCOVERY_FAILED,
                        outcome=jafaal_audit.Outcome.FAILURE,
                        level=logging.ERROR,
                        idp=idp.slug,
                        reason=type(err).__name__,
                    )
                    raise jafaal_exceptions.IdentityProviderError(
                        f"Could not reach the {idp.name} discovery endpoint, so the ID token cannot be "
                        "verified. Please try again later."
                    ) from err

                if not jwks_uri:
                    # Discovery succeeded but published no JWKS: there is no way
                    # to verify the ID token, so the same reasoning applies.
                    logger.error(f"OIDC discovery for IdP {idp.name} returned no jwks_uri")
                    jafaal_audit.record(
                        jafaal_audit.Event.IDP_DISCOVERY_FAILED,
                        outcome=jafaal_audit.Outcome.FAILURE,
                        level=logging.ERROR,
                        idp=idp.slug,
                        reason="no_jwks_uri",
                    )
                    raise jafaal_exceptions.IdentityProviderError(
                        f"Identity provider {idp.name} publishes no JWKS, so its ID token cannot be verified."
                    )

            # Retrieve nonce from database state
            expected_nonce = oauth_state.nonce

            # Exchange code for tokens
            redirect_uri = self._get_redirect_uri(idp.slug)

            try:
                client = self._create_oauth_client(
                    client_id=client_id,
                    client_secret=client_secret,
                    redirect_uri=redirect_uri,
                )

                token_kwargs: dict[str, Any] = {"grant_type": "authorization_code", "code": code}
                # Upstream PKCE: replay the stored code_verifier so the IdP can
                # bind this token exchange to the earlier authorization request
                # (defends against authorization-code injection/interception).
                if oauth_state.upstream_code_verifier:
                    token_kwargs["code_verifier"] = crypto.decrypt_token_fernet(oauth_state.upstream_code_verifier)

                token_response = await client.fetch_token(token_endpoint, **token_kwargs)
            except httpx.TimeoutException as err:
                logger.error(f"Timeout connecting to IdP {idp.name} token endpoint: {err}", exc_info=err)
                raise jafaal_exceptions.IdentityProviderTimeoutError(
                    f"Identity provider {idp.name} is not responding. Please try again later."
                ) from err
            except httpx.HTTPStatusError as err:
                logger.error(
                    f"HTTP error from IdP {idp.name} token endpoint: {err.response.status_code} - {err.response.text}",
                    exc_info=err,
                )
                # Check for common OAuth2 error responses
                if err.response.status_code == 400:
                    detail = "Authorization code is invalid or expired. Please try logging in again."
                elif err.response.status_code == 401:
                    detail = f"Identity provider {idp.name} rejected the authentication request. Please contact administrator."
                else:
                    detail = f"Identity provider {idp.name} returned an error. Please try again later."

                raise jafaal_exceptions.IdentityProviderError(detail) from err
            except httpx.RequestError as err:
                logger.error(f"Network error connecting to IdP {idp.name}: {err}", exc_info=err)
                raise jafaal_exceptions.IdentityProviderError(
                    f"Unable to connect to identity provider {idp.name}. Please check your network connection."
                ) from err
            except Exception as err:
                logger.error(f"Unexpected error during token exchange with IdP {idp.name}: {err}", exc_info=err)
                raise jafaal_exceptions.InternalError("Failed to complete authentication. Please try again.") from err

            # Get user information with ID token verification
            userinfo = await self._get_userinfo(
                token_response=token_response,
                userinfo_endpoint=userinfo_endpoint,
                client=client,
                jwks_uri=jwks_uri,
                expected_issuer=expected_issuer,
                expected_audience=client_id,
                expected_nonce=expected_nonce,
                # OIDC providers must present a verifiable ID token; oauth2 providers
                # legitimately identify the user via userinfo only.
                require_verified_id_token=(idp.provider_type == "oidc"),
            )

            # Extract subject (unique user identifier)
            subject = userinfo.get("sub") or userinfo.get("id")
            if not subject:
                logger.error(f"IdP {idp.name} did not provide 'sub' or 'id' claim in userinfo: {list(userinfo.keys())}")
                raise jafaal_exceptions.IdentityProviderError(
                    f"Identity provider {idp.name} did not provide required user identifier. Please contact administrator."
                )

            # Handle link mode differently from login mode
            if is_step_up_mode and link_user_id is not None:
                # STEP-UP RE-AUTH MODE: verify a fresh IdP sign-in and mint a grant
                return await self._handle_step_up_callback(idp, link_user_id, subject, userinfo, db)

            if is_link_mode and link_user_id:
                # LINK MODE: Associate IdP with existing authenticated user

                # Verify user exists
                user = jafaal_ports.get_user_repository().get_by_id(link_user_id, db)
                if not user:
                    raise jafaal_exceptions.NotFoundError("User not found")

                # Check if this IdP subject is already linked to ANY user
                existing_link = jafaal_identity_links_crud.get_user_identity_provider_by_subject_and_idp_id(
                    idp.id, subject, db
                )
                if existing_link:
                    # Check if it's already linked to THIS user
                    if existing_link.user_id == link_user_id:
                        raise jafaal_exceptions.ConflictError(
                            f"This {idp.name} account is already linked to your account"
                        )
                    else:
                        # Linked to a DIFFERENT user - security issue
                        raise jafaal_exceptions.ConflictError(
                            f"This {idp.name} account is already linked to another user"
                        )

                # Create the link
                jafaal_identity_links_crud.create_user_identity_provider(
                    user_id=link_user_id, idp_id=idp.id, idp_subject=subject, db=db
                )

                # Update user info if sync is enabled
                if idp.sync_user_info:
                    user = await self._update_user_from_idp(user, idp, userinfo, db)

                # Store IdP tokens for future use
                await self._store_idp_tokens(link_user_id, idp.id, token_response, db)

                logger.info(f"User {user.username} (id={link_user_id}) linked IdP {idp.name} (subject={subject})")

                # Return special structure for link mode (no new session created)
                return {
                    "user": user,
                    "token_data": token_response,
                    "userinfo": userinfo,
                    "mode": "link",  # Indicate this was a link operation
                }
            else:
                # LOGIN MODE: Find or create user and establish session
                user = await self._find_or_create_user(idp, subject, userinfo, db)

                # Store IdP tokens for future session renewal
                await self._store_idp_tokens(user.id, idp.id, token_response, db)

                logger.info(f"User {user.username} authenticated via IdP {idp.name}")

                return {
                    "user": user,
                    "token_data": token_response,
                    "userinfo": userinfo,
                }

        except jafaal_exceptions.JafaalError:
            # Re-raise JafaalErrors as-is (already have proper status codes and messages)
            raise
        except Exception as err:
            # Catch-all for unexpected errors
            logger.error(f"Unexpected error handling OAuth callback for IdP {idp.name}: {err}", exc_info=err)
            raise jafaal_exceptions.InternalError(
                f"An unexpected error occurred during authentication with {idp.name}. Please try again or contact administrator."
            ) from err

    async def _handle_step_up_callback(
        self,
        idp: idp_models.IdentityProvider,
        user_id: UserId,
        subject: str,
        claims: dict[str, Any],
        db: Session,
    ) -> dict[str, Any]:
        """Verify a fresh IdP re-authentication and mint a single-use step-up grant.

        Confirms that (1) the user still exists, (2) the re-authenticated IdP
        subject is the one already linked to this user — re-authentication must
        be the *same* identity, not a different account at the same provider —
        and (3) the provider asserted a recent ``auth_time``. On success a
        single-use step-up grant is recorded (consumed by the next sensitive
        operation via :func:`jafaal._internal.services.step_up_service.verify_step_up_credentials`).

        Args:
            idp: The identity provider the user re-authenticated against.
            user_id: The user that initiated the step-up (from the OAuth state).
            subject: The IdP ``sub`` from the verified claims.
            claims: The verified ID-token/userinfo claims (must carry ``auth_time``).
            db: Active database session.

        Returns:
            A callback result dict with ``mode='stepup'`` and the resolved user.

        Raises:
            JafaalError: 404 if the user is gone; 403 if the re-authenticated
                identity is not linked to this account; 401 if the provider did
                not assert a sufficiently recent ``auth_time``.
        """
        user = jafaal_ports.get_user_repository().get_by_id(user_id, db)
        if not user:
            raise jafaal_exceptions.NotFoundError("User not found")

        link = jafaal_identity_links_crud.get_user_identity_provider_by_subject_and_idp_id(idp.id, subject, db)
        if link is None or link.user_id != user_id:
            logger.warning(
                f"Step-up re-auth identity mismatch for user {user_id}, idp {idp.id}: "
                "the re-authenticated subject is not linked to this account"
            )
            raise jafaal_exceptions.AuthorizationError(
                "The identity you re-authenticated with is not linked to your account."
            )

        self._verify_reauth_freshness(claims)

        settings = jafaal_settings.get_settings()
        jafaal_security_stores.grant_step_up_reauth(
            user_id, idp_id=idp.id, ttl_seconds=settings.sso.step_up_grant_ttl_seconds
        )
        logger.info(f"User {user_id} completed IdP step-up re-authentication via {idp.name}")
        return {"user": user, "userinfo": claims, "mode": "stepup"}

    def _verify_reauth_freshness(self, claims: dict[str, Any]) -> None:
        """Assert the IdP asserted a recent ``auth_time`` for step-up.

        ``prompt=login`` and ``max_age`` are requested on re-authentication, but
        not every provider honours them, so the ID token's ``auth_time`` claim
        is the authoritative freshness check. A missing or stale ``auth_time``
        fails closed (the step-up grant is not minted).

        Args:
            claims: The verified ID-token/userinfo claims.

        Raises:
            JafaalError: 401 if ``auth_time`` is missing, malformed, or older
                than ``AuthSettings.step_up_reauth_max_age_seconds``.
        """
        settings = jafaal_settings.get_settings()
        auth_time = claims.get("auth_time")
        if isinstance(auth_time, bool) or not isinstance(auth_time, (int, float)):
            raise jafaal_exceptions.AuthenticationError(
                "The identity provider did not assert a fresh authentication time; step-up could not be verified."
            )
        age = datetime.now(UTC).timestamp() - float(auth_time)
        if age < -_REAUTH_CLOCK_SKEW_LEEWAY_SECONDS or age > settings.sso.step_up_reauth_max_age_seconds:
            raise jafaal_exceptions.AuthenticationError(
                "Your identity-provider sign-in was not recent enough for this action. Please try again."
            )

    async def _get_userinfo(
        self,
        token_response: dict[str, Any],
        userinfo_endpoint: str | None,
        client: AsyncOAuth2Client,
        jwks_uri: str | None,
        expected_issuer: str | None,
        expected_audience: str,
        expected_nonce: str | None = None,
        require_verified_id_token: bool = False,
    ) -> dict[str, Any]:
        """
        Retrieve user information from an identity provider using the provided token response.

        This method first attempts to fetch user information from the given `userinfo_endpoint` using the provided OAuth2 client.
        If the endpoint is unavailable or the request fails, it falls back to extracting claims from the `id_token` in the token response,
        verifying the ID token signature using JWKS before returning the claims.

        Security Enhancement:
        - ID tokens are now cryptographically verified using joserfc and JWKS
        - Signature verification prevents token forgery and tampering
        - Claims validation ensures token integrity (iss, aud, exp, nonce)
        - This replaces the insecure manual base64 decode previously used

        Args:
            token_response (dict[str, Any]): The OAuth2 token response containing access and/or ID tokens.
            userinfo_endpoint (str | None): The endpoint URL to fetch user information, if available.
            client (AsyncOAuth2Client): The asynchronous OAuth2 client used to make HTTP requests.
            jwks_uri (str | None): The JWKS endpoint URL for verifying ID token signatures.
            expected_issuer (str | None): Expected 'iss' claim value from OIDC discovery.
            expected_audience (str): Expected 'aud' claim value (typically the client_id).
            expected_nonce (str | None): Expected nonce value from session (optional, but recommended).
            require_verified_id_token (bool): When True (OIDC providers), the signed
                ID token is the identity assertion and unverified userinfo is never
                accepted as a fallback — the flow fails closed if the ID token is
                absent or cannot be verified. False (e.g. plain OAuth2 providers)
                identifies the user from the userinfo endpoint by design.

        Returns:
            dict[str, Any]: The user information claims retrieved from the identity provider.

        Raises:
            JafaalError: If user information cannot be retrieved from either the userinfo endpoint or the ID token,
                          or if ID token verification fails.
        """
        # Try to get from userinfo endpoint first
        userinfo_claims = None
        if userinfo_endpoint:
            # SSRF guard: the userinfo endpoint can come from admin config or
            # from the discovery document (whose contents are not otherwise
            # re-validated). Because this request carries the OAuth access
            # token in an Authorization header, an internal target could also
            # exfiltrate that token. Refuse private/internal addresses unless
            # explicitly opted in via SSRF_ALLOWED_HOSTS. Raised outside the
            # try/except below so the guard's 4xx is not swallowed as a
            # userinfo fetch failure.
            network.reject_private_url(userinfo_endpoint, purpose="oidc_userinfo", require_https=_idp_require_https())
            try:
                # Use the access token to fetch userinfo
                access_token = token_response.get("access_token")
                if access_token:
                    response = await cast("httpx.AsyncClient", client).get(
                        userinfo_endpoint,
                        headers={"Authorization": f"Bearer {access_token}"},
                    )
                    response.raise_for_status()
                    userinfo_claims = response.json()
                    logger.debug("Successfully retrieved userinfo from endpoint")
                else:
                    logger.warning("No access token available for userinfo request")
            except httpx.TimeoutException as err:
                logger.warning(f"Timeout fetching userinfo from endpoint: {err}", exc_info=err)
            except httpx.HTTPStatusError as err:
                logger.warning(
                    f"HTTP error {err.response.status_code} fetching userinfo: {err.response.text}", exc_info=err
                )
            except httpx.RequestError as err:
                logger.warning(f"Network error fetching userinfo: {err}", exc_info=err)
            except Exception as err:
                logger.warning(f"Unexpected error fetching userinfo from endpoint: {err}", exc_info=err)

        # Verify ID token if present (always do this for security, even if userinfo endpoint succeeded)
        id_token = token_response.get("id_token")
        if id_token and jwks_uri and expected_issuer:
            try:
                # SECURITY: Verify ID token signature using JWKS
                # This replaces the insecure manual base64 decode
                id_token_claims = await self.discovery.verify_id_token(
                    id_token=id_token,
                    jwks_uri=jwks_uri,
                    expected_issuer=expected_issuer,
                    expected_audience=expected_audience,
                    expected_nonce=expected_nonce,
                    access_token=token_response.get("access_token"),
                )

                logger.debug(f"Successfully verified ID token for sub={id_token_claims.get('sub')}")

                # If we got userinfo from endpoint, merge with ID token claims
                # ID token claims take precedence for standard claims (sub, iss, aud)
                if userinfo_claims:
                    # OIDC Core 1.0 §5.3.2: the userinfo ``sub`` MUST be verified
                    # to exactly match the ID token ``sub``, and on a mismatch the
                    # userinfo values MUST NOT be used. Overriding ``sub`` from the
                    # ID token is not sufficient — the *rest* of the userinfo body
                    # (notably ``email`` / ``email_verified``) would still be
                    # merged in and then drive email-based account linking in
                    # ``_find_or_create_user``, so a userinfo response describing a
                    # different principal becomes an account-takeover path.
                    id_token_verify.assert_userinfo_subject_matches(userinfo_claims, id_token_claims)
                    # Merge: userinfo endpoint data + ID token verified claims
                    # ID token claims override for security-critical fields
                    merged_claims = {**userinfo_claims, **id_token_claims}
                    logger.debug("Merged userinfo endpoint data with verified ID token claims")
                    return merged_claims
                else:
                    # Only ID token available, return verified claims
                    return id_token_claims

            except jafaal_exceptions.JafaalError:
                # Re-raise verification errors (signature failed, expired, etc.)
                # These are security-critical and should not be ignored
                raise
            except Exception as err:
                logger.error(f"Unexpected error verifying ID token: {err}", exc_info=err)
                raise jafaal_exceptions.InternalError("Failed to verify ID token") from err

        # Reaching this point means no ID token was cryptographically verified —
        # either the provider returned none, or JWKS/issuer were unavailable so it
        # could not be checked. For an OIDC provider the signed ID token *is* the
        # identity assertion, so fail closed here instead of trusting the userinfo
        # response: without a verified ID token (and with no PKCE/nonce binding on a
        # pure userinfo flow) an injected or stolen authorization code redeemed in
        # the attacker's session would resolve to the victim's identity
        # (authorization-code injection). A provider that legitimately issues no ID
        # token must be configured as provider_type="oauth2".
        if require_verified_id_token:
            if id_token:
                logger.error(
                    "OIDC provider returned an ID token that could not be verified "
                    "(missing JWKS URI or issuer from discovery); refusing to fall back to "
                    "unverified userinfo. Configure issuer_url so the ID token can be verified."
                )
            else:
                logger.error(
                    "OIDC provider returned no ID token; refusing to authenticate from "
                    "unverified userinfo. Use provider_type='oauth2' for userinfo-only providers."
                )
            raise jafaal_exceptions.IdentityProviderError(
                "Unable to securely verify your identity with the identity provider. Please contact administrator."
            )

        # Non-OIDC providers (provider_type="oauth2") identify the user from the
        # userinfo endpoint; they issue no ID token by design.
        if userinfo_claims:
            return userinfo_claims

        # Couldn't retrieve or verify any user information.
        logger.error("Failed to retrieve user information from userinfo endpoint or ID token")
        raise jafaal_exceptions.InternalError(
            "Unable to retrieve user information from identity provider. Please contact administrator."
        )

    async def _store_idp_tokens(
        self,
        user_id: UserId,
        idp_id: int,
        token_response: dict[str, Any],
        db: Session,
    ) -> None:
        """
        Store IdP tokens after successful authentication.

        This method extracts the refresh token from the OAuth token response, encrypts it,
        and stores it along with metadata for future session renewal. If no refresh token
        is provided by the IdP, the method logs a debug message and returns gracefully.

        Args:
            user_id (int): The ID of the authenticated user.
            idp_id (int): The ID of the identity provider.
            token_response (dict[str, Any]): The OAuth token response from the IdP containing
                access_token, refresh_token (optional), and expires_in.
            db (Session): The database session for storing tokens.

        Returns:
            None

        Security Note:
            - The refresh token is encrypted using Fernet before storage
            - If encryption fails, the error is logged but authentication continues
            - Missing refresh tokens are handled gracefully (not all IdPs provide them)

        Example token_response:
            {
                "access_token": "eyJhbGci...",
                "refresh_token": "eyJhbGci...",  # Optional
                "expires_in": 300,
                "token_type": "Bearer"
            }
        """
        # Extract refresh token from response
        refresh_token = token_response.get("refresh_token")

        if not refresh_token:
            logger.debug(
                f"No refresh token provided by IdP (user_id={user_id}, idp_id={idp_id}). "
                "User will need to re-authenticate when session expires."
            )
            return

        try:
            # Encrypt the refresh token using Fernet
            encrypted_refresh = crypto.encrypt_token_fernet(refresh_token)

            if not encrypted_refresh:
                logger.warning(
                    f"Failed to encrypt refresh token for user {user_id}, idp {idp_id}. Token will not be stored."
                )
                return

            # Calculate when the access token expires
            expires_in = token_response.get("expires_in", DEFAULT_TOKEN_EXPIRY_SECONDS)
            access_token_expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)

            # Store encrypted token and metadata in database
            jafaal_identity_links_crud.store_user_identity_provider_tokens(
                user_id=user_id,
                idp_id=idp_id,
                encrypted_refresh_token=encrypted_refresh,
                access_token_expires_at=access_token_expires_at,
                db=db,
            )

            logger.debug(
                f"Stored IdP refresh token for user {user_id}, idp {idp_id} "
                f"(expires at {access_token_expires_at.isoformat()})"
            )

        except Exception as err:
            # Log the error but don't fail the authentication flow
            logger.error(f"Error storing IdP refresh token for user {user_id}: {err}", exc_info=err)
            # Authentication succeeds even if token storage fails
            # User will need to re-auth when session expires, but that's acceptable

    def _map_user_claims(self, idp: idp_models.IdentityProvider, claims: dict[str, Any]) -> dict[str, Any]:
        """
        Maps user claims from an identity provider to a standardized user dictionary.

        This method takes an identity provider configuration and a dictionary of claims,
        then maps the claims to standard user fields (such as 'username', 'email', and 'name')
        using both default and custom mappings defined in the identity provider.

        Args:
            idp (idp_models.IdentityProvider): The identity provider instance containing optional custom user mapping.
            claims (dict[str, Any]): The dictionary of claims received from the identity provider.

        Returns:
            dict[str, Any]: A dictionary mapping standard user fields to their corresponding claim values.
        """
        # Default mapping
        default_mapping = {
            "username": ["preferred_username", "username", "email", "sub"],
            "email": ["email", "mail"],
            "name": ["name", "display_name", "full_name", "displayName"],
        }

        # Merge with custom mapping
        mapping = {**default_mapping, **(idp.user_mapping or {})}

        result = {}
        for field, claim_names in mapping.items():
            if isinstance(claim_names, str):
                claim_names = [claim_names]
            for claim in claim_names:
                if claims.get(claim):
                    result[field] = claims[claim]
                    break

        return result

    @staticmethod
    def _is_email_verified(claims: dict[str, Any]) -> bool:
        """Return ``True`` only when the IdP asserts a verified email.

        Honors the standard OIDC ``email_verified`` claim. Providers may
        send it as a JSON boolean (``true``) or, less correctly, as the
        string ``"true"``; both are accepted. Any other value — including
        a missing claim — is treated as *unverified* so that email-based
        account linking fails closed.

        Args:
            claims: Raw userinfo/ID-token claims from the identity provider.

        Returns:
            ``True`` if the email is explicitly asserted as verified.
        """
        value = claims.get("email_verified")
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() == "true"
        return False

    async def _find_or_create_user(
        self,
        idp: idp_models.IdentityProvider,
        subject: str,
        userinfo: dict[str, Any],
        db: Session,
    ) -> jafaal_ports.UserProtocol:
        """
        Finds an existing user linked to the given identity provider and subject, or creates a new user if allowed.

        This method attempts to:
        1. Find a user by their identity provider (IdP) link using the subject identifier.
        2. If not found, find a user by email and link their account to the IdP,
           but only when the IdP asserts the email is verified (account-takeover
           prevention via the OIDC ``email_verified`` claim).
        3. If still not found and auto-creation is enabled, create a new user from the IdP information.

        Args:
            idp (idp_models.IdentityProvider): The identity provider instance.
            subject (str): The unique subject identifier from the IdP.
            userinfo (Dict[str, Any]): User information/claims from the IdP.
            password_hasher (jafaal_password_hasher.PasswordHasher): The password hasher instance.
            db (Session): Database session.

        Returns:
            The found or newly created user instance.

        Raises:
            JafaalError: If an existing account matches the email but the IdP
                did not assert a verified email (403), or if user creation is
                disabled for the identity provider and no existing user is found.
        """
        # Try to find existing user by IdP link
        link = jafaal_identity_links_crud.get_user_identity_provider_by_subject_and_idp_id(idp.id, subject, db)

        if link:
            # Fetch the linked user through the CRUD layer so we work with
            # the UsersRead schema rather than reaching into the ORM
            # relationship (link.users) and crossing the module boundary.
            user = jafaal_ports.get_user_repository().get_by_id(link.user_id, db)
            if user is None:
                raise jafaal_exceptions.NotFoundError("User not found")
            # Update last login timestamp
            jafaal_identity_links_crud.update_user_identity_provider_last_login(link.user_id, idp.id, db)

            # Update user info if sync is enabled
            if idp.sync_user_info:
                user = await self._update_user_from_idp(user, idp, userinfo, db)
            return user

        # Try to find by email (for linking existing accounts).
        #
        # SECURITY (account-takeover prevention). Adopting an existing local
        # account on the strength of a matching email address means trusting
        # this provider to be authoritative for that address. Two gates, because
        # neither is sufficient alone:
        #
        # 1. ``allow_email_linking`` — off by default. ``email_verified`` is the
        #    provider's *own* assertion, and nothing stops a provider asserting
        #    it for an address in a domain it has no authority over. In a
        #    multi-provider deployment that turns the weakest enabled provider
        #    into a takeover path for every account: register
        #    victim@example.com there, sign in, and land inside the victim's
        #    account. So adopting existing accounts is a per-provider decision
        #    the operator makes about a provider they trust, not a default.
        # 2. ``email_verified`` — still required when linking is enabled, so an
        #    unverified address is never enough even from a trusted provider.
        #
        # Subject-based linking above is unaffected: that identity was
        # explicitly linked already.
        mapped_data = self._map_user_claims(idp, userinfo)
        email = mapped_data.get("email")

        if email:
            user = jafaal_ports.get_user_repository().get_by_email(email, db)
            if user:
                if not idp.allow_email_linking:
                    logger.warning(
                        f"Refusing to link IdP {idp.name} to existing account "
                        f"{user.username}: email linking is disabled for this provider"
                    )
                    jafaal_audit.record(
                        jafaal_audit.Event.IDP_EMAIL_LINK_REFUSED,
                        outcome=jafaal_audit.Outcome.BLOCKED,
                        level=logging.WARNING,
                        user_id=user.id,
                        idp=idp.slug,
                        reason="email_linking_disabled",
                    )
                    raise jafaal_exceptions.AuthorizationError(
                        "An account already exists with this email address. Sign in with it and link "
                        f"{idp.name} from your account settings."
                    )
                if not self._is_email_verified(userinfo):
                    logger.warning(
                        f"Refusing to link IdP {idp.name} to existing account "
                        f"{user.username}: provider did not assert a verified email"
                    )
                    jafaal_audit.record(
                        jafaal_audit.Event.IDP_EMAIL_LINK_REFUSED,
                        outcome=jafaal_audit.Outcome.BLOCKED,
                        level=logging.WARNING,
                        user_id=user.id,
                        idp=idp.slug,
                        reason="email_not_verified",
                    )
                    raise jafaal_exceptions.AuthorizationError(
                        "Cannot link this identity provider to an existing "
                        "account because the provider did not verify the "
                        "email address."
                    )

                # Link existing account to IdP
                jafaal_identity_links_crud.create_user_identity_provider(user.id, idp.id, subject, db)

                logger.info(f"Linked existing user {user.username} to IdP {idp.name}")
                jafaal_audit.record(
                    jafaal_audit.Event.IDP_EMAIL_LINKED,
                    level=logging.WARNING,
                    user_id=user.id,
                    idp=idp.slug,
                )
                # Tell the account owner out of band: this is a new way to sign
                # in to their account that they did not perform from a
                # session they were already holding.
                await jafaal_ports.adispatch_event(
                    "on_idp_account_linked",
                    jafaal_ports.IdpAccountLinked(
                        user_id=user.id,
                        username=user.username,
                        idp_name=idp.name,
                        idp_slug=idp.slug,
                        email=email,
                    ),
                )

                # Update user info if sync is enabled
                if idp.sync_user_info:
                    user = await self._update_user_from_idp(user, idp, userinfo, db)
                return user

        # Create new user if auto-creation is enabled
        if not idp.auto_create_users:
            raise jafaal_exceptions.AuthorizationError("User account creation is disabled for this identity provider")

        user = await self._create_user_from_idp(
            idp,
            subject,
            mapped_data,
            db,
            email_verified=self._is_email_verified(userinfo),
        )

        return user

    async def _create_user_from_idp(
        self,
        idp: idp_models.IdentityProvider,
        subject: str,
        mapped_data: dict[str, Any],
        db: Session,
        *,
        email_verified: bool,
    ) -> jafaal_ports.UserProtocol:
        """
        Create a new user from identity-provider claims via the host's UserRepository.

        JAFAAL resolves a unique username and hands the host a minimal
        :class:`~jafaal.ports.IdpIdentity`; the host provisions its own user row
        (profile shape and defaults are the host's concern). SSO accounts have no
        local password credential.

        ``email_verified`` carries the provider's own assertion through verbatim
        rather than being hardcoded to ``True``. Hardcoding it would let a first
        SSO sign-in at a permissive provider provision an account holding an
        address the provider never verified — squatting the address that the
        address's real owner would later be refused (the linking path in
        :meth:`_find_or_create_user` correctly fails closed on an unverified
        email, so the squatted account can never be reclaimed through SSO).

        Args:
            idp (idp_models.IdentityProvider): The identity provider instance.
            subject (str): The unique subject identifier from the IdP.
            mapped_data (Dict[str, Any]): User data mapped from the IdP (username, email, name, ...).
            db (Session): The database session.
            email_verified: Whether the provider asserted the email as verified.

        Returns:
            The newly created user.

        Raises:
            JafaalError: If user creation fails (e.g. duplicate username/email).
        """
        repo = jafaal_ports.get_user_repository()

        # Ensure username is unique
        base_username = mapped_data.get("username", f"user_{subject[:8]}")
        username = base_username
        while repo.get_by_username(username, db):
            # secrets.randbelow is a CSPRNG; generate a 6-digit suffix
            username = f"{base_username}_{secrets_module.randbelow(900000) + 100000}"

        # Hand the host a minimal identity; it provisions its own row + defaults.
        identity = jafaal_ports.IdpIdentity(
            subject=subject,
            idp_id=idp.id,
            email=mapped_data.get("email") or f"{username}@sso.local",
            email_verified=email_verified,
            suggested_username=username,
            display_name=mapped_data.get("name", username),
            claims=mapped_data,
        )
        created_user = repo.provision_from_idp(identity, db)

        # Create the IdP link
        jafaal_identity_links_crud.create_user_identity_provider(created_user.id, idp.id, subject, db)

        logger.info(f"Created new user {created_user.username} from IdP {idp.name}")

        return created_user

    async def _update_user_from_idp(
        self,
        user: jafaal_ports.UserProtocol,
        idp: idp_models.IdentityProvider,
        userinfo: dict[str, Any],
        db: Session,
    ) -> jafaal_ports.UserProtocol:
        """
        Sync host-owned profile fields from refreshed IdP claims.

        JAFAAL maps the IdP claims and hands them to the host's
        ``UserRepository.sync_from_idp``; the host decides which fields to update
        and resolves any email conflicts. Returns the (possibly updated) user.

        The mapped claims carry ``email_verified`` so the host can apply its own
        policy, and JAFAAL **withholds an unverified ``email`` entirely**. Sync
        runs on every login when it is enabled, so passing one through would
        quietly undo the gate that guards linking: a linked user who changes
        their address at the provider to an unverified ``victim@example.com``
        would have it written onto their local row — and the local email is what
        password reset is delivered to.

        Args:
            user: The user to update.
            idp (idp_models.IdentityProvider): The identity provider instance with user_mapping config.
            userinfo (Dict[str, Any]): The user information claims received from the IdP.
            db (Session): The SQLAlchemy database session.

        Returns:
            The updated user.
        """
        mapped_data = self._map_user_claims(idp, userinfo)
        email_verified = self._is_email_verified(userinfo)
        mapped_data["email_verified"] = email_verified

        if not email_verified and mapped_data.pop("email", None) is not None:
            logger.warning(f"Withholding unverified email from profile sync for user {user.id} (IdP {idp.name})")

        repo = jafaal_ports.get_user_repository()
        repo.sync_from_idp(user.id, mapped_data, db)
        return repo.get_by_id(user.id, db) or user

    async def refresh_idp_session(
        self,
        user_id: UserId,
        idp_id: int,
        db: Session,
    ) -> dict[str, Any] | None:
        """
        Attempt to refresh a user's IdP session using stored refresh token.

        This method enables silent session renewal without re-prompting the user to login.
        It retrieves the stored encrypted refresh token, decrypts it, and exchanges it
        with the IdP for new access and refresh tokens. If successful, the new tokens
        are encrypted and stored.

        Args:
            user_id (int): The ID of the user whose session should be refreshed.
            idp_id (int): The ID of the identity provider.
            db (Session): The database session for token retrieval and updates.

        Returns:
            Dict[str, Any] | None: A dictionary containing the new token response if successful,
                or None if the refresh failed (expired/revoked token, network error, etc.).

        Raises:
            JafaalError: If the IdP is not found, disabled, or misconfigured.

        Example return value:
            {
                "access_token": "eyJhbGci...",
                "refresh_token": "eyJhbGci...",  # May be the same or new token
                "expires_in": 300,
                "token_type": "Bearer"
            }

        Security Notes:
            - Refresh token is decrypted only in memory, never logged
            - If refresh fails (invalid/revoked), the stored token is cleared
            - Network errors do not clear the token (IdP may be temporarily down)
        """
        # Get the IdP configuration
        idp = idp_crud.get_identity_provider(idp_id, db)
        if not idp or not idp.enabled:
            raise jafaal_exceptions.NotFoundError(f"Identity provider (ID: {idp_id}) not found or disabled")

        # Get the encrypted refresh token from database
        encrypted_refresh_token = (
            jafaal_identity_links_utils.get_user_identity_provider_refresh_token_by_user_id_and_idp_id(
                user_id, idp_id, db
            )
        )

        if not encrypted_refresh_token:
            logger.debug(f"No refresh token stored for user {user_id}, idp {idp_id}. Cannot refresh session.")
            return None

        # Decrypt the refresh token
        try:
            refresh_token = crypto.decrypt_token_fernet(encrypted_refresh_token)
            if not refresh_token:
                raise ValueError("Decryption returned empty value")
        except Exception as err:
            logger.error(f"Failed to decrypt refresh token for user {user_id}, idp {idp_id}: {err}", exc_info=err)
            # Clear corrupted token (only if a concurrent refresh has not already
            # replaced it with a valid, freshly rotated one).
            jafaal_identity_links_crud.clear_user_identity_provider_refresh_token_if_matches(
                user_id, idp_id, encrypted_refresh_token, db
            )
            return None

        # Resolve endpoints and credentials using helper methods
        token_endpoint = await self.discovery.resolve_token_endpoint(idp)
        client_id = self._decrypt_client_id(idp)
        client_secret = self._decrypt_client_secret(idp)

        # Create OAuth client for token refresh
        try:
            client = self._create_oauth_client(
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=None,  # Not needed for refresh token flow
            )

            # Exchange refresh token for new tokens
            token_response = await client.fetch_token(
                token_endpoint,
                grant_type="refresh_token",
                refresh_token=refresh_token,
            )

            logger.debug(f"Successfully refreshed IdP session for user {user_id}, idp {idp_id}")

            # Store the new tokens (they may include a new refresh token)
            await self._store_idp_tokens(user_id, idp_id, token_response, db)

            return token_response

        except httpx.TimeoutException as err:
            logger.warning(f"Timeout refreshing IdP session for user {user_id}, idp {idp_id}: {err}", exc_info=err)
            # Don't clear token - IdP may be temporarily down
            return None

        except httpx.HTTPStatusError as err:
            # Check if this is a token revocation (400) or auth failure (401)
            if err.response.status_code in (400, 401):
                logger.warning(
                    f"IdP refresh token invalid/revoked for user {user_id}, idp {idp_id}: "
                    f"{err.response.status_code} - {err.response.text}",
                    exc_info=err,
                )
                # Clear invalid token from database. Use the conditional clear so
                # a concurrent refresh that already rotated the token (the loser
                # of the race gets a 400/401 for the now-stale token) does not
                # wipe the winner's freshly stored token.
                jafaal_identity_links_crud.clear_user_identity_provider_refresh_token_if_matches(
                    user_id, idp_id, encrypted_refresh_token, db
                )
                return None
            else:
                # Other HTTP errors (5xx) - don't clear token
                logger.warning(
                    f"HTTP error refreshing IdP session for user {user_id}, idp {idp_id}: "
                    f"{err.response.status_code} - {err.response.text}",
                    exc_info=err,
                )
                return None

        except httpx.RequestError as err:
            logger.warning(
                f"Network error refreshing IdP session for user {user_id}, idp {idp_id}: {err}", exc_info=err
            )
            # Don't clear token - network issue, not token issue
            return None

        except Exception as err:
            logger.error(
                f"Unexpected error refreshing IdP session for user {user_id}, idp {idp_id}: {err}", exc_info=err
            )
            return None

    async def revoke_idp_token(
        self,
        user_id: UserId,
        idp_id: int,
        db: Session,
    ) -> bool:
        """
        Attempt to revoke a refresh token at the IdP (RFC 7009).

        This method implements the OAuth2 Token Revocation specification (RFC 7009)
        to notify the IdP that a token is no longer needed. This is a best-effort
        operation - failure to revoke does not prevent local token clearing.

        Args:
            user_id (int): The ID of the user whose token should be revoked.
            idp_id (int): The ID of the identity provider.
            db (Session): The database session for token retrieval.

        Returns:
            bool: True if revocation succeeded or was not needed, False if revocation failed.

        Raises:
            Does not raise exceptions - all errors are caught and logged.

        Security Note:
            - Token revocation at the IdP provides defense in depth
            - Even if revocation fails, tokens are cleared locally
            - Network failures or unsupported IdPs return False (non-fatal)
            - Follows OAuth2 RFC 7009 specification

        RFC 7009 Specification:
            POST to revocation_endpoint with:
            - token: The refresh token to revoke
            - token_type_hint: "refresh_token" (optional)
            - client_id and client_secret for authentication

        Example:
            success = await idp_service.revoke_idp_token(user_id=123, idp_id=1, db=db)
            if success:
                # Token revoked at IdP
                clear_local_token()
            else:
                # Revocation failed (network, unsupported, etc.) but clear locally anyway
                clear_local_token()
        """
        try:
            # Get the IdP configuration
            idp = idp_crud.get_identity_provider(idp_id, db)
            if not idp or not idp.enabled:
                logger.debug(f"IdP (ID: {idp_id}) not found or disabled. Skipping token revocation.")
                return False

            # Get the encrypted refresh token from database
            encrypted_refresh_token = (
                jafaal_identity_links_utils.get_user_identity_provider_refresh_token_by_user_id_and_idp_id(
                    user_id, idp_id, db
                )
            )

            if not encrypted_refresh_token:
                # No token to revoke - consider this success
                logger.debug(f"No refresh token to revoke for user {user_id}, idp {idp_id}")
                return True

            # Decrypt the refresh token
            try:
                refresh_token = crypto.decrypt_token_fernet(encrypted_refresh_token)
                if not refresh_token:
                    logger.warning(f"Failed to decrypt refresh token for revocation (user {user_id}, idp {idp_id})")
                    return False
            except Exception as err:
                logger.warning(f"Error decrypting refresh token for revocation: {err}", exc_info=err)
                return False

            # Try to get revocation endpoint from OIDC discovery
            revocation_endpoint = None
            if idp.issuer_url:
                try:
                    config = await self.get_oidc_configuration(idp)
                    if config:
                        revocation_endpoint = config.get("revocation_endpoint")
                except Exception as err:
                    logger.debug(f"OIDC discovery failed for revocation endpoint (IdP {idp.name}): {err}", exc_info=err)

            if not revocation_endpoint:
                # IdP doesn't advertise a revocation endpoint
                logger.debug(
                    f"IdP {idp.name} does not support token revocation (no revocation_endpoint). "
                    "Token will be cleared locally only."
                )
                return False

            # SSRF guard + HTTPS policy: the revocation endpoint comes from the
            # discovery document (not otherwise re-validated) and this POST
            # carries the refresh token plus client credentials, so refuse
            # private/internal targets and (when enabled) cleartext transports.
            network.reject_private_url(
                revocation_endpoint, purpose="oidc_revocation", require_https=_idp_require_https()
            )

            # Decrypt client secret and id for authentication
            try:
                client_id = self._decrypt_client_id(idp)
                client_secret = self._decrypt_client_secret(idp)
            except Exception as err:
                logger.warning(f"Failed to decrypt client secret or id for revocation: {err}", exc_info=err)
                return False

            # Call the revocation endpoint (RFC 7009)
            try:
                client = await self.discovery.get_http_client()
                response = await client.post(
                    revocation_endpoint,
                    data={
                        "token": refresh_token,
                        "token_type_hint": "refresh_token",
                        "client_id": client_id,
                        "client_secret": client_secret,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    # This POST carries the client secret and the IdP refresh
                    # token in its body, and the pooled discovery client follows
                    # redirects. On a 307/308 httpx preserves both the method and
                    # the body, so a revocation_endpoint that redirects — one
                    # taken from a discovery document, i.e. not fully under our
                    # control — would replay those credentials to the redirect
                    # target. The SSRF guard blocks private addresses but not
                    # cross-origin replay to a public host, so redirects are
                    # refused outright here, matching _create_oauth_client.
                    follow_redirects=False,
                )

                # RFC 7009: The revocation endpoint responds with HTTP 200
                # for both successful revocations and invalid tokens
                if response.status_code == 200:
                    logger.info(f"Successfully revoked IdP token for user {user_id}, idp {idp_id}")
                    return True
                if response.is_redirect:
                    logger.warning(
                        f"IdP {idp.name} revocation endpoint returned a redirect ({response.status_code}); "
                        "refusing to replay client credentials to the redirect target. "
                        "The token is cleared locally only."
                    )
                    return False
                logger.warning(
                    f"IdP revocation endpoint returned {response.status_code} for user {user_id}, idp {idp_id}"
                )
                return False

            except httpx.TimeoutException as err:
                logger.warning(f"Timeout revoking token at IdP {idp.name} for user {user_id}: {err}", exc_info=err)
                return False

            except httpx.RequestError as err:
                logger.warning(
                    f"Network error revoking token at IdP {idp.name} for user {user_id}: {err}", exc_info=err
                )
                return False

            except Exception as err:
                logger.warning(
                    f"Unexpected error revoking token at IdP {idp.name} for user {user_id}: {err}", exc_info=err
                )
                return False

        except Exception as err:
            # Catch-all for unexpected errors
            logger.error(f"Error in revoke_idp_token for user {user_id}, idp {idp_id}: {err}", exc_info=err)
            return False

    def _is_token_expired_by_age(self, link: jafaal_identity_links_models.IdentityLink) -> bool:
        """
        Check if an IdP refresh token has exceeded the maximum age policy.

        According to security best practices, refresh tokens should have a maximum lifetime
        to limit the window of exposure. This method checks if a token is older than the
        configured maximum age.

        Args:
            link (jafaal_identity_links_models.IdentityLink): The user-IdP link containing token metadata.

        Returns:
            bool: True if the token exceeds maximum age, False otherwise.

        Policy:
            - Tokens older than MAX_IDP_TOKEN_AGE_DAYS are considered expired
            - Age is calculated from idp_refresh_token_updated_at (last refresh time)
            - If idp_refresh_token_updated_at is None, use linked_at (initial link time)

        Security Note:
            Enforcing maximum token age:
            - Reduces window of exposure for compromised tokens
            - Forces periodic re-authentication (validates user access)
            - Limits damage from undetected token theft
            - Complies with security frameworks (e.g., NIST 800-63B)
        """
        if not link or not link.idp_refresh_token:
            # No token stored - not expired
            return False

        now = datetime.now(UTC)

        # Determine when the token was first issued or last refreshed
        token_timestamp = link.idp_refresh_token_updated_at or link.linked_at

        if not token_timestamp:
            # No timestamp available - cannot determine age (should not happen)
            logger.warning(
                f"Warning: IdP link user_id={link.user_id}, idp_id={link.idp_id} has no timestamp for age calculation"
            )
            return False

        # Calculate token age (normalize to UTC-aware so the comparison is safe
        # on backends that return naive datetimes, e.g. SQLite).
        token_age = now - timeutils.ensure_aware_utc(token_timestamp)

        # Check if token exceeds maximum age
        max_age = timedelta(days=MAX_IDP_TOKEN_AGE_DAYS)
        return token_age > max_age

    def _should_refresh_idp_token(self, link: jafaal_identity_links_models.IdentityLink) -> TokenAction:
        """
        Determine what action to take for an IdP token based on expiry and age policies.

        This method checks multiple conditions to decide the appropriate action:
        1. Token age - if token exceeds maximum age, it must be cleared
        2. Token existence - whether a refresh token is stored
        3. Token expiry - whether the access token is close to expiry
        4. Rate limiting - whether the token was refreshed very recently

        Args:
            link (jafaal_identity_links_models.IdentityLink): The user-IdP link containing token metadata.

        Returns:
            TokenAction: The action to take (SKIP, REFRESH, or CLEAR).

        Policy:
            - CLEAR if refresh token exceeds maximum age
            - SKIP if no refresh token is stored
            - SKIP if expiry time is unknown (assume token is valid)
            - SKIP if token was refreshed in last defined time(rate limiting)
            - REFRESH if access token expires within defined minutes
            - SKIP if token is still valid and not close to expiry

        Example usage:
            link = jafaal_identity_links_crud.get_user_identity_provider_by_user_id_and_idp_id(user_id, idp_id, db)
            action = self._should_refresh_idp_token(link)
            if action == TokenAction.REFRESH:
                await self.refresh_idp_session(user_id, idp_id, db)
            elif action == TokenAction.CLEAR:
                jafaal_identity_links_crud.clear_user_identity_provider_refresh_token_by_user_id_and_idp_id(user_id, idp_id, db)
        """
        # Check if refresh token exists
        if not link or not link.idp_refresh_token:
            return TokenAction.SKIP

        # Check if token has exceeded maximum age (security policy)
        if self._is_token_expired_by_age(link):
            logger.info(
                f"IdP refresh token for user_id={link.user_id}, idp_id={link.idp_id} "
                f"has exceeded maximum age ({MAX_IDP_TOKEN_AGE_DAYS} days). Will be cleared."
            )
            return TokenAction.CLEAR

        # Check if we know when the access token expires
        if not link.idp_access_token_expires_at:
            # No expiry info - assume token is still valid
            return TokenAction.SKIP

        now = datetime.now(UTC)

        # Check if token was refreshed very recently (rate limiting)
        if link.idp_refresh_token_updated_at:
            time_since_refresh = now - timeutils.ensure_aware_utc(link.idp_refresh_token_updated_at)
            if time_since_refresh < timedelta(minutes=TOKEN_REFRESH_RATE_LIMIT_MINUTES):
                # Refreshed less than defined - don't refresh again
                return TokenAction.SKIP

        # Check if access token is close to expiry
        time_until_expiry = timeutils.ensure_aware_utc(link.idp_access_token_expires_at) - now
        if time_until_expiry < timedelta(minutes=TOKEN_EXPIRY_THRESHOLD_MINUTES):
            # Token expires soon - should refresh
            return TokenAction.REFRESH

        # Token is still valid and not close to expiry
        return TokenAction.SKIP


# Global service instance
idp_service = IdentityProviderService()


def get_identity_provider(idp_id: int, db: Session) -> idp_models.IdentityProvider | None:
    """Public facade over the identity-provider CRUD lookup.

    Lets non-auth callers (the browser IdP-link redirect router) fetch a provider
    without importing ``jafaal.identity_providers.crud`` directly, keeping the auth
    data layer behind the boundary enforced by import-linter.

    Args:
        idp_id: The identity provider id.
        db: Active database session.

    Returns:
        The identity provider, or ``None`` when it does not exist.
    """
    return idp_crud.get_identity_provider(idp_id, db)


def create_link_oauth_state(
    db: Session,
    *,
    state_id: str,
    idp_id: int,
    nonce: str,
    ip_address: str | None,
    user_id: UserId,
    client_id: str,
    redirect_uri: str,
    client_state: str | None = None,
) -> None:
    """Persist the OAuth-state row for a browser IdP-link flow (auth-boundary facade).

    Wraps ``jafaal.oauth_state.crud.create_oauth_state`` so the non-auth browser
    link router can start the link flow without importing the auth OAuth-state
    data layer directly.

    Args:
        db: Active database session.
        state_id: The generated OAuth ``state`` id.
        idp_id: The identity provider being linked.
        nonce: The OIDC nonce bound to this flow.
        ip_address: The initiating client IP, when known.
        user_id: The user the link is for (its presence marks link mode).
        client_id: The registered client that started the link.
        redirect_uri: Where to return the browser afterwards. Already matched
            exactly against the client's registration — the same gate as
            ``/auth/authorize``, so a link flow can no more be used as an open
            redirect than a login flow can.
        client_state: The client's opaque ``state``, echoed back on return.

    Returns:
        None.
    """
    oauth_state_crud.create_oauth_state(
        db=db,
        state_id=state_id,
        idp_id=idp_id,
        nonce=nonce,
        ip_address=ip_address,
        user_id=user_id,
        purpose="link",
        client_id=client_id,
        redirect_uri=redirect_uri,
        client_state=client_state,
    )
