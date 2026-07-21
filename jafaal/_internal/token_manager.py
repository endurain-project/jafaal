"""JWT token issuance and validation for the authentication module.

Defines :class:`TokenType`, :class:`TokenManager` (issue/decode/validate JWTs
and mint CSRF tokens) and an accessor used as a FastAPI dependency.
"""

import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from enum import Enum

from joserfc import jwt
from joserfc.errors import (
    DecodeError,
    ExpiredTokenError,
    InsecureClaimError,
    InvalidClaimError,
    InvalidPayloadError,
    InvalidTokenError,
    MissingClaimError,
)
from joserfc.jwk import OctKey
from joserfc.jwt import Token

import jafaal.exceptions as jafaal_exceptions
import jafaal.ports as jafaal_ports
import jafaal.scopes as jafaal_scopes
import jafaal.settings as jafaal_settings

logger = logging.getLogger(__name__)


class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"


class TokenManager:
    """
    TokenManager is a utility class for managing JSON Web Tokens (JWT) in user
    sessions.

    This class provides methods for creating, decoding, validating, and
    extracting claims from JWTs, as well as generating secure CSRF tokens. It
    signs tokens with HMAC-SHA256 (``HS256`` only — the algorithm is pinned via
    :data:`jafaal.settings.ALLOWED_ALGORITHMS`) and integrates with application
    logging and exception handling for robust security and error reporting.

    Attributes:
        algorithm (str): The algorithm used for token operations (default: "HS256").
            _key: The imported key object used for cryptographic operations.

    Methods:
        __init__(secret_key: str, algorithm: str = "HS256"):
        get_token_claim(token: str, claim: str) -> str | list[str] | int:
        decode_token(token: str) -> dict:
        validate_token_expiration(token: str, expected_type: TokenType) -> None:
        create_token(session_id: str, user: jafaal_ports.UserProtocol, token_type: TokenType) -> tuple[datetime, str]:
        create_csrf_token() -> str:
            Generates a secure random CSRF (Cross-Site Request Forgery) token.
        JafaalError: Raised for invalid, expired, or missing claims in JWT tokens.
        ValueError: Raised for missing or invalid parameters during token creation.
    """

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        *,
        access_token_expire_minutes: int = 15,
        refresh_token_expire_days: int = 7,
        issuer: str = "",
        audience: str = "",
    ):
        """
        Initializes the TokenManager with the provided secret key and settings.

        Args:
            secret_key (str): The secret key used for signing and verifying
                tokens.
            algorithm (str, optional): The algorithm to use for token
                operations. Defaults to "HS256". Must be a member of
                :data:`jafaal.settings.ALLOWED_ALGORITHMS` so that the
                allow-list passed to ``jwt.decode`` cannot drift from the
                signing algorithm.
            access_token_expire_minutes (int): Access-token lifetime in minutes.
            refresh_token_expire_days (int): Refresh-token lifetime in days.
            issuer (str): JWT ``iss`` claim value.
            audience (str): JWT ``aud`` claim value.
        """
        if algorithm not in jafaal_settings.ALLOWED_ALGORITHMS:
            raise ValueError(
                f"algorithm={algorithm!r} is not in the JWT allow-list {sorted(jafaal_settings.ALLOWED_ALGORITHMS)}."
            )
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.issuer = issuer
        self.audience = audience
        self._key = OctKey.import_key(secret_key)

    def get_token_claim(self, token: str, claim: str) -> str | list[str] | int:
        """
        Retrieves a specific claim from a decoded JWT token.

        Args:
            token (str): The JWT token string to decode.
            claim (str): The name of the claim to retrieve from the token.

        Returns:
            str | list[str] | int: The value of the requested claim, which can
                be a string, list of strings, or integer.

        Raises:
            JafaalError: If the claim is not found in the token or if there
                is an error retrieving the claim.
        """
        try:
            # Decode the token
            payload = self.decode_token(token)

            # Get the claim from the payload and return it
            return payload.claims[claim]
        except KeyError as err:
            logger.error(f"Claim '{claim}' not found in token: {err}", exc_info=err, extra={"token": "[REDACTED]"})
            raise jafaal_exceptions.InvalidTokenError(f"Claim '{claim}' is missing in the token.") from err
        except jafaal_exceptions.JafaalError:
            # decode_token already raised a properly-formed 401; re-raise as-is.
            raise
        except Exception as err:
            logger.error(
                f"Unexpected error retrieving claim: {type(err).__name__}", exc_info=err, extra={"token": "[REDACTED]"}
            )
            raise jafaal_exceptions.InvalidTokenError("Unable to retrieve claim") from err

    def decode_token(self, token: str) -> Token:
        """
        Decodes a JWT token and returns the parsed Token object.

        Args:
            token (str): The JWT token to decode.

        Returns:
            joserfc.jwt.Token: The decoded token (use ``.claims`` to access
                payload claims).

        Raises:
            JafaalError: If the token cannot be decoded, raises an HTTP 401
                Unauthorized exception.
        """
        try:
            # Decode the token and return the payload. The ``algorithms``
            # allow-list is mandatory: without it, joserfc would accept any
            # algorithm the token header advertises (including ``none`` or
            # asymmetric variants), which would let an attacker who controls
            # the unauthenticated token bypass the HMAC signature check.
            return jwt.decode(token, self._key, algorithms=[self.algorithm])
        except InvalidPayloadError as payload_err:
            logger.error(f"Invalid token payload: {payload_err}", exc_info=payload_err, extra={"token": "[REDACTED]"})
            raise jafaal_exceptions.InvalidTokenError("Invalid token payload") from payload_err
        except DecodeError as decode_err:
            logger.error(f"Error decoding token: {decode_err}", exc_info=decode_err, extra={"token": "[REDACTED]"})
            raise jafaal_exceptions.InvalidTokenError("Unable to decode token") from decode_err
        except Exception as err:
            logger.error(
                f"Unexpected error decoding token: {type(err).__name__}", exc_info=err, extra={"token": "[REDACTED]"}
            )
            raise jafaal_exceptions.InvalidTokenError("Unable to decode token") from err

    def validate_token_expiration(
        self,
        token: str,
        expected_type: TokenType,
    ) -> None:
        """
        Validates expiration, required claims, and type of a JWT.

        Checks that the token contains all essential claims, is not expired or
        used before its valid time, and that the ``typ`` claim matches the
        expected token type. This prevents refresh tokens from being used as
        access tokens and vice versa.

        Args:
            token: The JWT token to validate.
            expected_type: The expected token type
                (``TokenType.ACCESS`` or
                ``TokenType.REFRESH``).

        Raises:
            JafaalError: If the token is missing required claims, expired,
                not yet valid, contains invalid claims, or has the wrong type.
        """
        try:
            # Define required claims
            claims_requests = jwt.JWTClaimsRegistry(
                sid={"essential": True},
                iss={
                    "essential": True,
                    "value": self.issuer,
                },
                aud={
                    "essential": True,
                    "value": self.audience,
                },
                sub={"essential": True},
                scope={"essential": True},
                iat={"essential": True},
                nbf={"essential": True},
                exp={"essential": True},
                jti={"essential": True},
                typ={
                    "essential": True,
                    "value": expected_type.value,
                },
            )

            # Decode the token to get the payload
            payload = self.decode_token(token)

            # Validate token claims (incl. expiration and typ)
            claims_requests.validate(payload.claims)
        except MissingClaimError as missing_err:
            logger.error(f"JWT missing claim error: {missing_err}", exc_info=missing_err, extra={"token": "[REDACTED]"})
            raise jafaal_exceptions.InvalidTokenError("Token is missing required claims.") from missing_err
        except ExpiredTokenError as expired_err:
            raise jafaal_exceptions.TokenExpiredError("Token is expired.") from expired_err
        except InvalidTokenError as invalid_err:
            logger.error(
                f"JWT is not valid yet error: {invalid_err}", exc_info=invalid_err, extra={"token": "[REDACTED]"}
            )
            raise jafaal_exceptions.InvalidTokenError("Token is not valid yet.") from invalid_err
        except InsecureClaimError as insecure_err:
            logger.error(
                f"JWT insecure claim error: {insecure_err}", exc_info=insecure_err, extra={"token": "[REDACTED]"}
            )
            raise jafaal_exceptions.InvalidTokenError("Token has insecure claims.") from insecure_err
        except InvalidClaimError as claims_err:
            logger.error(
                f"JWT claims validation error: {claims_err}", exc_info=claims_err, extra={"token": "[REDACTED]"}
            )
            raise jafaal_exceptions.InvalidTokenError("Token has invalid claims.") from claims_err
        except jafaal_exceptions.JafaalError:
            # decode_token already raised a properly-formed 401; re-raise as-is.
            raise
        except Exception as err:
            logger.error(
                f"Unexpected error validating token: {type(err).__name__}", exc_info=err, extra={"token": "[REDACTED]"}
            )
            raise jafaal_exceptions.InvalidTokenError("Token expired or invalid.") from err

    def validate_access_expiration_logged(self, access_token: str) -> None:
        """
        Validate an access token's expiration and log failures consistently.

        Wraps :meth:`validate_token_expiration` for ``TokenType.ACCESS`` and
        applies the shared logging policy used by the access-token validation
        dependency and ``IdentityService``: expired tokens log at ``debug``
        (an expected, routine condition) while all other validation failures
        log at ``error``. The original :class:`JafaalError` is re-raised
        unchanged so callers keep the same 401 semantics.

        Args:
            access_token: The raw JWT access token to validate.

        Raises:
            JafaalError: 401 if the token is missing claims, expired, not
                yet valid, or otherwise invalid.
        """
        try:
            self.validate_token_expiration(access_token, TokenType.ACCESS)
        except jafaal_exceptions.JafaalError as http_err:
            is_expired = isinstance(http_err, jafaal_exceptions.TokenExpiredError)
            logger.log(
                logging.DEBUG if is_expired else logging.ERROR,
                f"Access token validation failed: {http_err.detail}",
                exc_info=None if is_expired else http_err,
                extra={"access_token": "[REDACTED]"},
            )
            raise

    def create_token(
        self,
        session_id: str,
        user: jafaal_ports.UserProtocol,
        token_type: TokenType,
    ) -> tuple[datetime, str]:
        """
        Creates a JWT token for a user session with appropriate access scope
        and expiration.

        Args:
            session_id (str): The unique identifier for the session.
            user (jafaal_ports.UserProtocol): The user object containing user
                details.
            token_type (TokenType): The type of token to create (access or
                refresh).

        Returns:
            tuple[datetime, str]: A tuple containing the token's expiration
                datetime and the encoded JWT token string.

        Raises:
            ValueError: If required parameters are missing or invalid.
        """
        # Check user access level and set scope accordingly
        catalog = jafaal_scopes.get_scope_catalog()
        scope = catalog.regular if not user.is_superuser else catalog.admin

        exp = datetime.now(UTC) + timedelta(minutes=self.access_token_expire_minutes)
        if token_type == TokenType.REFRESH:
            exp = datetime.now(UTC) + timedelta(days=self.refresh_token_expire_days)

        # Set now
        now = int(datetime.now(UTC).timestamp())

        # The JWT ``sub`` is JSON: an integer PK is kept as an int (byte-identical
        # to legacy tokens), while a UUID PK is serialised to its string form so
        # it round-trips. ``resolve_from_access_token`` / ``get_sub_from_*`` coerce
        # it back to the user table's PK type on the way in.
        sub = user.id if isinstance(user.id, int) else str(user.id)

        scope_dict = {
            "sid": session_id,
            "iss": self.issuer,
            "aud": self.audience,
            "sub": sub,
            "scope": scope,
            "iat": now,
            "nbf": now,
            "exp": exp,
            "jti": str(uuid.uuid4()),
            "typ": token_type.value,
        }

        encoded_token = jwt.encode(
            {"alg": self.algorithm},
            scope_dict.copy(),
            self._key,
        )

        # Return the expiration and the encoded token
        return exp, encoded_token

    @staticmethod
    def create_csrf_token() -> str:
        """
        Generate a secure random CSRF (Cross-Site Request Forgery) token.

        Returns:
            str: A URL-safe, securely generated random string suitable for use
                as a CSRF token.
        """
        return secrets.token_urlsafe(32)


_token_manager: TokenManager | None = None
_token_manager_generation: int = -1


def get_token_manager() -> TokenManager:
    """Return a process-wide :class:`TokenManager` built from settings.

    The instance is cached and transparently rebuilt if :func:`jafaal.configure`
    is called again (detected via the settings generation counter).

    Returns:
        TokenManager: Token manager bound to the installed ``AuthSettings``.
    """
    global _token_manager, _token_manager_generation
    generation = jafaal_settings.settings_generation()
    if _token_manager is None or _token_manager_generation != generation:
        settings = jafaal_settings.get_settings()
        _token_manager = TokenManager(
            settings.secret_key,
            settings.algorithm,
            access_token_expire_minutes=settings.access_token_expire_minutes,
            refresh_token_expire_days=settings.refresh_token_expire_days,
            issuer=settings.resolved_issuer,
            audience=settings.resolved_audience,
        )
        _token_manager_generation = generation
    return _token_manager
