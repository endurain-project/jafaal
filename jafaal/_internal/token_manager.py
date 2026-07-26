"""JWT token issuance and validation for the authentication module.

Defines :class:`TokenType`, :class:`TokenManager` (issue/decode/validate JWTs
and mint CSRF tokens) and an accessor used as a FastAPI dependency.
"""

import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from joserfc import jwt
from joserfc.errors import (
    BadSignatureError,
    DecodeError,
    ExpiredTokenError,
    InsecureClaimError,
    InvalidClaimError,
    InvalidPayloadError,
    InvalidTokenError,
    MissingClaimError,
)
from joserfc.jwk import KeySet, OctKey
from joserfc.jwt import Token

import jafaal.exceptions as jafaal_exceptions
import jafaal.ports as jafaal_ports
import jafaal.scopes as jafaal_scopes
import jafaal.settings as jafaal_settings
from jafaal._core import jwk_keys

logger = logging.getLogger(__name__)


class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"


# JOSE ``typ`` header values. RFC 9068 §2.1 registers ``at+jwt`` as the media
# type of an OAuth 2.0 access token, which lets a resource server reject a token
# minted for some other purpose before it even looks at the claims. There is no
# registered type for refresh tokens; ``rt+jwt`` is the widely-used analogue.
_TYP_HEADER_BY_TOKEN_TYPE: dict[TokenType, str] = {
    TokenType.ACCESS: "at+jwt",
    TokenType.REFRESH: "rt+jwt",
}

# Payload claim naming the token's use.
#
# RFC 9068 puts the token's media type in the JOSE ``typ`` *header*, so the
# payload claim carrying the same information must not also be called ``typ`` —
# that would collide with the registered header parameter. ``token_use`` (the
# AWS Cognito convention) keeps the two distinct.
TOKEN_USE_CLAIM = "token_use"


def token_use(claims: dict[str, Any]) -> str | None:
    """Return the token's use (``"access"`` / ``"refresh"``) from its claims.

    Args:
        claims: The decoded JWT payload.

    Returns:
        The token use, or ``None`` when the claim is absent or not a string.
    """
    value = claims.get(TOKEN_USE_CLAIM)
    return value if isinstance(value, str) else None


def scopes_from_claims(claims: dict[str, Any]) -> list[str] | None:
    """Return the granted scopes from a token's ``scope`` claim.

    ``scope`` is a space-delimited string (RFC 6749 §3.3 / RFC 9068 §2.2), which
    is what a resource server using a stock JWT library expects.

    Args:
        claims: The decoded JWT payload.

    Returns:
        The scope list, or ``None`` when the claim is missing or malformed.
    """
    scope = claims.get("scope")
    if isinstance(scope, str):
        return scope.split()
    return None


def _validate_token_use(claims: dict[str, Any], expected_type: TokenType) -> None:
    """Assert the token names ``expected_type`` as its use.

    Raises the same joserfc errors the claims registry would, so the caller's
    existing handlers map them consistently — in particular, an absent claim
    surfaces as ``MissingClaimError``, which the refresh-token dependency uses to
    detect an unusable cookie and clear it rather than looping.

    Args:
        claims: The decoded JWT payload.
        expected_type: The token type the caller requires.

    Raises:
        MissingClaimError: If the claim is not present.
        InvalidClaimError: If the token names a different use.
    """
    if TOKEN_USE_CLAIM not in claims:
        raise MissingClaimError(TOKEN_USE_CLAIM)
    if token_use(claims) != expected_type.value:
        raise InvalidClaimError(TOKEN_USE_CLAIM)


class TokenManager:
    """Issue, decode, and validate JWTs (and mint CSRF tokens) for user sessions.

    Signs with either ``HS256`` (symmetric, the default — a shared secret) or an
    asymmetric RSA/EC algorithm (``RS256``/``ES256``/…), where a private key
    signs and the corresponding public key is published at the JWKS endpoint so
    resource servers verify statelessly. The algorithm is pinned via
    :data:`jafaal.settings.ALLOWED_ALGORITHMS` and the same allow-list is passed
    to ``jwt.decode`` so it cannot drift (blocking ``alg=none`` and
    algorithm-confusion). Asymmetric tokens carry the active key's RFC 7638
    thumbprint as ``kid``. Validation failures raise a
    :class:`~jafaal.exceptions.JafaalError` (mapped to HTTP 401 at the router
    edge); the constructor raises :class:`ValueError` for an algorithm outside
    the allow-list or missing asymmetric key material.

    Attributes:
        algorithm: The JWT signing algorithm.
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
        secret_key_fallbacks: tuple[str, ...] = (),
        private_key: str = "",
        private_key_fallbacks: tuple[str, ...] = (),
        leeway_seconds: int = 0,
        client_id: str = "",
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
            secret_key_fallbacks (tuple[str, ...]): Additional keys accepted
                when *verifying* a token (never used to sign). Lets tokens
                issued before a ``secret_key`` rotation keep validating during
                the overlap window.
            private_key (str): PEM private key used to sign JWTs when
                ``algorithm`` is asymmetric (RSA/EC); ignored for HS256.
            private_key_fallbacks (tuple[str, ...]): Verify-only public/private
                PEM keys kept in the published JWKS during a signing-key
                rotation overlap.
            leeway_seconds (int): Clock-skew tolerance, in seconds, applied to
                the ``exp`` / ``nbf`` claims during validation. ``0`` is strict;
                a small value avoids spurious 401s when the issuing and
                validating clocks differ slightly.
            client_id (str): Value of the ``client_id`` claim RFC 9068 requires
                on an access token.
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
        self.leeway_seconds = leeway_seconds
        self.client_id = client_id

        self._is_symmetric: bool = algorithm not in jwk_keys.ASYMMETRIC_ALGORITHMS
        self._sign_key: Any
        self._sign_header: dict[str, str]
        self._encode_algorithms: list[str] | None
        self._decode_keys: list[Any]
        self._verify_keys: list[Any]
        self._verify_keyset: KeySet | None

        if self._is_symmetric:
            # HS256: sign and verify with the shared secret. Verification also
            # accepts any rotation fallbacks so a token signed before a
            # secret_key rotation still validates during the overlap window;
            # signing always uses the primary key.
            self._sign_key = OctKey.import_key(secret_key)
            self._sign_header = {"alg": algorithm}
            self._encode_algorithms = None
            self._decode_keys = [self._sign_key, *(OctKey.import_key(fallback) for fallback in secret_key_fallbacks)]
            self._verify_keys = []
            self._verify_keyset = None
        else:
            # Asymmetric: sign with the private key; verify/publish with the
            # public key(s). The token header carries the active key's RFC 7638
            # thumbprint as ``kid`` so verifiers and the JWKS agree on it, and
            # fallback public keys stay in the JWKS during a rotation overlap.
            if not private_key:
                raise ValueError(f"algorithm={algorithm!r} is asymmetric and requires a private_key.")
            self._sign_key = jwk_keys.import_private_signing_key(private_key, algorithm)
            self._sign_header = {"alg": algorithm, "kid": self._sign_key.thumbprint()}
            self._encode_algorithms = [algorithm]
            self._verify_keys = [
                jwk_keys.public_verification_key(self._sign_key, algorithm),
                *(jwk_keys.import_verification_key(fallback, algorithm) for fallback in private_key_fallbacks),
            ]
            self._verify_keyset = KeySet(self._verify_keys)
            self._decode_keys = []

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

        The ``algorithms`` allow-list (pinned to this manager's algorithm) is
        always passed to ``jwt.decode``: without it joserfc would trust whatever
        algorithm the token header advertises (``none`` or an
        algorithm-confusion variant), bypassing the signature check.

        In symmetric (HS256) mode the token is verified against the primary key
        then each rotation fallback. In asymmetric mode it is verified against
        the public-key set, which joserfc selects by the header ``kid`` (the
        active key plus any rotation fallbacks).

        Args:
            token (str): The JWT token to decode.

        Returns:
            joserfc.jwt.Token: The decoded token (use ``.claims`` to access
                payload claims).

        Raises:
            JafaalError: If the token cannot be decoded, raises an HTTP 401
                Unauthorized exception.
        """
        if self._is_symmetric:
            return self._decode_symmetric(token)
        return self._decode_asymmetric(token)

    def _decode_symmetric(self, token: str) -> Token:
        """Verify an HS256 token against the primary key then rotation fallbacks."""
        last_signature_err: BadSignatureError | None = None
        for key in self._decode_keys:
            try:
                return jwt.decode(token, key, algorithms=[self.algorithm])
            except BadSignatureError as sig_err:
                # Wrong key: try the next rotation fallback before giving up.
                last_signature_err = sig_err
                continue
            except InvalidPayloadError as payload_err:
                logger.error(
                    f"Invalid token payload: {payload_err}", exc_info=payload_err, extra={"token": "[REDACTED]"}
                )
                raise jafaal_exceptions.InvalidTokenError("Invalid token payload") from payload_err
            except DecodeError as decode_err:
                logger.error(f"Error decoding token: {decode_err}", exc_info=decode_err, extra={"token": "[REDACTED]"})
                raise jafaal_exceptions.InvalidTokenError("Unable to decode token") from decode_err
            except Exception as err:
                logger.error(
                    f"Unexpected error decoding token: {type(err).__name__}",
                    exc_info=err,
                    extra={"token": "[REDACTED]"},
                )
                raise jafaal_exceptions.InvalidTokenError("Unable to decode token") from err
        # Signature did not match the primary key or any rotation fallback.
        logger.error(
            "Token signature did not match any active signing key",
            exc_info=last_signature_err,
            extra={"token": "[REDACTED]"},
        )
        raise jafaal_exceptions.InvalidTokenError("Unable to decode token") from last_signature_err

    def _decode_asymmetric(self, token: str) -> Token:
        """Verify an asymmetric token against the public-key set (selected by ``kid``)."""
        keyset = self._verify_keyset
        if keyset is None:  # pragma: no cover - always built in asymmetric mode
            raise jafaal_exceptions.InvalidTokenError("Unable to decode token")
        try:
            return jwt.decode(token, keyset, algorithms=[self.algorithm])
        except BadSignatureError as sig_err:
            logger.error(
                "Token signature did not match any active signing key",
                exc_info=sig_err,
                extra={"token": "[REDACTED]"},
            )
            raise jafaal_exceptions.InvalidTokenError("Unable to decode token") from sig_err
        except InvalidPayloadError as payload_err:
            logger.error(f"Invalid token payload: {payload_err}", exc_info=payload_err, extra={"token": "[REDACTED]"})
            raise jafaal_exceptions.InvalidTokenError("Invalid token payload") from payload_err
        except DecodeError as decode_err:
            logger.error(f"Error decoding token: {decode_err}", exc_info=decode_err, extra={"token": "[REDACTED]"})
            raise jafaal_exceptions.InvalidTokenError("Unable to decode token") from decode_err
        except jafaal_exceptions.JafaalError:
            raise
        except Exception as err:
            logger.error(
                f"Unexpected error decoding token: {type(err).__name__}",
                exc_info=err,
                extra={"token": "[REDACTED]"},
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
        used before its valid time, and that it names the expected token use.
        This prevents refresh tokens from being used as access tokens and vice
        versa.

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
            # Define required claims. ``leeway`` applies a small clock-skew
            # tolerance to the time-based claims (``exp`` / ``nbf``) so slightly
            # skewed nodes do not spuriously reject otherwise-valid tokens.
            # The token-use claim is checked separately below.
            claims_requests = jwt.JWTClaimsRegistry(
                leeway=self.leeway_seconds,
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
            )

            # Decode the token to get the payload
            payload = self.decode_token(token)
            _validate_token_use(payload.claims, expected_type)

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

        claims: dict[str, Any] = {
            "sid": session_id,
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "nbf": now,
            "exp": exp,
            "jti": str(uuid.uuid4()),
            # RFC 9068 / RFC 7519 shapes, so a resource server verifying against
            # the published JWKS with a stock JWT library reads what it expects:
            # ``sub`` is a string (RFC 7519 §4.1.2 defines it as StringOrURI),
            # ``scope`` is space-delimited (RFC 6749 §3.3), and ``client_id`` is
            # present (RFC 9068 §2.2). ``coerce_user_id`` converts ``sub`` back
            # to the host user table's primary-key type on the way in.
            "sub": str(user.id),
            "scope": " ".join(scope),
            "client_id": self.client_id,
            TOKEN_USE_CLAIM: token_type.value,
        }
        # The media type goes in the JOSE ``typ`` header, not a payload claim.
        header = {**self._sign_header, "typ": _TYP_HEADER_BY_TOKEN_TYPE[token_type]}

        encoded_token = jwt.encode(
            header,
            claims.copy(),
            self._sign_key,
            algorithms=self._encode_algorithms,
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

    def jwks(self) -> dict[str, Any]:
        """Return the JSON Web Key Set of public verification keys.

        Empty (``{"keys": []}``) in symmetric (HS256) mode, which has no public
        key to publish. In asymmetric mode it contains the active signing key's
        public JWK plus any rotation fallbacks, each tagged with its ``kid``
        (RFC 7638 thumbprint), ``use: "sig"``, and ``alg`` — exactly what a
        resource server needs to verify JAFAAL's access tokens statelessly.
        """
        return {"keys": [jwk_keys.jwk_entry(key, self.algorithm) for key in self._verify_keys]}


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
            secret_key_fallbacks=settings.secret_key_fallbacks,
            private_key=settings.private_key,
            private_key_fallbacks=settings.private_key_fallbacks,
            leeway_seconds=settings.jwt_leeway_seconds,
            client_id=settings.resolved_client_id,
        )
        _token_manager_generation = generation
    return _token_manager
