"""Authentication package.

Provides the FastAPI router, JWT token issuance and validation,
password hashing, scope enforcement, API-key validation, and the
progressive-lockout stores used during login and MFA verification.

Persistence-bearing concerns (identity providers, IdP link tokens,
MFA backup codes, OAuth state) live in dedicated sub-packages and
expose their own models, schemas, and CRUD modules.

Exports:
    - Password hashing: ``PasswordHasher``, ``PasswordPolicyError``,
      ``get_password_hasher``
    - JWT: ``TokenManager``, ``TokenType``, ``get_token_manager``
    - Security dependencies: ``AuthContext``, ``oauth2_scheme``,
      ``validate_access_token``,
      ``check_auth_scopes``,
      ``get_sub_from_access_token``, ``get_sid_from_access_token``,
      ``get_sub_from_refresh_token``, ``get_sid_from_refresh_token``,
      ``validate_access_token_or_api_key``,

      Scope enforcement (``check_scopes``) is provided by
      :mod:`jafaal.dependencies`, which resolves the full principal.
    - Schemas: ``MFALoginRequest``,
      ``MFARequiredResponse``,
      ``TokenResponseWeb``, ``TokenResponseMobile``,
      ``LogoutResponse``
    - Stores: ``PendingMFALogin``, ``FailedLoginAttempts``,
      ``StepUpAttempts``, ``get_pending_mfa_store``,
      ``get_failed_login_attempts``, ``get_step_up_attempts``,
      ``cleanup_expired_pending_mfa_logins``,
      ``clear_pending_mfa_for_user``
    - Helpers: ``authenticate_user``, ``complete_login``,
      ``create_tokens``
    - User model mixins: ``UserMixin``, ``IntPKUserMixin``,
      ``UUIDPKUserMixin`` (extensible base for the host app's user table)
"""

from importlib import import_module as _import_module
from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _version
from typing import TYPE_CHECKING

# Eager, model-free foundation — safe to import before ``jafaal.map_models()``.
# The model-touching public API (security dependencies, login helpers, API-key
# scope config) transitively imports the ORM model layer, which does not exist
# until the host calls ``jafaal.map_models(...)``. That API is therefore loaded
# lazily via ``__getattr__`` (see the TYPE_CHECKING / ``_LAZY_EXPORTS`` block
# near the bottom of this module).
from ._internal.password_hasher import (
    PasswordHasher,
    PasswordPolicyError,
    get_password_hasher,
)
from ._internal.security_stores import (
    FailedLoginAttempts,
    PendingLogin,
    PendingMFALogin,
    StepUpAttempts,
    StepUpStore,
    cleanup_expired_pending_mfa_logins,
    clear_pending_mfa_for_user,
    get_failed_login_attempts,
    get_pending_mfa_store,
    get_step_up_attempts,
)
from ._internal.token_manager import TokenManager, TokenType, get_token_manager
from .error_handler import jafaal_exception_handler, register_exception_handlers
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    IdentityProviderError,
    IdentityProviderTimeoutError,
    InactiveAccountError,
    InternalError,
    InvalidApiKeyError,
    InvalidCredentialsError,
    InvalidMFACodeError,
    InvalidRequestError,
    InvalidTokenError,
    JafaalError,
    MissingScopeError,
    NotFoundError,
    PreconditionFailedError,
    RateLimitedError,
    ServiceUnavailableError,
    SessionExpiredError,
    StaleRefreshTokenError,
    StepUpReauthRequiredError,
    StoreUnavailableError,
    TokenExpiredError,
    UnprocessableError,
    UpstreamError,
    UpstreamTimeoutError,
)
from .factory import RouterPrefixes, create_auth_router, shutdown, verify_configuration
from .jwks import get_jwks
from .metadata import get_authorization_server_metadata
from .orm import (
    Base,
    autonomous_session,
    configure_sessionmaker,
    get_active_base,
    is_models_mapped,
    map_models,
    savepoint,
    session_scope,
    unit_of_work,
)
from .ports import (
    AccountLocked,
    AuthenticatorChanged,
    AuthEventSink,
    EmailVerificationRequested,
    IdpAccountLinked,
    IdpIdentity,
    NewDeviceLogin,
    NullAuthEventSink,
    NullPasswordBreachChecker,
    PasswordBreachChecker,
    PasswordPolicy,
    PasswordResetRequested,
    RefreshTokenTheftDetected,
    ScopeResolver,
    SettingsProvider,
    SignupApproved,
    SignupConfig,
    SignupPendingAdminApproval,
    TieredScopeResolver,
    UserProtocol,
    UserRepository,
    configure_event_sink,
    configure_password_breach_checker,
    configure_scope_resolver,
    configure_settings_provider,
    configure_user_repository,
    get_event_sink,
    get_password_breach_checker,
    get_scope_resolver,
    get_settings_provider,
    get_user_repository,
    reset_ports,
)
from .rate_limit import (
    NoOpRateLimiter,
    RateLimiter,
    configure_rate_limiter,
    get_rate_limiter,
    reset_rate_limiter,
)
from .schema import (
    LogoutResponse,
    MFALoginRequest,
    MFARequiredResponse,
    SignUpRequest,
    StepUpVerification,
    TokenIntrospectionResponse,
    TokenResponseMobile,
    TokenResponseWeb,
)
from .scopes import (
    AUTH_INTROSPECT,
    DEFAULT_SCOPE_CATALOG,
    ScopeCatalog,
    configure_scopes,
    get_scope_catalog,
    reset_scopes,
)
from .settings import (
    ApiKeySettings,
    AuditSettings,
    AuthSettings,
    MfaSettings,
    NetworkSettings,
    OAuthClient,
    PasswordSettings,
    RateLimitSettings,
    Secrets,
    SessionSettings,
    SsoSettings,
    TokenSettings,
    WebAuthnSettings,
    configure,
    get_settings,
    reset,
)
from .state_store import (
    InMemoryStateStore,
    StateStore,
    StateStoreUnavailableError,
    TieredFailureOutcome,
    configure_state_store,
    get_state_store,
    reset_state_store,
)
from .user_model import IntPKUserMixin, UserMixin, UUIDPKUserMixin

# ---------------------------------------------------------------------------
# Lazy, model-touching public API.
#
# These symbols transitively import the ORM model layer, which is not defined
# until the host calls ``jafaal.map_models(...)``. They are therefore imported
# on first access via ``__getattr__`` (by which time the host has mapped the
# models). Declared under TYPE_CHECKING so static type checkers still see their
# real signatures.
# ---------------------------------------------------------------------------
if TYPE_CHECKING:
    from ._internal.internal_dependencies import (
        AuthContext,
        get_sid_from_access_token,
        get_sid_from_refresh_token,
        get_sub_from_access_token,
        get_sub_from_refresh_token,
        header_csrf_token_scheme,
        oauth2_scheme,
        validate_access_token_or_api_key,
    )
    from .api_keys.utils import (
        configure_api_key_scopes,
        get_api_key_scopes,
        reset_api_key_scopes,
    )
    from .dependencies import check_auth_scopes
    from .utils import (
        authenticate_user,
        complete_login,
        create_tokens,
    )

_LAZY_EXPORTS: dict[str, str] = {
    "AuthContext": "jafaal._internal.internal_dependencies",
    "get_sid_from_access_token": "jafaal._internal.internal_dependencies",
    "get_sid_from_refresh_token": "jafaal._internal.internal_dependencies",
    "get_sub_from_access_token": "jafaal._internal.internal_dependencies",
    "get_sub_from_refresh_token": "jafaal._internal.internal_dependencies",
    "header_csrf_token_scheme": "jafaal._internal.internal_dependencies",
    "oauth2_scheme": "jafaal._internal.internal_dependencies",
    "validate_access_token_or_api_key": "jafaal._internal.internal_dependencies",
    "check_auth_scopes": "jafaal.dependencies",
    "authenticate_user": "jafaal.utils",
    "complete_login": "jafaal.utils",
    "create_tokens": "jafaal.utils",
    "configure_api_key_scopes": "jafaal.api_keys.utils",
    "get_api_key_scopes": "jafaal.api_keys.utils",
    "reset_api_key_scopes": "jafaal.api_keys.utils",
}


def __getattr__(name: str) -> object:
    """Lazily import the model-touching public API on first access (PEP 562)."""
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(_import_module(module_name), name)
    globals()[name] = value  # cache so later access skips __getattr__
    return value


try:
    __version__ = _version("jafaal")
except _PackageNotFoundError:  # pragma: no cover - running from an unbuilt source tree
    __version__ = "0.0.0+unknown"

__all__ = [
    # Package metadata
    "__version__",
    # Configuration
    "ApiKeySettings",
    "AuditSettings",
    "AuthSettings",
    "Base",
    "MfaSettings",
    "NetworkSettings",
    "OAuthClient",
    "PasswordSettings",
    "RateLimitSettings",
    "RouterPrefixes",
    "Secrets",
    "SessionSettings",
    "SsoSettings",
    "TokenSettings",
    "WebAuthnSettings",
    "configure",
    "configure_sessionmaker",
    "create_auth_router",
    "get_active_base",
    "get_authorization_server_metadata",
    "get_jwks",
    "get_settings",
    "is_models_mapped",
    "map_models",
    "reset",
    "shutdown",
    "verify_configuration",
    # Transactions (the caller owns the unit of work)
    "autonomous_session",
    "savepoint",
    "session_scope",
    "unit_of_work",
    # Ports (host-implemented boundary)
    "AccountLocked",
    "AuthEventSink",
    "EmailVerificationRequested",
    "IdpIdentity",
    "NewDeviceLogin",
    "NullAuthEventSink",
    "NullPasswordBreachChecker",
    "PasswordBreachChecker",
    "PasswordPolicy",
    "PasswordResetRequested",
    "AuthenticatorChanged",
    "IdpAccountLinked",
    "RefreshTokenTheftDetected",
    "ScopeResolver",
    "SettingsProvider",
    "SignupApproved",
    "SignupConfig",
    "SignupPendingAdminApproval",
    "TieredScopeResolver",
    "UserProtocol",
    "UserRepository",
    "configure_event_sink",
    "configure_password_breach_checker",
    "configure_scope_resolver",
    "configure_settings_provider",
    "configure_user_repository",
    "get_event_sink",
    "get_password_breach_checker",
    "get_scope_resolver",
    "get_settings_provider",
    "get_user_repository",
    "reset_ports",
    # Exceptions + edge handler
    "AuthenticationError",
    "AuthorizationError",
    "ConflictError",
    "IdentityProviderError",
    "IdentityProviderTimeoutError",
    "InternalError",
    "InactiveAccountError",
    "InvalidApiKeyError",
    "InvalidCredentialsError",
    "InvalidMFACodeError",
    "InvalidRequestError",
    "InvalidTokenError",
    "JafaalError",
    "MissingScopeError",
    "NotFoundError",
    "PreconditionFailedError",
    "RateLimitedError",
    "ServiceUnavailableError",
    "SessionExpiredError",
    "StaleRefreshTokenError",
    "StepUpReauthRequiredError",
    "StoreUnavailableError",
    "TokenExpiredError",
    "UnprocessableError",
    "UpstreamError",
    "UpstreamTimeoutError",
    "jafaal_exception_handler",
    "register_exception_handlers",
    # Security dependencies
    "AuthContext",
    "FailedLoginAttempts",
    # Schemas
    "LogoutResponse",
    "MFALoginRequest",
    "MFARequiredResponse",
    "SignUpRequest",
    "StepUpVerification",
    "TokenIntrospectionResponse",
    # Password hashing
    "PasswordHasher",
    "PasswordPolicyError",
    # Auth security stores / lockout
    "PendingLogin",
    "PendingMFALogin",
    "StepUpAttempts",
    "StepUpStore",
    # State store (ephemeral lockout / MFA-secret backend)
    "InMemoryStateStore",
    "StateStore",
    "StateStoreUnavailableError",
    "TieredFailureOutcome",
    "configure_state_store",
    "get_state_store",
    "reset_state_store",
    # Rate limiting (host-injected enforcement)
    "NoOpRateLimiter",
    "RateLimiter",
    "configure_rate_limiter",
    "get_rate_limiter",
    "reset_rate_limiter",
    # Scopes (host-extensible catalog)
    "AUTH_INTROSPECT",
    "DEFAULT_SCOPE_CATALOG",
    "ScopeCatalog",
    "configure_scopes",
    "get_scope_catalog",
    "reset_scopes",
    # API-key scopes (host-configured allow-list)
    "configure_api_key_scopes",
    "get_api_key_scopes",
    "reset_api_key_scopes",
    # JWT / token management
    "TokenManager",
    "TokenResponseMobile",
    "TokenResponseWeb",
    "TokenType",
    # User model mixins
    "IntPKUserMixin",
    "UUIDPKUserMixin",
    "UserMixin",
    # Helpers
    "authenticate_user",
    "check_auth_scopes",
    "cleanup_expired_pending_mfa_logins",
    "clear_pending_mfa_for_user",
    "complete_login",
    "create_tokens",
    "get_failed_login_attempts",
    "get_password_hasher",
    "get_pending_mfa_store",
    "get_sid_from_access_token",
    "get_sid_from_refresh_token",
    "get_step_up_attempts",
    "get_sub_from_access_token",
    "get_sub_from_refresh_token",
    "get_token_manager",
    "header_csrf_token_scheme",
    "oauth2_scheme",
    "validate_access_token_or_api_key",
]
