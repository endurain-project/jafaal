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
      ``validate_access_token_expiration``, ``validate_refresh_token``,
      ``check_auth_scopes``,
      ``get_sub_from_access_token``, ``get_sid_from_access_token``,
      ``get_sub_from_refresh_token``, ``get_sid_from_refresh_token``,
      ``validate_access_token_or_api_key``,
      ``header_client_type_scheme``, ``header_csrf_token_scheme``

      Scope enforcement (``check_scopes``) is provided by
      :mod:`jafaal.dependencies`, which resolves the full principal.
    - Schemas: ``LoginRequest``, ``MFALoginRequest``,
      ``MFARequiredResponse``, ``MobileSessionResponse``,
      ``TokenResponseWeb``, ``TokenResponseMobile``,
      ``LogoutResponse``
    - Stores: ``PendingMFALogin``, ``FailedLoginAttempts``,
      ``StepUpAttempts``, ``get_pending_mfa_store``,
      ``get_failed_login_attempts``, ``get_step_up_attempts``,
      ``cleanup_expired_pending_mfa_logins``,
      ``clear_pending_mfa_for_user``
    - Helpers: ``authenticate_user``, ``complete_login``,
      ``create_tokens``, ``create_mobile_pkce_session_response``
    - User model mixins: ``UserMixin``, ``IntPKUserMixin``,
      ``UUIDPKUserMixin`` (extensible base for the host app's user table)
"""

# Register every JAFAAL ORM model on ``jafaal.orm.Base`` at import time so that
# their relationships — and the reverse relationships a host user model inherits
# from ``UserMixin`` — all resolve at mapper-configuration time. Importing each
# ``models`` module is what registers its mapped classes on the shared registry.
from ._internal.internal_dependencies import (
    AuthContext,
    get_sid_from_access_token,
    get_sid_from_refresh_token,
    get_sub_from_access_token,
    get_sub_from_refresh_token,
    header_client_type_scheme,
    header_csrf_token_scheme,
    oauth2_scheme,
    validate_access_token_expiration,
    validate_access_token_or_api_key,
    validate_refresh_token,
)
from ._internal.password_hasher import (
    PasswordHasher,
    PasswordPolicyError,
    get_password_hasher,
)
from ._internal.security_stores import (
    FailedLoginAttempts,
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
from .api_keys import models as _api_keys_models  # noqa: F401
from .credentials import models as _credentials_models  # noqa: F401
from .dependencies import check_auth_scopes
from .error_handler import jafaal_exception_handler, register_exception_handlers
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    IdentityProviderError,
    IdentityProviderTimeoutError,
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
    StoreUnavailableError,
    TokenExpiredError,
    UnprocessableError,
    UpstreamError,
    UpstreamTimeoutError,
)
from .identity_providers import models as _idp_models  # noqa: F401
from .identity_providers.link_tokens import models as _idp_link_token_models  # noqa: F401
from .identity_providers.links import models as _idp_link_models  # noqa: F401
from .mfa import models as _mfa_models  # noqa: F401
from .mfa.backup_codes import models as _mfa_backup_codes_models  # noqa: F401
from .oauth_state import models as _oauth_state_models  # noqa: F401
from .orm import Base, configure_sessionmaker
from .password_reset_tokens import models as _password_reset_tokens_models  # noqa: F401
from .ports import (
    AuthEventSink,
    EmailVerificationRequested,
    IdpIdentity,
    NullAuthEventSink,
    PasswordPolicy,
    PasswordResetRequested,
    SettingsProvider,
    SignupApproved,
    SignupConfig,
    SignupPendingAdminApproval,
    UserProtocol,
    UserRepository,
    configure_event_sink,
    configure_settings_provider,
    configure_user_repository,
    get_event_sink,
    get_settings_provider,
    get_user_repository,
    reset_ports,
)
from .schema import (
    LoginRequest,
    LogoutResponse,
    MFALoginRequest,
    MFARequiredResponse,
    MobileSessionResponse,
    SignUpRequest,
    StepUpVerification,
    TokenResponseMobile,
    TokenResponseWeb,
)
from .sessions import models as _sessions_models  # noqa: F401
from .sessions.rotated_refresh_tokens import models as _rotated_token_models  # noqa: F401
from .settings import AuthSettings, configure, get_settings, reset
from .sign_up_tokens import models as _sign_up_tokens_models  # noqa: F401
from .user_model import IntPKUserMixin, UserMixin, UUIDPKUserMixin
from .utils import (
    authenticate_user,
    complete_login,
    create_mobile_pkce_session_response,
    create_tokens,
)

__all__ = [
    # Configuration
    "AuthSettings",
    "Base",
    "configure",
    "configure_sessionmaker",
    "get_settings",
    "reset",
    # Ports (host-implemented boundary)
    "AuthEventSink",
    "EmailVerificationRequested",
    "IdpIdentity",
    "NullAuthEventSink",
    "PasswordPolicy",
    "PasswordResetRequested",
    "SettingsProvider",
    "SignupApproved",
    "SignupConfig",
    "SignupPendingAdminApproval",
    "UserProtocol",
    "UserRepository",
    "configure_event_sink",
    "configure_settings_provider",
    "configure_user_repository",
    "get_event_sink",
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
    "LoginRequest",
    "LogoutResponse",
    "MFALoginRequest",
    "MFARequiredResponse",
    "MobileSessionResponse",
    "SignUpRequest",
    "StepUpVerification",
    # Password hashing
    "PasswordHasher",
    "PasswordPolicyError",
    # Auth security stores / lockout
    "PendingMFALogin",
    "StepUpAttempts",
    "StepUpStore",
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
    "create_mobile_pkce_session_response",
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
    "header_client_type_scheme",
    "header_csrf_token_scheme",
    "oauth2_scheme",
    "validate_access_token_expiration",
    "validate_access_token_or_api_key",
    "validate_refresh_token",
]
