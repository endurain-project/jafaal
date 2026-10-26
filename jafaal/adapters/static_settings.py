"""Static, in-code :class:`~jafaal.ports.SettingsProvider`.

The simple "static config" mode: a host that does not store auth policy in a
database installs this with constants instead of implementing the port. Values
default to JAFAAL's recommended baseline and can be overridden per instance.
"""

from __future__ import annotations

from jafaal.ports import (
    LoginMethods,
    PasswordPolicy,
    SessionPolicy,
    SignupConfig,
    TokenLifetimes,
    session_policy_from_settings,
    tokens_from_settings,
)

__all__ = [
    "DEFAULT_PASSWORD_POLICY",
    "DEFAULT_SIGNUP_CONFIG",
    "StaticSettingsProvider",
]

#: Recommended baseline password policy.
#:
#: NIST SP 800-63B-4 §3.1.1.2 states verifiers **SHALL NOT** impose composition
#: rules (the r3 wording was a SHOULD NOT), so the default is ``length_only``.
#: Length carries the strength that character classes used to pretend to: the
#: regular minimum is the 15 characters §3.1.1.1 recommends, not the 8 it merely
#: permits. Pair this with breach screening — dropping composition rules without
#: a blocklist is the wrong half of the guidance, and
#: ``jafaal.adapters.HibpBreachChecker`` needs no credentials.
#:
#: A host bound by legacy composition requirements can still pass
#: ``PasswordPolicy(..., password_type="strict")`` explicitly.
DEFAULT_PASSWORD_POLICY = PasswordPolicy(
    min_length_regular=15,
    min_length_admin=20,
    password_type="length_only",
)

#: Conservative sign-up default: open sign-up, no email/admin gating.
DEFAULT_SIGNUP_CONFIG = SignupConfig(
    enabled=True,
    require_email_verification=False,
    require_admin_approval=False,
)


class StaticSettingsProvider:
    """A ``SettingsProvider`` returning fixed, in-code configuration."""

    def __init__(
        self,
        *,
        password_policy: PasswordPolicy | None = None,
        signup_config: SignupConfig | None = None,
        token_lifetimes: TokenLifetimes | None = None,
        session_policy: SessionPolicy | None = None,
        login_methods: LoginMethods | None = None,
    ) -> None:
        """Create the provider.

        Args:
            password_policy: Override for the password policy. Defaults to
                :data:`DEFAULT_PASSWORD_POLICY`.
            signup_config: Override for the sign-up configuration. Defaults to
                :data:`DEFAULT_SIGNUP_CONFIG`.
            token_lifetimes: Override for the token lifetimes. Defaults to the
                values in :class:`~jafaal.settings.AuthSettings`.
            session_policy: Override for the session policy. Defaults to the
                values in :class:`~jafaal.settings.AuthSettings`.
            login_methods: Override for the allowed login methods. Defaults to
                all enabled.
        """
        self._password_policy = password_policy or DEFAULT_PASSWORD_POLICY
        self._signup_config = signup_config or DEFAULT_SIGNUP_CONFIG
        self._token_lifetimes = token_lifetimes
        self._session_policy = session_policy
        self._login_methods = login_methods

    def get_password_policy(self) -> PasswordPolicy:
        return self._password_policy

    def get_signup_config(self) -> SignupConfig:
        return self._signup_config

    def get_token_lifetimes(self) -> TokenLifetimes:
        return self._token_lifetimes or tokens_from_settings()

    def get_session_policy(self) -> SessionPolicy:
        return self._session_policy or session_policy_from_settings()

    def get_login_methods(self) -> LoginMethods:
        return self._login_methods or LoginMethods()
