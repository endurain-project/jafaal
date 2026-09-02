# Changelog

All notable changes to JAFAAL are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

What counts as a breaking change, and what does not, is defined in [API stability](docs/api-stability.md). During the pre-1.0 series, its public surface is a compatibility target rather than a frozen guarantee: breaking changes may ship in a minor release and are documented here. The full major-version guarantee begins with 1.0.0.

## [0.1.2] - 2026-09-02

### Fixed

- All rate-limited routes now receive the HTTP request explicitly, ensuring the built-in limiter enforces their budgets and host adapters such as SlowAPI can decorate them safely.

## [0.1.1] - 2026-09-01

### Added

- Authenticated `/profile/mfa` routes for TOTP status, setup, enable, disable, verification, and backup-code status and replacement.

## [0.1.0] - 2026-08-31

Initial pre-1.0 release. The documented public surface is available for integration feedback and may still change between v0.x minor releases. The 1.0.0 compatibility guarantees in [API stability](docs/api-stability.md) remain future-facing until the surface has been validated with production consumers.

### Added

**Authentication**

- Username/password login with Argon2id hashing, transparent cost upgrades, and no password truncation.
- NFC normalization before password policy, breach screening, hashing, and verification. Canonically equivalent spellings interoperate, while compatibility characters remain distinct. A separate NFKC form is checked only as a blocklist alias.
- A default `length_only` policy with a 15-character minimum for regular users and 20 for administrators. Hosts that require composition rules can select `password_type="strict"`.
- A shared password input limit controlled by `PasswordSettings.max_length`.
- Breached-password screening through the Have I Been Pwned range API or a host-supplied offline blocklist. Deployed `length_only` configurations require a checker unless `allow_no_password_breach_check_when_deployed=True` is set. The HIBP adapter fails open during service outages.
- Progressive login lockout by account and source IP, including trusted-proxy handling, bounded password input, and timing-equalized authentication failures.
- Local sign-up, optional email verification, optional administrator approval, and enumeration-safe sign-up and password-reset responses. User and credential creation share one transaction.
- Login requires both `is_active` and `is_verified`.
- `POST /auth/password/change`, `POST /auth/password/renew`, and `POST /auth/password/user/{user_id}` for self-service changes, required replacements, and administrator resets.
- `jafaal.set_password()` and `jafaal.clear_password()` for trusted host tools such as administrator bootstrap, support workflows, and account imports. Callers remain responsible for authorization.
- Optional forced password replacement through `must_change=True` and the `password_change_required` error.
- Password changes and resets revoke affected sessions, API keys, outstanding reset tokens, and pending authentication grants. Self-service changes preserve the caller's current session by default.
- Non-blocking authentication events for password reset, email verification, account approval, lockout, new-device login, and other security-sensitive changes.

**Tokens and sessions**

- Authorization-code flow for registered first-party public clients, with mandatory PKCE, single-use codes, exact client and redirect bindings, and local or upstream identity-provider authentication.
- Browser authorization handoff through `login_ui_url` and an `auth_request` handle, including MFA and passkey completion without exposing tokens to the login page.
- Redirect URIs limited to complete HTTPS URLs, IP-literal HTTP loopback URLs, and reverse-domain private-use schemes. Loopback ports may vary; other components match exactly.
- Private-use redirect registrations must use single-slash syntax such as `com.example.app:/callback` instead of authority syntax such as `com.example.app://callback`.
- Deployed `base_url` and issuer values require absolute HTTPS URLs. Local HTTP development is limited to `127.0.0.1` and `[::1]`.
- Authorization-server metadata at the issuer-derived location, with a compatibility route under the aggregate router. Mounted routes, external issuers, and trusted ASGI `root_path` values are reflected in advertised endpoints.
- OAuth authorization, token, introspection, and revocation endpoints return OAuth error objects for missing, malformed, non-text, or repeated parameters instead of FastAPI validation bodies.
- RFC 9068 JWT access tokens with validated `typ`, `token_use`, and non-empty `client_id` claims.
- HS256 signing by default, plus RS, PS, and ES algorithms with JWKS publication for asymmetric keys. Symmetric deployments omit `jwks_uri` and return `404` from the JWKS route.
- Configurable clock-skew handling for token and identity-provider time claims.
- Requested scopes can narrow a grant and cannot be widened during MFA, passkey completion, authorization-code exchange, or refresh.
- Client registration controls refresh-token delivery (`body` or `cookie`) and the maximum allowed scope.
- `/auth/token` supports authorization-code and refresh-token grants. `/auth/refresh` additionally accepts refresh tokens from an `HttpOnly` cookie or `Authorization` header.
- Refresh-token rotation, bounded retry handling, family-wide reuse detection, and a `stale_refresh_token` response for losing concurrent rotations.
- Bounded absolute session lifetime, optional idle timeout, CSRF-bound browser sessions, and stable device metadata.
- Zero-downtime signing-key and encryption-key rotation through configured fallback keys.
- Token responses and credential-handling endpoints set `Cache-Control: no-store` and `Pragma: no-cache`.
- Token introspection and client-bound revocation. Valid access-token revocation returns `unsupported_token_type` when access-token denylisting is disabled.
- RFC 6750 bearer challenges for missing, invalid, expired, or insufficiently scoped credentials. Refresh failures use `400 invalid_grant`.

**Multi-factor**

- TOTP enrollment and verification with QR provisioning, single-use backup codes, and replay protection. Pending MFA logins remain bound to their original client and requested scope.
- WebAuthn passkey registration, passwordless authentication, and optional use as a second factor. Passkey registration and deletion require step-up authentication.
- Enumeration-resistant passwordless discovery using decoy credential identifiers for unknown or passkey-less users.
- `passkey_login_satisfies_mfa` controls whether a verified passwordless passkey can complete login for an account that also has TOTP enabled.
- `AuthenticatorChanged` events for TOTP, backup-code, and passkey changes.
- Step-up authentication for sensitive operations, including fresh upstream authentication for SSO-only accounts.

**Identity providers**

- OpenID Connect login and account linking with discovery, PKCE, userinfo retrieval, and ID-token signature and claim validation.
- Validation of `iss`, `aud`, `exp`, `iat`, `nonce`, `azp`, `at_hash`, and userinfo `sub`, with configurable clock-skew allowance.
- Provider issuer verification during discovery and callback processing, including support for providers that omit `kid` and automatic JWKS refresh during key rotation.
- Provider authorization errors returned to the registered client with bounded descriptions and normalized error codes.
- Asymmetric provider JWKS validation. Symmetric verification keys are rejected.
- Optional email-based account linking through `allow_email_linking`; the provider must assert `email_verified`. New links emit an `IdpAccountLinked` event.
- Profile synchronization that passes verified email addresses and host-selected profile claims to `UserRepository.sync_from_idp`.
- Outbound request safeguards including HTTPS enforcement, public-address resolution, pinned connections, redirect refusal for credential-bearing requests, timeouts, and response-size limits.

**Authorization and integration**

- API keys with host-configured scope allow-lists, optional expiry, revocation, deletion, and immediate scope narrowing after account-role changes.
- `reauthorize_scopes_per_request` for applying current account permissions to access tokens before expiry.
- An extensible scope catalog with descriptions for OpenAPI authorization controls. Scope denials include an `insufficient_scope` bearer challenge.
- Host-provided ports for users, dynamic settings, event delivery, password breach checks, rate limiting, scope resolution, and shared state.
- Built-in SQLAlchemy user, static settings, logging event, HIBP and blocklist, state-store rate-limit, and Redis state adapters.
- Caller-owned SQLAlchemy transactions. Repository and service operations flush without committing, and `jafaal.unit_of_work()` provides an optional transaction boundary.
- Structured security events on the `jafaal.audit` logger, with optional PII scrubbing.
- Bounded, non-blocking `AuthEventSink` delivery with reserved capacity for security-critical events.
- Stable domain error codes and centralized FastAPI exception handling.
- Alembic migrations for JAFAAL companion tables, using a dedicated version table alongside the host application's migration history.

**Packaging**

- Typed package support for Python 3.12 and later, tested through Python 3.14.
- SQLite, PostgreSQL, and MySQL support, plus in-memory and Redis state stores.
- Optional extras for `mfa`, `sso`, `webauthn`, `redis`, and `migrations`. Missing extras fail with an installation hint when the feature is used.
- Direct dependency declarations for imported runtime packages, including Starlette.
- Startup validation for required host adapters and deployed-environment safeguards. `verify=False` can disable router startup verification.
- Deployed environments require a configured rate limiter and distributed state store. Environment names are validated, including `staging`, `production`, and `demo`.
- A startup warning when HS256 is used with registered OAuth clients; asymmetric signing is recommended for independently deployed resource servers.

See [Security](https://jafaal.endurain.com/security/) and [Threat model](https://jafaal.endurain.com/threat-model/) for the security design and the host's responsibilities.

[0.1.2]: https://github.com/endurain-project/jafaal/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/endurain-project/jafaal/releases/tag/v0.1.1
[0.1.0]: https://github.com/endurain-project/jafaal/releases/tag/v0.1.0