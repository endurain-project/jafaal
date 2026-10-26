# Changelog

All notable changes to JAFAAL are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

What counts as a breaking change, and what does not, is defined in [API stability](docs/api-stability.md). During the pre-1.0 series, its public surface is a compatibility target rather than a frozen guarantee: breaking changes may ship in a minor release and are documented here. The full major-version guarantee begins with 1.0.0.

## [Unreleased]

### Upgrading from 0.3

The tables are renamed (see below), so the upgrade is a migration, done before the new code serves requests:

1. **Stop every process running 0.3.** It looks the old table names up; a rolling deployment across this release is not possible.
2. **Migrate**, by whichever way the database was built:
   - With `jafaal.migrations` (a `jafaal_alembic_version` table exists): `migrations.upgrade(engine)`.
   - With `Base.metadata.create_all()` (no version table): `migrations.adopt_existing_schema(engine)`, then `migrations.upgrade(engine)`.
3. **Start 0.4.** `migrations.verify_schema_current(engine)` at startup confirms the upgrade ran.

An application that calls `create_all()` at startup must still migrate first. On a database that holds the old tables, `create_all()` now raises `SchemaCompatibilityError` instead of creating empty `jafaal_*` tables beside them — which would have run the application with no sessions, MFA enrolments, identity-provider configurations, passkeys or API keys while the data sat untouched in the old tables. To go back to 0.3, run `migrations.downgrade(engine, "0007_credential_must_change")` with 0.4 before deploying 0.3. Application SQL that names JAFAAL's tables directly needs the new names.

### Breaking

- **Every JAFAAL table, index and named constraint is prefixed `jafaal_`.** `users_sessions`, `oauth_states`, `identity_providers`, `password_reset_tokens` and the rest become `jafaal_users_sessions`, `jafaal_oauth_states`, …; the named constraints read `uq_jafaal_...` and the backup-code index `idx_jafaal_user_unused_codes`. The tables live in the host's database and registry, and a generic name could collide with the host's own. No column or row changes.
  - Migration `0008_prefix_table_names` renames each table in place with its indexes and named unique constraints, and on PostgreSQL its primary-key index and `id` sequence. PostgreSQL, MySQL and MariaDB rename in place; SQLite recreates the indexes under the new names. Foreign keys between JAFAAL's tables follow the rename. **Stop every process running 0.3 or earlier before running it**; a rolling deployment across it is not possible. Downgrading restores the old names.
  - A fresh database is created with the final names directly, so a host that already owns a table called `identity_providers` can install JAFAAL. This holds for `jafaal.migrations.upgrade()` only: a host that runs JAFAAL's revisions from its own Alembic history gets the unprefixed tables from `0001_initial` first, which `0008` then renames.
  - `jafaal.orm.jafaal_table_names()` returns the new names; `jafaal.orm.legacy_table_names()` returns the old ones, for migration tooling. `jafaal.migrations.jafaal_include_object` no longer includes the unprefixed names, so a host's own table of that name is never diffed or dropped.
- **`Base.metadata.create_all()` refuses to create JAFAAL's tables beside a 0.3 schema**, raising `jafaal.migrations.SchemaCompatibilityError` that names the migration to run. `jafaal.map_models()` registers the check on the host's metadata. A 0.3 schema is recognised by two or more of the old names specific to JAFAAL (`users_local_credentials`, `idp_link_tokens`, `mfa_backup_codes`, …; `jafaal.orm.is_legacy_schema()`), the same test `upgrade()` and `adopt_existing_schema()` use, so a host's own tables with generic old names such as `password_reset_tokens` and `sign_up_tokens` never trigger it.
- **`jafaal.migrations.upgrade()` refuses a database that has JAFAAL tables but no recorded revision**, raising `SchemaCompatibilityError` and pointing to `adopt_existing_schema()`. It used to create whatever tables were missing, leave the rest unchecked and record the head revision, which certified schemas that had never been validated, including a host's own table that happened to share a JAFAAL name. It also refuses to start without the host's `users` table.

### Changed

- **Token lifetimes, session timeouts and the allowed login methods can be changed at runtime** through the `SettingsProvider`, without `jafaal.configure()`. A provider may implement `get_token_lifetimes()`, `get_session_policy()` and `get_login_methods()`; JAFAAL reads them on each use through `resolve_token_lifetimes()`, `resolve_session_policy()` and `resolve_login_methods()`, instead of fixing the values at configuration time. New tokens and the refresh cookie use the new lifetimes at once, and an existing session is judged against the current absolute and idle timeouts on its next check. A provider with only the two 0.3 methods, no provider, and `StaticSettingsProvider` without overrides all keep today's behaviour, derived from `AuthSettings`. See [Runtime policy](docs/configuration.md#runtime-policy).
- `TokenManager` takes an optional `lifetimes_resolver`. The manager `get_token_manager()` returns uses it; one built directly keeps using its constructor lifetimes.
- The access-token denylist entry written when a refresh token is revoked no longer derives its TTL from the lifetime in force at revocation alone: it lives for the longest of that, the `AuthSettings` default and `max_access_token_minutes`, so shortening the lifetime does not let it lapse before a token issued earlier.
- **The revisions are explicit DDL.** `0001_initial` used to create the tables from the current models, so its meaning changed with every release, and `0002`–`0007` inspected the database and skipped any change they found already made, or whose table was missing, while still recording themselves as applied. `0001_initial` is now the schema as it stood at that revision, every later revision makes its change unconditionally, and a revision that cannot apply fails the migration. The type of `users.id` and the host's naming convention still come from the host, as they do for the models. No published release recorded a revision older than `0007_credential_must_change`, so existing databases are unaffected.
- **`adopt_existing_schema()` adopts an older revision's schema.** Unversioned tables are matched exactly against the head schema, then against each earlier revision's schema, newest first — including the unprefixed schema of 0.3 and earlier — and the first match is recorded, so the `upgrade()` that follows applies the later revisions. A 0.3 database built with `create_all` is adopted at `0007_credential_must_change` and then renamed. Older schemas are derived from the migrations' own `downgrade` functions, never maintained separately. No match still raises `SchemaCompatibilityError`, now naming the closest revision and listing its differences.

### Fixed

- `adopt_existing_schema()` works on MariaDB, which reflects a `now()` server default as `current_timestamp()`; it rejected every MariaDB schema as incompatible.
- The advisory `ty` type check passes. `handle_db_errors` has a single generic signature, so a decorated sync CRUD function is no longer typed as returning a coroutine; the optional `webauthn` and `authlib` imports are typed as their modules; `SsrfGuardAsyncTransport.__aexit__` takes the standard exception arguments. `ty` is configured like mypy: it skips the ORM model modules and the optional extras its job does not install. No runtime change.

### Added

- `TokenLifetimes`, `SessionPolicy` and `LoginMethods` (frozen dataclasses, validated on construction), the optional protocols `TokenLifetimesProvider`, `SessionPolicyProvider` and `LoginMethodsProvider`, and the `resolve_*` functions, all exported from `jafaal`. `StaticSettingsProvider` accepts `token_lifetimes`, `session_policy` and `login_methods`.
- Optional ceilings on what a provider may set: `TokenSettings.max_access_token_minutes`, `TokenSettings.max_refresh_token_days` and `SessionSettings.max_absolute_timeout_hours` (default `None`, no cap, so nothing changes for an existing deployment). A provider value above a ceiling is clamped and logged with `warning_code` `token_lifetime_clamped` or `session_timeout_clamped`.
- **`LoginMethods` is enforced by JAFAAL.** With `password=False`, `POST /auth/login` (including the `/auth/authorize` password step) is refused; with `identity_providers=False`, `/auth/authorize` with an `idp` and the login callback are refused and `GET /public/idp` returns an empty list; with `passkeys=False`, `/public/webauthn/authenticate/*` is refused. Linking a provider, IdP step-up, passkeys as a second factor and credential management are never blocked. A refusal is `LoginMethodDisabledError` (403, code `login_method_disabled`), raised before any credential is checked.
- `SettingsUnavailableError` (503, code `settings_unavailable`): a `SettingsProvider` method that raises, or returns the wrong type, fails closed instead of falling back to defaults.
- CI runs the suite, migrations included, against MariaDB 11.4 alongside PostgreSQL and MySQL.

## [0.3.1] - 2026-10-26

### Changed

- Updated all runtime, optional, and development dependencies to their latest releases and raised the declared minimum versions to match the lockfile.
- Pinned the uv toolchain to 0.13.x and refreshed the GitHub Actions to their latest releases, pinned by commit hash.

### Added

- Added the `ty` type checker alongside mypy as a non-blocking advisory check in CI; mypy remains the blocking gate.

## [0.3.0] - 2026-09-06

### Breaking

- Removed the unsafe public `jafaal.migrations.stamp()` API. Existing deployments must use validated schema adoption rather than recording an arbitrary revision without checking the physical schema.

### Added

- Added `jafaal.migrations.adopt_existing_schema(engine)` and `SchemaCompatibilityError` for safely adopting complete legacy unversioned JAFAAL tables. Adoption validates columns, types, nullability, primary keys, uniqueness, foreign keys, and required indexes before recording the packaged head, while leaving host tables and additional non-unique host indexes untouched.

## [0.2.1] - 2026-09-03

### Added

- A host-facing `PasswordChanged` security event for committed self-service changes, forced renewals, password-reset confirmations, and administrator resets. Delivery is best-effort and contains only account metadata and the number of revoked sessions.
- Structured startup diagnostics with stable `warning_code` values for unconfigured rate limiting, wildcard trusted proxies, disabled password-breach checking, symmetric OAuth signing, and token or cookie URL-prefix mismatches. Hosts can selectively filter individual warnings without bypassing fail-closed deployed-configuration guards.

## [0.2.0] - 2026-09-02

### Added

- Email-verification sign-ups now return an opaque, enumeration-safe polling handle and expose `GET /auth/sign-up/status`; the route has a distinct configurable `polling` rate-limit budget.

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

[0.3.1]: https://github.com/endurain-project/jafaal/releases/tag/v0.3.1
[0.3.0]: https://github.com/endurain-project/jafaal/releases/tag/v0.3.0
[0.2.1]: https://github.com/endurain-project/jafaal/releases/tag/v0.2.1
[0.2.0]: https://github.com/endurain-project/jafaal/releases/tag/v0.2.0
[0.1.2]: https://github.com/endurain-project/jafaal/releases/tag/v0.1.2
[0.1.1]: https://github.com/endurain-project/jafaal/releases/tag/v0.1.1
[0.1.0]: https://github.com/endurain-project/jafaal/releases/tag/v0.1.0