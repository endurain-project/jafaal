# API stability

JAFAAL follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html), but
`0.1.0` is pre-1.0 software. The public surface below is the compatibility
target for the v0.x series and the intended contract for 1.0; it is not yet a
frozen 1.0 API. Before 1.0, a breaking change may ship in a minor release. Such
changes are documented in the changelog and, where practical, deprecated for
at least one prior minor release. Patch releases remain compatible except when
a security fix or stricter rejection of previously accepted invalid input makes
that impossible.

From 1.0.0 onwards, a breaking change to anything listed as **public** below
requires a major-version bump.

This page is the contract. If something is not listed as public, it is not
covered, even if it happens to be importable.

The runtime descriptions below apply to v0.1. Compatibility statements such as
"never renamed within a major version" describe the policy that takes effect at
1.0. Until then, the pre-1.0 policy above governs every listed surface.

## Product boundary

JAFAAL is an embedded FastAPI authentication library and a standards-shaped
authorization server for applications controlled by one host. It may issue
JWTs to that host's resource servers and run authorization-code plus PKCE flows
for that host's browser and native clients.

Every registered client is a trusted, statically configured, first-party public
client. JAFAAL does not provide third-party client management, confidential
client authentication, consent or grant records, or dynamic client
registration. The host owns the configuration, operator policy, users,
database, clients, and resource servers. Mounting JAFAAL in a dedicated FastAPI
service does not broaden that trust boundary.

`POST /auth/login` is a JAFAAL credential endpoint for the host's first-party
applications, not the OAuth resource-owner password grant. When JAFAAL
federates to an upstream identity provider, JAFAAL acts separately as an OAuth
client and OpenID Connect Relying Party.

## What is public

### 1. The package namespace

Everything exported from `jafaal.__all__`:

```python
import jafaal

jafaal.AuthSettings, jafaal.Secrets, jafaal.TokenSettings, ...   # configuration
jafaal.UserRepository, jafaal.ScopeResolver, jafaal.AuthEventSink, ...  # ports
jafaal.create_auth_router, jafaal.verify_configuration, jafaal.shutdown
jafaal.unit_of_work, jafaal.session_scope, jafaal.savepoint
jafaal.JafaalError and every exception subclass
```

Names reachable through a submodule but absent from `jafaal.__all__` are not
public. `jafaal.maintenance` is the one exception: its `__all__` is public too,
because scheduling is necessarily a host concern.

#### Extension surface

A subset of `__all__` exists so a host can **replace** a JAFAAL component or
drive a flow itself, rather than because a normal integration needs it. Wiring
an auth library up should not require any of it, and freezing internals nobody
integrates against is how a library ends up carrying design mistakes for years.

These names are supported and documented. From 1.0 onwards they carry a weaker
promise than the rest of the public surface: they may change in a **minor**
release, after at least one release during which the old form keeps working and
emits a `DeprecationWarning`.

| Group | Names |
|---|---|
| Test hooks | `reset`, `reset_api_key_scopes`, `reset_ports`, `reset_rate_limiter`, `reset_scopes`, `reset_state_store` |
| State-store payloads and stores | `FailedLoginAttempts`, `PendingLogin`, `PendingMFALogin`, `StepUpAttempts`, `StepUpStore`, `StepUpVerification`, `TieredFailureOutcome` |
| Token machinery | `TokenManager`, `TokenType` |
| Low-level flow helpers | `authenticate_user`, `complete_login`, `create_tokens` |
| Pending-MFA maintenance | `cleanup_expired_pending_mfa_logins`, `clear_pending_mfa_for_user` |
| Component accessors mirroring `configure_*` | `get_event_sink`, `get_failed_login_attempts`, `get_password_breach_checker`, `get_password_hasher`, `get_pending_mfa_store`, `get_rate_limiter`, `get_scope_resolver`, `get_settings_provider`, `get_state_store`, `get_step_up_attempts`, `get_token_manager`, `get_user_repository` |

Everything else in `__all__` — the settings objects, the ports, the exceptions,
the router factories, the transaction helpers, the user mixins, the request and
response schemas, the FastAPI dependencies, and `configure_*` — is covered by
the full SemVer promise above from 1.0 onwards.

### 2. Exception `code` slugs

Every `JafaalError` subclass carries a stable, machine-readable
[`code`](https://github.com/endurain-project/jafaal/blob/main/jafaal/exceptions.py) — `"invalid_credentials"`, `"token_expired"`,
`"missing_scope"`, and so on. These are the framework-neutral API contract: a
non-HTTP host switches on them, and a frontend maps them to messages. Slugs are
never renamed within a major version. New ones may be added.

`status_code`, `headers`, and `detail` are HTTP *hints* and may be refined in a
minor release when a status becomes more accurate.

### 3. The HTTP surface

Route paths, methods, request shapes, and response fields of the routers
assembled by `create_auth_router`, including:

- the OAuth 2.0 authorization endpoint (`/auth/authorize`) and token endpoint
  (`/auth/token`), their parameters, and the `authorization_code` /
  `refresh_token` grants;
- the token response body (`access_token`, `token_type`, `expires_in`, `scope`,
  `refresh_token_expires_in`, `session_id`, and `csrf_token` / `refresh_token`
  according to the client's registered `token_delivery`);
- the RFC 6749 §5.2 error body (`error`, `error_description`) for OAuth
  parameter and grant failures, the JAFAAL domain-error body (`detail`, `code`)
  for extension and bearer failures, and FastAPI's native `422` detail array for
  request-schema failures on extension routes;
- the `X-CSRF-Token` and `X-API-Key` header contracts;
- the RFC 7662 introspection and RFC 7009 revocation responses; and
- the RFC 8414 metadata document and the JWKS document.

Response bodies may gain fields in a minor release; existing fields are not
removed or retyped.

### 4. Token and cookie wire formats

The JWT claim set (`sub`, `sid`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`,
`scope`, `client_id`, `token_use`), the `at+jwt` / `rt+jwt` `typ` headers, and
the refresh-cookie name and attributes. A resource server verifying JAFAAL
tokens with a stock JWT library depends on these.

### 5. The audit stream

The logger name `jafaal.audit`, the `event` slugs in `jafaal.audit.Event`, the
`outcome` values, and the presence of `audit=True` on every record. New events
and new per-event fields may be added; existing slugs are not renamed.

### 6. The database schema, via migrations

JAFAAL's tables are public in the sense that the packaged Alembic revisions in
`jafaal.migrations` will always carry a deployment forward. The column layout
itself is not a direct API: query it through JAFAAL, not with your own SQL.

## What is NOT public

| Not public | Why |
|---|---|
| `jafaal._core.*`, `jafaal._internal.*` | Leading underscore. Implementation detail; changes in any release. |
| Any module-level name starting with `_` | Same. |
| CRUD modules (`jafaal.sessions.crud`, …) | Reachable, but the supported entry points are `IdentityService`, `LocalCredentialStore`, the ports, and the routers. |
| ORM model classes | Mapped into the host's registry, but their attributes are internal. |
| Log message text | Only the `jafaal.audit` structured fields are contractual. |
| Exact `detail` strings | Human-readable; use `code`. |
| Argon2 / HKDF / rate-limit *default values* | Security parameters are raised as guidance evolves. A default change is not breaking. |

## Deprecation policy

Before 1.0, breaking public API changes are listed in the changelog with a
migration note and, where practical, deprecated for at least one prior minor
release. From 1.0 onwards:

1. A public API being removed or changed is first **deprecated**: it keeps
  working and emits a `DeprecationWarning` naming the replacement.
2. It stays for **at least two minor releases** after the deprecation lands.
3. Removal happens only in a major release, and is listed in the changelog under
  *Removed* with the migration step.

Anything that cannot be deprecated safely — a change forced by a security
finding — is documented in `SECURITY.md` and the changelog, and may land in a
patch release. Security beats compatibility; we will say so explicitly when it
happens.

## Things that will change and are not "breaking"

- **Default security parameters.** Argon2 cost, token lifetimes, rate-limit
  budgets, and lockout tiers are tuned upward over time. Pin them explicitly if
  your deployment depends on a specific value.
- **New required ports.** A new capability may introduce a port — but it will
  always ship with a working default adapter, so an existing host keeps running.
- **Additional audit events and response fields.** Additive only.
- **Stricter validation of previously-accepted-but-invalid configuration.** If
  `AuthSettings` starts rejecting a value that was always wrong, that is a bug
  fix, and it fails loudly at startup rather than silently at runtime.

## Supported Python and dependency versions

- Python: the versions listed in the `requires-python` range and the trove
  classifiers. Dropping a Python version that is past upstream end-of-life is a
  minor-release change.
- FastAPI / SQLAlchemy / Pydantic: floor versions are declared in
  `pyproject.toml`. Raising a floor is a minor-release change.

## Checking your integration

`jafaal.verify_configuration()` fails fast at startup with one message listing
every missing required component. Call it from your lifespan — it is the
supported way to detect an integration that has drifted.
