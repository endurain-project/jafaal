# API stability

JAFAAL follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). From
1.0.0 onwards, a breaking change to anything listed as **public** below requires
a major-version bump.

This page is the contract. If something is not listed as public, it is not
covered — even if it happens to be importable.

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

### 2. Exception `code` slugs

Every `JafaalError` subclass carries a stable, machine-readable
[`code`](../jafaal/exceptions.py) — `"invalid_credentials"`, `"token_expired"`,
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
- the token response body (`access_token`, `token_type`, `expires_in`,
  `refresh_token_expires_in`, `session_id`, and `csrf_token` / `refresh_token`
  by client type);
- the `X-Client-Type`, `X-CSRF-Token`, and `X-API-Key` header contracts;
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
| CRUD modules (`jafaal.sessions.crud`, …) | Reachable, but the supported entry points are `IdentityService`, the ports, and the routers. |
| ORM model classes | Mapped into the host's registry, but their attributes are internal. |
| Log message text | Only the `jafaal.audit` structured fields are contractual. |
| Exact `detail` strings | Human-readable; use `code`. |
| Argon2 / HKDF / rate-limit *default values* | Security parameters are raised as guidance evolves. A default change is not breaking. |

## Deprecation policy

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
