# Configuration

JAFAAL never reads environment variables or secret files itself. The host
application builds configuration and injects it once at startup. Every setting is
data **you** own.

## `AuthSettings`

Build a frozen, validated [`AuthSettings`][jafaal.AuthSettings] and install it
with [`jafaal.configure`][jafaal.configure]. Misconfiguration fails fast at
construction (e.g. a short signing key or an invalid Fernet key is rejected).

```python
import jafaal
from cryptography.fernet import Fernet

jafaal.configure(
    jafaal.AuthSettings(
        secret_key="<32+ byte JWT signing secret>",  # HS256 signing key
        fernet_key=Fernet.generate_key().decode(),   # at-rest token encryption
        base_url="https://app.example.com",
        app_name="Example",                           # MFA issuer shown in authenticators
        environment="production",                     # drives the cookie Secure flag
    )
)
```

Every component reads the installed settings through
[`jafaal.get_settings`][jafaal.get_settings]. Re-calling `configure()` replaces
the settings and invalidates settings-derived caches (e.g. the token manager).

### Selected fields

| Field | Default | Purpose |
| --- | --- | --- |
| `secret_key` | — (required) | HMAC key that signs/verifies JWTs (≥ 32 chars). |
| `fernet_key` | — (required) | Fernet key encrypting at-rest tokens (IdP secrets, MFA secret, rotated refresh tokens). |
| `secret_key_fallbacks` | `()` | Extra HMAC keys accepted only when *verifying* JWTs (rotation overlap). |
| `fernet_key_fallbacks` | `()` | Extra Fernet keys accepted only when *decrypting* at-rest tokens (rotation overlap). |
| `access_token_expire_minutes` | `15` | Access-token lifetime. |
| `refresh_token_expire_days` | `7` | Refresh-token lifetime. |
| `jwt_leeway_seconds` | `0` | Clock-skew tolerance (seconds) for JWT `exp`/`nbf`; `0` is strict, keep any value small. |
| `algorithm` | `"HS256"` | JWT signing algorithm: `HS256` (symmetric) or an asymmetric RSA/EC algorithm (see [below](#asymmetric-signing-jwks)). |
| `private_key` | `""` | PEM private key for asymmetric signing (required when `algorithm` is asymmetric). |
| `private_key_fallbacks` | `()` | Verify-only PEM keys kept in the published JWKS during a signing-key rotation. |
| `session_idle_timeout_hours` | `1` | Idle-session timeout (when enabled). |
| `session_absolute_timeout_hours` | `24` | Absolute session lifetime. |
| `base_url` | `""` | Public base URL; default JWT issuer/audience and SSO redirect base. |
| `environment` | `"production"` | `production`/`demo` are treated as deployed (cookie `Secure`). |
| `refresh_cookie_prefix` | `""` | Optional `__Secure-`/`__Host-` refresh-cookie name prefix, applied only when deployed (`__Host-` requires `refresh_cookie_path="/"`). |
| `allow_api_key_query_param` | `False` | Whether API keys may be sent via `?api_key=` (header only by default). |
| `allow_in_memory_state_store_when_deployed` | `False` | Permit the in-memory state store in a deployed environment (single-worker only; otherwise `create_auth_router()` raises at startup). |
| `allow_no_rate_limit_when_deployed` | `False` | Permit a deployed environment with no enforcing rate limiter (otherwise `create_auth_router()`/`verify_configuration()` raise at startup). |
| `argon2_time_cost` | `3` | Argon2 time cost (iterations) for password hashing. |
| `argon2_memory_cost` | `65536` | Argon2 memory cost, in KiB. |
| `argon2_parallelism` | `4` | Argon2 parallelism (lanes). |
| `password_max_length` | `128` | Maximum accepted password length (minimum 64), enforced before hashing. |
| `mfa_totp_replay_fail_open` | `False` | On a state-store outage, accept a TOTP code without replay protection instead of failing closed (503). |
| `rate_limit_sensitive` | `"10/minute"` | Budget hint for sensitive endpoints. |
| `rate_limit_write` | `"30/minute"` | Budget hint for write endpoints. |
| `trusted_proxies` | `()` | Peers whose `X-Forwarded-For`/`X-Real-IP` are honoured (empty = trust only the direct peer). |
| `ssrf_allowed_hosts` | `()` | Hosts/CIDRs exempted from the SSRF private-address guard. |
| `audit_include_pii` | `True` | Include direct identifiers (username/IP/email) in `jafaal.audit` records; set `False` for PII-minimal retention. |

!!! warning "Behind a proxy"
    `trusted_proxies` defaults to `()` — only the direct TCP peer is trusted, so
    `X-Forwarded-For`/`X-Real-IP` from arbitrary clients are ignored (a client
    cannot spoof the IP that keys the progressive-lockout counters). When running
    behind a reverse proxy, set it to your proxy addresses/CIDRs so the real
    client IP is used; `("*",)` trusts every peer (only safe when a trusted proxy
    always overwrites the header).

### Key rotation

Both the JWT signing key and the Fernet encryption key rotate without downtime by
keeping the previous key as a *fallback* for an overlap window. New material is
always produced with the primary key; the fallbacks are verify-/decrypt-only.

```python
jafaal.configure(
    jafaal.AuthSettings(
        secret_key=NEW_SIGNING_KEY,                  # signs all new JWTs
        secret_key_fallbacks=(OLD_SIGNING_KEY,),     # still verifies tokens signed before rotation
        fernet_key=NEW_FERNET_KEY,                    # encrypts all new at-rest secrets
        fernet_key_fallbacks=(OLD_FERNET_KEY,),      # still decrypts data written with the old key
        base_url="https://app.example.com",
        app_name="Example",
    )
)
```

Once every token signed with — and every secret encrypted with — the old key has
expired or been re-written, drop the fallback.

## Asymmetric signing & JWKS

By default JAFAAL signs its access/refresh tokens with **HS256** (a shared
secret), so any service that verifies them needs that secret. To let other
services verify tokens **statelessly with a public key** — no secret sprawl —
set an asymmetric `algorithm` and a PEM `private_key`:

```python
import jafaal
from cryptography.fernet import Fernet

jafaal.configure(jafaal.AuthSettings(
    secret_key="<32+ byte secret>",   # STILL required: keys the HMAC hashing of refresh/CSRF tokens
    fernet_key=Fernet.generate_key().decode(),
    base_url="https://app.example.com",
    algorithm="RS256",                 # or ES256, PS256, RS384/512, ES384/512, PS384/512
    private_key=open("jwt-signing-key.pem").read(),
))
```

JAFAAL signs with the private key (tagging each token with the key's RFC 7638
thumbprint as `kid`) and publishes the **public** key(s) as a JSON Web Key Set:

```text
GET  <your-api-root>/.well-known/jwks.json
```

A resource server verifies a JAFAAL access token the same way it would any OIDC
provider's — fetch the JWKS and check the signature and claims (no call back to
JAFAAL):

```python
import jwt                      # PyJWT, in the *resource server*
from jwt import PyJWKClient

jwks = PyJWKClient("https://app.example.com/api/v1/.well-known/jwks.json")
signing_key = jwks.get_signing_key_from_jwt(access_token)
claims = jwt.decode(
    access_token,
    signing_key.key,
    algorithms=["RS256"],
    issuer="https://app.example.com",      # == base_url
    audience="https://app.example.com",    # == base_url
)
assert claims["typ"] == "access"
```

[`get_jwks()`][jafaal.get_jwks] is also exported, so you can serve the set at the
conventional root path `/.well-known/jwks.json` from your own app instead of the
API-root path above.

!!! note "`secret_key` is always required"
    Even with asymmetric JWTs, `secret_key` still keys the HMAC hashing of
    refresh tokens (reuse detection) and CSRF tokens, so it stays mandatory.

!!! note "EdDSA is not offered yet"
    `EdDSA` is intentionally excluded: the underlying `joserfc` marks the
    `EdDSA` JOSE identifier as deprecated (RFC 9864) and warns on use. Use
    `ES256` (compact) or `RS256` (most widely interoperable) instead.

See [Key rotation](key-rotation.md#rotating-the-asymmetric-signing-key) for
rotating the signing key without downtime.

## Database: your `Base` and the session factory

You own the declarative registry; JAFAAL maps its companion tables into it with
[`map_models`][jafaal.map_models], so both share one metadata. Build your model
on your own `DeclarativeBase` — it **must** be the class `Users` mapped to the
`users` table — call `map_models`, and register a session factory bound to your
engine.

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
import jafaal
from jafaal import IntPKUserMixin


class Base(DeclarativeBase):
    ...  # your own base — naming conventions, schema, your other models


class Users(IntPKUserMixin, Base):
    __tablename__ = "users"


jafaal.map_models(Base)  # map JAFAAL's tables into your registry

engine = create_engine("postgresql+psycopg://...")
jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False))
Base.metadata.create_all(engine)  # fine for dev/tests; use jafaal.migrations in production (below)
```

`map_models(...)` must run once at startup, **after** you define `Users` and
**before** `create_auth_router()` or any DB use (importing a JAFAAL model before
it is a configuration error). Omit the argument — `jafaal.map_models()` — to use
JAFAAL's own convenience `jafaal.orm.Base` instead of owning one.

The reverse relationships (`users_sessions`, `local_credential`, `auth_mfa`, …)
and the `mfa_enabled` property are supplied by the mixin — you declare none of
them. Choose an integer or UUID primary key with
[`IntPKUserMixin`][jafaal.IntPKUserMixin] or
[`UUIDPKUserMixin`][jafaal.UUIDPKUserMixin].

### Supported databases

JAFAAL is database-agnostic — it owns no engine and uses only portable
SQLAlchemy types. The test suite runs on **SQLite**, **PostgreSQL**, and
**MySQL** in CI on every change, so cross-dialect portability is a guarantee
rather than an accident. Use whichever backend your host app already uses (e.g.
`postgresql+psycopg://…`, `mysql+pymysql://…`, or `sqlite:///…`).

!!! warning "SQLite caveats"
    SQLite is ideal for development, tests, and small single-node deployments,
    but it has **no real write concurrency** (writes serialize on a
    database-level lock). Combined with the default in-memory
    [`StateStore`][jafaal.StateStore], a SQLite deployment is effectively
    **single-process**: run a single worker, or move to PostgreSQL/MySQL **and**
    a distributed `StateStore` (e.g.
    [`RedisStateStore`](ports-and-adapters.md#redisstatestore)) for multi-worker
    setups. Note that `Uuid` primary keys and `DateTime(timezone=True)` columns
    are stored differently across dialects (SQLite keeps UUIDs as 32-char hex and
    can return naive datetimes); JAFAAL normalizes timestamps back to
    timezone-aware UTC on read, so this stays transparent to callers.

### Migrations

JAFAAL ships its schema as **Alembic** migrations (the `jafaal[migrations]`
extra) so its companion tables can evolve across releases. They run on a
dedicated version table (`jafaal_alembic_version`) and touch only JAFAAL's own
tables — your `users` table and your Alembic history are left alone.

```python
from jafaal import migrations

migrations.upgrade(engine)                  # create/upgrade JAFAAL's tables
# migrations.stamp(engine)                  # existing DB whose tables already exist
# migrations.verify_schema_current(engine)  # fail fast at startup if not migrated
```

Your `users` table must exist first (JAFAAL's tables reference `users.id`), so
run your own migrations before JAFAAL's. Prefer a single, unified Alembic
history? Point your `env.py` at `jafaal.orm.Base.metadata` and add the package's
`versions` directory to your `version_locations` instead.

## Scopes

JAFAAL ships only auth/identity scopes. Layer your application scopes on top of
`DEFAULT_SCOPE_CATALOG`:

```python
from jafaal import DEFAULT_SCOPE_CATALOG, configure_scopes, configure_api_key_scopes

configure_scopes(
    DEFAULT_SCOPE_CATALOG.extend(
        regular=("reports:read",),
        admin=("reports:read", "reports:write"),
        descriptions={"reports:read": "Read reports", "reports:write": "Manage reports"},
    )
)

# Opt each scope an API key may carry in explicitly (empty by default):
configure_api_key_scopes(["reports:read"])
```

## Rate limiting and the state store

By default JAFAAL runs in a single process with an in-memory
[`StateStore`][jafaal.StateStore] and **no** rate limiting. Both are host
infrastructure you inject:

```python
# jafaal.configure_rate_limiter(StateStoreRateLimiter())  # batteries-included limiter
# jafaal.configure_state_store(...)   # inject Redis for multi-worker lockout state
```

`create_auth_router()` logs a startup **warning** when the no-op rate limiter is
still active, and **refuses to start** (raises `RuntimeError`) when the in-memory
state store is used in a *deployed* environment — set
`allow_in_memory_state_store_when_deployed=True` to override for a single-worker
deployment (see [Security → Deployment hardening](security.md#deployment-hardening)).
The batteries-included
[`StateStoreRateLimiter`](ports-and-adapters.md#statestoreratelimiter) needs no
extra dependency and satisfies the limiter warning. For multi-worker/replica
deployments, also inject a distributed [`StateStore`][jafaal.StateStore] (e.g.
[`RedisStateStore`](ports-and-adapters.md#redisstatestore)); the limiter then
enforces budgets cluster-wide automatically.

Call `jafaal.verify_configuration()` once at startup (e.g. in a FastAPI lifespan
handler) to fail fast if a required component — the settings object, the session
factory, the user repository, or the settings provider — has not been installed,
instead of hitting a `RuntimeError` on the first request that needs it.
