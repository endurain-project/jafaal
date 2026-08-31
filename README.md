# Just Another FastAPI Authentication Library (JAFAAL)

[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/endurain-project/jafaal/blob/main/LICENSE.md)
[![Release](https://img.shields.io/badge/dynamic/json?url=https://api.github.com/repos/endurain-project/jafaal/releases/latest&query=$.tag_name&label=release&color=blue)](https://github.com/endurain-project/jafaal/releases)
[![PyPI version](https://img.shields.io/pypi/v/jafaal)](https://pypi.org/project/jafaal/)
[![PyPI downloads](https://img.shields.io/pypi/dm/jafaal)](https://pypi.org/project/jafaal/)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://pypi.org/project/jafaal/)
[![Docs](https://img.shields.io/badge/docs-jafaal.endurain.com-blue)](https://jafaal.endurain.com/)
[![Stars](https://img.shields.io/badge/dynamic/json?url=https://api.github.com/repos/endurain-project/jafaal&query=$.stars_count&label=stars&logo=github)](https://github.com/endurain-project/jafaal)

## What is JAFAAL?

JAFAAL is a batteries-included, embedded FastAPI authentication library and a
standards-shaped authorization server for applications controlled by one host.
It integrates with synchronous SQLAlchemy and owns the security-critical parts
of auth so your app doesn't have to:

- **Password login** (Argon2id) with progressive per-account lockout
- **JWT access/refresh tokens** (HS256) with refresh-token **rotation + reuse detection**
- **Sessions** with idle/absolute timeout, CSRF binding, and web/mobile (PKCE) flows
- **MFA** (TOTP + single-use backup codes) with replay protection
- **API keys** with a host-controlled scope allow-list
- **SSO / OIDC** identity providers with SSRF-guarded outbound calls
- **Password reset & sign-up** flows that emit events (you deliver the email)
- A **`JafaalError` → HTTP** edge handler, so the core never imports HTTP concerns

JAFAAL depends only on a small set of **ports** you implement (your user table,
your dynamic settings, and how you deliver notifications). Everything else —
tables, routers, token logic — ships with the library.

## What JAFAAL is (and is not)

JAFAAL authenticates **your** users for **your** API. Concretely, it plays four
roles, and implements the standards that govern each:

| Role | Standards |
|---|---|
| **JWT issuer** for your own resource servers | RFC 9068 (`at+jwt` access tokens), RFC 7519, RFC 7517 / 7638 (JWKS + `kid` thumbprints), RFC 8414 (discovery) |
| **Bearer-token resource server** | RFC 6750 (header extraction, `WWW-Authenticate` challenges incl. `insufficient_scope`) |
| **Authorization server for your own native apps** | RFC 6749 §4.1 (authorization code), RFC 7636 (PKCE S256), RFC 8252 (native apps / public clients), RFC 9700 (exact redirect-URI matching) |
| **OAuth client / OIDC Relying Party** for SSO | RFC 6749 *client* role, RFC 7636, OIDC Core 1.0 (`nonce`, `azp`, `at_hash`, userinfo `sub` check), RFC 9700 |
| **Credential authority** | NIST SP 800-63B-4 (NFC + length policy + configured blocklist), RFC 6238 (TOTP), W3C WebAuthn L2 (passkeys), RFC 7662 (introspection), RFC 7009 (revocation) |

NIST password alignment is conditional on a configured checker being available.
The HIBP adapter fails open during an outage; use a local fail-closed blocklist
when uninterrupted enforcement is required.

> [!IMPORTANT]
> **JAFAAL is an authorization server for clients you own.**
>
> That is the boundary, and it is deliberate rather than unfinished. Register
> your applications via `AuthSettings.oauth_clients` and drive `/auth/authorize`
> → `/auth/token` with any standard OAuth client library — PKCE mandatory,
> `code` the only response type, redirect URIs matched byte-for-byte except for
> native IP-loopback ports, clients public per RFC 8252.
>
> **Not planned:** third-party clients (consent screen, client secrets, dynamic
> registration), being an OpenID Provider (`id_token`, userinfo, the logout
> specs, certification), `client_credentials`, and the implicit/hybrid/ROPC
> grants that OAuth 2.1 removes. If you need to *be* an identity provider, put a
> real one in front of JAFAAL — it already speaks to Keycloak, Authentik,
> Authelia, Casdoor and Pocket ID as a relying party.
>
> `POST /auth/login` authenticates a first-party user directly; it is **not** the
> resource-owner password-credentials grant, and the discovery document
> deliberately does not advertise it. A native app should prefer
> `/auth/authorize`, which keeps the password out of the app entirely
> (RFC 8252 §8.1).

Both **web and mobile** clients are first-class. They differ only in refresh-token
delivery: browsers get an `HttpOnly`, `SameSite=Strict` cookie (so page script
never touches it, per RFC 9700 §7.2), native clients get it in the response body.

## Current limitations

- **Synchronous SQLAlchemy only.** JAFAAL's endpoints and CRUD layer take a
    `Session`, not an `AsyncSession`, and the registered factory must be a sync
    `sessionmaker`. FastAPI runs synchronous handlers in its worker thread pool;
    JAFAAL's writes cannot share a transaction with host `AsyncSession` work.
- **One process-wide configuration.** `jafaal.configure()` and the
    `configure_*` adapter functions install module-level settings, ports, stores,
    and registries shared by every JAFAAL router in the process. Two differently
    configured JAFAAL instances cannot be isolated in one process. Each worker
    must configure itself, and replicas need distributed state where documented.
- **First-party public clients only.** OAuth clients are trusted applications
    owned by the same host, registered statically in `AuthSettings.oauth_clients`,
    and authenticated with PKCE rather than a client secret. JAFAAL v0.1 has no
    third-party client lifecycle, consent records, confidential-client
    authentication, or dynamic registration.

## Installation

```bash
pip install jafaal
# or
uv add jafaal
```

Requires Python 3.12+.

### Optional features

A minimal "login + JWT + sessions" deployment needs no extras. Multi-factor
authentication and single sign-on pull in additional packages, so they ship as
optional extras. Install only what you use:

```bash
pip install 'jafaal[mfa]'        # TOTP MFA (pyotp) + QR provisioning (qrcode)
pip install 'jafaal[webauthn]'   # passkeys / WebAuthn (py_webauthn)
pip install 'jafaal[sso]'        # OpenID Connect identity providers (authlib)
pip install 'jafaal[redis]'      # distributed StateStore adapter (redis)
pip install 'jafaal[migrations]' # packaged Alembic revisions
pip install 'jafaal[all]'        # everything
```

If a feature is used without its extra installed, JAFAAL fails fast with a clear
install hint (a `MissingDependencyError`) rather than an obscure error.

### Verifying a release

Releases are built and published by [this repository's release workflow](.github/workflows/publish-jafaal.yml) through PyPI Trusted Publishing, with [PEP 740](https://peps.python.org/pep-0740/) attestations. You can confirm a downloaded artifact came from that workflow and was not substituted:

```bash
uvx pypi-attestations verify pypi \
    --repository https://github.com/endurain-project/jafaal \
    pypi:jafaal-<version>-py3-none-any.whl
```

A successful run prints `OK: <filename>`. `Provenance for file ... was not found` means the artifact predates attested publishing rather than that verification failed.

Each release run also produces a CycloneDX SBOM and `SHA256SUMS`, generated from a clean install of the built wheel. These are retained as workflow artifacts on the release run rather than published to PyPI.

## Quickstart

### 1. Configure the library

JAFAAL never reads environment variables itself — you build the settings and
inject them once at startup. Configuration is grouped by concern, so you only
read the groups you actually use.

```python
import jafaal
from cryptography.fernet import Fernet

jafaal.configure(
    jafaal.AuthSettings(
        secrets=jafaal.Secrets(
            secret_key="<32+ byte JWT signing secret>",
            fernet_key=Fernet.generate_key().decode(),  # at-rest token encryption
        ),
        base_url="https://app.example.com",
        app_name="Example",  # shown in authenticator apps
        environment="production",  # drives the cookie Secure flag
        # Every other group has working defaults; override only what you need:
        # tokens=jafaal.TokenSettings(access_token_expire_minutes=10),
        # sessions=jafaal.SessionSettings(idle_timeout_enabled=True),
        # webauthn=jafaal.WebAuthnSettings(second_factor_enabled=True),
    )
)
```

### 2. Own your `Base`, map JAFAAL's tables in, and register a session factory

You own the declarative registry; JAFAAL maps its companion tables into it with
`map_models`, so both share one metadata. Your model **must** be named `Users`,
mapped to the `users` table.

```python
from sqlalchemy import String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from jafaal import IntPKUserMixin


class Base(DeclarativeBase):  # you own the base
    pass


class Users(IntPKUserMixin, Base):
    __tablename__ = "users"
    # Add any app-specific profile columns — JAFAAL never touches them:
    display_name: Mapped[str | None] = mapped_column(String(250))


jafaal.map_models(Base)  # map JAFAAL's companion tables into your registry

engine = create_engine("postgresql+psycopg://...")
jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False))
Base.metadata.create_all(engine)  # or use Alembic migrations
```

The reverse relationships (`users_sessions`, `local_credential`, `auth_mfa`, …)
and the `mfa_enabled` property are supplied by the mixin — you declare none of them.

### 3. Implement the ports

```python
from jafaal import (
    PasswordPolicy,
    SignupConfig,
    UserProtocol,
    configure_settings_provider,
    configure_user_repository,
)


class SqlUserRepository:
    def get_by_id(self, user_id, db) -> UserProtocol | None:
        return db.get(Users, user_id)

    def get_by_email(self, email, db):
        return db.query(Users).filter(Users.email == email).one_or_none()

    def get_by_username(self, username, db):
        return db.query(Users).filter(Users.username == username).one_or_none()

    def create_local_user(self, username, email, db, *, is_active, is_verified):
        user = Users(username=username, email=email, is_active=is_active, is_verified=is_verified)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def provision_from_idp(self, identity, db): ...  # SSO auto-provisioning
    def sync_from_idp(self, user_id, claims, db): ...  # optional profile sync
    def set_email_verified(self, user_id, db, *, activate):
        user = db.get(Users, user_id)
        user.is_verified = True
        if activate:
            user.is_active = True
        db.commit()


class StaticSettingsProvider:
    def get_password_policy(self) -> PasswordPolicy:
        return PasswordPolicy(min_length_regular=15, min_length_admin=20, password_type="length_only")

    def get_signup_config(self) -> SignupConfig:
        return SignupConfig(enabled=True, require_email_verification=False, require_admin_approval=False)


configure_user_repository(SqlUserRepository())
configure_settings_provider(StaticSettingsProvider())
```

Notifications (password-reset / sign-up emails, admin pings) are optional — JAFAAL
emits events to an `AuthEventSink`; install one with `jafaal.configure_event_sink(...)`
to deliver them, or skip it and those flows simply mint tokens without sending mail.

### 4. Mount the router, and run maintenance

```python
import contextlib

from fastapi import FastAPI
import jafaal


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Sweeps consumed OAuth states, rotated refresh tokens and expired
    # reset/sign-up tokens. Without it those tables grow without bound.
    # Already have a scheduler? Call jafaal.maintenance.run_due_tasks() from it.
    jafaal.maintenance.start_background_scheduler()
    yield
    # Closes the pooled OIDC HTTP client, stops the sweeper, drains events.
    await jafaal.shutdown()


app = FastAPI(lifespan=lifespan)
# Registers the JafaalError→HTTP handler and aggregates every sub-router.
app.include_router(jafaal.create_auth_router(app=app), prefix="/api/v1")
```

That's it — you now have `/api/v1/auth/login`, `/refresh`, `/logout`, session
management, MFA, API keys, SSO, sign-up and password-reset endpoints.

### 5. Transactions: you own the unit of work

Every JAFAAL function that takes a `Session` participates in **your**
transaction and never commits — the CRUD layer only flushes. JAFAAL's own
endpoints commit exactly once per request; when *you* drive JAFAAL's services,
you decide the boundary:

```python
with jafaal.unit_of_work(db):
    user = repo.create_local_user("ada", "ada@example.com", db, is_active=True, is_verified=False)
    identity_service.set_local_password_hash(user.id, hashed)
    db.add(MyProfile(user_id=user.id))
# one commit — any failure rolls back all three
```

### 6. Optional configuration

```python
from jafaal import DEFAULT_SCOPE_CATALOG, configure_scopes, configure_api_key_scopes

# Layer your application scopes on top of JAFAAL's auth/identity scopes:
configure_scopes(
    DEFAULT_SCOPE_CATALOG.extend(
        regular=("reports:read",),
        admin=("reports:read", "reports:write"),
        descriptions={"reports:read": "Read reports", "reports:write": "Manage reports"},
    )
)

# Opt each scope an API key may carry in explicitly (empty by default):
configure_api_key_scopes(["reports:read"])

# Native apps use the standard RFC 6749 authorization-code flow with PKCE.
# Register each one so redirect URIs can be matched exactly (RFC 9700 §4.1):
# jafaal.AuthSettings(..., oauth_clients=(
#     jafaal.OAuthClient(client_id="com.example.app",
#                       redirect_uris=("com.example.app:/oauth/callback",)),
# ))

# Richer authorisation than the built-in is_superuser two tiers? Implement the
# ScopeResolver port and JAFAAL stamps whatever you return into its tokens:
# jafaal.configure_scope_resolver(MyRoleBasedResolver())

# jafaal.configure_rate_limiter(...)  # inject a real limiter (e.g. slowapi)
# jafaal.configure_state_store(...)   # inject Redis for multi-worker lockout state
```

By default JAFAAL runs in a single process with an in-memory state store and no
rate limiting. For multi-worker/replica deployments, inject a distributed
`StateStore` and a `RateLimiter`.

## Examples

[`examples/`](examples/) has a complete, runnable app — user model, ports and
router in one file — plus the two client-side walkthroughs it drives:

```bash
cd examples/minimal_app
uv run --with 'jafaal[all]' --with uvicorn uvicorn app:app --reload
```

- [Web client walkthrough](examples/web_client.md) — cookie refresh, CSRF, page
  reload, MFA
- [Mobile client walkthrough](examples/mobile_client.md) — the authorization-code
  flow with PKCE

## Documentation

Full documentation lives at [jafaal.endurain.com](https://jafaal.endurain.com/).
The [client integration reference](https://jafaal.endurain.com/clients/) is the
HTTP contract your front end codes against.

## Sponsors

A huge thank you to the project sponsors! Your support helps keep this project going.

Support Endurain's development on:

- [Buy Me a Coffee](https://buymeacoffee.com/endurain)
- [liberapay](https://liberapay.com/endurain/)
- [Patreon](https://patreon.com/u84745218)
- [GitHub Sponsors using archived repo](https://github.com/endurain-project/endurain)

## Contributing

Contributions are welcomed! Please open an issue to discuss any changes or improvements before submitting a PR. Check out the [Contributing Guidelines](CONTRIBUTING.md) for more details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.

<div align="center">
  <sub>Built with ❤️ from Portugal | Part of the <a href="https://github.com/endurain-project">Endurain</a> ecosystem</sub>
</div>