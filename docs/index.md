# JAFAAL

<div>
    <a href="https://github.com/endurain-project/jafaal/blob/main/LICENSE.md">
      <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
    </a>
    <a href="https://github.com/endurain-project/jafaal/releases">
      <img src="https://img.shields.io/badge/dynamic/json?url=https://api.github.com/repos/endurain-project/jafaal/releases/latest&query=$.tag_name&label=release&color=blue" alt="Release">
    </a>
    <a href="https://pypi.org/project/jafaal/">
      <img src="https://img.shields.io/pypi/v/jafaal" alt="PyPI version">
    </a>
    <a href="https://github.com/endurain-project/jafaal">
      <img src="https://img.shields.io/badge/dynamic/json?url=https://api.github.com/repos/endurain-project/jafaal&query=$.stars_count&label=stars&logo=github" alt="Stars">
    </a>
</div>

**Just Another FastAPI Authentication Library.** JAFAAL is a batteries-included,
embedded FastAPI authentication library and a standards-shaped authorization
server for applications controlled by one host. It integrates with synchronous
SQLAlchemy and owns the security-critical parts of auth so your app doesn't have
to.

## Features

- **Password login** (Argon2id) with progressive per-account lockout
- **JWT access/refresh tokens** (HS256) with refresh-token **rotation + reuse detection**
- **Sessions** with idle/absolute timeout, CSRF binding, and web/mobile (PKCE) flows
- **MFA** (TOTP + single-use backup codes) with replay protection
- **Passkeys / WebAuthn** — passwordless login and passkey-as-second-factor (incl. usernameless)
- **API keys** with a host-controlled scope allow-list
- **SSO / OIDC** identity providers with SSRF-guarded outbound calls
- **Password reset & sign-up** flows that emit events (you deliver the email)
- A **`JafaalError` → HTTP** edge handler, so the core never imports HTTP concerns

JAFAAL depends only on a small set of **ports** you implement (your user table,
your dynamic settings, and how you deliver notifications). Everything else —
tables, routers, token logic — ships with the library, and ready-made
[adapters](ports-and-adapters.md#batteries-included-adapters) cover the common cases.

## What JAFAAL is (and is not)

JAFAAL authenticates **your** users for **your** API. Concretely, it plays five
roles, and implements the standards that govern each:

| Role | Standards |
|---|---|
| **JWT issuer** for your own resource servers | RFC 9068 (`at+jwt` access tokens), RFC 7519, RFC 7517 / 7638 (JWKS + `kid` thumbprints), RFC 8414 (discovery) |
| **Bearer-token resource server** | RFC 6750 (header extraction, `WWW-Authenticate` challenges incl. `insufficient_scope`) |
| **Authorization server for your own apps** | RFC 6749 §4.1 (authorization code), RFC 7636 (PKCE S256), RFC 8252 (native apps / public clients), RFC 9207 (`iss`), RFC 9700 (exact redirect-URI matching) |
| **OAuth client / OIDC Relying Party** for SSO | RFC 6749 *client* role, RFC 7636, OIDC Core 1.0 (`nonce`, `azp`, `at_hash`, userinfo `sub` check), RFC 9207, RFC 9700 |
| **Credential authority** | NIST SP 800-63B (password policy + breach screening), RFC 6238 (TOTP), W3C WebAuthn L2 (passkeys), RFC 7662 (introspection), RFC 7009 (revocation) |

### The boundary

**JAFAAL is an authorization server for clients you own.**

That is the whole of it, and it is a deliberate boundary rather than an
unfinished one. Everything inside it is implemented to the letter of the specs
above; nothing outside it is planned.

**Inside the boundary.** Register your applications as
[`OAuthClient`][jafaal.OAuthClient]s and drive `/auth/authorize` → `/auth/token`
with any standard OAuth client library. PKCE is mandatory, `code` is the only
response type, and redirect URIs match byte-for-byte. Clients are public
(RFC 8252): a native app or browser cannot keep a secret, so PKCE — not a client
credential — is what binds a code to its requester.

**Outside the boundary, and not planned:**

| Not planned | Why |
|---|---|
| **Third-party clients** (consent screen, client secrets, per-grant storage, [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) dynamic registration) | Letting a client you *don't* control obtain tokens for your users needs a consent UI, a grant store, and a client-management surface — each a new attack surface (consent phishing, redirect handling, secret leakage) in a library whose value is that its attack surface is small and reviewed. |
| **Being an OpenID Provider** (`id_token`, the `openid` scope, userinfo, `/.well-known/openid-configuration`, pairwise subjects, session management, the logout specs) | That is a product, not a feature. An uncertified OP inherits all of an OP's risk and none of its credibility; doing it properly means [OpenID Foundation certification](https://openid.net/certification/). Put a real OP (Keycloak, Authentik, Authelia, …) in front of JAFAAL instead — JAFAAL already speaks to all of them as a relying party. |
| **`client_credentials`** | Service-to-service auth is covered by scoped API keys, which need no user and no grant. |
| **Implicit and hybrid flows** | Removed by OAuth 2.1; RFC 9700 §2.1.2 recommends against issuing tokens in a redirect. |
| **The resource-owner password-credentials grant** | Removed by OAuth 2.1. `POST /auth/login` authenticates a first-party user directly and is deliberately **not** advertised in the [discovery document](configuration.md#discovery-rfc-8414) as a `token_endpoint`, precisely so no client attempts it. |

!!! tip "Which endpoint should my app use?"
    A **first-party app you ship** (your own SPA, your own mobile app) can use
    either: `/auth/login` is one request and needs no browser redirect;
    `/auth/authorize` → `/auth/token` is the standard flow and is what a native
    app should prefer, because it keeps the password out of the app entirely
    (RFC 8252 §8.1).

    Anything else must use `/auth/authorize` → `/auth/token`.

Both **web and mobile** clients are first-class. They differ only in
refresh-token delivery: browsers get an `HttpOnly`, `SameSite=Strict` cookie (so
page script never touches it, per RFC 9700 §7.2), native clients get it in the
response body.

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

A minimal "login + JWT + sessions" deployment needs no extras. Install only what
you use:

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

## Verifying a release

Releases are built and published by [this repository's release workflow](https://github.com/endurain-project/jafaal/blob/main/.github/workflows/publish-jafaal.yml) through PyPI Trusted Publishing, with [PEP 740](https://peps.python.org/pep-0740/) attestations. You can confirm a downloaded artifact came from that workflow and was not substituted:

```bash
uvx pypi-attestations verify pypi \
  --repository https://github.com/endurain-project/jafaal \
  pypi:jafaal-<version>-py3-none-any.whl
```

A successful run prints `OK: <filename>`. `Provenance for file ... was not found` means the artifact predates attested publishing rather than that verification failed.

Each release run also produces a CycloneDX SBOM and `SHA256SUMS`, generated from a clean install of the built wheel. These are retained as workflow artifacts on the release run rather than published to PyPI.

## Quickstart

```python
import jafaal
from cryptography.fernet import Fernet
from fastapi import FastAPI
from sqlalchemy import String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from jafaal import IntPKUserMixin
from jafaal.adapters import SqlAlchemyUserRepository, StaticSettingsProvider

# 1. Configure the library (you build settings; JAFAAL reads no env itself).
jafaal.configure(
    jafaal.AuthSettings(
        secrets=jafaal.Secrets(
            secret_key="<32+ byte JWT signing secret>",
            fernet_key=Fernet.generate_key().decode(),
        ),
        base_url="https://app.example.com",
        app_name="Example",
        environment="production",
    )
)


# 2. You own the Base; build your user model on it (any class name, table `users`).
class Base(DeclarativeBase):
    pass


class Account(IntPKUserMixin, Base):
    __tablename__ = "users"
    display_name: Mapped[str | None] = mapped_column(String(250))


jafaal.map_models(Base, user_model=Account)  # map JAFAAL's companion tables into your registry

engine = create_engine("postgresql+psycopg://...")
jafaal.configure_sessionmaker(sessionmaker(bind=engine, autoflush=False))
Base.metadata.create_all(engine)  # or use Alembic migrations

# 3. Install the ports (here via the batteries-included adapters).
jafaal.configure_user_repository(SqlAlchemyUserRepository())
jafaal.configure_settings_provider(StaticSettingsProvider())

# 4. Mount the router — registers the JafaalError→HTTP handler and every sub-router.
app = FastAPI()
app.include_router(jafaal.create_auth_router(app=app), prefix="/api/v1")
```

That's it — you now have `/api/v1/auth/login`, `/refresh`, `/logout`, session
management, MFA, API keys, SSO, sign-up and password-reset endpoints.

## Where to next

- **[Configuration](configuration.md)** — `AuthSettings`, sessions, scopes, rate
  limiting, and the distributed state store.
- **[Client integration](clients.md)** — the HTTP contract your web and mobile
  clients code against: endpoints, wire formats, scopes, and error semantics.
- **[Ports & Adapters](ports-and-adapters.md)** — the host boundary you implement
  and the ready-made adapters that satisfy it.
- **[Security](security.md)** — the threat model, built-in protections, and
  deployment hardening.
- **[API Reference](api.md)** — the full public API.

Prefer to read code? [`examples/`](https://github.com/endurain-project/jafaal/tree/main/examples)
has a complete runnable app plus web and mobile walkthroughs.
