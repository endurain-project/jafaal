# JAFAAL examples

A complete, runnable deployment plus the two client-side walkthroughs that drive
it. Everything here is verified against the library in this repository.

| File | What it covers |
|---|---|
| [minimal_app/app.py](minimal_app/app.py) | A whole JAFAAL host in one file: user model, the three ports, the router |
| [web_client.md](web_client.md) | Browser / SPA integration — cookie refresh, CSRF, page reload, MFA |
| [mobile_client.md](mobile_client.md) | Native app integration — the authorization-code flow with PKCE |

## Run it

```bash
cd minimal_app
uv run --with 'jafaal[all]' --with uvicorn uvicorn app:app --reload
```

Then open <http://127.0.0.1:8000/docs>. A demo account is seeded on first start:

```
username: demo
password: correct-horse-battery-staple
```

The database is SQLite in `minimal_app/example.db` — delete it to start over.

> [!NOTE]
> The app logs a startup warning about HS256 signing. That is intentional: it is
> the zero-configuration default, and the warning tells you what you give up
> (a resource server cannot verify without also being able to mint). See
> [Key rotation](../docs/key-rotation.md) for the asymmetric setup.

## What the app shows

1. **Configuration** — `jafaal.configure(AuthSettings(...))`. JAFAAL never reads
   the environment itself; the host injects settings once at startup.
2. **One declarative registry** — the host owns `Base`; `jafaal.map_models(Base)`
   maps JAFAAL's companion tables into it so foreign keys to `users.id` resolve.
3. **The three ports** — `UserRepository`, `SettingsProvider`, `AuthEventSink`.
   That is the entire contract. JAFAAL owns passwords, tokens, sessions, MFA and
   the routers; the host owns its user table, its dynamic settings, and delivery.
4. **The router** — `create_auth_router()` returns everything below, ready to
   mount.

> [!TIP]
> The example writes its own `UserRepository` because it is instructive, but you
> usually do not have to: `jafaal.adapters.SqlAlchemyUserRepository()` implements
> the whole port against your mapped user model with no arguments. Same for
> `jafaal.adapters.StaticSettingsProvider`.

## The endpoints you get

Mounted under `/api/v1` by the example, except the issuer-derived RFC 8414
metadata route at the application root.

### Core authentication

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/login` | First-party username/password login. **Not** an OAuth grant |
| `POST` | `/auth/mfa/verify` | Complete a login that returned an MFA challenge |
| `POST` | `/auth/refresh` | Rotate a refresh token (JAFAAL's native request shape) |
| `POST` | `/auth/logout` | End the session and clear the refresh cookie |

### OAuth 2.0

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/auth/authorize` | Authorization endpoint — PKCE mandatory, `code` only |
| `POST` | `/auth/token` | `authorization_code` and `refresh_token` grants |
| `POST` | `/auth/introspect` | RFC 7662 introspection (requires `auth:introspect`) |
| `POST` | `/auth/revoke` | RFC 7009 revocation |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 metadata for the example's root issuer |
| `GET` | `/.well-known/jwks.json` | Public keys (404 under HS256 — there are none) |

### Account and credential management

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/sign-up/request` · `/auth/sign-up/confirm` | Enumeration-safe sign-up |
| `POST` | `/auth/password-reset/request` · `/auth/password-reset/confirm` | Enumeration-safe reset |
| `GET`/`DELETE` | `/auth/sessions/user/{user_id}` | List / revoke the user's sessions |
| `GET`/`POST` | `/auth/api-keys` | API-key management |
| `POST` | `/auth/webauthn/register/begin` · `/register/complete` | Passkey enrolment |
| `POST` | `/public/webauthn/authenticate/begin` · `/authenticate/complete` | Passwordless login |
| `GET` | `/public/idp` | Identity providers a client may offer |
| `GET` | `/public/idp/callback/{idp_slug}` | SSO callback |

## Registered clients decide the shape

Every token-issuing request names a `client_id` registered in
`AuthSettings.oauth_clients`. **The registration, not the request, decides how
tokens come back** — so a caller cannot switch delivery mode or widen scope.

The example registers two:

| `client_id` | `token_delivery` | Refresh token arrives as |
|---|---|---|
| `example-web` | `cookie` | `HttpOnly`, `SameSite=Strict` cookie — page script never sees it |
| `example-mobile` | `body` | A field in the JSON response — the app stores it in the platform keystore |

That single setting is the *only* difference between the web and mobile flows.
