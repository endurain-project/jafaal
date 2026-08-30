# API Reference

## HTTP route classification

The paths below use the default [`RouterPrefixes`][jafaal.RouterPrefixes] and
are relative to the path where the host mounts
[`create_auth_router()`][jafaal.create_auth_router]. A host may override the
prefixes, so deployed absolute paths can differ.

JAFAAL's registered clients are trusted, statically configured, first-party
public clients. Calling a route an OAuth endpoint describes its wire contract;
it does not make JAFAAL a third-party authorization service. The OIDC RP routes
communicate with an upstream identity provider. Every other route is a JAFAAL
extension, even when it implements a standard such as WebAuthn internally.

### OAuth authorization-server endpoints

| Method | Path | Contract |
|---|---|---|
| `GET` | `/auth/authorize` | RFC 6749 authorization endpoint; authorization code only, with PKCE S256 required |
| `POST` | `/auth/token` | RFC 6749 token endpoint; authorization-code and refresh-token grants |
| `POST` | `/auth/introspect` | RFC 7662 token introspection |
| `POST` | `/auth/revoke` | RFC 7009 token revocation |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 authorization-server metadata |
| `GET` | `/.well-known/jwks.json` | RFC 7517 JSON Web Key Set used to verify asymmetric tokens |

### Upstream OIDC relying-party integration

| Method | Path | Contract |
|---|---|---|
| `GET` | `/public/idp/callback/{idp_slug}` | OAuth/OIDC callback from a configured upstream provider |
| `POST` | `/auth/idp/step-up/reauth/{idp_id}` | JAFAAL extension that starts fresh upstream OIDC authentication for step-up |

These routes are part of JAFAAL's role as an OAuth client and OpenID Connect
Relying Party. They are not OpenID Provider endpoints.

### JAFAAL extension endpoints

| Methods | Paths | Purpose |
|---|---|---|
| `POST` | `/auth/login` | First-party password login; not the OAuth resource-owner password grant |
| `POST` | `/auth/mfa/verify` | Complete a pending login with TOTP or a backup code |
| `POST` | `/auth/refresh` | Native cookie/header alias for the refresh-token grant; OAuth clients use `/auth/token` |
| `POST` | `/auth/logout` | Delete the current JAFAAL session; not an OIDC logout endpoint |
| `POST` | `/auth/password/change` | Change the authenticated user's password after step-up |
| `POST` | `/auth/password/renew` | Replace a password marked as requiring change |
| `POST` | `/auth/password/user/{user_id}` | Administrative password reset |
| `POST` | `/auth/password-reset/request`, `/auth/password-reset/confirm` | Request and consume a password-reset token |
| `POST` | `/auth/sign-up/request`, `/auth/sign-up/confirm` | Create a local account and confirm its email token |
| `GET` | `/auth/sessions/user/{user_id}` | List a user's sessions |
| `DELETE` | `/auth/sessions/{session_id}/user/{user_id}`, `/auth/sessions/user/{user_id}` | Revoke one or all of a user's sessions |
| `GET`, `POST` | `/auth/api-keys` | List or create API keys |
| `PATCH` | `/auth/api-keys/{api_key_id}/revoke` | Revoke an API key while retaining its record |
| `DELETE` | `/auth/api-keys/{api_key_id}` | Delete an API key |
| `GET` | `/public/idp` | List enabled upstream identity providers for a login picker |
| `GET`, `POST` | `/auth/idp` | List or create configured identity providers |
| `GET` | `/auth/idp/templates` | List built-in identity-provider templates |
| `PUT`, `DELETE` | `/auth/idp/{idp_id}` | Update or delete an identity provider |
| `POST` | `/auth/webauthn/register/begin`, `/auth/webauthn/register/complete` | Register a passkey |
| `GET` | `/auth/webauthn/credentials` | List the authenticated user's passkeys |
| `POST` | `/auth/webauthn/credentials/{credential_pk}/delete` | Delete a passkey after step-up |
| `POST` | `/auth/webauthn/mfa/begin`, `/auth/webauthn/mfa/complete` | Complete a pending password login with a passkey second factor |
| `POST` | `/public/webauthn/authenticate/begin`, `/public/webauthn/authenticate/complete` | Passwordless passkey login |

Login, MFA, passkey, password, signup, session, API-key, and administrative
routes are not OAuth grants or endpoints. They use JAFAAL's `{"detail",
"code"}` error contract rather than the OAuth error body.

## Python API

The curated public API is everything exported from the top-level `jafaal`
package. Each symbol below is generated from its source docstring.

::: jafaal
    handler: python
    options:
      docstring_style: google
      show_root_heading: false
      show_source: true
      members_order: source
