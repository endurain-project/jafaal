# Key rotation runbook

JAFAAL uses two independent secrets, both supplied by the host through
[`AuthSettings`](configuration.md):

- **`secret_key`** — the HMAC key that signs and verifies JWTs (access/refresh).
- **`fernet_key`** — the symmetric key that encrypts at-rest secrets (IdP client
  secrets, MFA secrets, and rotated refresh tokens).

Both support **zero-downtime rotation** through verify-/decrypt-only fallbacks,
so you can roll a key without invalidating live tokens or having to bulk
re-encrypt stored secrets.

!!! info "The golden rule"
    New material is always produced with the **primary** key (the first one).
    Fallbacks are only ever used to *verify* (JWT) or *decrypt* (Fernet). Put the
    **new** key first and keep the **old** key as a fallback during the overlap.

## Rotating the JWT signing key (`secret_key`)

A JWT signed with the old key must keep validating until every token minted under
it has expired. The overlap window must therefore be **at least
`refresh_token_expire_days`** (refresh tokens are the longest-lived; default 7
days).

1. **Generate** a new high-entropy key (≥ 32 bytes):

    ```python
    import secrets
    print(secrets.token_urlsafe(32))
    ```

2. **Deploy the overlap.** Set the new key as `secret_key` and move the previous
   key into `secret_key_fallbacks`:

    ```python
    jafaal.configure(jafaal.AuthSettings(
        secret_key=NEW_KEY,
        secret_key_fallbacks=(OLD_KEY,),
        fernet_key=FERNET_KEY,
        # ...rest unchanged...
    ))
    ```

    New tokens are now signed with `NEW_KEY`; tokens still bearing `OLD_KEY`
    signatures continue to verify.

3. **Wait out the overlap** — at least `refresh_token_expire_days`. Every active
   session refreshes onto a `NEW_KEY` token during this window.

4. **Drop the old key.** Remove `OLD_KEY` from `secret_key_fallbacks` and
   redeploy. Any token still signed with it is now rejected (those sessions were
   already expired).

## Rotating the asymmetric signing key

When signing with an asymmetric `algorithm` (RS256/ES256/…), rotation is driven
by `private_key` (the active signer) and `private_key_fallbacks` (verify-only
keys still published in the JWKS). Verifiers pick the key by the token's `kid`,
so old and new tokens both validate during the overlap.

1. **Generate** a new key pair (e.g. RSA):

    ```bash
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out new-signing-key.pem
    ```

2. **Deploy the overlap.** Make the new key the `private_key` and keep the old
   key (private, or just its public half) as a verify-only fallback:

    ```python
    jafaal.configure(jafaal.AuthSettings(
        secret_key=SECRET_KEY,
        fernet_key=FERNET_KEY,
        algorithm="RS256",
        private_key=NEW_PRIVATE_KEY_PEM,
        private_key_fallbacks=(OLD_PUBLIC_KEY_PEM,),   # verify-only; stays in the JWKS
        # ...rest unchanged...
    ))
    ```

    New tokens are signed with the new key (new `kid`); both keys appear in the
    JWKS, so tokens bearing either `kid` verify. Verifiers pick up the change
    within their JWKS cache's `Cache-Control` max-age (300s by default).

3. **Wait out the overlap** — at least `refresh_token_expire_days`, so every live
   token has been re-signed with the new key.

4. **Drop the old key.** Remove it from `private_key_fallbacks` and redeploy; the
   JWKS then advertises only the new key.

    !!! tip "Only public keys leave the process"
        The JWKS publishes public keys only (the private component is never
        serialised), so a fallback may be a public-only PEM.

## Rotating the encryption key (`fernet_key`)

Fernet rotation has **no time pressure** — a secret encrypted with the old key
stays decryptable as long as the old key remains a fallback. You may re-encrypt
eagerly or let values roll forward naturally as they are rewritten.

1. **Generate** a new key:

    ```python
    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())
    ```

2. **Deploy the overlap.** Set the new key as `fernet_key` and move the previous
   key into `fernet_key_fallbacks`:

    ```python
    jafaal.configure(jafaal.AuthSettings(
        secret_key=SECRET_KEY,
        fernet_key=NEW_FERNET_KEY,
        fernet_key_fallbacks=(OLD_FERNET_KEY,),
        # ...rest unchanged...
    ))
    ```

    New writes use `NEW_FERNET_KEY`; existing ciphertext decrypts via the
    fallback (JAFAAL uses `MultiFernet` under the hood).

3. **(Optional) Re-encrypt eagerly.** If you want to retire the old key quickly,
   trigger a rewrite of the stored secrets (e.g. re-save IdP configurations and
   have users re-enrol MFA), or run a migration that decrypts-then-re-encrypts
   each value. Otherwise, values re-encrypt naturally on their next write.

4. **Drop the old key** once you are confident nothing is still encrypted under
   it: remove `OLD_FERNET_KEY` from `fernet_key_fallbacks` and redeploy.

    !!! warning
        Dropping a Fernet fallback while any stored value is still encrypted with
        it makes that value **permanently undecryptable**. When in doubt, keep the
        fallback or re-encrypt first.

## What else `secret_key` protects

`secret_key` does two jobs. Besides signing HS256 JWTs, it is stretched (HKDF-SHA256,
one subkey per purpose) into the key that MACs every **stored token digest**:

| Digest | Written when |
|---|---|
| Session refresh token | login, and every `/auth/refresh` |
| Rotated refresh token | every `/auth/refresh` (reuse/theft detection) |
| Session CSRF token | login bootstrap and every rotation |
| API key | key creation |
| Password-reset token | reset requested |
| Sign-up / email-verification token | sign-up |
| IdP account-link token | link initiated |

Those digests are covered by the same `secret_key_fallbacks` overlap: the read
side computes the digest under the primary subkey **and** each fallback subkey,
so nothing minted before the rotation stops working. New digests are always
written with the primary subkey, so records re-key themselves as they are
rewritten — a session on its next refresh, a reset token when the next one is
issued.

!!! warning "API keys need the overlap most"
    An API-key row is long-lived and is never rewritten on its own, so it cannot
    "roll forward" the way a session does. JAFAAL therefore **re-keys the row in
    place** the first time a key is authenticated via a fallback subkey. That
    means every API key must be *used at least once* during the overlap window to
    survive the old key being dropped. If you cannot guarantee that, keep the
    fallback in place longer, or plan to re-issue keys.

!!! note "Passkeys"
    The WebAuthn *user handle* is also derived from `secret_key`. Authentication
    resolves the user from the presented credential ID, never from the handle, so
    rotation does not break sign-in — but passkeys registered before and after a
    rotation carry different account handles, which some authenticators display
    as two entries. Cosmetic only.

## Emergency rotation (suspected key compromise)

A leaked key is different from a routine roll — you cannot wait out an overlap.

- **`secret_key` compromised:** rotate as above but **do not** keep the leaked key
  as a fallback (an attacker could forge tokens the fallback would accept).
  Dropping it immediately invalidates every live access/refresh token, forcing a
  global re-login — the correct trade-off under compromise. It also invalidates
  every **API key** (their stored digests were keyed by the leaked secret), so
  plan to re-issue them; that is likewise correct under compromise, since an
  attacker with the old key could otherwise verify captured keys offline. Rotate
  the value in your secret manager too.
- **`fernet_key` compromised:** set the new key primary, keep the old key as a
  fallback **only long enough to re-encrypt** every stored secret, then drop it.
  Treat the previously-encrypted IdP/MFA secrets as exposed: rotate IdP client
  secrets at the provider and require MFA re-enrolment.

## Checklist

- [ ] New key generated with sufficient entropy (`secret_key` ≥ 32 bytes;
      `fernet_key` via `Fernet.generate_key()`).
- [ ] New key set **primary**, old key added as **fallback**, and deployed.
- [ ] Overlap observed (JWT: ≥ `refresh_token_expire_days`; Fernet: until
      re-encrypted).
- [ ] For `secret_key`: every API key used at least once during the overlap (so
      its stored digest is re-keyed), or re-issue plan agreed.
- [ ] Old key removed from fallbacks and redeployed.
- [ ] Secret-manager entry rotated; rotation recorded in your change log.
