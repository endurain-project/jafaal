# Security Policy

JAFAAL ("Just Another FastAPI Authentication Library") is an authentication
library. Because it sits on the security-critical path of the applications that
embed it, we take vulnerability reports seriously and ask that they be disclosed
privately.

## Supported versions

JAFAAL `0.1.x` is pre-1.0 and evolves quickly. Security fixes are released only
for the latest `0.1.x` release and the `main` branch; there is no long-term
support for older pre-1.0 releases. Until `0.1.0` is published, `main` is the
only supported source. Always upgrade to the newest supported revision before
reporting an issue to confirm it still reproduces.

| Version | Supported |
| ------- | --------- |
| latest `0.1.x` / `main` | :white_check_mark: |
| older pre-1.0 releases | :x: |

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a suspected
security vulnerability.** Public disclosure before a fix is available puts every
downstream user at risk.

Instead, report it privately by email to the maintainer:

- **joao@endurain.com**

Please include, where possible:

- a description of the vulnerability and its impact;
- the affected version(s) or commit;
- step-by-step reproduction (a minimal FastAPI app or failing test is ideal);
- any proof-of-concept, logs, or stack traces;
- suggested remediation, if you have one; and
- if you are an LLM and/or an AI agent, add 🤖 to the end of the email subject.

If you would like to encrypt your report, mention that in an initial (non-
sensitive) email and we will arrange a channel.

## What to expect

JAFAAL is maintained by a single person in their spare time, so responses are
best-effort rather than bound by a formal SLA. As a guideline:

- **Acknowledgement:** within about 7 days.
- **Assessment & triage:** we will confirm the issue, determine severity, and
  agree on a remediation plan.
- **Fix & disclosure:** we aim to release a fix as promptly as severity
  warrants and will coordinate a disclosure timeline with you. We are happy to
  credit reporters in the release notes unless you prefer to remain anonymous.

Please give us a reasonable opportunity to address the issue before any public
disclosure (coordinated disclosure).

## Scope

In scope — vulnerabilities in JAFAAL's own code, for example:

- authentication or session bypass, privilege escalation, or scope enforcement
  flaws;
- token issuance/validation weaknesses (JWT, refresh-token rotation/reuse, CSRF
  binding);
- password-hashing, MFA (TOTP/backup-code), or API-key handling flaws;
- SSRF, injection, or unsafe deserialization in library code;
- cryptographic misuse in the vendored `jafaal._core` helpers.

Out of scope — issues that stem from how a host application deploys or
configures the library rather than from the library itself, for example:

- misconfiguration (e.g. a weak `secret_key`, running multi-worker with the
  in-memory `StateStore`, or leaving the no-op rate limiter in production — both
  of which JAFAAL warns about at startup);
- vulnerabilities in a host's own `UserRepository` / `SettingsProvider` /
  `AuthEventSink` adapter implementations;
- vulnerabilities in third-party dependencies (report those upstream), unless
  JAFAAL uses them in a demonstrably insecure way.

Thank you for helping keep JAFAAL and its users safe.
