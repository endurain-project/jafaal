---
name: jafaal-library
description: JAFAAL library conventions (ports, adapters, auth flows, public API, migrations). Use when adding, moving, refactoring or reviewing code in jafaal/ or tests/.
---

# JAFAAL library

`docs/api-stability.md` defines the public surface, `docs/ports-and-adapters.md` the host boundary and `[tool.importlinter]` in `pyproject.toml` the architecture.
Where this skill and any of them disagree, they win.

## Core rules (always apply)

- The core depends on ports, never on `jafaal.adapters`; a host can drop any adapter, and `import jafaal` never loads an optional dependency (`redis`, `webauthn`).
- If an import contract blocks you, the design is wrong; do not edit the contract or add `ignore_imports` to pass.
- `jafaal._core` and `jafaal._internal` are private. A name is public only if `docs/api-stability.md` lists it or it is in `jafaal.__all__` (and `jafaal.maintenance.__all__`).
- Raise a `JafaalError` subclass from the core; the edge handler is the only place that knows HTTP. Never put SQL, paths, tokens or stack detail in `detail`.
- A released error `code` never changes; a new failure mode gets a new subclass with `code`, `status_code` and `default_detail`.
- The host owns users, the database and the policy: take a user through `UserRepository` and the scope resolvers, never assume a class name or column beyond the documented protocol.
- A new public name goes in `jafaal/__init__.py` (or a listed module), the `docs/api-stability.md` table, the docs page that explains it and `CHANGELOG.md`.
- A rename, removal, signature change, error-code change, token/cookie/claim change, endpoint change or stored-schema change is breaking: mark it `!` and say so in the changelog.
- A table or column change is an explicit-DDL Alembic revision in `jafaal/migrations/versions/` with a working downgrade; new tables use the `jafaal_` prefix.
- KISS, YAGNI, DRY: search the package for an existing helper first; add no parameter, port, setting or adapter without a current caller; extract on the third repetition.
- Comments and docstrings say what the code does now and why; history goes in the commit message.

## Read on demand

| When you are | Read |
| --- | --- |
| Writing code, docstrings, logging, errors or typing | `references/code-standards.md` |
| Writing or fixing tests | `references/testing.md` |
| Touching tokens, sessions, passwords, MFA, cookies, redirects, outbound calls or secrets | `references/security.md` |

## Before finishing

```bash
uv run ruff check . && uv run ruff format --check .
uv run lint-imports
uv run mypy
uv run pytest
```

`uv run pytest` enforces the `fail_under` coverage total.
`uv run ty check` is advisory in CI and not a gate.

## Repo hygiene

- Do only what was asked: no extra docs, summaries or READMEs.
- Prefer existing patterns and utilities over new files; keep it simple, build only what is needed now, do not repeat existing code.
- Do not touch CI, publish configuration, supported Python versions or dependency constraints unless asked.
- Local notes go in `devdocs/`, helper scripts in `devscripts/` (gitignored).
- Never run `git commit` unless asked; use the `conventional-commits` skill for messages.
