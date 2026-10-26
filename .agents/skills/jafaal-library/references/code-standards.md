# Code standards

## Python
- Python 3.12 syntax (`requires-python = ">=3.12"`): `int | None`, `list[str]`; no `typing.Optional/List/Dict`. Do not use syntax newer than 3.12.
- Lines up to 120 characters, code and prose alike (ruff format does not wrap docstrings; keep paragraphs readable).
- Imports grouped stdlib / third-party / local; `TYPE_CHECKING` to avoid cycles.
- Every module has a top-level docstring.
- Comments and docstrings state what the code does now and why. History goes in the commit message.

## Docstrings (PEP 257, Google sections)
- Summary on the opening line, then a blank line, then sections.
- Every public module, class, function and method has a docstring.
- `Args`: every parameter of a public function. A `_private` helper gets a summary and `Args` only for a non-obvious parameter.
- `Returns`: when a value comes back. `Returns: None.` is not required.
- `Raises`: the exceptions the function raises or deliberately lets propagate, especially the ones with a security meaning. Omit it when there are none.
- Classes: summary plus `Attributes`.
- No examples in docstrings; they belong in `docs/`.
- A docstring is not a design document: what, then why, in the fewest lines.
- A docstring with backslashes is a raw string (`r"""`).

## Typing
- `mypy` is the gate (`check_untyped_defs`); every new function is fully annotated.
- Do not add `# type: ignore` or `# noqa` to pass; fix the type or the code. A `per-file-ignores` entry in `pyproject.toml` needs a comment saying why (false positives on `token_type`-style names are the existing precedent).
- ORM model modules bind to the host-owned base at runtime and are excluded from mypy; do not give them host-specific types.

## SQLAlchemy 2
- `Mapped[...]` with `mapped_column()`; every column typed; synchronous sessions only.
- JAFAAL joins the host's transaction through `unit_of_work`, `session_scope` and `savepoint`; do not commit, roll back or create an engine elsewhere.
- Tables, indexes and named constraints are prefixed `jafaal_`.

## Pydantic v2
- `ConfigDict`, `field_validator`; no class `Config`, no `@validator`.
- Request and response shapes live in `schema.py` or the feature's schema module; keep ORM and schema names distinct.

## FastAPI
- Routers validate and delegate; auth rules live in the services under `_internal/services/` and the feature packages.
- Mount through `create_auth_router`; the core never imports HTTP concerns, so route code is the only place for `Request`, `Response` and cookies.
- Response models on every JSON route; status 200 (read), 201 (create), 204 (delete).

## Errors
- Raise `JafaalError` subclasses (`jafaal/exceptions.py`); the edge handler (`jafaal.error_handler`) renders them.
- Authentication failures answer identically for "no such user" and "wrong credential" (anti-enumeration).
- Do not swallow an exception to keep a flow going; a failed write of a rotated token or credential propagates.

## Logging
- `logging.getLogger(__name__)` for diagnostics; security events go through `jafaal.audit` (logger `jafaal.audit`) with the existing event-name constants.
- The host owns handlers, levels and formatting; never call `basicConfig`, add handlers or set levels.
- Never log passwords, tokens, refresh tokens, API keys, TOTP codes, backup codes, authorization codes or client secrets.
- Log text and error wording are not public API.

## Dependencies and extras
- The core stays small; Redis, WebAuthn and similar live behind extras and are imported lazily (`jafaal._core.optional_deps`).
- Adding or changing a dependency is a request-level decision: ask first.
