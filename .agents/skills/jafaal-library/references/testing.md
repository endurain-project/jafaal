# Testing

- Tests live in `tests/`, files `test_*.py`, grouped in `Test*` classes; shared fixtures in `tests/conftest.py`.
- Tests are hermetic: in-memory SQLite (`StaticPool`), in-memory state store, `fakeredis`, no network, time injected. Nothing sleeps.
- `conftest` gives every test a fresh schema and state store (`_isolate`); do not rely on state left by another test.
- Pytest runs with `asyncio_mode = "auto"` and `--strict-markers`; a new marker is declared in `pyproject.toml`.
- Cover empty/None, missing entity, errors, malformed input and the refusal path of every security check, not only the happy path.
- `with pytest.raises(...) as exc_info` for exceptions; assert the error `code`, not just the type.
- Skips need `reason=`.
- Coverage: `fail_under` in `pyproject.toml` is a ratchet; raise it when coverage rises and never lower it.
- Do not mock the session to check a query or a commit; use a real database.
- A host-agnostic rule (no assumed user class name, no HTTP in the core) is pinned by a test in `tests/test_host_agnostic.py`.
- Examples under `examples/` are executed by `tests/test_examples.py`; a public API change updates them.

## Matrices

| Question | Use |
| --- | --- |
| Does this query or constraint behave? | the default in-memory SQLite |
| Does it hold on PostgreSQL or MySQL? | set `JAFAAL_TEST_DATABASE_URL` to a disposable database |
| Does it hold on the distributed state store? | set `JAFAAL_TEST_STATE_STORE=redis` (uses `fakeredis`) |

```bash
uv run pytest tests/test_flows_http.py -v
uv run pytest --cov=jafaal --cov-report=term-missing
```
