"""Smoke test for the runnable example under ``examples/``.

An example that does not run is worse than no example, and this one is the first
thing a new integrator copies. It exercises the whole wiring — settings, the
declarative registry, the three ports, the router — so an API change that would
break a host's integration fails here rather than in their repository.

Runs in a subprocess because the example configures JAFAAL process-wide at
import (which is exactly how a real host uses it) and would otherwise clobber the
suite's own session-scoped configuration.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "minimal_app"

# Drives the example end to end: seeded login, a protected endpoint, the refresh
# rotation, and the discovery document. Printed markers are asserted below so a
# silent failure cannot pass as success.
_DRIVER = """
import logging, sys
logging.disable(logging.CRITICAL)
from fastapi.testclient import TestClient
import app as example

with TestClient(example.app) as client:
    login = client.post(
        "/api/v1/auth/login",
        data={
            "username": "demo",
            "password": "correct-horse-battery-staple",
            "client_id": "example-web",
        },
    )
    assert login.status_code == 200, login.text
    body = login.json()

    # A cookie-delivery client must never receive the refresh token in the body.
    assert "refresh_token" not in body, body
    assert body["token_type"] == "Bearer"
    assert example.jafaal.get_settings().sessions.refresh_cookie_name in client.cookies

    me = client.get(
        "/api/v1/me",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert me.status_code == 200, me.text
    assert me.json()["user_id"] == 1

    refreshed = client.post("/api/v1/auth/refresh", data={"client_id": "example-web"})
    assert refreshed.status_code == 200, refreshed.text
    # Rotation must hand back a new access token, not replay the old one.
    assert refreshed.json()["access_token"] != body["access_token"]

    metadata = client.get("/api/v1/.well-known/oauth-authorization-server")
    assert metadata.status_code == 200
    assert metadata.json()["code_challenge_methods_supported"] == ["S256"]

print("EXAMPLE_OK")
"""


def test_the_example_app_runs_a_full_login_and_refresh():
    """The documented example must actually work against the current library."""
    repo_root = EXAMPLE_DIR.parent.parent
    env = dict(os.environ)
    env["JAFAAL_SECRET_KEY"] = "example-smoke-test-secret-key-32-bytes!"
    # The subprocess runs from the example directory, so put the working tree on
    # its path: the example must be exercised against *this* checkout whether or
    # not jafaal happens to be installed in the environment.
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(repo_root), env.get("PYTHONPATH", "")]))

    result = subprocess.run(
        [sys.executable, "-c", _DRIVER],
        cwd=EXAMPLE_DIR,
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert "EXAMPLE_OK" in result.stdout, f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
    assert result.returncode == 0, result.stderr
