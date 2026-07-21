"""Extra network-guard tests: trusted-proxy CIDRs, SSRF allow-list, hostname refresh."""

import dataclasses
from contextlib import contextmanager

import pytest
from starlette.requests import Request

import jafaal
import jafaal._core.network as network
import jafaal.exceptions as exc


@contextmanager
def _settings(**overrides):
    original = jafaal.get_settings()
    jafaal.configure(dataclasses.replace(original, **overrides))
    try:
        yield
    finally:
        jafaal.configure(original)


def _request(client_host, headers=None):
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": raw,
        "client": (client_host, 5555),
        "scheme": "http",
        "server": ("t", 80),
    }
    return Request(scope)


def test_trusted_proxy_cidr_honours_xff():
    with _settings(trusted_proxies=("10.0.0.0/8",)):
        # Peer inside the trusted CIDR → XFF honoured.
        req = _request("10.1.2.3", {"X-Forwarded-For": "1.2.3.4"})
        assert network.get_ip_address(req) == "1.2.3.4"


def test_untrusted_peer_ignores_xff():
    with _settings(trusted_proxies=("10.0.0.0/8",)):
        # Peer outside the trusted CIDR → XFF ignored, direct peer returned.
        req = _request("203.0.113.1", {"X-Forwarded-For": "1.2.3.4"})
        assert network.get_ip_address(req) == "203.0.113.1"


def test_exact_ip_trusted_peer():
    with _settings(trusted_proxies=("203.0.113.7",)):
        req = _request("203.0.113.7", {"X-Real-IP": "9.9.9.9"})
        assert network.get_ip_address(req) == "9.9.9.9"


def test_ssrf_allowlist_permits_private_host():
    # Loopback is normally rejected...
    with pytest.raises(exc.InvalidRequestError):
        network.reject_private_url("http://127.0.0.1/cb")
    # ...unless explicitly allow-listed.
    with _settings(ssrf_allowed_hosts=("127.0.0.1",)):
        network.reject_private_url("http://127.0.0.1/cb")  # does not raise


def test_ssrf_allowlist_cidr():
    with _settings(ssrf_allowed_hosts=("10.0.0.0/8",)):
        network.reject_private_url("http://10.1.2.3/cb")  # does not raise


def test_refresh_trusted_proxy_hostnames_resolves_localhost():
    with _settings(trusted_proxies=("localhost",)):
        resolved = network.refresh_trusted_proxy_hostnames(force=True)
        assert "localhost" in resolved
        assert resolved["localhost"]  # at least one resolved IP
