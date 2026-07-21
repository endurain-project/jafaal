"""Extra network-guard tests: trusted-proxy CIDRs, SSRF allow-list, hostname refresh."""

import dataclasses
from contextlib import contextmanager

import httpx
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


async def test_ssrf_request_hook_blocks_redirect_to_private_address():
    """A 302 from a public endpoint to the metadata IP is rejected mid-redirect."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "8.8.8.8":
            # Public first hop tries to redirect into the cloud metadata service.
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        # Must never be reached: the hook rejects the redirect target first.
        return httpx.Response(200, json={"secret": "leaked"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
        event_hooks={"request": [network.ssrf_request_hook]},
    ) as client:
        with pytest.raises(exc.InvalidRequestError):
            await client.get("http://8.8.8.8/.well-known/openid-configuration")


async def test_ssrf_request_hook_allows_public_redirect():
    """A redirect to another public address is still followed normally."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "8.8.8.8":
            return httpx.Response(301, headers={"Location": "http://1.1.1.1/openid-configuration"})
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
        event_hooks={"request": [network.ssrf_request_hook]},
    ) as client:
        resp = await client.get("http://8.8.8.8/.well-known/openid-configuration")

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
