"""Extra network-guard tests: trusted-proxy CIDRs, SSRF allow-list, hostname refresh."""

from contextlib import contextmanager

import httpx
import pytest
from conftest import replace_settings
from starlette.requests import Request

import jafaal
import jafaal._core.network as network
import jafaal.exceptions as exc


@contextmanager
def _settings(**overrides):
    original = jafaal.get_settings()
    jafaal.configure(replace_settings(original, **overrides))
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


# --------------------------------------------------------------------------- #
# Pinned-IP SSRF transport (DNS-rebinding TOCTOU closure)
# --------------------------------------------------------------------------- #


def _fake_getaddrinfo(*ips):
    """Return a fake ``getaddrinfo`` resolving to the given IP(s)."""

    def _resolver(host, port, *args, **kwargs):
        return [(0, 0, 0, "", (ip, port or 0)) for ip in ips]

    return _resolver


def test_resolve_and_validate_host_returns_public_ip(monkeypatch):
    monkeypatch.setattr("jafaal._core.network.socket.getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    assert network._resolve_and_validate_host("example.test") == "93.184.216.34"


def test_resolve_and_validate_host_rejects_private_answer(monkeypatch):
    monkeypatch.setattr("jafaal._core.network.socket.getaddrinfo", _fake_getaddrinfo("10.1.2.3"))
    with pytest.raises(exc.InvalidRequestError):
        network._resolve_and_validate_host("rebind.test")


def test_resolve_and_validate_host_rejects_when_any_answer_private(monkeypatch):
    # A rebinding answer that mixes a public and a private address is rejected
    # (strict: a single private answer aborts).
    monkeypatch.setattr("jafaal._core.network.socket.getaddrinfo", _fake_getaddrinfo("93.184.216.34", "10.0.0.5"))
    with pytest.raises(exc.InvalidRequestError):
        network._resolve_and_validate_host("mixed.test")


def test_resolve_and_validate_host_rejects_ipv4_mapped_metadata(monkeypatch):
    # A resolver answer of the IPv4-mapped cloud-metadata address must be rejected
    # rather than treated as a public IPv6 address.
    monkeypatch.setattr("jafaal._core.network.socket.getaddrinfo", _fake_getaddrinfo("::ffff:169.254.169.254"))
    with pytest.raises(exc.InvalidRequestError):
        network._resolve_and_validate_host("rebind-mapped.test")


def test_resolve_and_validate_host_ip_literals():
    assert network._resolve_and_validate_host("93.184.216.34") == "93.184.216.34"
    with pytest.raises(exc.InvalidRequestError):
        network._resolve_and_validate_host("127.0.0.1")


def test_pin_request_rewrites_hostname_and_preserves_tls_identity(monkeypatch):
    monkeypatch.setattr("jafaal._core.network.socket.getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    req = httpx.Request("GET", "https://idp.example/token")
    network._pin_request_to_validated_ip(req)
    # Dials the validated IP, but TLS + vhost routing still target the hostname.
    assert req.url.host == "93.184.216.34"
    assert req.extensions["sni_hostname"] == "idp.example"
    assert req.headers["Host"] == "idp.example"


def test_pin_request_ip_literal_left_unchanged():
    req = httpx.Request("GET", "https://93.184.216.34/token")
    network._pin_request_to_validated_ip(req)
    assert req.url.host == "93.184.216.34"
    assert "sni_hostname" not in req.extensions


def test_pin_request_rejects_forbidden_scheme():
    req = httpx.Request("GET", "ftp://example.test/x")
    with pytest.raises(exc.InvalidRequestError):
        network._pin_request_to_validated_ip(req)


def test_pin_request_allowlisted_private_is_pinned(monkeypatch):
    monkeypatch.setattr("jafaal._core.network.socket.getaddrinfo", _fake_getaddrinfo("10.1.2.3"))
    with _settings(ssrf_allowed_hosts=("10.0.0.0/8",)):
        req = httpx.Request("GET", "https://internal.idp/token")
        network._pin_request_to_validated_ip(req)
        assert req.url.host == "10.1.2.3"  # allow-listed private host is dialed


async def test_ssrf_guard_transport_pins_and_forwards(monkeypatch):
    monkeypatch.setattr("jafaal._core.network.socket.getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["host"] = request.url.host
        seen["sni"] = request.extensions.get("sni_hostname")
        seen["host_header"] = request.headers.get("Host")
        return httpx.Response(200, json={"ok": True})

    transport = network.SsrfGuardAsyncTransport(httpx.MockTransport(handler))
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await client.get("https://idp.example/x")

    assert resp.status_code == 200
    assert seen["host"] == "93.184.216.34"
    assert seen["sni"] == "idp.example"
    assert seen["host_header"] == "idp.example"


async def test_ssrf_guard_transport_blocks_rebinding_to_private(monkeypatch):
    # DNS rebinding: the transport re-resolves at connect time and refuses the
    # private answer, so the inner transport is never reached even though the URL
    # host looks public. This is the TOCTOU that reject_private_url alone leaves.
    monkeypatch.setattr("jafaal._core.network.socket.getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    reached = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        reached["count"] += 1
        return httpx.Response(200, json={"secret": "leaked"})

    transport = network.SsrfGuardAsyncTransport(httpx.MockTransport(handler))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(exc.InvalidRequestError):
            await client.get("https://rebind.evil/x")

    assert reached["count"] == 0
