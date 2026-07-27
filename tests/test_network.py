"""Tests for the SSRF guard and proxy-aware client IP extraction."""

import ipaddress
from contextlib import contextmanager

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
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": raw_headers,
        "client": (client_host, 12345),
        "server": ("test", 80),
        "scheme": "http",
    }
    return Request(scope)


def test_reject_forbidden_scheme():
    with pytest.raises(exc.InvalidRequestError, match="scheme"):
        network.reject_private_url("ftp://example.com")
    with pytest.raises(exc.InvalidRequestError, match="scheme"):
        network.reject_private_url("file:///etc/passwd")


def test_require_https_url_accepts_https():
    # https passes with no DNS resolution or private-address check, so it is
    # safe for the browser-facing authorization endpoint (which may be a
    # private/self-hosted host).
    network.require_https_url("https://idp.example.com/authorize")


def test_require_https_url_rejects_http():
    with pytest.raises(exc.InvalidRequestError, match="HTTPS"):
        network.require_https_url("http://idp.example.com/authorize")


def test_reject_private_url_require_https_rejects_http_scheme():
    # The https requirement is enforced at the scheme check, before any DNS
    # resolution, so an http:// IdP endpoint is refused outright.
    with pytest.raises(exc.InvalidRequestError, match="HTTPS"):
        network.reject_private_url("http://idp.example.com/token", require_https=True)


def test_reject_missing_hostname():
    with pytest.raises(exc.InvalidRequestError, match="hostname"):
        network.reject_private_url("http://")


def test_reject_loopback():
    with pytest.raises(exc.InvalidRequestError, match="non-public"):
        network.reject_private_url("http://127.0.0.1/token")


def test_reject_private_range():
    with pytest.raises(exc.InvalidRequestError, match="non-public"):
        network.reject_private_url("http://10.0.0.5")
    with pytest.raises(exc.InvalidRequestError, match="non-public"):
        network.reject_private_url("http://169.254.169.254/latest/meta-data")


def test_ipv4_mapped_ipv6_is_classified_by_embedded_address():
    # ::ffff:a.b.c.d must be classified by its embedded IPv4 address so a mapped
    # metadata/loopback/private literal is caught even on Python 3.12.0-3.12.3,
    # where ipaddress does not decompose it inside is_private/is_global (the OS
    # still routes it to the embedded IPv4 target).
    assert network._is_private_or_reserved(ipaddress.ip_address("::ffff:169.254.169.254")) is True
    assert network._is_private_or_reserved(ipaddress.ip_address("::ffff:127.0.0.1")) is True
    assert network._is_private_or_reserved(ipaddress.ip_address("::ffff:10.0.0.5")) is True
    # A genuinely public mapped address is not over-rejected, and normal public
    # IPv6 is unaffected.
    assert network._is_private_or_reserved(ipaddress.ip_address("::ffff:93.184.216.34")) is False
    assert network._is_private_or_reserved(ipaddress.ip_address("2606:4700:4700::1111")) is False


def test_get_ip_address_honours_xff_when_peer_trusted():
    # With a trust-all proxy list, XFF is honoured for any peer.
    with _settings(trusted_proxies=("*",)):
        req = _request("203.0.113.1", {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
        assert network.get_ip_address(req) == "1.2.3.4"


def test_get_ip_address_uses_real_ip_header():
    with _settings(trusted_proxies=("*",)):
        req = _request("203.0.113.1", {"X-Real-IP": "9.9.9.9"})
        assert network.get_ip_address(req) == "9.9.9.9"


def test_get_ip_address_ignores_proxy_headers_by_default():
    # The safe default (trusted_proxies=()) trusts only the direct peer, so a
    # spoofed X-Forwarded-For from an arbitrary client is ignored.
    req = _request("203.0.113.1", {"X-Forwarded-For": "1.2.3.4"})
    assert network.get_ip_address(req) == "203.0.113.1"


def test_get_ip_address_falls_back_to_peer():
    req = _request("203.0.113.9")
    assert network.get_ip_address(req) == "203.0.113.9"


def test_get_ip_address_unknown_when_no_client():
    scope = {"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": [], "scheme": "http"}
    assert network.get_ip_address(Request(scope)) == "unknown"


# --------------------------------------------------------------------------- #
# X-Forwarded-For spoofing
#
# A proxy configured the usual way (nginx's proxy_add_x_forwarded_for) APPENDS
# the peer it saw to whatever the client sent, so the leftmost element is
# attacker-controlled. The chain must be resolved right-to-left, skipping known
# infrastructure, or a caller could pick its own apparent source IP and evade the
# per-IP login lockout and the rate limiter.
# --------------------------------------------------------------------------- #


def test_spoofed_leftmost_xff_entry_is_ignored():
    # Client sent "X-Forwarded-For: 1.2.3.4"; the proxy (203.0.113.1) appended
    # the address it actually observed (198.51.100.7).
    with _settings(trusted_proxies=("203.0.113.1",)):
        req = _request("203.0.113.1", {"X-Forwarded-For": "1.2.3.4, 198.51.100.7"})
        assert network.get_ip_address(req) == "198.51.100.7"


def test_spoofed_xff_cannot_vary_the_resolved_ip():
    # Whatever the client prepends, the resolved IP is stable — otherwise the
    # per-IP lockout key could be rotated at will.
    with _settings(trusted_proxies=("203.0.113.1",)):
        for forged in ("9.9.9.9", "8.8.8.8, 7.7.7.7", "unknown", ""):
            header = f"{forged}, 198.51.100.7" if forged else "198.51.100.7"
            req = _request("203.0.113.1", {"X-Forwarded-For": header})
            assert network.get_ip_address(req) == "198.51.100.7"


def test_multi_hop_chain_skips_every_listed_proxy():
    # CDN edge (198.51.100.0/24) → reverse proxy (203.0.113.1) → app. Both hops
    # are infrastructure, so the client is the rightmost address that is not.
    with _settings(trusted_proxies=("203.0.113.1", "198.51.100.0/24")):
        req = _request("203.0.113.1", {"X-Forwarded-For": "1.2.3.4, 192.0.2.55, 198.51.100.7"})
        assert network.get_ip_address(req) == "192.0.2.55"


def test_unlisted_intermediate_hop_stops_the_walk():
    # Only the direct proxy is listed, so the walk stops at the hop it appended.
    with _settings(trusted_proxies=("203.0.113.1",)):
        req = _request("203.0.113.1", {"X-Forwarded-For": "1.2.3.4, 192.0.2.55, 198.51.100.7"})
        assert network.get_ip_address(req) == "198.51.100.7"


def test_xff_hop_with_port_is_normalized():
    with _settings(trusted_proxies=("203.0.113.1",)):
        req = _request("203.0.113.1", {"X-Forwarded-For": "198.51.100.7:41234"})
        assert network.get_ip_address(req) == "198.51.100.7"


def test_bracketed_ipv6_hop_is_normalized():
    with _settings(trusted_proxies=("203.0.113.1",)):
        req = _request("203.0.113.1", {"X-Forwarded-For": "[2001:db8::1]:8080"})
        assert network.get_ip_address(req) == "2001:db8::1"


def test_non_ip_xff_hops_are_skipped():
    # RFC 7239 obfuscated identifiers and junk must never reach a lockout key.
    with _settings(trusted_proxies=("203.0.113.1",)):
        req = _request("203.0.113.1", {"X-Forwarded-For": "_hidden, 198.51.100.7, unknown"})
        assert network.get_ip_address(req) == "198.51.100.7"


def test_wholly_unusable_xff_falls_back_to_peer():
    with _settings(trusted_proxies=("203.0.113.1",)):
        req = _request("203.0.113.1", {"X-Forwarded-For": "unknown, not-an-ip"})
        assert network.get_ip_address(req) == "203.0.113.1"


def test_all_hops_trusted_returns_leftmost():
    # trusted_proxies=("*",) asserts a trusted proxy always overwrites the
    # header, so there is no untrusted hop and the leftmost is the client.
    with _settings(trusted_proxies=("*",)):
        req = _request("203.0.113.1", {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
        assert network.get_ip_address(req) == "1.2.3.4"


def test_malformed_real_ip_falls_back_to_peer():
    with _settings(trusted_proxies=("203.0.113.1",)):
        req = _request("203.0.113.1", {"X-Real-IP": "not-an-ip"})
        assert network.get_ip_address(req) == "203.0.113.1"
