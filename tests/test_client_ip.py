"""Covers utils/client_ip.get_client_ip - the value that keys the per-IP auth
rate limits. Getting this wrong is not cosmetic: behind the Next.js proxy
every caller shares the proxy's address, so a bucket keyed on
`request.client.host` would lock out the entire user base at once."""

from types import SimpleNamespace

import pytest

from utils import client_ip


def make_request(headers=None, host="10.0.0.1"):
    return SimpleNamespace(headers=headers or {}, client=SimpleNamespace(host=host) if host else None)


@pytest.fixture
def untrusted(monkeypatch):
    monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)


@pytest.fixture
def trusted(monkeypatch):
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "TRUE")


def test_untrusted_ignores_forwarded_headers(untrusted):
    """Default posture: a caller cannot choose its own rate-limit bucket."""
    request = make_request({"x-client-ip": "1.2.3.4", "x-forwarded-for": "5.6.7.8"})

    assert client_ip.get_client_ip(request) == "10.0.0.1"


def test_trusted_prefers_x_client_ip(trusted):
    request = make_request({"x-client-ip": "1.2.3.4", "x-forwarded-for": "5.6.7.8"})

    assert client_ip.get_client_ip(request) == "1.2.3.4"


def test_trusted_takes_leftmost_forwarded_for(trusted):
    request = make_request({"x-forwarded-for": "1.2.3.4, 5.6.7.8, 9.9.9.9"})

    assert client_ip.get_client_ip(request) == "1.2.3.4"


def test_trusted_falls_back_to_x_real_ip(trusted):
    request = make_request({"x-real-ip": "1.2.3.4"})

    assert client_ip.get_client_ip(request) == "1.2.3.4"


def test_trusted_falls_back_to_socket_peer(trusted):
    assert client_ip.get_client_ip(make_request()) == "10.0.0.1"


def test_blank_header_is_not_used(trusted):
    """An empty forwarded value must not produce an empty bucket key that all
    such callers would share."""
    request = make_request({"x-client-ip": "  ", "x-forwarded-for": "1.2.3.4"})

    assert client_ip.get_client_ip(request) == "1.2.3.4"


def test_missing_client_returns_none(trusted):
    assert client_ip.get_client_ip(make_request(host=None)) is None


def test_separate_clients_get_separate_buckets(trusted):
    """The point of the whole helper: two callers behind one proxy must not
    collapse into the same rate-limit identity."""
    a = client_ip.get_client_ip(make_request({"x-client-ip": "1.2.3.4"}))
    b = client_ip.get_client_ip(make_request({"x-client-ip": "5.6.7.8"}))

    assert a != b
