"""T-S4 tests: the shared URL guard at both urlopen call sites.

The timestamp submitter and the SCITT transparency client both use
``raucle.url_guard.validate_url`` before ``urlopen``. These tests pin:
scheme allow-list, private address classes, the explicit opt-in, and
that both call sites reject before any socket is opened.
"""

from __future__ import annotations

import hashlib

import pytest

from raucle.timestamp import build_timestamp_request, new_nonce, submit_timestamp_request
from raucle.transparency import SCITTAnchorClient
from raucle.url_guard import validate_url

_DIGEST = hashlib.sha256(b"ts4").digest()


@pytest.fixture
def block_private(monkeypatch):
    """Remove the suite-wide opt-in so the guard is active."""
    monkeypatch.delenv("RAUCLE_ALLOW_PRIVATE_URLS", raising=False)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8443/tsa",
        "https://localhost/tsa",
        "http://0.0.0.0/tsa",
        "http://10.0.0.1/tsa",
        "http://192.168.1.10/tsa",
        "http://172.16.0.9/tsa",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/tsa",
        "http://metadata.internal/tsa",
        "http://tsa.local/tsa",
        "https://240.0.0.1/tsa",
    ],
)
def test_validate_url_rejects_private_targets(url, block_private):
    """Loopback/link-local/RFC1918/CGNAT/reserved/named-private are all rejected."""
    with pytest.raises(ValueError, match="RAUCLE_ALLOW_PRIVATE_URLS"):
        validate_url(url)


@pytest.mark.parametrize(
    "url",
    ["https://8.8.8.8/x", "https://api.example.com/v1", "http://52.95.255.1:8443/v1"],
)
def test_validate_url_allows_public(url):
    assert validate_url(url, purpose="test") is None


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "ftp://example.com/tsa", "gopher://example.com", "data:text/plain,x"],
)
def test_validate_url_scheme_allowlist(url):
    with pytest.raises(ValueError, match="http"):
        validate_url(url, purpose="test")


def test_validate_url_userinfo_and_missing_host():
    with pytest.raises(ValueError, match="userinfo"):
        validate_url("https://user:pass@example.com/tsa")
    with pytest.raises(ValueError, match="no host"):
        validate_url("http:///path/only")


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_opt_in_allows_private(monkeypatch, value):
    monkeypatch.setenv("RAUCLE_ALLOW_PRIVATE_URLS", value)
    validate_url("http://127.0.0.1:9999/tsa")


# ---------------------------------------------------------------------------
# Call site 1: timestamp submitter
# ---------------------------------------------------------------------------


def test_timestamp_submit_rejects_file_scheme():
    with pytest.raises(ValueError, match="timestamp request"):
        submit_timestamp_request(
            "file:///etc/passwd", build_timestamp_request(_DIGEST, new_nonce())
        )


def test_timestamp_submit_rejects_loopback_before_socket(monkeypatch, block_private):
    """The guard rejects a loopback TSA URL before connect is even attempted."""

    def _boom(*a, **k):
        raise AssertionError("socket opened despite invalid URL")

    monkeypatch.setattr("raucle.timestamp.urllib.request.urlopen", _boom)
    with pytest.raises(ValueError, match="RAUCLE_ALLOW_PRIVATE_URLS"):
        submit_timestamp_request(
            "http://127.0.0.1:1/tsa", build_timestamp_request(_DIGEST, new_nonce())
        )


def test_timestamp_submit_allows_public(monkeypatch, block_private):
    """A public URL passes the guard; urlopen is reached with the request."""
    seen = {}

    def _fake_urlopen(req, *_a, **_k):
        seen["url"] = req.full_url
        raise OSError("stop here - guard already passed")

    monkeypatch.setattr("raucle.timestamp.urllib.request.urlopen", _fake_urlopen)
    with pytest.raises(OSError):
        submit_timestamp_request(
            "https://8.8.8.8/tsa", build_timestamp_request(_DIGEST, new_nonce()), timeout=0.2
        )
    assert seen["url"] == "https://8.8.8.8/tsa"


# ---------------------------------------------------------------------------
# Call site 2: SCITT transparency client
# ---------------------------------------------------------------------------


def test_transparency_client_rejects_private_service_url(monkeypatch, block_private):
    with pytest.raises(ValueError, match="RAUCLE_ALLOW_PRIVATE_URLS"):
        SCITTAnchorClient("http://127.0.0.1:9999")


def test_transparency_client_rejects_non_http_scheme():
    with pytest.raises(ValueError, match="http"):
        SCITTAnchorClient("file:///srv/registry.json")


def test_transparency_client_request_rejects_private_url(monkeypatch, block_private):
    """Location-header-derived URLs get the same guard at _request time."""
    block_private  # fixture already active
    client = SCITTAnchorClient("https://8.8.8.8")
    with pytest.raises(ValueError, match="RAUCLE_ALLOW_PRIVATE_URLS"):
        client._request("POST", "http://127.0.0.1:9999/entries", b"{}")
