"""Unit-level tests for testssl_py Python bindings.

These tests verify the Python API surface: constructors, type contracts,
parse_target logic. No network access required.
"""

import pytest

try:
    import testssl_py

    NATIVE_AVAILABLE = True
except ImportError:
    NATIVE_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not NATIVE_AVAILABLE, reason="testssl_py not installed — run `maturin develop` first"
)


# ── Module-level functions ────────────────────────────────────────────────────


def test_version_returns_string():
    v = testssl_py.version()
    assert isinstance(v, str)
    assert len(v) > 0


# ── parse_target ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "uri, expected_host, expected_port",
    [
        ("example.com", "example.com", "443"),
        ("example.com:8443", "example.com", "8443"),
        ("https://example.com/", "example.com", "443"),
        ("https://example.com:8443/path", "example.com", "8443"),
        ("http://example.com/", "example.com", "443"),  # TLS scanner defaults to 443
        ("[::1]:443", "::1", "443"),
    ],
)
def test_parse_target(uri, expected_host, expected_port):
    result = testssl_py.parse_target(uri)
    assert result == [expected_host, expected_port], f"parse_target({uri!r}) = {result}"


def test_parse_target_invalid_ipv6_raises():
    with pytest.raises(Exception):
        testssl_py.parse_target("[::1")


# ── TlsScanner constructor ────────────────────────────────────────────────────


def test_tls_scanner_instantiates():
    scanner = testssl_py.TlsScanner()
    assert scanner is not None


def test_tls_scanner_version_static():
    v = testssl_py.TlsScanner.version()
    assert isinstance(v, str)
    assert len(v) > 0


def test_tls_scanner_repr():
    scanner = testssl_py.TlsScanner()
    r = repr(scanner)
    assert "TlsScanner" in r


# ── ScanOptions ───────────────────────────────────────────────────────────────


def test_scan_options_default():
    opts = testssl_py.ScanOptions()
    assert opts is not None


def test_scan_options_fields_settable():
    opts = testssl_py.ScanOptions()
    opts.check_protocols = True
    opts.check_certificate = True
    opts.check_vulnerabilities = False
    opts.check_ciphers = False
    opts.check_rating = True
    opts.timeout = 30
    opts.connect_timeout = 10
    opts.sni = "example.com"
    opts.ipv6 = False
    opts.parallel = 4

    assert opts.check_protocols is True
    assert opts.check_certificate is True
    assert opts.check_vulnerabilities is False
    assert opts.timeout == 30
    assert opts.sni == "example.com"
