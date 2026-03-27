"""Integration tests for testssl_py — requires network + TESTSSL_INTEGRATION=1.

Run with:
    TESTSSL_INTEGRATION=1 pytest tests/test_integration.py
"""

import pytest

try:
    import testssl_py

    NATIVE_AVAILABLE = True
except ImportError:
    NATIVE_AVAILABLE = False

pytestmark = [
    pytest.mark.skipif(
        not NATIVE_AVAILABLE, reason="testssl_py not installed"
    ),
    pytest.mark.asyncio,
]


# ── Scanner fixture ───────────────────────────────────────────────────────────


@pytest.fixture
def scanner():
    return testssl_py.TlsScanner()


def minimal_opts(**kwargs) -> testssl_py.ScanOptions:
    opts = testssl_py.ScanOptions()
    opts.check_protocols = kwargs.get("check_protocols", False)
    opts.check_certificate = kwargs.get("check_certificate", False)
    opts.check_vulnerabilities = kwargs.get("check_vulnerabilities", False)
    opts.check_ciphers = kwargs.get("check_ciphers", False)
    opts.check_http_headers = kwargs.get("check_http_headers", False)
    opts.check_rating = kwargs.get("check_rating", False)
    opts.timeout = kwargs.get("timeout", 30)
    return opts


# ── Protocol tests ────────────────────────────────────────────────────────────


async def test_tls12_offered_on_badssl(integration, scanner):
    opts = minimal_opts(check_protocols=True)
    result = await scanner.scan("badssl.com:443", opts)
    assert result.protocols is not None
    assert result.protocols.tls12 is True
    assert result.protocols.ssl2 is False


async def test_tls10_server_detected(integration, scanner):
    opts = minimal_opts(check_protocols=True)
    result = await scanner.scan("tls-v1-0.badssl.com:1010", opts)
    assert result.protocols is not None
    assert result.protocols.tls10 is True


async def test_tls11_server_detected(integration, scanner):
    opts = minimal_opts(check_protocols=True)
    result = await scanner.scan("tls-v1-1.badssl.com:1011", opts)
    assert result.protocols is not None
    assert result.protocols.tls11 is True


# ── Certificate tests ─────────────────────────────────────────────────────────


async def test_certificate_valid(integration, scanner):
    cert = await scanner.check_certificate("badssl.com:443")
    assert not cert.expired
    assert not cert.self_signed
    assert cert.days_left > 0
    assert len(cert.fingerprint_sha256) == 64


async def test_certificate_expired_detected(integration, scanner):
    cert = await scanner.check_certificate("expired.badssl.com:443")
    assert cert.expired, "expired.badssl.com must be detected as expired"


async def test_certificate_self_signed_detected(integration, scanner):
    cert = await scanner.check_certificate("self-signed.badssl.com:443")
    assert cert.self_signed, "self-signed.badssl.com must be detected as self-signed"


async def test_certificate_rsa2048(integration, scanner):
    cert = await scanner.check_certificate("rsa2048.badssl.com:443")
    assert cert.key_type == "RSA"
    assert cert.key_bits == 2048


async def test_certificate_rsa4096(integration, scanner):
    cert = await scanner.check_certificate("rsa4096.badssl.com:443")
    assert cert.key_type == "RSA"
    assert cert.key_bits == 4096


async def test_certificate_ecc256(integration, scanner):
    cert = await scanner.check_certificate("ecc256.badssl.com:443")
    assert cert.key_type == "EC"
    assert cert.key_bits == 256


async def test_certificate_sha256_signature_name(integration, scanner):
    """After OID fix: should show 'sha256WithRSAEncryption', not '1.2.840.113549.1.1.11'."""
    cert = await scanner.check_certificate("sha256.badssl.com:443")
    assert "sha256" in cert.signature_algorithm.lower(), (
        f"Expected sha256 in signature_algorithm, got: {cert.signature_algorithm!r}"
    )
    assert "." not in cert.signature_algorithm.split("With")[0], (
        f"Should not show raw OID, got: {cert.signature_algorithm!r}"
    )


# ── Vulnerability tests ───────────────────────────────────────────────────────


async def test_critical_vulns_not_present_on_badssl(integration, scanner):
    report = await scanner.check_vulnerabilities("badssl.com:443")
    assert report is not None

    critical = ["heartbleed", "ccs_injection", "poodle", "drown", "robot"]
    for name in critical:
        vuln = getattr(report, name, None)
        if vuln is not None:
            assert vuln.status != "VULNERABLE", (
                f"badssl.com must not be vulnerable to {name}"
            )


async def test_rc4_vulnerable_on_rc4_server(integration, scanner):
    report = await scanner.check_vulnerabilities("rc4.badssl.com:443")
    assert report.rc4 is not None
    assert report.rc4.status == "VULNERABLE", (
        "rc4.badssl.com must be detected as RC4 vulnerable"
    )


# ── HTTP headers tests ────────────────────────────────────────────────────────


async def test_hsts_present_on_hsts_server(integration, scanner):
    opts = minimal_opts(check_http_headers=True)
    result = await scanner.scan("hsts.badssl.com:443", opts)
    assert result.http_headers is not None
    assert result.http_headers.hsts is not None, "hsts.badssl.com must have HSTS header"
    assert result.http_headers.hsts_max_age is not None
    assert result.http_headers.hsts_max_age > 0


# ── Batch scan ────────────────────────────────────────────────────────────────


async def test_scan_batch(integration, scanner):
    opts = minimal_opts(check_protocols=True)
    results = await scanner.scan_batch(
        ["badssl.com:443", "expired.badssl.com:443"], opts
    )
    assert len(results) == 2
    assert results[0].protocols is not None
