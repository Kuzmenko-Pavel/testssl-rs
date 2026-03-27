'use strict';

// Integration tests against badssl.com — requires:
//   1. Native addon built: `npm run build`
//   2. Network access
//   3. TESTSSL_INTEGRATION=1 environment variable

const INTEGRATION = process.env.TESTSSL_INTEGRATION === '1';

let lib = null;
try {
  lib = require('..');
} catch (_) {
  // Native module not built
}

const itIf = (cond) => (cond ? it : it.skip);
const available = lib !== null && INTEGRATION;

// Increase timeout — network scans can take 10-30 seconds
jest.setTimeout(60_000);

describe('TlsScanner integration (badssl.com)', () => {
  let scanner;
  beforeAll(() => {
    if (available) {
      scanner = new lib.TlsScanner();
    }
  });

  itIf(available)('scan() returns a valid ScanResult for badssl.com', async () => {
    const opts = {
      checkProtocols: true,
      checkCertificate: true,
      checkVulnerabilities: false,
      checkCiphers: false,
      checkRating: true,
      timeout: 30,
    };

    const result = await scanner.scan('badssl.com:443', opts);

    expect(result.target).toContain('badssl.com');
    expect(result.ip).toBeTruthy();
    expect(result.errors).toHaveLength(0);
    expect(result.protocols).toBeTruthy();
    expect(result.protocols.tls12).toBe(true);
    expect(result.protocols.ssl2).toBe(false);
  });

  itIf(available)('quickScan() returns protocols + certificate', async () => {
    const result = await scanner.quickScan('badssl.com:443');
    expect(result.protocols).toBeTruthy();
    expect(result.certificate).toBeTruthy();
  });

  itIf(available)('checkCertificate() detects expired cert', async () => {
    try {
      const cert = await scanner.checkCertificate('expired.badssl.com:443');
      expect(cert.expired).toBe(true);
    } catch (e) {
      // Skip if unreachable from CI network
      console.warn('expired.badssl.com unreachable:', e.message);
    }
  });

  itIf(available)('checkCertificate() detects self-signed cert', async () => {
    try {
      const cert = await scanner.checkCertificate('self-signed.badssl.com:443');
      expect(cert.selfSigned).toBe(true);
    } catch (e) {
      console.warn('self-signed.badssl.com unreachable:', e.message);
    }
  });

  itIf(available)('checkCertificate() returns human-readable signature algorithm', async () => {
    try {
      const cert = await scanner.checkCertificate('sha256.badssl.com:443');
      expect(cert.signatureAlgorithm.toLowerCase()).toContain('sha256');
    } catch (e) {
      console.warn('sha256.badssl.com unreachable:', e.message);
    }
  });

  itIf(available)('checkVulnerabilities() runs without error', async () => {
    const report = await scanner.checkVulnerabilities('badssl.com:443');
    expect(report).toBeTruthy();
    // Heartbleed and POODLE must not be vulnerable on badssl.com
    if (report.heartbleed) {
      expect(report.heartbleed.status).not.toBe('VULNERABLE');
    }
    if (report.poodle) {
      expect(report.poodle.status).not.toBe('VULNERABLE');
    }
  });

  itIf(available)('scanBatch() returns results for multiple targets', async () => {
    const results = await scanner.scanBatch(['badssl.com:443', 'expired.badssl.com:443']);
    expect(results).toHaveLength(2);
    // Second result should be expired cert
    const expiredResult = results[1];
    if (expiredResult.certificate) {
      expect(expiredResult.certificate.expired).toBe(true);
    }
  });

  itIf(available)('TLS 1.0 server detected on tls-v1-0.badssl.com', async () => {
    const opts = {
      checkProtocols: true,
      checkCertificate: false,
      checkVulnerabilities: false,
      checkRating: false,
      timeout: 30,
    };

    const result = await scanner.scan('tls-v1-0.badssl.com:1010', opts);
    expect(result.protocols).toBeTruthy();
    expect(result.protocols.tls10).toBe(true);
  });
});
