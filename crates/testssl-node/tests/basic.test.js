'use strict';

// Load native module if available (requires `npm run build` first).
// Tests are skipped if the native addon is not built.
let lib = null;
try {
  lib = require('..');
} catch (_) {
  // Native module not built
}

const itIf = (cond) => (cond ? it : it.skip);
const native = lib !== null;

describe('testssl-node (native)', () => {
  itIf(native)('version() returns a non-empty string', () => {
    const v = lib.version();
    expect(typeof v).toBe('string');
    expect(v.length).toBeGreaterThan(0);
  });

  itIf(native)('TlsScanner can be instantiated', () => {
    const scanner = new lib.TlsScanner();
    expect(scanner).toBeDefined();
  });

  itIf(native)('TlsScanner.version() returns a non-empty string', () => {
    const v = lib.TlsScanner.version();
    expect(typeof v).toBe('string');
    expect(v.length).toBeGreaterThan(0);
  });

  describe('parseTarget()', () => {
    itIf(native)('parses bare hostname — defaults to port 443', () => {
      const [host, port] = lib.parseTarget('example.com');
      expect(host).toBe('example.com');
      expect(port).toBe('443');
    });

    itIf(native)('parses host:port', () => {
      const [host, port] = lib.parseTarget('example.com:8443');
      expect(host).toBe('example.com');
      expect(port).toBe('8443');
    });

    itIf(native)('strips https:// scheme', () => {
      const [host, port] = lib.parseTarget('https://example.com/');
      expect(host).toBe('example.com');
      expect(port).toBe('443');
    });

    itIf(native)('parses https:// with custom port', () => {
      const [host, port] = lib.parseTarget('https://example.com:8443/path');
      expect(host).toBe('example.com');
      expect(port).toBe('8443');
    });

    itIf(native)('parses IPv6 address', () => {
      const [host, port] = lib.parseTarget('[::1]:443');
      expect(host).toBe('::1');
      expect(port).toBe('443');
    });

    itIf(native)('throws on invalid IPv6', () => {
      expect(() => lib.parseTarget('[::1')).toThrow();
    });
  });
});

describe('testssl-node native module availability', () => {
  it('reports build status', () => {
    if (!native) {
      console.warn(
        'Native module not built — run `npm run build` in crates/testssl-node to enable full tests'
      );
    }
    // This test always passes; it just reports the status
    expect(true).toBe(true);
  });
});
