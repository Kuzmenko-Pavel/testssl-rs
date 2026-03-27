# testssl-rs

A full-featured Rust port of [testssl.sh](https://github.com/testssl/testssl.sh) (branch 3.3dev) — the de-facto standard for TLS/SSL auditing, 9k+ GitHub stars.

## What is this?

`testssl-rs` implements **functional parity** with the original `testssl.sh` bash script (~25 000 lines) as a Rust workspace with three targets:

| Crate | Description |
|---|---|
| `testssl-core` | Library with all scanning logic |
| `testssl-bin` | Standalone CLI binary (statically linked) |
| `testssl-node` | NAPI-RS native Node.js addon |
| `testssl-py` | PyO3/maturin Python bindings |

## Features

### Protocol checks
- SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3
- Actual version negotiation verification (not just connection success)

### Cipher enumeration
- All **372 cipher suites** from `etc/cipher-mapping.txt` (OpenSSL ↔ IANA mapping)
- Efficient O(n) algorithm: send all ciphers → server picks one → remove → repeat
- Categories: NULL, aNULL, EXPORT, LOW, 3DES/SWEET32, RC4, STRONG, PFS

### Vulnerability checks (17 total)
| CVE | Check |
|---|---|
| CVE-2014-0160 | Heartbleed |
| CVE-2014-0224 | CCS Injection |
| CVE-2019-1559 | ROBOT (Return Of Bleichenbacher's Oracle Threat) |
| CVE-2014-3566 | POODLE (SSLv3) |
| RFC 7507 | TLS_FALLBACK_SCSV |
| CVE-2016-2183 | SWEET32 (3DES/Blowfish) |
| CVE-2015-0204 | FREAK |
| CVE-2016-0800 | DROWN |
| CVE-2015-4000 | Logjam |
| CVE-2011-3389 | BEAST |
| CVE-2013-0169 | Lucky13 |
| CVE-2012-4929 | CRIME |
| — | BREACH |
| — | RC4 |
| CVE-2016-9244 | Ticketbleed |
| — | Secure Renegotiation |
| CVE-2014-6321 | WINSHOCK |

### Certificate analysis
- Chain completeness, expiry, self-signed detection
- Trust verification against **5 CA stores**: Mozilla, Microsoft, Apple, Java, Linux
- OCSP stapling, CRL, Must-Staple
- Certificate Transparency (SCT)
- Key type/size, signature algorithm
- SANs, wildcards

### HTTP security headers
- HSTS (max-age, includeSubDomains, preload)
- X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
- Content-Security-Policy, Referrer-Policy, Permissions-Policy
- Set-Cookie flags (Secure, HttpOnly, SameSite)
- Server / X-Powered-By information disclosure

### STARTTLS (12 protocols)
SMTP, LMTP, IMAP, POP3, FTP, LDAP, XMPP, XMPP-Server, PostgreSQL, MySQL, NNTP, Sieve, IRC

### Client simulation
173 browser/client profiles from `etc/client-simulation.txt` (Chrome, Firefox, Safari, IE, curl, OpenSSL, etc.)

### Rating
SSL Labs-compatible grading: A+ / A / B / C / D / F

---

## Architecture

```
testssl-rs/
├── Cargo.toml                        # workspace
├── Makefile                          # build targets
├── crates/
│   ├── testssl-core/                 # library crate
│   │   ├── build.rs                  # generates cipher/profile/CA data at compile time
│   │   └── src/
│   │       ├── tls/                  # raw TLS record layer (no rustls for handshake)
│   │       │   ├── socket.rs         # raw TCP socket
│   │       │   ├── client_hello.rs   # wire-format ClientHello builder
│   │       │   ├── server_hello.rs   # ServerHello parser
│   │       │   ├── sslv2.rs          # SSLv2 (DROWN)
│   │       │   └── extensions.rs     # all TLS extensions
│   │       ├── checks/               # all checks
│   │       │   ├── protocols.rs
│   │       │   ├── ciphers.rs        # O(n) cipher enumeration
│   │       │   ├── certificate.rs
│   │       │   ├── http_headers.rs
│   │       │   ├── server_defaults.rs
│   │       │   ├── server_preference.rs
│   │       │   ├── forward_secrecy.rs
│   │       │   ├── client_simulation.rs
│   │       │   ├── grease.rs
│   │       │   ├── rating.rs
│   │       │   └── vulnerabilities/  # 17 checks
│   │       ├── starttls/             # 8 STARTTLS protocols
│   │       ├── data/                 # embedded data (no runtime file I/O)
│   │       │   ├── cipher_mapping.rs # 372 ciphers (generated from etc/)
│   │       │   ├── client_profiles.rs# 173 profiles (generated from etc/)
│   │       │   ├── ca_stores.rs      # 5 CA bundles (embedded via build.rs)
│   │       │   └── tls_data.rs
│   │       ├── output/               # terminal, JSON, CSV, HTML
│   │       ├── scanner/              # orchestrator
│   │       └── dns.rs
│   ├── testssl-bin/                  # CLI binary
│   │   └── src/main.rs
│   ├── testssl-node/                 # Node.js native addon
│   │   ├── src/lib.rs                # NAPI-RS bindings
│   │   ├── build.rs
│   │   └── package.json
│   └── testssl-py/                   # Python bindings
│       ├── src/lib.rs                # PyO3 bindings
│       ├── pyproject.toml            # maturin config + pytest
│       ├── python/testssl_py/        # Python package stub
│       └── tests/                    # pytest unit + integration tests
└── tmp_rep_origin_testssl/           # testssl.sh 3.3dev (reference)
```

### Key design decisions

1. **Raw TLS handshake** — `rustls` / `tokio-tls` are NOT used for the main handshake path.
   The tool builds ClientHello bytes manually (like the original `testssl.sh` does via `/dev/tcp`).
   This is required to test legacy/broken ciphers that modern TLS libraries refuse to send.

2. **SSLv2** — implemented via raw sockets only. No modern library supports it.

3. **All data embedded** — cipher suites, CA bundles, client profiles are compiled into the binary
   via `build.rs` + `include_bytes!` / `include!`. No runtime file access needed.

4. **Async throughout** — `tokio` runtime, all checks are `async fn`.

---

## Prerequisites

### CLI (testssl binary)

- **Rust** stable 1.70+ — [rustup.rs](https://rustup.rs/):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  rustc --version   # rustc 1.70.0 or newer
  ```
- **make** — [gnu.org/software/make](https://www.gnu.org/software/make/):
  ```bash
  apt install make       # Linux (Debian/Ubuntu)
  brew install make      # macOS
  ```

### Node.js bindings (`testssl-node`)

In addition to CLI prerequisites:

- **Node.js** 18+ — [nodejs.org](https://nodejs.org/)
- **@napi-rs/cli** — native addon build tool:
  ```bash
  npm install -g @napi-rs/cli
  ```

### Python bindings (`testssl-py`)

In addition to CLI prerequisites:

- **Python** 3.8+ — [python.org](https://www.python.org/)
- **maturin** — PyO3 wheel builder ([maturin.rs](https://www.maturin.rs/)):
  ```bash
  pip install maturin
  maturin --version   # verify
  ```

### Development / Contributing

In addition to the relevant prerequisites above:

- **cargo-llvm-cov** — required for `make coverage`:
  ```bash
  rustup component add llvm-tools-preview   # LLVM libraries
  cargo install cargo-llvm-cov              # cargo subcommand
  cargo llvm-cov --version                  # verify
  ```
  > Both commands are needed: `llvm-tools-preview` provides the LLVM instrumentation libraries; `cargo-llvm-cov` is the cargo subcommand that drives them.

- **musl toolchain** — optional, only for `make build-static` (fully static Linux binary):
  ```bash
  rustup target add x86_64-unknown-linux-musl
  apt install musl-tools   # Linux only
  ```

- **GPG** — optional, only for `make version` (signed release tags):
  ```bash
  gpg --list-secret-keys   # verify a key is configured
  ```

---

## Installation

### Build from source

```bash
git clone <repo>
cd testssl-rs

# Debug build
cargo build

# Release build
cargo build --release

# Binary is at:
./target/release/testssl
```

### Static single binary (Linux)

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Build
make build-static

# Verify (should say "not a dynamic executable")
make check-static
```

---

## CLI Usage

### Basic scan

```bash
# Default scan: protocols + certificate (~15-20 sec, no network-heavy checks)
testssl example.com

# Specific port
testssl example.com:8443

# HTTPS URI
testssl https://example.com

# Full scan — all checks including ciphers, vulnerabilities, HTTP headers, rating
testssl -a example.com
```

### Protocol checks

```bash
testssl -p example.com          # all protocols
testssl --tls1_3 example.com    # only TLS 1.3
testssl --sslv2 example.com     # SSLv2 check
```

### Cipher enumeration

```bash
testssl -e example.com          # each cipher (-e)
testssl -E example.com          # ciphers per protocol (-E)
testssl -f example.com          # forward secrecy ciphers
```

### Vulnerability checks

```bash
testssl -U example.com          # all vulnerabilities
testssl --heartbleed example.com
testssl --robot example.com
testssl --poodle example.com
```

### Certificate

```bash
testssl -x example.com          # certificate info
```

### HTTP headers

```bash
testssl -h example.com
```

### STARTTLS

```bash
testssl -t smtp mail.example.com:25
testssl -t imap mail.example.com:143
testssl -t postgres db.example.com:5432
```

### Output formats

```bash
testssl --jsonfile results.json example.com
testssl --csvfile results.csv example.com
testssl --htmlfile results.html example.com
testssl --jsonfile-pretty example.com     # pretty JSON to stdout
```

### All CLI flags

```
Options:
  --sslv2 / --sslv3 / --tls1 / --tls1_1 / --tls1_2 / --tls1_3
  -p  --protocols          All protocols
  -S  --server-defaults    Server defaults (cert, session, etc.)
  -P  --server-preference  Server cipher preference order
  -x  --server-certificate Certificate details
  -e  --each-cipher        Enumerate all ciphers
  -E  --cipher-per-proto   Ciphers per protocol
  -f  --fs                 Forward secrecy
  -h  --headers            HTTP security headers
  -U  --vulnerable         All vulnerability checks
  -a  --all                Everything

  --heartbleed / --ccs-injection / --ticketbleed / --robot
  --poodle / --tls-fallback / --sweet32 / --beast / --lucky13
  --freak / --drown / --logjam / --breach / --crime / --rc4 / --winshock

  -t  --starttls <proto>   smtp|lmtp|imap|pop3|ftp|ldap|xmpp|xmpp-server|postgres|mysql|nntp|sieve|irc
      --sni-name <name>    Override SNI
      --ip <ip>            Specific IP
      --timeout <secs>     Timeout (default: 10)
  -q  --quiet
  -w  --wide
      --color 0|1|2
      --jsonfile / --csvfile / --htmlfile / --logfile <file>
      --jsonfile-pretty
      --debug
      --rating
      --grease
      --client-simulation
      --parallel
      --fast
```

---

## Node.js API

### Installation

```bash
cd crates/testssl-node

# Requires @napi-rs/cli
npm install -g @napi-rs/cli

npm install
npm run build
```

### Usage

```typescript
import { TlsScanner } from 'testssl-node';

const scanner = new TlsScanner();

// Full scan
const result = await scanner.scan('example.com:443', {
  checkProtocols: true,
  checkCiphers: true,
  checkVulnerabilities: true,
  checkCertificate: true,
  checkHttpHeaders: true,
  timeout: 10,
});

console.log(result.protocols);       // { ssl2: false, ssl3: false, tls13: true, ... }
console.log(result.vulnerabilities); // { heartbleed: { status: 'not_vulnerable', ... }, ... }
console.log(result.certificate);     // { cn: 'example.com', daysLeft: 120, ... }
console.log(result.rating);          // 'A+'

// Individual checks
const vulns = await scanner.checkVulnerabilities('example.com:443');
const cert  = await scanner.checkCertificate('example.com:443');
const ciphers = await scanner.enumerateCiphers('example.com:443');

// STARTTLS
const smtpResult = await scanner.scan('mail.example.com:25', {
  starttls: 'smtp',
  checkProtocols: true,
  checkVulnerabilities: true,
});

// Batch scanning
const results = await scanner.scanBatch([
  'host1.example.com:443',
  'host2.example.com:443',
]);
```

### TypeScript types

```typescript
interface ScanOptions {
  checkProtocols?: boolean;
  checkCiphers?: boolean;
  checkVulnerabilities?: boolean;
  checkCertificate?: boolean;
  checkHttpHeaders?: boolean;
  checkForwardSecrecy?: boolean;
  checkServerDefaults?: boolean;
  checkServerPreference?: boolean;
  checkClientSimulation?: boolean;
  checkGrease?: boolean;
  checkRating?: boolean;
  timeout?: number;          // seconds
  connectTimeout?: number;
  sni?: string;
  starttls?: 'smtp' | 'imap' | 'pop3' | 'ftp' | 'ldap' | 'xmpp' | 'postgres' | 'mysql';
  ipv6?: boolean;
  parallel?: number;
}

interface ScanResult {
  target: string;
  ip: string;
  rdns?: string;
  protocols?: ProtocolResults;
  vulnerabilities?: VulnerabilityReport;
  certificate?: CertificateReport;
  ciphers?: CipherResult[];
  httpHeaders?: HttpHeaderReport;
  rating?: string;            // 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
  scanDurationMs: number;
  errors: string[];
}
```

---

## Python API

### Installation

```bash
# From PyPI
pip install testssl-py

# Or build from source (requires Rust + maturin)
cd crates/testssl-py
pip install maturin
maturin develop          # dev install into current venv
# or: maturin build --release && pip install ../../target/wheels/testssl_py-*.whl
```

### Usage

```python
import asyncio
import testssl_py

scanner = testssl_py.TlsScanner()

# Full scan
async def main():
    opts = testssl_py.ScanOptions()
    opts.check_protocols = True
    opts.check_certificate = True
    opts.check_vulnerabilities = True
    opts.check_ciphers = True
    opts.check_http_headers = True
    opts.timeout = 30

    result = await scanner.scan("example.com:443", opts)
    print(result.protocols)       # ProtocolResults object
    print(result.certificate)     # CertificateReport object
    print(result.rating)          # 'A+', 'A', 'B', ...

    # Individual checks
    cert   = await scanner.check_certificate("example.com:443")
    vulns  = await scanner.check_vulnerabilities("example.com:443")

    # Batch scanning
    results = await scanner.scan_batch(["host1.com:443", "host2.com:443"], opts)

asyncio.run(main())
```

### Quick helpers

```python
# Parse a target string → [host, port]
host, port = testssl_py.parse_target("https://example.com:8443/path")
# → ["example.com", "8443"]

# Library version
print(testssl_py.version())
```

### ScanOptions fields

| Field | Type | Default | Description |
|---|---|---|---|
| `check_protocols` | bool | False | SSLv2/3, TLS 1.0–1.3 |
| `check_certificate` | bool | False | Chain, expiry, SANs, key type |
| `check_vulnerabilities` | bool | False | All 17 CVE checks |
| `check_ciphers` | bool | False | 372 cipher enumeration |
| `check_http_headers` | bool | False | HSTS, CSP, etc. |
| `check_rating` | bool | False | SSL Labs-compatible grade |
| `timeout` | int | 10 | Per-check timeout (seconds) |
| `connect_timeout` | int | 5 | TCP connect timeout (seconds) |
| `sni` | str \| None | None | Override SNI hostname |
| `ipv6` | bool | False | Prefer IPv6 |
| `parallel` | int | 1 | Parallel check workers |

---

## Development Guide

### Getting started

```bash
git clone <repo> && cd testssl-rs

# 1. Verify tools (see Prerequisites above)
rustc --version && cargo --version && make --version

# 2. Build and verify
make build-release
make smoke-test

# 3. Run unit tests — no network, ~3 seconds
make test-unit
```

### Local `.env` for integration tests

```bash
# Create .env (already in .gitignore — never committed)
echo "TESTSSL_INTEGRATION=1" >> .env

# Now integration tests work without passing the variable each time:
make test-integration
# instead of: TESTSSL_INTEGRATION=1 make test-integration
```

The Makefile picks up `.env` automatically via `-include .env` + `.EXPORT_ALL_VARIABLES`.

### Running tests

| Command | Requires pre-build | Network |
|---|---|---|
| `make test-unit` | — | no |
| `make test-integration` | — | yes (badssl.com) |
| `make test-node` | `make build-node-install` | no |
| `make test-integration-node` | `make build-node-install` | yes |
| `make test-py` | `make build-py-dev` | no |
| `make test-integration-py` | `make build-py-dev` | yes |
| `make test-all-unit` | node + py built | no |
| `make test-all-integration` | node + py built | yes |

### Coverage

```bash
# One-time setup (see Prerequisites → Development)
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov

# Generate lcov.info (uploaded to Codecov in CI)
make coverage

# HTML report for local browsing
cargo llvm-cov --html
xdg-open target/llvm-cov/html/index.html   # Linux
open target/llvm-cov/html/index.html        # macOS
```

### Lint & Format

```bash
make fmt          # auto-fix formatting
make fmt-check    # check only (same as CI)
make clippy       # clippy -D warnings
```

### Creating a release

```bash
# 1. Ensure everything is committed and tests pass
make test-unit

# 2. Create a signed tag interactively
make version
# Enter version e.g.: v0.2.0
# Creates Changelog-v0.2.0.txt and a signed annotated tag

# 3. Push the tag — triggers release.yml → GitHub Release + npm + PyPI
git push --tags
```

### Makefile reference

Full list with descriptions: `make help`. Key groups:

```bash
make build / build-release / build-static    # Rust binary builds
make build-node-install / build-py-dev       # native addon builds
make test-unit / test-node / test-py         # unit tests
make test-integration / test-all-*           # integration tests
make coverage                                # LLVM coverage → lcov.info
make fmt / fmt-check / clippy                # code quality
make version                                 # create release tag
```

### Cross-compilation targets

```bash
make build-static        # x86_64-unknown-linux-musl
make build-static-arm64  # aarch64-unknown-linux-musl
make build-macos-x64     # x86_64-apple-darwin
make build-macos-arm64   # aarch64-apple-darwin
```

---

## Comparison with testssl.sh

| Feature | testssl.sh | testssl-rs |
|---|---|---|
| Language | bash + openssl | Rust |
| Single binary | No (requires openssl, bash) | Yes (statically linked) |
| Node.js API | No | Yes (NAPI-RS) |
| Python API | No | Yes (PyO3/maturin) |
| Performance | Sequential | Async + parallel |
| SSLv2 check | Yes | Yes |
| DROWN | Yes | Yes |
| All 17 CVE checks | Yes | Yes |
| 372 cipher suites | Yes | Yes |
| 173 client profiles | Yes | Yes |
| 5 CA stores | Yes | Yes |
| STARTTLS protocols | 12 | 12 |
| Output formats | terminal, JSON, CSV, HTML | terminal, JSON, CSV, HTML |

---

## License

AGPL-3.0 — same as the original [testssl.sh](https://github.com/testssl/testssl.sh).

## Credits

This project is a Rust port of [testssl.sh](https://github.com/testssl/testssl.sh) by Dirk Wetter and contributors.
All TLS testing logic, cipher lists, vulnerability checks, client simulation data, and CA bundles
are derived from or compatible with the original testssl.sh 3.3dev.
