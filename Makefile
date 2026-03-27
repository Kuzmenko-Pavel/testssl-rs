-include .env
export

GIT_STAMP ?= $(shell git describe 2>/dev/null || echo v0.1.0)

# colors
GREEN  = $(shell tput -Txterm setaf 2)
YELLOW = $(shell tput -Txterm setaf 3)
WHITE  = $(shell tput -Txterm setaf 7)
RESET  = $(shell tput -Txterm sgr0)
GRAY   = $(shell tput -Txterm setaf 6)
TARGET_MAX_CHAR_NUM = 30

.EXPORT_ALL_VARIABLES:

.DEFAULT_GOAL := help


# ── Build ─────────────────────────────────────────────────────────────────────

.PHONY: build
## Debug build (full workspace) | Build
build:
	cargo build

.PHONY: build-release
## Release binary (testssl-bin)
build-release:
	cargo build --release -p testssl-bin

.PHONY: build-static
## Static musl binary — Linux (rustup target add x86_64-unknown-linux-musl)
build-static:
	cargo build --release --target x86_64-unknown-linux-musl -p testssl-bin

.PHONY: build-static-arm64
## ARM64 static binary (rustup target add aarch64-unknown-linux-musl)
build-static-arm64:
	cargo build --release --target aarch64-unknown-linux-musl -p testssl-bin

.PHONY: build-macos-x64
## macOS x86_64 binary (run on macOS)
build-macos-x64:
	cargo build --release --target x86_64-apple-darwin -p testssl-bin

.PHONY: build-macos-arm64
## macOS arm64 binary (run on macOS)
build-macos-arm64:
	cargo build --release --target aarch64-apple-darwin -p testssl-bin

.PHONY: build-node-install
## Node.js addon — npm install + build (CI: fresh checkout)
build-node-install:
	cd crates/testssl-node && npm install && npm run build

.PHONY: build-node
## Node.js addon — build only (deps already installed)
build-node:
	cd crates/testssl-node && npm run build

.PHONY: build-node-debug
## Node.js addon — debug build
build-node-debug:
	cd crates/testssl-node && npm run build:debug

.PHONY: build-py
## Python wheel release (requires maturin: pip install maturin)
build-py:
	cd crates/testssl-py && maturin build --release

.PHONY: build-py-dev
## Python dev install into current virtualenv (CI + local dev)
build-py-dev:
	cd crates/testssl-py && maturin develop


# ── Test ──────────────────────────────────────────────────────────────────────

.PHONY: test
## All Rust tests | Test
test:
	cargo test --workspace

.PHONY: test-unit
## Rust unit tests — no network required (CI)
test-unit:
	cargo test -p testssl-core --test unit_tests
	cargo test --workspace --lib

.PHONY: test-integration
## Rust integration tests — requires network (TESTSSL_INTEGRATION=1)
test-integration:
	TESTSSL_INTEGRATION=1 cargo test -p testssl-core --test integration_tests

.PHONY: test-node
## Node.js unit tests (requires built addon: make build-node-install)
test-node:
	cd crates/testssl-node && npm test

.PHONY: test-integration-node
## Node.js integration tests — requires network
test-integration-node:
	cd crates/testssl-node && npm run test:integration

.PHONY: test-py
## Python unit tests (requires wheel: make build-py-dev)
test-py:
	cd crates/testssl-py && pytest tests/test_basic.py -v

.PHONY: test-integration-py
## Python integration tests — requires network
test-integration-py:
	cd crates/testssl-py && TESTSSL_INTEGRATION=1 pytest tests/test_integration.py -v

.PHONY: test-all-unit
## All unit tests: Rust + Node.js + Python
test-all-unit: test-unit test-node test-py

.PHONY: test-all-integration
## All integration tests: Rust + Node.js + Python
test-all-integration: test-integration test-integration-node test-integration-py

.PHONY: coverage
## Generate LLVM coverage → lcov.info (requires cargo-llvm-cov)
coverage:
	cargo llvm-cov --no-report -p testssl-core --test unit_tests
	cargo llvm-cov --no-report -p testssl-core --lib
	cargo llvm-cov report --lcov --output-path lcov.info


# ── Lint ──────────────────────────────────────────────────────────────────────

.PHONY: fmt-check
## Check formatting without changes (CI) | Lint
fmt-check:
	cargo fmt --all -- --check

.PHONY: fmt
## Auto-fix formatting
fmt:
	cargo fmt --all

.PHONY: clippy
## Run clippy with -D warnings
clippy:
	cargo clippy --workspace --all-targets -- -D warnings


# ── Dev ───────────────────────────────────────────────────────────────────────

.PHONY: check
## cargo check --workspace | Dev
check:
	cargo check --workspace

.PHONY: smoke-test
## Quick binary sanity check
smoke-test: build-release
	./target/release/testssl --version
	./target/release/testssl --help

.PHONY: check-static
## Verify static linking of musl binary
check-static: build-static
	@echo "=== Binary info ==="
	@file target/x86_64-unknown-linux-musl/release/testssl
	@echo "=== ldd (should be 'not a dynamic executable') ==="
	@ldd target/x86_64-unknown-linux-musl/release/testssl || true
	@echo "=== Size ==="
	@du -sh target/x86_64-unknown-linux-musl/release/testssl

.PHONY: install
## Install binary to ~/.local/bin/testssl-rs
install: build-release
	cp target/release/testssl ~/.local/bin/testssl-rs

.PHONY: clean
## Clean all build artifacts
clean:
	cargo clean


# ── Release ───────────────────────────────────────────────────────────────────

.PHONY: version
## Create signed git tag with auto-generated changelog | Release
version: check-git-clean
	$(eval GIT_TAG ?= $(shell git describe --abbrev=0 2>/dev/null || echo "none"))
	$(eval VERSION ?= $(shell read -p "Version (previous: $(GIT_TAG)): " VERSION; echo $$VERSION))
	echo "Tagged release $(VERSION)\n" > Changelog-$(VERSION).txt
	git log --no-decorate --no-merges --format="%h %s%n%w(0,8,8)%b%n" $(GIT_TAG)..HEAD >> Changelog-$(VERSION).txt
	git tag -s -a -e -F Changelog-$(VERSION).txt $(VERSION)

.PHONY: check-git-clean
## Verify git working tree is clean before tagging
check-git-clean:
	@status=$$(git status --porcelain); \
	if [ ! -z "$${status}" ]; then \
	    echo "${YELLOW}There are uncommitted changes. Commit before tagging.${RESET}"; \
	    exit 1; \
	fi


# ── Help ──────────────────────────────────────────────────────────────────────

.PHONY: help
## Show this help | Help
help:
	@echo ''
	@echo 'Usage:'
	@echo ''
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk '/^[a-zA-Z\-_]+:/ { \
	    helpMessage = match(lastLine, /^## (.*)/); \
	    if (helpMessage) { \
	        if (index(lastLine, "|") != 0) { \
	            stage = substr(lastLine, index(lastLine, "|") + 1); \
	            printf "\n ${GRAY}%s: \n\n", stage;  \
	        } \
	        helpCommand = substr($$1, 0, index($$1, ":")-1); \
	        helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
	        if (index(lastLine, "|") != 0) { \
	            helpMessage = substr(helpMessage, 0, index(helpMessage, "|")-1); \
	        } \
	        printf "  ${YELLOW}%-$(TARGET_MAX_CHAR_NUM)s${RESET} ${GREEN}%s${RESET}\n", helpCommand, helpMessage; \
	    } \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)
	@echo ''
