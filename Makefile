# Test entry points of the tpm-rs workspace (the verification list of AGENTS.md).
#
#   make test               the full suite: every target below
#   make test-workspace     `cargo test --release` (BoringSSL backend)
#   make test-reference-rng the tpm2-impl tests with the reference RNG port
#   make test-backends      the crypto backend tests (Rust and Crux)
#   make test-differential  the differential tests, one run per target
#   make test-<target>      the differential tests against one target (see DIFFERENTIAL_TARGETS)
#   make test-inproc        the in-process reference tests (`fuzz-inproc`)
#   make lint               fmt, clippy (also of every differential target and
#                           without SHA-512) and docs
#
# Every test runs with `--release` (AGENTS.md, "Build Profile Guideline").
#
# A differential run builds `testing` with one `target-*` feature: tpm-rs gets
# the profile of that C reference TPM (its `tpm2`/`tpm2-impl` features, see
# testing/Cargo.toml) and every E2E and Go parity test is compared with it.
# `mstpm20-v185` needs access to the TCG-internal TPM-Internal repository;
# without it, run e.g. `make test DIFFERENTIAL_TARGETS="mstpm20 ibmswtpm2"`.
#
# BoringSSL is built by `bssl-sys` (cmake, ninja, bindgen and libclang are
# needed; set BORINGSSL_BUILD_DIR to reuse a build), and the C references need
# git, a C compiler, OpenSSL's libcrypto.a and libclang (see testing/build.rs).

CARGO ?= cargo
# The differential targets: the `target-*` features of `testing`.
DIFFERENTIAL_TARGETS ?= mstpm20 mstpm20-v185 ibmswtpm2
# The target of the in-process reference tests.
INPROC_TARGET ?= mstpm20
# Extra arguments for every `cargo test` (e.g. CARGO_TEST_ARGS="--no-fail-fast").
CARGO_TEST_ARGS ?=

DIFFERENTIAL_TESTS := $(addprefix test-,$(DIFFERENTIAL_TARGETS))
DIFFERENTIAL_CLIPPY := $(addprefix clippy-,$(DIFFERENTIAL_TARGETS))

.PHONY: test test-workspace test-reference-rng test-backends test-differential \
	$(DIFFERENTIAL_TESTS) test-inproc lint fmt clippy $(DIFFERENTIAL_CLIPPY) doc

test: test-workspace test-reference-rng test-backends test-differential test-inproc

test-workspace:
	$(CARGO) test --release $(CARGO_TEST_ARGS)

test-reference-rng:
	$(CARGO) test --release -p tpm2-impl --features reference-rng $(CARGO_TEST_ARGS)

# The crates that support other crypto backends (AGENTS.md, "Testing Different
# Cryptographic Backends"); `testing` supports only BoringSSL.
test-backends:
	$(CARGO) test --release -p tpm2-crypto-tests --no-default-features --features rust,sha512 $(CARGO_TEST_ARGS)
	$(CARGO) test --release -p tpm2-crypto-tests --no-default-features --features crux,sha512 $(CARGO_TEST_ARGS)
	$(CARGO) test --release -p tpm2-impl --no-default-features --features dev_crypto_rust,sha512 $(CARGO_TEST_ARGS)
	$(CARGO) test --release -p tpm2-impl --no-default-features --features dev_crypto_crux,sha512 $(CARGO_TEST_ARGS)

# The targets run one after the other: each builds the tpm-rs stack with its
# own features into the same target directory (and the `reference` binary that
# its tests launch).
test-differential:
	@set -e; for target in $(DIFFERENTIAL_TARGETS); do \
		$(MAKE) --no-print-directory test-$$target; \
	done

$(DIFFERENTIAL_TESTS): test-%:
	$(CARGO) test --release -p testing --features target-$* $(CARGO_TEST_ARGS)

test-inproc:
	$(CARGO) test --release -p testing --features target-$(INPROC_TARGET),fuzz-inproc --lib inproc $(CARGO_TEST_ARGS)
	$(CARGO) test --release -p testing --features target-$(INPROC_TARGET),fuzz-inproc --test e2e reset_determinism $(CARGO_TEST_ARGS)

lint: fmt clippy doc

fmt:
	$(CARGO) fmt --all -- --check

clippy: $(DIFFERENTIAL_CLIPPY)
	$(CARGO) clippy --all-targets -- -D warnings
	$(CARGO) clippy --all-targets -p tpm2-impl --features reference-rng -- -D warnings
	# A TPM without SHA-512 (every crate without its default `sha512` feature).
	$(CARGO) clippy --all-targets -p tpm2-impl -p tpm2-crypto-rust -p tpm2-crypto-crux \
		-p tpm2-crypto-bssl -p tpm2-client --no-default-features \
		--features tpm2-impl/dev_crypto_bssl,tpm2-impl/reference-rng -- -D warnings

$(DIFFERENTIAL_CLIPPY): clippy-%:
	$(CARGO) clippy --all-targets -p testing --features target-$* -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps
