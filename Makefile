# Test entry points of the tpm-rs workspace (the verification list of AGENTS.md).
#
#   make test               the full suite: every target below
#   make test-workspace     `cargo test --release` (BoringSSL backend)
#   make test-reference-rng the tpm2-engine tests with the reference RNG port
#   make test-no-sha512     the tpm2-engine tests of a TPM without SHA-512
#   make test-backends      the crypto backend tests (Rust and Crux)
#   make test-differential  the differential tests, one run per target
#   make test-<target>      the differential tests against one target (see DIFFERENTIAL_TARGETS)
#   make test-inproc        the in-process reference tests (`fuzz-inproc`)
#   make test-features      tpm2-engine and the E2E tests with every optional feature
#   make lint               fmt, clippy (also of every differential target, with
#                           every optional feature, each optional feature alone
#                           and without SHA-512) and docs (tcgtpm is built without
#                           SHA-512, see TARGET_ARGS_tcgtpm)
#
# Every test runs with `--release` (AGENTS.md, "Build Profile Guideline").
#
# A differential run builds `testing` with one `target-*` feature: tpm-rs gets
# the profile of that C reference TPM (its `tpm2`/`tpm2-engine` features, see
# testing/Cargo.toml) and every E2E and Go parity test is compared with it.
# `tcgtpm-v185` needs access to the TCG-internal TPM-Internal repository;
# without it, run e.g. `make test DIFFERENTIAL_TARGETS="tcgtpm ibmswtpm2"`.
#
# BoringSSL is built by `bssl-sys` (cmake, ninja, bindgen and libclang are
# needed; set BORINGSSL_BUILD_DIR to reuse a build), and the C references need
# git, a C compiler, OpenSSL's libcrypto.a and libclang (see testing/build.rs).

CARGO ?= cargo
# The differential targets: the `target-*` features of `testing`.
DIFFERENTIAL_TARGETS ?= tcgtpm tcgtpm-v185 ibmswtpm2
# The target of the in-process reference tests.
INPROC_TARGET ?= tcgtpm
# Extra arguments for every `cargo test` (e.g. CARGO_TEST_ARGS="--no-fail-fast").
CARGO_TEST_ARGS ?=
# Extra `cargo` arguments of each target's build of `testing` (TARGET_ARGS_<target>).
# The public TCG reference has no SHA-512 upstream (`ALG_SHA512 NO`), so tpm-rs is
# built without its default `sha512` feature for it.
TARGET_ARGS_tcgtpm := --no-default-features

# The optional algorithm, command and setting features of tpm2-engine that `testing`
# forwards under the same names (testing/Cargo.toml). No target enables all of them
# (e.g. `camellia192`, `hash_mldsa`), so `test-features` and `clippy` also build
# tpm-rs with every one of them, and `clippy-features` with each one alone.
OPTIONAL_FEATURES := ecc_curve_nist_p192 ecc_curve_bn_p638 ecc_curve_sm2_p256 sm2 ecschnorr \
	rsa3072 rsa4096 camellia128 camellia192 camellia256 cmac ecmqv mlkem mldsa hash_mldsa \
	cc-ec-ephemeral cc-zgen-2phase cc-ecc-encrypt cc-ecc-decrypt \
	cc-policy-capability cc-policy-parameters cc-policy-physical-presence cc-pp-commands \
	cc-policy-ac-send-select cc-set-algorithm-set \
	cc-nv-define-space2 cc-nv-read-public2 cc-read-only-control vendor-permanent-auth \
	cc-sign-digest cc-verify-digest-signature cc-sign-sequence-start \
	cc-sign-sequence-complete cc-verify-sequence-start cc-verify-sequence-complete \
	cc-encapsulate cc-decapsulate sec-channel cc-policy-transport-spdm
comma := ,
empty :=
space := $(empty) $(empty)
ALL_OPTIONAL_FEATURES := $(subst $(space),$(comma),$(strip $(OPTIONAL_FEATURES)))

DIFFERENTIAL_TESTS := $(addprefix test-,$(DIFFERENTIAL_TARGETS))
DIFFERENTIAL_CLIPPY := $(addprefix clippy-,$(DIFFERENTIAL_TARGETS))

.PHONY: test test-workspace test-reference-rng test-no-sha512 test-backends test-differential \
	$(DIFFERENTIAL_TESTS) test-inproc test-features lint fmt clippy clippy-features \
	$(DIFFERENTIAL_CLIPPY) doc

test: test-workspace test-reference-rng test-no-sha512 test-backends test-differential test-inproc \
	test-features

test-workspace:
	$(CARGO) test --release $(CARGO_TEST_ARGS)

test-reference-rng:
	$(CARGO) test --release -p tpm2-engine --features reference-rng $(CARGO_TEST_ARGS)

# A TPM without SHA-512 (as the tcgtpm target), with and without the reference RNG.
test-no-sha512:
	$(CARGO) test --release -p tpm2-engine --no-default-features --features dev_crypto_bssl $(CARGO_TEST_ARGS)
	$(CARGO) test --release -p tpm2-engine --no-default-features --features dev_crypto_bssl,reference-rng $(CARGO_TEST_ARGS)

# The crates that support other crypto backends (AGENTS.md, "Testing Different
# Cryptographic Backends"); `testing` supports only BoringSSL.
test-backends:
	$(CARGO) test --release -p tpm2-crypto-tests --no-default-features --features rust,sha512 $(CARGO_TEST_ARGS)
	$(CARGO) test --release -p tpm2-crypto-tests --no-default-features --features crux,sha512 $(CARGO_TEST_ARGS)
	$(CARGO) test --release -p tpm2-engine --no-default-features --features dev_crypto_rust,sha512 $(CARGO_TEST_ARGS)
	$(CARGO) test --release -p tpm2-engine --no-default-features --features dev_crypto_crux,sha512 $(CARGO_TEST_ARGS)

# The targets run one after the other: each builds the tpm-rs stack with its
# own features into the same target directory (and the `reference` binary that
# its tests launch).
test-differential:
	@set -e; for target in $(DIFFERENTIAL_TARGETS); do \
		$(MAKE) --no-print-directory test-$$target; \
	done

$(DIFFERENTIAL_TESTS): test-%:
	$(CARGO) test --release -p testing $(TARGET_ARGS_$*) --features target-$* $(CARGO_TEST_ARGS)

test-inproc:
	$(CARGO) test --release -p testing $(TARGET_ARGS_$(INPROC_TARGET)) \
		--features target-$(INPROC_TARGET),fuzz-inproc --lib inproc $(CARGO_TEST_ARGS)
	$(CARGO) test --release -p testing $(TARGET_ARGS_$(INPROC_TARGET)) \
		--features target-$(INPROC_TARGET),fuzz-inproc --test e2e reset_determinism $(CARGO_TEST_ARGS)

test-features:
	$(CARGO) test --release -p tpm2-engine --features $(ALL_OPTIONAL_FEATURES) $(CARGO_TEST_ARGS)
	$(CARGO) test --release -p testing --features $(ALL_OPTIONAL_FEATURES) $(CARGO_TEST_ARGS)

lint: fmt clippy doc

fmt:
	$(CARGO) fmt --all -- --check

clippy: $(DIFFERENTIAL_CLIPPY) clippy-features
	$(CARGO) clippy --all-targets -- -D warnings
	$(CARGO) clippy --all-targets -p tpm2-engine -p testing --features $(ALL_OPTIONAL_FEATURES) -- -D warnings
	$(CARGO) clippy --all-targets -p tpm2-engine --features reference-rng -- -D warnings
	# A TPM without SHA-512 (every crate without its default `sha512` feature).
	$(CARGO) clippy --all-targets -p tpm2-engine -p tpm2-crypto-rust -p tpm2-crypto-crux \
		-p tpm2-crypto-bssl -p tpm2-client --no-default-features \
		--features tpm2-engine/dev_crypto_bssl,tpm2-engine/reference-rng -- -D warnings
	# `testing` without SHA-512 is `clippy-tcgtpm` (TARGET_ARGS_tcgtpm).

# Each optional feature alone (on a TPM without the other optional features and without
# `vendor-permanent-auth`, which the default features of tpm2-engine turn on).
clippy-features:
	@set -e; for feature in $(OPTIONAL_FEATURES); do \
		echo "clippy: tpm2-engine with $$feature"; \
		$(CARGO) clippy --all-targets -p tpm2-engine --no-default-features \
			--features dev_crypto_bssl,sha512,$$feature -- -D warnings; \
	done

$(DIFFERENTIAL_CLIPPY): clippy-%:
	$(CARGO) clippy --all-targets -p testing $(TARGET_ARGS_$*) --features target-$* -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps
