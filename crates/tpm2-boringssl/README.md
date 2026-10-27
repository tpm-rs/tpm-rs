# tpm2-boringssl

[BoringSSL](https://boringssl.googlesource.com/boringssl) cryptography backend
for [`tpm2::crypto`](../tpm2/src/crypto/mod.rs).

This crate is `#![no_std]` and links BoringSSL's `libcrypto` statically.
Building it requires a local BoringSSL build and the environment variables
below. No other crate in the workspace depends on it (except optionally, via
the `boringssl` feature of the `testing-crypto` crate), so the rest of the
workspace builds without BoringSSL.

## Requirements

- A BoringSSL source tree.
- A BoringSSL CMake build directory configured with Rust bindings
  (`-DRUST_BINDINGS=<target-triple>`) and, recommended, a symbol prefix
  (`-DBORINGSSL_PREFIX=<prefix>`).
- [`bindgen`](https://github.com/rust-lang/rust-bindgen) (the CLI, e.g.
  `cargo install bindgen-cli`) on `PATH`, both for BoringSSL's CMake build and
  for this crate's `build.rs` (which generates bindings for BoringSSL's
  internal `bcm_interface.h` and `curve25519/internal.h` headers).
- A C++ runtime library (BoringSSL's `libcrypto` is written in C++).

## Building BoringSSL

```sh
git clone https://boringssl.googlesource.com/boringssl
cd boringssl
cmake -GNinja -B build \
    -DRUST_BINDINGS=x86_64-unknown-linux-gnu \
    -DBORINGSSL_PREFIX=BSSL
    # optionally: -DBINDGEN_EXECUTABLE=/path/to/bindgen
ninja -C build
```

Use your Rust target triple for `-DRUST_BINDINGS` (it must match the Cargo
target, e.g. `aarch64-apple-darwin`). The build directory then contains
`libcrypto.a` and `rust/bssl-sys/wrapper_<target>.rs`.

### Why the symbol prefix?

Tests compare this backend against `tpm2-openssl`, so the same test binary
links both BoringSSL and OpenSSL. Both libraries export the same C symbols
(`RSA_new`, `EVP_sha256`, ...), and without a prefix one library's calls
resolve to the other's implementation, which crashes (e.g. segfaults) due to
incompatible struct layouts. `-DBORINGSSL_PREFIX=BSSL` renames all of
BoringSSL's symbols (`BSSL_RSA_new`, ...); the generated bindings and this
crate's `build.rs` (which reads `BORINGSSL_PREFIX` from
`$BORINGSSL_BUILD_DIR/CMakeCache.txt`) handle the prefix automatically.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `BORINGSSL_SOURCE_DIR` | Yes | BoringSSL source tree (containing `include/` and `crypto/`). |
| `BORINGSSL_BUILD_DIR` | Yes | BoringSSL CMake build directory (see above). |
| `BINDGEN` | No | Path to the `bindgen` binary (default: `bindgen` on `PATH`). |
| `BORINGSSL_RUST_CPPLIB` | No | C++ runtime library to link (default: `c++` on macOS, `stdc++` on other Unix targets; empty to link none). |

`build.rs` fails with an error if a required variable is missing or invalid.

`build.rs` copies `libcrypto.a` into Cargo's `OUT_DIR` as
`libtpm2_bssl_crypto.a` and links that copy, rather than adding
`BORINGSSL_BUILD_DIR` as a library search path. This ensures binaries which
also link OpenSSL (`openssl-sys` emits `-lcrypto -lssl`) still find OpenSSL's
`libcrypto`, not BoringSSL's.

## Building and testing

```sh
export BORINGSSL_SOURCE_DIR=/path/to/boringssl
export BORINGSSL_BUILD_DIR=/path/to/boringssl/build

cargo build -p tpm2-boringssl
cargo build -p tpm2-boringssl --features non-fips
```

The tests live in the `testing-crypto` crate (`testing/crypto`), which runs the
shared backend test suite and interoperability tests against the other
backends:

```sh
cargo test -p testing-crypto --features boringssl
# Also test the `non-fips` algorithms:
cargo test -p testing-crypto --features boringssl-non-fips
```

## Cargo features

- `non-fips` (disabled by default): enables `Ed25519` and `X25519`, which are
  implemented outside BoringSSL's FIPS module.
