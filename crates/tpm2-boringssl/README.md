# tpm2-boringssl

[BoringSSL](https://boringssl.googlesource.com/boringssl) cryptography backend
for [`tpm2::crypto`](../tpm2/src/crypto/mod.rs).

This crate is `#![no_std]`. Its build script builds BoringSSL's `libcrypto`
from source and links it statically, and generates bindings to BoringSSL's
public C API with [`bindgen`](https://github.com/rust-lang/rust-bindgen). It
isn't one of the workspace's default members, so `cargo build`, `cargo check`,
and `cargo test` at the workspace root work without the tools below.

This is not a FIPS-validated build of BoringSSL. See the crate documentation
(`src/lib.rs`) for the supported algorithms, and for how it uses the RNG passed
to randomized operations.

## Requirements

- The BoringSSL source, in the `boringssl` git submodule
  (`git submodule update --init`), or in `$BORINGSSL_SOURCE_DIR`.
- [CMake](https://cmake.org/) 3.22 or later.
- A C11 and C++17 compiler.
- libclang, for `bindgen` (set `LIBCLANG_PATH` if it isn't found).

Go and Perl aren't needed. Windows targets aren't supported.

## Environment variables

| Variable | Description |
|----------|-------------|
| `BORINGSSL_SOURCE_DIR` | BoringSSL source tree to build instead of the `boringssl` submodule. |
| `BORINGSSL_RUST_CPPLIB` | C++ runtime library to link (default: `c++` on macOS and the BSDs, `stdc++` elsewhere; empty to link none). |

The `cmake` and `bindgen` crates also read their usual variables (e.g.
`CMAKE_GENERATOR`, `CC`, `CXX`, and `LIBCLANG_PATH`).

## Symbol prefix

`build.rs` builds BoringSSL with `-DBORINGSSL_PREFIX=TPM2_BSSL`, and links a
copy of `libcrypto.a` named `libtpm2_bssl_crypto.a`. This lets this crate be
linked into the same binary as OpenSSL (e.g. `tpm2-openssl` in the tests) or
another copy of BoringSSL: both export the same C symbols (`RSA_new`, ...), and
both name their library `libcrypto`.

## Building and testing

```sh
git submodule update --init
cargo build -p tpm2-boringssl
```

The tests live in the `testing-crypto` crate (`testing/crypto`), which runs the
shared backend test suite and interoperability tests against the other
backends:

```sh
cargo test -p testing-crypto --features boringssl
```
