# tpm2-boringssl

[BoringSSL](https://boringssl.googlesource.com/boringssl) cryptography backend
for [`tpm2::crypto`](../tpm2/src/crypto/mod.rs).

This crate is `#![no_std]`. It uses BoringSSL's public C API through
BoringSSL's own [`bssl-sys`](https://boringssl.googlesource.com/boringssl/+/HEAD/rust/bssl-sys)
crate. This is not a FIPS-validated build of BoringSSL. See the crate
documentation (`src/lib.rs`) for the supported algorithms, and for how it uses
the RNG passed to randomized operations.

## Using BoringSSL's `bssl-sys`

This crate depends on `bssl-sys = "0.1.0"`, which on crates.io is a placeholder
that fails to compile. To use this crate, replace it with BoringSSL's own
`bssl-sys`, at the revision of the BoringSSL you build, in your workspace's
`.cargo/config.toml` (or `Cargo.toml`):

```toml
[patch.crates-io]
bssl-sys = { git = "https://boringssl.googlesource.com/boringssl", rev = "<revision>" }
```

Every crate in your build that uses `bssl-sys` then shares one BoringSSL.

`bssl-sys` doesn't build BoringSSL: it links a prebuilt BoringSSL from the
directory in `BORINGSSL_BUILD_DIR` (an absolute path). Build BoringSSL with CMake
and `-DRUST_BINDINGS=<rust-target>`, which needs the
[`bindgen`](https://github.com/rust-lang/rust-bindgen) CLI. `bssl-sys` uses
these files from the build:

- `libcrypto.a` and `libssl.a`
- `rust/bssl-sys/wrapper_<rust-target>.rs` (the generated bindings)
- `rust/bssl-sys/librust_wrapper.a`

## Linking with OpenSSL

`bssl-sys` links BoringSSL as `-lcrypto` and `-lssl` from `BORINGSSL_BUILD_DIR`,
so a binary can't also link OpenSSL's `libcrypto` (e.g. through `openssl-sys`):
the linker would use BoringSSL's library for both. Even a symbol-prefixed
BoringSSL build (`-DBORINGSSL_PREFIX`) doesn't help, as the library names still
clash.
