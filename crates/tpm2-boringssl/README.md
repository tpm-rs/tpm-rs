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

## Developing in this workspace

This workspace's `.cargo/config.toml` patches `bssl-sys` to BoringSSL's git
repository at a pinned revision, and sets `BORINGSSL_BUILD_DIR` to
`target/boringssl`. `tpm2-boringssl` isn't one of the workspace's default
members, so `cargo build`, `cargo check`, and `cargo test` at the workspace root
work without a BoringSSL build.

Before building `tpm2-boringssl` (including `cargo check`, `cargo clippy`, and
`cargo doc`), and again after `cargo clean` or after changing the `bssl-sys`
revision, run:

```sh
crates/tpm2-boringssl/boringssl.py build
```

This builds Cargo's checkout of the patched `bssl-sys` (so the source always
matches the pinned revision) into `$BORINGSSL_BUILD_DIR`. It needs CMake, a
C/C++ compiler, Python 3, and the `bindgen` CLI (`cargo install bindgen-cli`). Until
it has run, building fails with `Could not copy bindings from
'.../target/boringssl/rust/bssl-sys/wrapper_<target>.rs'`.

`boringssl.py` reads `BORINGSSL_BUILD_DIR` (default: `target/boringssl`) and
`BINDGEN` (the `bindgen` CLI, default: `bindgen` on `PATH`). CMake's own
variables, such as `CMAKE_GENERATOR=Ninja`, also apply.

Then run the shared backend tests, and the interop tests against RustCrypto:

```sh
cargo test -p testing-crypto --no-default-features --features boringssl,rustcrypto
```

## docs.rs

docs.rs can't build BoringSSL or patch `bssl-sys`. So `Cargo.toml` asks it to
build with `--cfg docsrs`, which drops the `bssl-sys` dependency, and the crate
is documented against `src/docsrs_bindings.rs` instead: bindings (for x86_64),
which are never linked. rustdoc doesn't type-check function bodies, so these
only have the BoringSSL types and constants named in signatures, fields, and
constants (and what they depend on).

`boringssl.py docs-bindings` finds that set automatically: starting from no
bindings, it builds the docs as docs.rs does, adds the items rustdoc couldn't
find, and repeats. Rerun it when the crate's types or the `bssl-sys` revision
change:

```sh
crates/tpm2-boringssl/boringssl.py docs-bindings
```

CI checks that they're up to date (which also builds the docs as docs.rs
does).
