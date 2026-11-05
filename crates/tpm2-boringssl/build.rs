//! Build script for `tpm2-boringssl`.
//!
//! 1. Builds BoringSSL's `crypto` library with CMake, from the `boringssl`
//!    submodule (or `$BORINGSSL_SOURCE_DIR`), with all symbols prefixed by
//!    [`PREFIX`].
//! 2. Links a uniquely named copy of `libcrypto.a` (plus the C++ runtime). Only
//!    the directory containing that copy is added as a link search path, so
//!    binaries which also link OpenSSL's `libcrypto` (e.g. via `openssl-sys`)
//!    still resolve `-lcrypto` to OpenSSL.
//! 3. Generates bindings to BoringSSL's public C API (the headers listed in
//!    `wrapper.h`) with `bindgen`, `include!`d by the crate's `bssl_sys`
//!    module.
//!
//! See the crate's `README.md` for the required tools.

use std::{env, fs, path::PathBuf};

/// Prefix added to all of BoringSSL's symbols, so it can be linked into the
/// same binary as OpenSSL or another copy of BoringSSL.
const PREFIX: &str = "TPM2_BSSL";
/// Name of the copied `libcrypto.a` (as `lib<name>.a`).
const CRYPTO_LIB_NAME: &str = "tpm2_bssl_crypto";

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    assert!(
        target_os != "windows",
        "tpm2-boringssl does not support Windows targets"
    );
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-env-changed=BORINGSSL_SOURCE_DIR");
    let src = env::var_os("BORINGSSL_SOURCE_DIR")
        .filter(|dir| !dir.is_empty())
        .map_or_else(|| manifest_dir.join("boringssl"), PathBuf::from);
    assert!(
        src.join("CMakeLists.txt").is_file(),
        "BoringSSL source not found in {}: run `git submodule update --init`, or set \
         BORINGSSL_SOURCE_DIR to a BoringSSL source tree",
        src.display()
    );
    for dir in [
        "CMakeLists.txt",
        "cmake",
        "crypto",
        "gen",
        "include",
        "third_party/fiat",
    ] {
        println!("cargo:rerun-if-changed={}", src.join(dir).display());
    }

    // 1. Build `libcrypto.a`. Without `BUILD_TESTING`, CMake only needs the
    // sources included in the published package (see `Cargo.toml`).
    let dst = cmake::Config::new(&src)
        .define("BORINGSSL_PREFIX", PREFIX)
        .define("BUILD_TESTING", "OFF")
        .profile("Release")
        .build_target("crypto")
        .build();

    // 2. Link a uniquely named copy of it.
    let lib_dir = out_dir.join("lib");
    fs::create_dir_all(&lib_dir).unwrap();
    fs::copy(
        dst.join("build/libcrypto.a"),
        lib_dir.join(format!("lib{CRYPTO_LIB_NAME}.a")),
    )
    .unwrap();
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static={CRYPTO_LIB_NAME}");
    if let Some(cpp_lib) = cpp_runtime_lib(&target_os) {
        println!("cargo:rustc-link-lib={cpp_lib}");
    }

    // 3. Generate bindings, using the same options as BoringSSL's `bssl-sys`
    // (`rust/bssl-sys/CMakeLists.txt`). Clang turns the symbol prefix into
    // `#[link_name]` attributes, so the Rust names are unprefixed.
    bindgen::Builder::default()
        .header(manifest_dir.join("wrapper.h").to_str().unwrap())
        .clang_arg(format!("-I{}", src.join("include").display()))
        .clang_arg(format!("-DBORINGSSL_PREFIX={PREFIX}"))
        .use_core()
        .derive_default(false)
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .allowlist_file(r".*[/\\]include[/\\]openssl[/\\].*\.h")
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("bssl_sys.rs"))
        .unwrap();
}

/// Returns the C++ runtime library BoringSSL's `libcrypto` needs, overridable
/// with `BORINGSSL_RUST_CPPLIB` (as in `bssl-sys`; empty to link none).
fn cpp_runtime_lib(target_os: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed=BORINGSSL_RUST_CPPLIB");
    if let Ok(cpp_lib) = env::var("BORINGSSL_RUST_CPPLIB") {
        return (!cpp_lib.is_empty()).then_some(cpp_lib);
    }
    match target_os {
        "macos" | "ios" | "freebsd" | "openbsd" => Some("c++".into()),
        _ => Some("stdc++".into()),
    }
}
