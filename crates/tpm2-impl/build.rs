//! Builds the reference RNG library of the opt-in `reference-rng` feature.
//!
//! With the feature, `tpm-rs` draws its random numbers with the original C code of the TCG
//! reference TPM (`mstpm20`), linked into this crate without any hand-written C:
//!
//! 1. The build clones `https://github.com/TrustedComputingGroup/TPM` at the commit the
//!    differential tests pin (checked against `testing/build.rs`) and applies the same patches
//!    as the differential reference (`testing/patches/mstpm20/*.patch`, in sorted file-name
//!    order), so that the code is compiled with exactly the profile the reference runs with
//!    (none of the patches changes the random-number generation).
//! 2. It compiles the unmodified reference files the random-number code consists of
//!    ([`SOURCES`]) with the reference's compiler flags, plus command-line macros that redirect
//!    the three mutable globals involved to accessor functions implemented in Rust
//!    ([`GLOBAL_REDIRECTIONS`]; e.g. `go` becomes `(*tpmrs_refrng_go())`, so that
//!    `drbgDefault`, `go.drbgState`, is the calling TPM's DRBG). `CryptRsa.c` is compiled with
//!    `-fkeep-static-functions`, and its `static` encoders that Rust calls are made global
//!    ([`STATIC_ENTRY_POINTS`]).
//! 3. The objects are partially linked (`ld -r`) with OpenSSL's `libcrypto.a`, the reference's
//!    big-number and hash backend, discarding every section the entry points do not reach
//!    (`--gc-sections`). The entry points ([`ENTRY_POINTS`]) and the platform functions the
//!    reference code calls ([`PLATFORM_FUNCTIONS`], implemented in Rust) are renamed with the
//!    `tpmrs_refrng_` prefix, and every other symbol is made local, so that neither the
//!    reference's nor OpenSSL's symbols can collide with BoringSSL (`bssl-sys`) or a C
//!    reference TPM linked into the same binary. The result is `libtpmrs_refrng.a`.
//! 4. `bindgen` generates the Rust declarations of the reference's types and entry points
//!    (linking to the prefixed names) from the reference headers, as `refrng_bindings.rs` in
//!    `OUT_DIR` (included by `src/reference_rng/ffi.rs`, which implements the rest of the glue).
//!
//! Without the feature, nothing is built and no C toolchain, libclang or network access is
//! needed.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "reference-rng")]
    reference_rng::build();
}

#[cfg(feature = "reference-rng")]
mod reference_rng {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// Git repository of the TCG reference TPM.
    const MSTPM20_REPO: &str = "https://github.com/TrustedComputingGroup/TPM";
    /// Pinned commit of [`MSTPM20_REPO`]; must be the commit the differential tests use for the
    /// `mstpm20` reference (checked against `testing/build.rs`).
    const MSTPM20_COMMIT: &str = "3b1f0e623f244abe2015df9e3ba86de5c9118524";

    /// Name of the static library (`lib<name>.a`).
    const LIB_NAME: &str = "tpmrs_refrng";
    /// Prefix of every symbol the library shares with Rust.
    const PREFIX: &str = "tpmrs_refrng_";

    /// The unmodified reference sources (relative to `TPMCmd/`) that are compiled. Their
    /// functions that the entry points do not reach are discarded by the partial link.
    const SOURCES: [&str; 26] = [
        // The DRBG.
        "tpm/src/crypt/CryptRand.c",
        // Hashes (OAEP, PSS, MGF1, KDFa).
        "tpm/src/crypt/CryptHash.c",
        // RSA key generation and encodings.
        "tpm/src/crypt/CryptRsa.c",
        "tpm/src/crypt/CryptPrime.c",
        "tpm/src/crypt/CryptPrimeSieve.c",
        "tpm/src/crypt/PrimeData.c",
        // ECC key generation and signing.
        "tpm/src/crypt/CryptEccMain.c",
        "tpm/src/crypt/CryptEccData.c",
        "tpm/src/crypt/CryptEccSignature.c",
        "tpm/src/crypt/ecc/TpmEcc_Signature_ECDSA.c",
        // Referenced by `CryptEccSign()` for ECDAA signatures, which Rust never requests.
        "tpm/src/crypt/ecc/TpmEcc_Signature_ECDAA.c",
        "tpm/src/crypt/ecc/TpmEcc_Signature_Util.c",
        "tpm/src/crypt/ecc/TpmEcc_Util.c",
        "tpm/src/crypt/math/TpmMath_Util.c",
        // The big-number library (TpmBigNum over OpenSSL).
        "tpm/cryptolibs/TpmBigNum/BnConvert.c",
        "tpm/cryptolibs/TpmBigNum/BnEccConstants.c",
        "tpm/cryptolibs/TpmBigNum/BnMath.c",
        "tpm/cryptolibs/TpmBigNum/BnMemory.c",
        "tpm/cryptolibs/TpmBigNum/BnUtil.c",
        "tpm/cryptolibs/TpmBigNum/TpmBigNumThunks.c",
        "tpm/cryptolibs/Ossl/BnToOsslMath.c",
        "tpm/cryptolibs/Ossl/TpmToOsslSupport.c",
        // Support functions.
        "tpm/src/support/Memory.c",
        "tpm/src/support/MathOnByteBuffers.c",
        "tpm/src/support/Bits.c",
        // Instances the hash and curve OIDs referenced by the algorithm tables (the TPM's
        // other globals are discarded, or redirected to Rust).
        "tpm/src/support/Global.c",
    ];

    /// The reference functions Rust calls (renamed `tpmrs_refrng_<name>`).
    const ENTRY_POINTS: [&str; 16] = [
        "DRBG_Instantiate",
        "CryptRandStartup",
        "DRBG_Reseed",
        "CryptRandomStir",
        "DRBG_Generate",
        "DRBG_InstantiateSeeded",
        "DRBG_AdditionalData",
        "CryptRsaGenerateKey",
        "OaepEncode",
        "RSAES_PKCS1v1_5Encode",
        "PssEncode",
        "CryptEccGenerateKey",
        "CryptEccNewKeyPair",
        "CryptEccSign",
        "CryptEccValidateSignature",
        "CryptEccPointMultiply",
    ];

    /// The `static` functions of `CryptRsa.c` among [`ENTRY_POINTS`] (made global).
    const STATIC_ENTRY_POINTS: [&str; 3] = ["OaepEncode", "RSAES_PKCS1v1_5Encode", "PssEncode"];

    /// The platform functions the reference code calls, implemented in Rust (renamed
    /// `tpmrs_refrng_<name>` in the C objects). `CryptTestAlgorithm` is the self test that the
    /// reference's `TPM_DO_SELF_TEST()` runs for an untested algorithm (`ENABLE_SELF_TESTS`):
    /// `tpm-rs` runs the algorithm self tests itself (`crate::self_test`), so the linked code's
    /// `g_toTest` (a zero-initialized global that no linked code sets) never requests one.
    const PLATFORM_FUNCTIONS: [&str; 5] = [
        "_plat__GetEntropy",
        "_plat__InFailureMode",
        "_plat__IsCanceled",
        "EnterFailureMode",
        "CryptTestAlgorithm",
    ];

    /// The mutable globals of the compiled reference code, redirected by command-line macros to
    /// accessor functions implemented in Rust (each declaration `T global;` becomes the
    /// function declaration `T (*accessor());`): `(global, accessor)`.
    const GLOBAL_REDIRECTIONS: [(&str, &str); 3] = [
        // `ORDERLY_DATA go`, of which `CryptRand.c` uses `drbgState` (`drbgDefault`).
        ("go", "tpmrs_refrng_go"),
        // `CRYPTO_SELF_TEST_STATE g_cryptoSelfTestState`, the DRBG self-test flags.
        ("g_cryptoSelfTestState", "tpmrs_refrng_self_test"),
        // `uint32_t primeLimit` of `CryptPrimeSieve.c`, the sieve limit.
        ("primeLimit", "tpmrs_refrng_prime_limit"),
    ];

    /// The reference's include directories (relative to `TPMCmd/`), as in `testing/build.rs`.
    const INCLUDE_DIRS: [&str; 15] = [
        "TpmConfiguration",
        "tpm/include",
        "tpm/include/tpm_public",
        "tpm/include/private",
        "tpm/include/private/prototypes",
        "tpm/include/platform_interface",
        "tpm/include/platform_interface/prototypes",
        "Platform/include",
        "Platform/include/prototypes",
        "Simulator/include",
        "Simulator/include/prototypes",
        "tpm/cryptolibs",
        "tpm/cryptolibs/common/include",
        "tpm/cryptolibs/TpmBigNum/include",
        "tpm/cryptolibs/Ossl/include",
    ];

    /// The reference's configuration macros (as in `testing/build.rs`).
    const DEFINES: [&str; 6] = [
        "-DRADIX_BITS=64",
        "-DSIMULATION=1",
        "-DHASH_LIB=Ossl",
        "-DSYM_LIB=Ossl",
        "-DMATH_LIB=TpmBigNum",
        "-DBN_MATH_LIB=Ossl",
    ];

    /// The reference's other compiler flags (as in `testing/build.rs`), plus one section per
    /// function and object for `--gc-sections`.
    const CFLAGS: [&str; 6] = [
        "-O2",
        "-fPIC",
        "-w",
        "-std=gnu11",
        "-ffunction-sections",
        "-fdata-sections",
    ];

    /// The reference types, prototypes and constants Rust uses (`bindgen` allowlists).
    const BINDGEN_TYPES: &str = "DRBG_STATE|RAND_STATE|ORDERLY_DATA|CRYPTO_SELF_TEST_STATE|TPM2B|\
        TPMT_PUBLIC|TPMT_SENSITIVE|OBJECT|TPMT_SIGNATURE|TPMS_ECC_POINT|TPM2B_ECC_PARAMETER|\
        TPM2B_DIGEST";
    const BINDGEN_VARS: &str = "TESTED|RSA_prime_flag|MAX_RSA_KEY_BYTES|DRBG_MAGIC";

    pub(super) fn build() {
        let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
        let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
        let tpm_cmd = build_library(&manifest, &out);
        generate_bindings(&tpm_cmd, &out);
        println!("cargo:rustc-link-search=native={}", out.display());
        println!("cargo:rustc-link-lib=static={LIB_NAME}");
        // OpenSSL's `libcrypto.a` is built with zlib and zstd support.
        println!("cargo:rustc-link-lib=dylib=z");
        println!("cargo:rustc-link-lib=dylib=zstd");
    }

    /// Runs `cmd`, panicking with its output if it fails, and returns its stdout.
    fn run(cmd: &mut Command, desc: &str) -> String {
        let out = cmd
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn {desc}: {e}"));
        assert!(
            out.status.success(),
            "{desc} failed ({}):\nstdout: {}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// The patches of the differential `mstpm20` reference, in the order they are applied.
    fn patch_files(dir: &Path) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
            .map(|e| e.expect("dir entry").path())
            .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("patch"))
            .collect();
        files.sort();
        assert!(!files.is_empty(), "no patches in testing/patches/mstpm20");
        files
    }

    /// Appends `path` (its name and contents) to the build stamp `stamp`, and asks Cargo to
    /// rerun the build script when it changes.
    fn stamp_file(stamp: &mut Vec<u8>, path: &Path) {
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        stamp.extend_from_slice(format!("{}\n{}\n", path.display(), bytes.len()).as_bytes());
        stamp.extend_from_slice(&bytes);
    }

    /// Clones (or reuses) the reference at [`MSTPM20_COMMIT`] in `repo_dir` and applies
    /// `patches` (as `testing/build.rs` does for the differential reference).
    fn checkout(repo_dir: &Path, patches: &[PathBuf]) {
        if !repo_dir.join(".git").exists() {
            let _ = std::fs::remove_dir_all(repo_dir);
            run(
                Command::new("git")
                    .args(["clone", "--no-checkout", MSTPM20_REPO])
                    .arg(repo_dir),
                &format!("git clone {MSTPM20_REPO}"),
            );
        }
        let git = |args: &[&str], desc: &str| {
            run(Command::new("git").arg("-C").arg(repo_dir).args(args), desc)
        };
        // A checkout made before the pinned commit existed may lack it.
        let has_commit = Command::new("git")
            .arg("-C")
            .arg(repo_dir)
            .args(["cat-file", "-e", &format!("{MSTPM20_COMMIT}^{{commit}}")])
            .status()
            .is_ok_and(|s| s.success());
        if !has_commit {
            git(&["fetch", "origin"], "git fetch mstpm20");
        }
        git(
            &["checkout", "--force", MSTPM20_COMMIT],
            &format!("git checkout mstpm20@{MSTPM20_COMMIT}"),
        );
        let head = git(&["rev-parse", "HEAD"], "git rev-parse mstpm20");
        assert_eq!(
            head.trim(),
            MSTPM20_COMMIT,
            "mstpm20 checkout is not at the pinned commit"
        );
        git(&["clean", "-fdx"], "git clean mstpm20");
        // One `git apply` per patch, in sorted order, so that a failure names the patch.
        for patch in patches {
            run(
                Command::new("git")
                    .arg("-C")
                    .arg(repo_dir)
                    .arg("apply")
                    .arg(patch),
                &format!("git apply {}", patch.display()),
            );
        }
    }

    /// The path of OpenSSL's `libcrypto.a` (found via `pkg-config`, as in `testing/build.rs`).
    fn libcrypto_archive() -> PathBuf {
        let libcrypto_a = Command::new("pkg-config")
            .args(["--variable=libdir", "libcrypto"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|dir| PathBuf::from(dir.trim()).join("libcrypto.a"))
            .filter(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from("/usr/lib/x86_64-linux-gnu/libcrypto.a"));
        assert!(
            libcrypto_a.is_file(),
            "libcrypto.a not found at {}",
            libcrypto_a.display()
        );
        libcrypto_a
    }

    /// The `nm --format=posix` lines of `obj` for the given extra `nm` flags.
    fn nm_symbols(obj: &Path, flags: &[&str]) -> Vec<(String, String)> {
        run(
            Command::new("nm")
                .arg("--format=posix")
                .args(flags)
                .arg(obj),
            &format!("nm {}", obj.display()),
        )
        .lines()
        .filter_map(|l| {
            let mut fields = l.split_whitespace();
            Some((fields.next()?.to_owned(), fields.next()?.to_owned()))
        })
        .collect()
    }

    /// Clones and patches the reference, and builds `lib<LIB_NAME>.a` in `out` unless an
    /// up-to-date one exists. Returns the reference's `TPMCmd` directory.
    fn build_library(manifest: &Path, out: &Path) -> PathBuf {
        let patch_dir = manifest.join("../../testing/patches/mstpm20");
        let testing_build = manifest.join("../../testing/build.rs");
        println!("cargo:rerun-if-changed={}", patch_dir.display());
        println!("cargo:rerun-if-changed={}", testing_build.display());

        // The library must reproduce the reference the differential tests compare with.
        let testing_build_rs =
            std::fs::read_to_string(&testing_build).expect("read testing/build.rs");
        assert!(
            testing_build_rs.contains(MSTPM20_COMMIT),
            "MSTPM20_COMMIT differs from the mstpm20 commit pinned by testing/build.rs"
        );

        let patches = patch_files(&patch_dir);
        // Everything the library is built from (the pinned commit, the patches in their order
        // and this build script) is part of the stamp, so a change never reuses a stale library.
        let mut expected_stamp = format!("{MSTPM20_REPO}@{MSTPM20_COMMIT}\n").into_bytes();
        for patch in &patches {
            stamp_file(&mut expected_stamp, patch);
        }
        expected_stamp.extend_from_slice(include_bytes!("build.rs"));

        let repo_dir = out.join("mstpm20");
        let tpm_cmd = repo_dir.join("TPMCmd");
        let archive = out.join(format!("lib{LIB_NAME}.a"));
        let stamp_path = out.join(format!("{LIB_NAME}.stamp"));
        if archive.is_file()
            && std::fs::read(&stamp_path)
                .ok()
                .is_some_and(|s| s == expected_stamp)
        {
            return tpm_cmd;
        }
        checkout(&repo_dir, &patches);

        let obj_dir = out.join(format!("{LIB_NAME}-objs"));
        let _ = std::fs::remove_dir_all(&obj_dir);
        std::fs::create_dir_all(&obj_dir).expect("create obj_dir");
        let objects: Vec<PathBuf> = SOURCES
            .iter()
            .enumerate()
            .map(|(i, src)| {
                let stem = Path::new(src).file_stem().and_then(|s| s.to_str()).unwrap();
                obj_dir.join(format!("{i:03}_{stem}.o"))
            })
            .collect();

        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
        std::thread::scope(|s| {
            for (src, obj) in SOURCES.iter().zip(objects.iter()) {
                let (cc, tpm_cmd) = (&cc, &tpm_cmd);
                s.spawn(move || {
                    let mut cmd = Command::new(cc);
                    cmd.args(CFLAGS).args(DEFINES);
                    for (global, accessor) in GLOBAL_REDIRECTIONS {
                        cmd.arg(format!("-D{global}=(*{accessor}())"));
                    }
                    if src.ends_with("CryptRsa.c") {
                        // Emit the `static` encoders even where they are inlined.
                        cmd.arg("-fkeep-static-functions");
                    }
                    for inc in INCLUDE_DIRS {
                        cmd.arg("-I").arg(tpm_cmd.join(inc));
                    }
                    cmd.arg("-c").arg(tpm_cmd.join(src)).arg("-o").arg(obj);
                    run(&mut cmd, &format!("cc {src}"));
                });
            }
        });

        // Make the `static` encoders of `CryptRsa.c` global, after checking that the emitted
        // symbols are the functions themselves (not clones with a different signature, which
        // would carry a suffix such as `.isra.0`).
        let rsa_obj = &objects[SOURCES
            .iter()
            .position(|s| s.ends_with("CryptRsa.c"))
            .unwrap()];
        let rsa_symbols = nm_symbols(rsa_obj, &["--defined-only"]);
        for name in STATIC_ENTRY_POINTS {
            assert!(
                rsa_symbols.iter().any(|(n, t)| n == name && t == "t"),
                "CryptRsa.o lacks the local function {name}"
            );
        }
        let mut globalize = Command::new("objcopy");
        for name in STATIC_ENTRY_POINTS {
            globalize.arg(format!("--globalize-symbol={name}"));
        }
        run(globalize.arg(rsa_obj), "objcopy globalize CryptRsa.o");

        // Partial link with libcrypto.a, keeping only what the entry points reach. `-dc`
        // allocates common symbols (e.g. OpenSSL's `OPENSSL_ia32cap_P`) so that they can be
        // localized too.
        let all_o = obj_dir.join(format!("{LIB_NAME}_all.o"));
        let mut ld = Command::new("ld");
        ld.args(["-r", "-dc", "--gc-sections"]);
        for name in ENTRY_POINTS {
            ld.arg(format!("--require-defined={name}"));
        }
        ld.arg("-o")
            .arg(&all_o)
            .args(&objects)
            .arg(libcrypto_archive());
        run(&mut ld, &format!("ld -r {LIB_NAME}_all.o"));

        // Prefix the entry points and the platform functions.
        let renamed_o = obj_dir.join(format!("{LIB_NAME}_renamed.o"));
        let mut rename = Command::new("objcopy");
        for name in ENTRY_POINTS.iter().chain(PLATFORM_FUNCTIONS.iter()) {
            rename.arg(format!("--redefine-sym={name}={PREFIX}{name}"));
        }
        run(
            rename.arg(&all_o).arg(&renamed_o),
            "objcopy prefix entry points",
        );

        // Localize every symbol but the entry points, and drop the symbols that no relocation
        // uses any more (e.g. undefined references of discarded sections).
        let exports: Vec<String> = ENTRY_POINTS
            .iter()
            .map(|name| format!("{PREFIX}{name}"))
            .collect();
        let isolated_o = obj_dir.join(format!("{LIB_NAME}_isolated.o"));
        let mut localize = Command::new("objcopy");
        for sym in &exports {
            localize.arg(format!("--keep-global-symbol={sym}"));
        }
        localize
            .arg("--strip-unneeded")
            .arg(&renamed_o)
            .arg(&isolated_o);
        run(
            &mut localize,
            &format!("objcopy localize {LIB_NAME} symbols"),
        );

        check_isolation(&isolated_o, &exports);

        let _ = std::fs::remove_file(&archive);
        run(
            Command::new("ar").arg("crs").arg(&archive).arg(&isolated_o),
            &format!("ar crs lib{LIB_NAME}.a"),
        );
        std::fs::write(&stamp_path, &expected_stamp)
            .unwrap_or_else(|e| panic!("write {LIB_NAME}.stamp: {e}"));
        tpm_cmd
    }

    /// Checks that `obj` exports exactly `exports`, and that the only symbols it needs from Rust
    /// are the platform functions and global accessors (everything else it needs comes from
    /// libc, zlib and zstd).
    fn check_isolation(obj: &Path, exports: &[String]) {
        let mut defined: Vec<String> = nm_symbols(obj, &["--defined-only", "--extern-only"])
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        defined.sort();
        let mut expected = exports.to_vec();
        expected.sort();
        assert_eq!(
            defined, expected,
            "the library must export exactly the prefixed entry points"
        );

        let mut from_rust: Vec<String> = PLATFORM_FUNCTIONS
            .iter()
            .map(|name| format!("{PREFIX}{name}"))
            .chain(GLOBAL_REDIRECTIONS.iter().map(|(_, a)| (*a).to_owned()))
            .collect();
        from_rust.sort();
        let undefined: Vec<String> = nm_symbols(obj, &["--undefined-only"])
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        let mut needed: Vec<String> = undefined
            .iter()
            .filter(|n| n.starts_with(PREFIX))
            .cloned()
            .collect();
        needed.sort();
        assert!(
            needed.iter().all(|n| from_rust.contains(n)),
            "unexpected Rust symbols needed: {needed:?}"
        );
        // Reference functions that the linked code still needs would be unresolved.
        let internal: Vec<&String> = undefined
            .iter()
            .filter(|n| {
                [
                    "_plat__", "Crypt", "Tpm", "Ext", "Bn", "DRBG", "Memory", "Enter",
                ]
                .iter()
                .any(|p| n.starts_with(p))
            })
            .collect();
        assert!(
            internal.is_empty(),
            "unresolved reference symbols: {internal:?}"
        );
    }

    /// Links the `bindgen` declarations of the entry points to their prefixed names.
    #[derive(Debug)]
    struct PrefixLinkNames;

    impl bindgen::callbacks::ParseCallbacks for PrefixLinkNames {
        fn generated_link_name_override(
            &self,
            item: bindgen::callbacks::ItemInfo<'_>,
        ) -> Option<String> {
            ENTRY_POINTS
                .contains(&item.name)
                .then(|| format!("{PREFIX}{}", item.name))
        }
    }

    /// Generates `refrng_bindings.rs` in `out`: the reference's types, constants and the
    /// prototypes of the entry points that have one in the headers.
    fn generate_bindings(tpm_cmd: &Path, out: &Path) {
        let mut builder = bindgen::Builder::default()
            .header_contents("refrng.h", "#include \"Tpm.h\"\n")
            .clang_args(DEFINES)
            .clang_args(
                INCLUDE_DIRS
                    .iter()
                    .map(|d| format!("-I{}", tpm_cmd.join(d).display())),
            )
            .use_core()
            .rust_edition(bindgen::RustEdition::Edition2024)
            .allowlist_type(BINDGEN_TYPES)
            .allowlist_var(BINDGEN_VARS)
            .derive_default(false)
            .layout_tests(false)
            .parse_callbacks(Box::new(PrefixLinkNames));
        for name in ENTRY_POINTS {
            if !STATIC_ENTRY_POINTS.contains(&name) {
                builder = builder.allowlist_function(name);
            }
        }
        builder
            .generate()
            .expect("bindgen for the mstpm20 headers")
            .write_to_file(out.join("refrng_bindings.rs"))
            .expect("write refrng_bindings.rs");
    }
}
