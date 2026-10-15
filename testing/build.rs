//! Builds the C reference TPMs for differential testing.
//!
//! With the `differential` feature, the build clones every reference
//! implementation at a pinned commit, applies its patches, compiles it into a
//! symbol-isolated static library (exporting only the `difftest_*` entry
//! points) and links that library into the reference binary of the same name
//! (see `src/differential/mod.rs`):
//!
//! * `mstpm20`: the TCG / Microsoft reference implementation, in one of two
//!   versions (see [`Version`]):
//!   * `v185`: the TCG-internal repository
//!     `https://github.com/TrustedComputingGroup/TPM-Internal` at tag
//!     `v185.0.0` (specification version 185), patched by
//!     `testing/patches/mstpm20-v185/*.patch`, used whenever the user's `git`
//!     may clone it;
//!   * `public`: the public repository
//!     `https://github.com/TrustedComputingGroup/TPM`, patched by
//!     `testing/patches/mstpm20/*.patch`, used otherwise;
//! * `ibmswtpm2`: `https://github.com/kgoldman/ibmswtpm2` (the IBM software
//!   TPM), patched by `testing/patches/ibmswtpm2/*.patch`.
//!
//! The version of a reference is the first of its [`Reference::versions`]
//! that is available (already checked out at its pinned commit, or its
//! repository can be listed by `git ls-remote` without prompting for
//! credentials). The environment variable `<NAME>_VERSION` (e.g.
//! `MSTPM20_VERSION=public` or `MSTPM20_VERSION=v185`) selects a version
//! explicitly; the build fails if that version cannot be cloned. The selected
//! version is passed to the crate as the compile-time environment variable
//! `DIFFERENTIAL_<NAME>_VERSION`.
//!
//! Every patch file holds one individual fix (a spec-deviation bug fix, a
//! profile or platform setting, harness plumbing or a build fix), described by
//! the plain-text header before its first `diff --git` line, and is named
//! `<classification>-<fix>.patch` (see [`PATCH_CLASSES`]). The patches of a
//! version are applied with `git apply` in sorted file-name order.
//!
//! Without the feature, nothing is built.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A C reference TPM implementation built for differential testing.
struct Reference {
    /// Name of the implementation, its static library (`lib<name>.a`) and the
    /// binary it is linked into.
    name: &'static str,
    /// The versions the implementation can be built from, in order of
    /// preference: the first available one is used unless `<NAME>_VERSION`
    /// selects one (see [`select_version`]).
    versions: &'static [Version],
}

/// One version of a reference implementation: where its code comes from, how
/// it is patched and how it is compiled.
struct Version {
    /// Label of the version (the value of `<NAME>_VERSION` that selects it).
    label: &'static str,
    /// Git repository of the version.
    repo: &'static str,
    /// Pinned commit of `repo`.
    commit: &'static str,
    /// Name of the patch directory (`testing/patches/<patch_dir>/`), which is
    /// also the name of the checkout directory in `OUT_DIR`.
    patch_dir: &'static str,
    /// The C sources to compile, given the checkout directory.
    sources: fn(&Path) -> Vec<PathBuf>,
    /// The include directories, given the checkout directory.
    include_dirs: fn(&Path) -> Vec<PathBuf>,
    /// Compiler flags (besides the include directories).
    cflags: &'static [&'static str],
}

/// The reference implementations.
const REFERENCES: [Reference; 2] = [
    Reference {
        name: "mstpm20",
        versions: &[
            // The TCG-internal repository, which only TCG members can clone.
            Version {
                label: "v185",
                repo: "https://github.com/TrustedComputingGroup/TPM-Internal",
                // Tag `v185.0.0`.
                commit: "80a8b19436d742f42e00fba8527272071284b42c",
                patch_dir: "mstpm20-v185",
                sources: mstpm20_v185_sources,
                include_dirs: mstpm20_v185_include_dirs,
                cflags: &[
                    "-O2",
                    "-fPIC",
                    "-w",
                    "-std=gnu11",
                    "-DRADIX_BITS=64",
                    "-DSIMULATION=1",
                    // The crypto libraries the version's CMake build selects
                    // by default (`TPMCmd/CMakeLists.txt`).
                    "-DSYM_LIB=Ossl",
                    "-DHASH_LIB=Ossl",
                    "-DRAND_LIB=RandRef",
                    "-DKDF_LIB=KdfRef",
                    "-DMATH_LIB=TpmBigNum",
                    "-DBN_MATH_LIB=Ossl",
                    "-DRSA_LIB=RsaRef",
                    "-DECC_LIB=EccRef",
                    "-DMLKEM_LIB=Ossl",
                    "-DMLDSA_LIB=Ossl",
                ],
            },
            Version {
                label: "public",
                repo: "https://github.com/TrustedComputingGroup/TPM",
                commit: "3b1f0e623f244abe2015df9e3ba86de5c9118524",
                patch_dir: "mstpm20",
                sources: mstpm20_sources,
                include_dirs: mstpm20_include_dirs,
                cflags: &[
                    "-O2",
                    "-fPIC",
                    "-w",
                    "-std=gnu11",
                    "-DRADIX_BITS=64",
                    "-DSIMULATION=1",
                    "-DHASH_LIB=Ossl",
                    "-DSYM_LIB=Ossl",
                    "-DMATH_LIB=TpmBigNum",
                    "-DBN_MATH_LIB=Ossl",
                ],
            },
        ],
    },
    Reference {
        name: "ibmswtpm2",
        versions: &[Version {
            label: "public",
            repo: "https://github.com/kgoldman/ibmswtpm2",
            commit: "e1df46e46fc2671e55372d65f27ecbb3c789d992",
            patch_dir: "ibmswtpm2",
            sources: ibmswtpm2_sources,
            include_dirs: ibmswtpm2_include_dirs,
            cflags: &[
                "-O2",
                "-fPIC",
                "-w",
                "-std=gnu11",
                "-DTPM_POSIX",
                "-D_POSIX_",
                "-DUSE_BIT_FIELD_STRUCTURES=NO",
                "-DSYM_LIB=Ossl",
                "-DHASH_LIB=Ossl",
                "-DMATH_LIB=TpmBigNum",
                "-DBN_MATH_LIB=Ossl",
            ],
        }],
    },
];

/// The entry points every patched reference exports (see
/// `src/bin/shared/ffi.rs`); every other symbol is localized.
const EXPORTED_SYMBOLS: [&str; 15] = [
    "difftest_init",
    "difftest_advance_clock",
    "difftest_signal_power_on",
    "difftest_signal_power_off",
    "difftest_signal_reset",
    "difftest_signal_nv_on",
    "difftest_signal_nv_off",
    "difftest_signal_physical_presence_on",
    "difftest_signal_physical_presence_off",
    "difftest_signal_cancel_on",
    "difftest_signal_cancel_off",
    "difftest_signal_hash_start",
    "difftest_signal_hash_data",
    "difftest_signal_hash_end",
    "difftest_run_command",
];

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("CARGO_FEATURE_DIFFERENTIAL").is_some() {
        let versions: Vec<&Version> = REFERENCES
            .iter()
            .map(|reference| select_version(reference, &out))
            .collect();
        // The references are independent; build them concurrently.
        std::thread::scope(|s| {
            for (reference, version) in REFERENCES.iter().zip(&versions) {
                let (manifest, out) = (&manifest, &out);
                s.spawn(move || build_reference(reference.name, version, manifest, out));
            }
        });
        for (reference, version) in REFERENCES.iter().zip(&versions) {
            let name = reference.name;
            println!(
                "cargo:rustc-env=DIFFERENTIAL_{}_VERSION={}",
                name.to_uppercase(),
                version.label
            );
            let archive = out.join(format!("lib{name}.a"));
            // Each library goes into its own binary only (both export the
            // same `difftest_*` entry points).
            println!("cargo:rustc-link-arg-bin={name}={}", archive.display());
            println!("cargo:rustc-link-arg-bin={name}=-lz");
            println!("cargo:rustc-link-arg-bin={name}=-lzstd");
        }
    }
}

/// Selects the version of `reference` to build: the one `<NAME>_VERSION`
/// names, or else the first of [`Reference::versions`] that is available
/// (see [`version_available`]), falling back to the last one.
///
/// # Panics
/// If `<NAME>_VERSION` names no version of `reference`.
fn select_version<'a>(reference: &'a Reference, out: &Path) -> &'a Version {
    let env = format!("{}_VERSION", reference.name.to_uppercase());
    println!("cargo:rerun-if-env-changed={env}");
    let labels = || {
        reference
            .versions
            .iter()
            .map(|v| v.label)
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(label) = std::env::var(&env).ok().filter(|l| !l.is_empty()) {
        return reference
            .versions
            .iter()
            .find(|v| v.label == label)
            .unwrap_or_else(|| {
                panic!(
                    "{env}={label} names no {} version ({})",
                    reference.name,
                    labels()
                )
            });
    }
    let (last, preferred) = reference.versions.split_last().expect("versions");
    preferred
        .iter()
        .find(|v| version_available(v, out))
        .unwrap_or(last)
}

/// Whether `version` can be built: its checkout in `out` already holds its
/// pinned commit, or the user's `git` can list its repository (without
/// prompting for credentials, so a repository the user may not access is
/// reported unavailable instead of blocking the build).
fn version_available(version: &Version, out: &Path) -> bool {
    has_commit(&out.join(version.patch_dir), version.commit)
        || Command::new("git")
            .args(["ls-remote", "--exit-code", version.repo, "HEAD"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

/// Whether the git checkout `repo_dir` exists and holds `commit`.
fn has_commit(repo_dir: &Path, commit: &str) -> bool {
    repo_dir.join(".git").exists()
        && Command::new("git")
            .arg("-C")
            .arg(repo_dir)
            .args(["cat-file", "-e", &format!("{commit}^{{commit}}")])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

/// Runs `cmd`, panicking with its output if it fails.
fn run(cmd: &mut Command, desc: &str) {
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
}

/// The classifications a patch file name must start with (followed by `-`):
/// a fix of a specification deviation of the reference, a build fix, harness
/// plumbing, a platform setting, or a profile setting.
const PATCH_CLASSES: [&str; 5] = ["bug-fix", "build-fix", "harness", "platform", "profile"];

/// Returns the patches in `testing/patches/<name>/`: every `*.patch` file, in
/// sorted file-name order (the order in which they are applied), and asks
/// Cargo to rerun the build script when the directory or any patch changes.
///
/// # Panics
/// If there is no patch, or a patch file name does not start with one of
/// [`PATCH_CLASSES`].
fn patch_files(manifest: &Path, name: &str) -> Vec<PathBuf> {
    let dir = manifest.join("patches").join(name);
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut patches: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir testing/patches/{name}: {e}"))
        .map(|e| e.expect("patch dir entry").path())
        .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("patch"))
        .collect();
    patches.sort();
    assert!(!patches.is_empty(), "no patches in testing/patches/{name}");
    for patch in &patches {
        let file = patch
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();
        assert!(
            PATCH_CLASSES.iter().any(|class| file
                .strip_prefix(class)
                .is_some_and(|rest| rest.starts_with('-'))),
            "testing/patches/{name}/{file}: the file name must start with its classification \
             ({}-)",
            PATCH_CLASSES.join("-, ")
        );
        println!("cargo:rerun-if-changed={}", patch.display());
    }
    patches
}

/// Clones `version` of reference `name` at its pinned commit, applies its
/// patches, compiles it, partially links it with `libcrypto.a` while
/// localizing every symbol but the `difftest_*` entry points (so that neither
/// the reference's nor OpenSSL's symbols collide with `bssl-sys`), and
/// archives the result as `lib<name>.a` in `out`.
fn build_reference(name: &str, version: &Version, manifest: &Path, out: &Path) {
    let patch_dir = version.patch_dir;
    let patches = patch_files(manifest, patch_dir);

    let mut expected_stamp = format!("{}@{}\n", version.repo, version.commit).into_bytes();
    // Every patch (its file name, which determines the order, and its
    // contents) is part of the stamp, so adding, removing, renaming or
    // editing a patch never reuses a stale library.
    for patch in &patches {
        let file_name = patch
            .file_name()
            .expect("patch file name")
            .to_string_lossy();
        let bytes = std::fs::read(patch)
            .unwrap_or_else(|e| panic!("read testing/patches/{patch_dir}/{file_name}: {e}"));
        expected_stamp.extend_from_slice(format!("{file_name}\n{}\n", bytes.len()).as_bytes());
        expected_stamp.extend_from_slice(&bytes);
    }
    // The build recipe (compiler flags, sources, exported symbols) is part of
    // the stamp too, so changing it never reuses a stale library.
    expected_stamp.extend_from_slice(include_bytes!("build.rs"));

    let archive = out.join(format!("lib{name}.a"));
    let stamp_file = out.join(format!("{name}.stamp"));
    if archive.is_file()
        && std::fs::read(&stamp_file)
            .ok()
            .is_some_and(|s| s == expected_stamp)
    {
        return;
    }

    // Every version has its own checkout, so that switching versions does not
    // clone again.
    let repo_dir = out.join(patch_dir);
    if !repo_dir.join(".git").exists() {
        let _ = std::fs::remove_dir_all(&repo_dir);
        run(
            Command::new("git")
                .args(["clone", "--no-checkout", version.repo])
                .arg(&repo_dir)
                .env("GIT_TERMINAL_PROMPT", "0"),
            &format!("git clone {}", version.repo),
        );
    }
    let git = |args: &[&str], desc: &str| {
        run(
            Command::new("git").arg("-C").arg(&repo_dir).args(args),
            desc,
        );
    };
    // A checkout made before the pinned commit existed may lack it.
    if !has_commit(&repo_dir, version.commit) {
        git(&["fetch", "origin"], &format!("git fetch {patch_dir}"));
    }
    git(
        &["checkout", "--force", version.commit],
        &format!("git checkout {patch_dir}@{}", version.commit),
    );
    let head = Command::new("git")
        .arg("-C")
        .arg(&repo_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("spawn git rev-parse");
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        version.commit,
        "{patch_dir} checkout is not at the pinned commit"
    );
    git(&["clean", "-fdx"], &format!("git clean {patch_dir}"));
    // One `git apply` per patch, in sorted order, so that a failure names the
    // patch.
    for patch in &patches {
        let file_name = patch
            .file_name()
            .expect("patch file name")
            .to_string_lossy();
        run(
            Command::new("git")
                .arg("-C")
                .arg(&repo_dir)
                .arg("apply")
                .arg(patch),
            &format!("git apply testing/patches/{patch_dir}/{file_name}"),
        );
    }

    let c_files = (version.sources)(&repo_dir);
    let include_dirs = (version.include_dirs)(&repo_dir);

    let obj_dir = out.join(format!("{name}-objs"));
    let _ = std::fs::remove_dir_all(&obj_dir);
    std::fs::create_dir_all(&obj_dir).expect("create obj_dir");

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let obj_paths: Vec<PathBuf> = c_files
        .iter()
        .enumerate()
        .map(|(i, src)| {
            let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("obj");
            obj_dir.join(format!("{i:03}_{stem}.o"))
        })
        .collect();

    let jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let chunk_size = c_files.len().div_ceil(jobs).max(1);
    std::thread::scope(|s| {
        for (src_chunk, obj_chunk) in c_files.chunks(chunk_size).zip(obj_paths.chunks(chunk_size)) {
            let (cc, include_dirs) = (&cc, &include_dirs);
            s.spawn(move || {
                for (src, obj) in src_chunk.iter().zip(obj_chunk.iter()) {
                    let mut cmd = Command::new(cc);
                    cmd.args(version.cflags);
                    for inc in include_dirs {
                        cmd.arg("-I").arg(inc);
                    }
                    cmd.arg("-c").arg(src).arg("-o").arg(obj);
                    let out = cmd.output().expect("spawn cc");
                    assert!(
                        out.status.success(),
                        "cc {} failed:\n{}",
                        src.display(),
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
            });
        }
    });

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

    let all_o = obj_dir.join(format!("{name}_all.o"));
    let isolated_o = obj_dir.join(format!("{name}_isolated.o"));
    let mut ld_cmd = Command::new("ld");
    ld_cmd.args(["-r", "-dc", "-o"]).arg(&all_o);
    for obj in &obj_paths {
        ld_cmd.arg(obj);
    }
    ld_cmd.arg(&libcrypto_a);
    run(&mut ld_cmd, &format!("ld -r {name}_all.o"));

    // `getpid()` (which seeds the reference's `rand()` together with the
    // clock) is redirected to the harness's `difftest_getpid()`, so that a
    // fixed seed (`TPM_REFERENCE_SEED`) can reproduce a run. This is a
    // link-level redirection; the C code is not changed.
    let redirected_o = obj_dir.join(format!("{name}_redirected.o"));
    run(
        Command::new("objcopy")
            .arg("--redefine-sym=getpid=difftest_getpid")
            .arg(&all_o)
            .arg(&redirected_o),
        &format!("objcopy redirect {name} getpid"),
    );
    let all_o = redirected_o;

    let mut objcopy_cmd = Command::new("objcopy");
    for sym in EXPORTED_SYMBOLS {
        objcopy_cmd.arg(format!("--keep-global-symbol={sym}"));
    }
    objcopy_cmd.arg(&all_o).arg(&isolated_o);
    run(
        &mut objcopy_cmd,
        &format!("objcopy localize {name} symbols"),
    );

    let _ = std::fs::remove_file(&archive);
    run(
        Command::new("ar").arg("crs").arg(&archive).arg(&isolated_o),
        &format!("ar crs lib{name}.a"),
    );

    std::fs::write(&stamp_file, &expected_stamp)
        .unwrap_or_else(|e| panic!("write {name}.stamp: {e}"));
}

/// Collects the `.c` files under `dir` (recursively, sorted) into `out`.
fn collect_c(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_c(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("c") {
            out.push(path);
        }
    }
}

/// The TCG reference's TPM library, platform and simulator command layer
/// (without the TCP server).
fn mstpm20_sources(repo: &Path) -> Vec<PathBuf> {
    let tpm_cmd = repo.join("TPMCmd");
    let mut c_files = Vec::new();
    collect_c(&tpm_cmd.join("Platform/src"), &mut c_files);
    collect_c(&tpm_cmd.join("TpmConfiguration"), &mut c_files);
    collect_c(&tpm_cmd.join("tpm/src"), &mut c_files);
    collect_c(&tpm_cmd.join("tpm/cryptolibs"), &mut c_files);
    c_files.push(tpm_cmd.join("Simulator/src/TPMCmdp.c"));
    c_files
}

fn mstpm20_include_dirs(repo: &Path) -> Vec<PathBuf> {
    let tpm_cmd = repo.join("TPMCmd");
    [
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
    ]
    .into_iter()
    .map(|d| tpm_cmd.join(d))
    .collect()
}

/// The TPM library, platform and simulator command layer (without the TCP
/// server) of the TCG reference's version 185, whose crypto code is split
/// into a common part and one implementation per algorithm family
/// (`tpm/cryptolibs/implementations/`); the implementations are the ones the
/// cflags select (as in the version's CMake build).
fn mstpm20_v185_sources(repo: &Path) -> Vec<PathBuf> {
    let tpm_cmd = repo.join("TPMCmd");
    let mut c_files = Vec::new();
    collect_c(&tpm_cmd.join("Platform/src"), &mut c_files);
    collect_c(&tpm_cmd.join("TpmConfiguration"), &mut c_files);
    collect_c(&tpm_cmd.join("tpm/src"), &mut c_files);
    collect_c(&tpm_cmd.join("tpm/cryptolibs/common"), &mut c_files);
    for implementation in MSTPM20_V185_CRYPTO_IMPLEMENTATIONS {
        collect_c(
            &tpm_cmd
                .join("tpm/cryptolibs/implementations")
                .join(implementation),
            &mut c_files,
        );
    }
    c_files.push(tpm_cmd.join("Simulator/src/TPMCmdp.c"));
    c_files
}

/// The crypto implementations (`TPMCmd/tpm/cryptolibs/implementations/`) the
/// TCG reference's version 185 is built with (its CMake defaults).
const MSTPM20_V185_CRYPTO_IMPLEMENTATIONS: [&str; 7] = [
    "EccRef",
    "KdfRef",
    "Ossl",
    "RandRef",
    "RsaRef",
    "TestTpmBigNum",
    "TpmBigNum",
];

fn mstpm20_v185_include_dirs(repo: &Path) -> Vec<PathBuf> {
    let tpm_cmd = repo.join("TPMCmd");
    let mut dirs: Vec<PathBuf> = [
        "TpmConfiguration",
        "tpm/include",
        "tpm/include/private",
        "tpm/include/private/prototypes",
        "tpm/include/platform_interface/Tpm_Platform_Interface",
        "tpm/include/platform_interface/Tpm_Platform_Interface/prototypes",
        "tpm/cryptolibs/common/include",
        "tpm/cryptolibs/interfaces",
        "Platform/include",
        "Platform/include/prototypes",
        "Simulator/include",
        "Simulator/include/prototypes",
    ]
    .into_iter()
    .map(|d| tpm_cmd.join(d))
    .collect();
    // Not every implementation has headers (e.g. `KdfRef`).
    dirs.extend(
        MSTPM20_V185_CRYPTO_IMPLEMENTATIONS
            .iter()
            .map(|implementation| {
                tpm_cmd
                    .join("tpm/cryptolibs/implementations")
                    .join(implementation)
                    .join("include")
            })
            .filter(|dir| dir.is_dir()),
    );
    dirs
}

/// The IBM TPM's object files of its Linux makefile (`OBJFILES` of
/// `src/makefile-common`), without the TCP server and `main()`
/// (`TPMCmds.c`).
fn ibmswtpm2_sources(repo: &Path) -> Vec<PathBuf> {
    let src = repo.join("src");
    let makefile = std::fs::read_to_string(src.join("makefile-common"))
        .expect("read ibmswtpm2 src/makefile-common");
    let list = makefile
        .split_once("OBJFILES =")
        .expect("OBJFILES in ibmswtpm2 makefile-common")
        .1;
    let mut c_files = Vec::new();
    for line in list.lines() {
        let line = line.trim().trim_end_matches('\\').trim();
        if line.is_empty() && !c_files.is_empty() {
            break;
        }
        let Some(stem) = line.strip_suffix(".o") else {
            continue;
        };
        if stem != "TPMCmds" {
            c_files.push(src.join(format!("{stem}.c")));
        }
    }
    assert!(c_files.len() > 100, "unexpected ibmswtpm2 OBJFILES list");
    c_files
}

fn ibmswtpm2_include_dirs(repo: &Path) -> Vec<PathBuf> {
    vec![repo.join("src")]
}
