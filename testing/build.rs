//! Builds the C reference TPMs for differential testing.
//!
//! With the `differential` feature, the build clones every reference
//! implementation at a pinned commit, applies its patches, compiles it into a
//! symbol-isolated static library (exporting only the `difftest_*` entry
//! points) and links that library into the reference binary of the same name
//! (see `src/differential/mod.rs`):
//!
//! * `mstpm20`: `https://github.com/TrustedComputingGroup/TPM` (the TCG / Microsoft
//!   reference implementation), patched by `testing/patches/mstpm20/*.patch`;
//! * `ibmswtpm2`: `https://github.com/kgoldman/ibmswtpm2` (the IBM software
//!   TPM), patched by `testing/patches/ibmswtpm2/*.patch`.
//!
//! Every patch file holds one individual fix (a spec-deviation bug fix, a
//! profile or platform setting, harness plumbing or a build fix), described by
//! the plain-text header before its first `diff --git` line, and is named
//! `<classification>-<fix>.patch` (see [`PATCH_CLASSES`]). The patches of a
//! reference are applied with `git apply` in sorted file-name order.
//!
//! Without the feature, nothing is built.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A C reference TPM implementation built for differential testing.
struct Reference {
    /// Name of the implementation, its patch directory
    /// (`testing/patches/<name>/`), its static library (`lib<name>.a`) and the
    /// binary it is linked into.
    name: &'static str,
    /// Git repository of the implementation.
    repo: &'static str,
    /// Pinned commit of `repo`.
    commit: &'static str,
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
        repo: "https://github.com/TrustedComputingGroup/TPM",
        commit: "3b1f0e623f244abe2015df9e3ba86de5c9118524",
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
    Reference {
        name: "ibmswtpm2",
        repo: "https://github.com/kgoldman/ibmswtpm2",
        commit: "e1df46e46fc2671e55372d65f27ecbb3c789d992",
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
        // The references are independent; build them concurrently.
        std::thread::scope(|s| {
            for reference in &REFERENCES {
                let (manifest, out) = (&manifest, &out);
                s.spawn(move || build_reference(reference, manifest, out));
            }
        });
        for reference in &REFERENCES {
            let name = reference.name;
            let archive = out.join(format!("lib{name}.a"));
            // Each library goes into its own binary only (both export the
            // same `difftest_*` entry points).
            println!("cargo:rustc-link-arg-bin={name}={}", archive.display());
            println!("cargo:rustc-link-arg-bin={name}=-lz");
            println!("cargo:rustc-link-arg-bin={name}=-lzstd");
        }
    }
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

/// Returns the patches of reference `name`: every `*.patch` file in
/// `testing/patches/<name>/`, in sorted file-name order (the order in which
/// they are applied), and asks Cargo to rerun the build script when the
/// directory or any patch changes.
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

/// Clones `reference` at its pinned commit, applies its patches, compiles it,
/// partially links it with `libcrypto.a` while localizing every symbol but
/// the `difftest_*` entry points (so that neither the reference's nor
/// OpenSSL's symbols collide with `bssl-sys`), and archives the result as
/// `lib<name>.a` in `out`.
fn build_reference(reference: &Reference, manifest: &Path, out: &Path) {
    let name = reference.name;
    let patches = patch_files(manifest, name);

    let mut expected_stamp = format!("{}@{}\n", reference.repo, reference.commit).into_bytes();
    // Every patch (its file name, which determines the order, and its
    // contents) is part of the stamp, so adding, removing, renaming or
    // editing a patch never reuses a stale library.
    for patch in &patches {
        let file_name = patch
            .file_name()
            .expect("patch file name")
            .to_string_lossy();
        let bytes = std::fs::read(patch)
            .unwrap_or_else(|e| panic!("read testing/patches/{name}/{file_name}: {e}"));
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

    let repo_dir = out.join(name);
    if !repo_dir.join(".git").exists() {
        let _ = std::fs::remove_dir_all(&repo_dir);
        run(
            Command::new("git")
                .args(["clone", "--no-checkout", reference.repo])
                .arg(&repo_dir),
            &format!("git clone {}", reference.repo),
        );
    }
    let git = |args: &[&str], desc: &str| {
        run(
            Command::new("git").arg("-C").arg(&repo_dir).args(args),
            desc,
        );
    };
    // A checkout made before the pinned commit existed may lack it.
    let has_commit = Command::new("git")
        .arg("-C")
        .arg(&repo_dir)
        .args([
            "cat-file",
            "-e",
            &format!("{}^{{commit}}", reference.commit),
        ])
        .status()
        .is_ok_and(|s| s.success());
    if !has_commit {
        git(&["fetch", "origin"], &format!("git fetch {name}"));
    }
    git(
        &["checkout", "--force", reference.commit],
        &format!("git checkout {name}@{}", reference.commit),
    );
    let head = Command::new("git")
        .arg("-C")
        .arg(&repo_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("spawn git rev-parse");
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        reference.commit,
        "{name} checkout is not at the pinned commit"
    );
    git(&["clean", "-fdx"], &format!("git clean {name}"));
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
            &format!("git apply testing/patches/{name}/{file_name}"),
        );
    }

    let c_files = (reference.sources)(&repo_dir);
    let include_dirs = (reference.include_dirs)(&repo_dir);

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
                    cmd.args(reference.cflags);
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
