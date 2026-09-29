use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const BORINGSSL_REPO_URL: &str = "https://boringssl.googlesource.com/boringssl";

// Keep in sync with the list in include/openssl/opensslconf.h
const OSSL_CONF_DEFINES: &[&str] = &[
    "OPENSSL_NO_ASYNC",
    "OPENSSL_NO_BF",
    "OPENSSL_NO_BLAKE2",
    "OPENSSL_NO_BUF_FREELISTS",
    "OPENSSL_NO_CAMELLIA",
    "OPENSSL_NO_CAPIENG",
    "OPENSSL_NO_CAST",
    "OPENSSL_NO_CMS",
    "OPENSSL_NO_COMP",
    "OPENSSL_NO_CT",
    "OPENSSL_NO_DANE",
    "OPENSSL_NO_DEPRECATED",
    "OPENSSL_NO_DGRAM",
    "OPENSSL_NO_DYNAMIC_ENGINE",
    "OPENSSL_NO_EC_NISTP_64_GCC_128",
    "OPENSSL_NO_EC2M",
    "OPENSSL_NO_EGD",
    "OPENSSL_NO_ENGINE",
    "OPENSSL_NO_GMP",
    "OPENSSL_NO_GOST",
    "OPENSSL_NO_HEARTBEATS",
    "OPENSSL_NO_HW",
    "OPENSSL_NO_IDEA",
    "OPENSSL_NO_JPAKE",
    "OPENSSL_NO_KRB5",
    "OPENSSL_NO_MD2",
    "OPENSSL_NO_MDC2",
    "OPENSSL_NO_OCB",
    "OPENSSL_NO_OCSP",
    "OPENSSL_NO_RC2",
    "OPENSSL_NO_RC5",
    "OPENSSL_NO_RFC3779",
    "OPENSSL_NO_RIPEMD",
    "OPENSSL_NO_RMD160",
    "OPENSSL_NO_SCTP",
    "OPENSSL_NO_SEED",
    "OPENSSL_NO_SM2",
    "OPENSSL_NO_SM3",
    "OPENSSL_NO_SM4",
    "OPENSSL_NO_SRP",
    "OPENSSL_NO_SSL_TRACE",
    "OPENSSL_NO_SSL2",
    "OPENSSL_NO_SSL3",
    "OPENSSL_NO_SSL3_METHOD",
    "OPENSSL_NO_STATIC_ENGINE",
    "OPENSSL_NO_STORE",
    "OPENSSL_NO_WHIRLPOOL",
];

fn get_cpp_runtime_lib() -> Option<String> {
    println!("cargo:rerun-if-env-changed=BORINGSSL_RUST_CPPLIB");

    if let Ok(cpp_lib) = env::var("BORINGSSL_RUST_CPPLIB") {
        return Some(cpp_lib);
    }

    if env::var_os("CARGO_CFG_UNIX").is_some() {
        match env::var("CARGO_CFG_TARGET_OS").as_deref() {
            Ok("macos") => Some("c++".into()),
            _ => Some("stdc++".into()),
        }
    } else {
        None
    }
}

fn ensure_bssl_source(out_dir: &PathBuf) -> PathBuf {
    let bssl_source_dir = match env::var("BORINGSSL_SOURCE_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => out_dir.join("boringssl"),
    };

    if !bssl_source_dir.exists() {
        println!(
            "cargo:warning=Cloning official BoringSSL repository from {} into {}...",
            BORINGSSL_REPO_URL,
            bssl_source_dir.display()
        );
        let clone_status = Command::new("git")
            .args([
                "clone",
                "--depth=1",
                BORINGSSL_REPO_URL,
                bssl_source_dir.to_str().unwrap(),
            ])
            .status()
            .expect("Failed to execute git clone for BoringSSL");

        if !clone_status.success() {
            panic!(
                "Failed to clone official BoringSSL repository from {}",
                BORINGSSL_REPO_URL
            );
        }
    }

    bssl_source_dir
}

fn main() {
    println!("cargo:rerun-if-env-changed=BORINGSSL_BUILD_DIR");
    println!("cargo:rerun-if-env-changed=BORINGSSL_SOURCE_DIR");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set"));

    // If BORINGSSL_BUILD_DIR is set, use it. Otherwise, use an idiomatic build path in OUT_DIR.
    let bssl_build_dir = match env::var("BORINGSSL_BUILD_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => out_dir.join("build"),
    };

    let bssl_source_dir = ensure_bssl_source(&out_dir);

    let target = env::var("TARGET").unwrap_or_else(|_| "x86_64-unknown-linux-gnu".to_string());
    let bssl_sys_build_dir = bssl_build_dir.join("rust/bssl-sys");
    let binding_file = bssl_sys_build_dir.join(format!("wrapper_{}.rs", target));

    if !binding_file.exists() {
        println!(
            "cargo:warning=BoringSSL bindings not found at {}. Building BoringSSL...",
            binding_file.display()
        );

        // 1. Run CMake (always use Release build)
        let cmake_status = Command::new("cmake")
            .arg("-GNinja")
            .arg("-S")
            .arg(&bssl_source_dir)
            .arg("-B")
            .arg(&bssl_build_dir)
            .arg("-DCMAKE_BUILD_TYPE=Release")
            .arg(format!("-DRUST_BINDINGS={}", target))
            .arg("-DBUILD_TESTING=OFF")
            .status()
            .expect("Failed to execute cmake");

        if !cmake_status.success() {
            panic!("CMake configuration failed for BoringSSL");
        }

        // 2. Run Ninja
        let ninja_status = Command::new("ninja")
            .arg("-C")
            .arg(&bssl_build_dir)
            .status()
            .expect("Failed to execute ninja");

        if !ninja_status.success() {
            panic!("Ninja build failed for BoringSSL");
        }
    }

    // Copy the generated target platform bindings into OUT_DIR/bindgen.rs.
    let bindgen_out_file = out_dir.join("bindgen.rs");
    fs::copy(&binding_file, &bindgen_out_file).unwrap_or_else(|e| {
        panic!(
            "Could not copy bindings from '{}' to '{}': {}",
            binding_file.display(),
            bindgen_out_file.display(),
            e
        )
    });
    println!("cargo:rerun-if-changed={}", binding_file.display());

    // Generate OUT_DIR/bssl_sys_lib.rs from official BoringSSL's rust/bssl-sys/src/lib.rs,
    // filtering out top-level inner attributes (#![...]) so it can be cleanly included.
    let upstream_lib_rs = bssl_source_dir.join("rust/bssl-sys/src/lib.rs");
    let lib_content = fs::read_to_string(&upstream_lib_rs).unwrap_or_else(|e| {
        panic!(
            "Could not read upstream bssl-sys lib.rs at '{}': {}",
            upstream_lib_rs.display(),
            e
        )
    });
    let filtered_lib_content: String = lib_content
        .lines()
        .filter(|line| !line.trim_start().starts_with("#!["))
        .collect::<Vec<_>>()
        .join("\n");
    let lib_out_file = out_dir.join("bssl_sys_lib.rs");
    fs::write(&lib_out_file, filtered_lib_content).unwrap_or_else(|e| {
        panic!(
            "Could not write generated bssl_sys_lib.rs to '{}': {}",
            lib_out_file.display(),
            e
        )
    });

    // Statically link BoringSSL libraries.
    println!(
        "cargo:rustc-link-search=native={}",
        bssl_build_dir.display()
    );
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    println!(
        "cargo:rustc-link-search=native={}",
        bssl_sys_build_dir.display()
    );
    println!("cargo:rustc-link-lib=static=rust_wrapper");

    if let Some(cpp_lib) = get_cpp_runtime_lib() {
        println!("cargo:rustc-link-lib={}", cpp_lib);
    }

    println!("cargo:conf={}", OSSL_CONF_DEFINES.join(","));
}
