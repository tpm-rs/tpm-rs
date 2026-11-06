#!/usr/bin/env python3
"""BoringSSL tooling for tpm2-boringssl. The source is Cargo's checkout of the
`bssl-sys` patched in the workspace's `.cargo/config.toml`, so it's always the
pinned revision.

  boringssl.py build  Build BoringSSL into $BORINGSSL_BUILD_DIR (default:
                      target/boringssl), for $RUST_TARGET (default: the host).

Needs CMake, a C/C++ compiler, and the `bindgen` CLI (or $BINDGEN). CMake uses
its default generator unless $CMAKE_GENERATOR is set (e.g. to `Ninja`).
"""

import json, os, re, subprocess, sys
from pathlib import Path

CRATE = Path(__file__).resolve().parent
ROOT = CRATE.parents[1]
BINDGEN = os.environ.get("BINDGEN", "bindgen")


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, text=True, **kwargs)


def boringssl_src():
    meta = json.loads(run("cargo", "metadata", "--format-version=1", capture_output=True).stdout)
    return next(Path(p["manifest_path"]).parents[2] for p in meta["packages"] if p["name"] == "bssl-sys")


def build():
    out = os.environ.get("BORINGSSL_BUILD_DIR", ROOT / "target/boringssl")
    host = re.search(r"host: (\S+)", run("rustc", "-vV", capture_output=True).stdout)[1]
    target = os.environ.get("RUST_TARGET", host)
    os.environ.setdefault("CMAKE_BUILD_PARALLEL_LEVEL", str(os.cpu_count()))
    run("cmake", "-S", boringssl_src(), "-B", out, "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_TESTING=OFF", f"-DRUST_BINDINGS={target}", f"-DBINDGEN_EXECUTABLE={BINDGEN}")
    run("cmake", "--build", out, "--target", "bssl_sys")
    # `bssl-sys` only reruns its build script when the bindings change.
    run("cargo", "clean", "--quiet", "-p", "bssl-sys")


if __name__ == "__main__":
    commands = {"build": build}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit(__doc__)
    commands[sys.argv[1]]()
