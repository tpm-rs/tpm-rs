#!/usr/bin/env python3
"""Triage of a `diff_conversation` campaign (see ../SKILL.md).

  triage.py group <campaign dir> [--top N] [--no-render]
      Replays every artifact in <dir>/art on the campaign's frozen binary
      <dir>/diff_conversation and computes its signature (cached in
      <dir>/signatures.json). Groups signatures into families, copies the
      smallest input of each family's most frequent signature to
      <dir>/fam/NNN-<name>, minimizes the top N (default 40) families and
      renders each with `to_test` into <dir>/families.md.

  triage.py replay <old campaign dir> [binary]
      Replays the old campaign's artifacts on a newer binary (default: a
      fresh in-process build of the current tree) and reports, per old family,
      how many still reproduce. Writes <old dir>/replay.json.

Signature: the sorted set of finding strings of one input, with the round
number replaced by `round*`; otherwise PANIC[...], TIMEOUT, OOM, HANG,
NO_REPRO[...] (input no longer fails) or OTHER[rc=..].
Family: the same set of references and the same (tpm-rs rc, reference rc)
pair of the first divergence, for any command.
Tags: `us-only` (every reference answers TPM_RC_COMMAND_CODE and tpm-rs does
not), `them-only` (tpm-rs answers TPM_RC_COMMAND_CODE and the references
succeed), `spec` (everything else: check the spec).

Rendering with `to_test` uses process mode, so the reference binaries must be
built (`cargo build --release -p testing --features differential --bins`).
"""
import collections
import concurrent.futures as cf
import json
import os
import re
import shutil
import subprocess
import sys

R = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../.."))
CARGO = os.environ.get("CARGO", os.path.expanduser("~/.cargo/bin/cargo"))
SIG = re.compile(
    r"(DIVERGENCE|MALFORMED_RESPONSE|UNPARSEABLE_RESPONSE|BAD_RESPONSE_HMAC|"
    r"BAD_RESPONSE_AUTH|ACCEPTED_CORRUPT_HMAC)\[[^\]\s]*\]"
)
DIV = re.compile(r"DIVERGENCE\[([^:]+):[^:]+:([^:]+):([^:]+):([^\]]+)\]")
PANIC = re.compile(r"panicked at ([^\n]*):\n([^\n]*)")
ENV = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
CC_RC = "0x143"  # TPM_RC_COMMAND_CODE
UNRENDERABLE = ("NO_REPRO", "HANG", "TIMEOUT", "OOM")


def run(binary, path, extra=()):
    p = subprocess.run(
        [binary, path, "-detect_leaks=0", "-timeout=20", *extra],
        cwd=R, capture_output=True, text=True, errors="replace", env=ENV, timeout=300,
    )
    return p.returncode, p.stderr


def signature(binary, path):
    name = os.path.basename(path)
    try:
        rc, err = run(binary, path)
    except subprocess.TimeoutExpired:
        return "HANG"
    sigs = sorted({re.sub(r":round\d+:", ":round*:", m.group(0)) for m in SIG.finditer(err)})
    if sigs:
        return " ".join(sigs)
    m = PANIC.search(err)
    if m:
        return f"PANIC[{m.group(1)}: {m.group(2)[:120]}]"
    if "ERROR: libFuzzer: timeout" in err:
        return "TIMEOUT"
    if "out-of-memory" in err:
        return "OOM"
    if rc == 0:
        return f"NO_REPRO[{name.split('-')[0]}]"
    return f"OTHER[rc={rc}]"


def signatures(binary, files, workers=os.cpu_count() or 8):
    with cf.ThreadPoolExecutor(workers) as ex:
        return dict(zip(files, ex.map(lambda f: signature(binary, f), files)))


def family_of(sig):
    ds = DIV.findall(sig)
    if not ds:
        return sig, None
    impls = ",".join(sorted({d[0] for d in ds}))
    return f"{impls} tpm-rs {ds[0][2]} vs ref {ds[0][3]}", ds[0][1]


def tag(sig):
    parts = re.findall(r"DIVERGENCE\[[^:]+:[^:]+:[^:]+:([^:]+):([^\]]+)\]", sig)
    if parts and all(ref == CC_RC and rs != CC_RC for rs, ref in parts):
        return "us-only"
    if parts and all(rs == CC_RC and ref == "0x0" for rs, ref in parts):
        return "them-only"
    return "spec"


def minimize(binary, rep, sig):
    """Minimizes `rep`; keeps the result only if it has the same signature."""
    out = rep + ".min"
    try:
        subprocess.run([binary, rep, "-detect_leaks=0", "-minimize_crash=1",
                        "-max_total_time=60", f"-exact_artifact_path={out}"],
                       cwd=R, capture_output=True, env=ENV, timeout=200)
    except subprocess.TimeoutExpired:
        pass
    if os.path.exists(out) and signature(binary, out) == sig:
        return out
    return rep


def build_to_test():
    subprocess.run([CARGO, "build", "-q", "--release", "--manifest-path",
                    "testing/fuzz/Cargo.toml", "--bin", "to_test"], cwd=R, check=True)
    return os.path.join(R, "testing/fuzz/target/release/to_test")


def render(to_test, rep):
    env = dict(ENV, MSTPM20_BIN=f"{R}/target/release/mstpm20",
               IBMSWTPM2_BIN=f"{R}/target/release/ibmswtpm2")
    p = subprocess.run([to_test, rep], cwd=R, capture_output=True, text=True,
                       errors="replace", env=env, timeout=600)
    note = ("// NOTE: no finding when replayed on the current source (fixed since?)\n"
            if "without a finding" in p.stderr else "")
    return note + (p.stdout or p.stderr).rstrip()


def group(d, top, do_render):
    binary = os.path.join(d, "diff_conversation")
    art = os.path.join(d, "art")
    cache = os.path.join(d, "signatures.json")
    if os.path.exists(cache):
        sigs = json.load(open(cache))
    else:
        files = [os.path.join(art, f) for f in sorted(os.listdir(art))]
        sigs = signatures(binary, files)
        json.dump(sigs, open(cache, "w"), indent=0)
    fams = {}
    for path, sig in sigs.items():
        fam, cc = family_of(sig)
        f = fams.setdefault(fam, {"n": 0, "sigs": {}, "ccs": set()})
        f["n"] += 1
        f["sigs"].setdefault(sig, []).append(path)
        if cc:
            f["ccs"].add(cc)
    order = sorted(fams.items(), key=lambda kv: -kv[1]["n"])
    out_dir = os.path.join(d, "fam")
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir)
    reps = []
    for n, (fam, f) in enumerate(order):
        sig, paths = max(f["sigs"].items(), key=lambda kv: len(kv[1]))
        best = min(paths, key=os.path.getsize)
        rep = os.path.join(out_dir, f"{n:03d}-{os.path.basename(best)}")
        shutil.copy(best, rep)
        reps.append((sig, rep))
    renderable = [i for i, (s, _) in enumerate(reps[:top]) if not s.startswith(UNRENDERABLE)]
    with cf.ThreadPoolExecutor(12) as ex:
        for i, m in zip(renderable, ex.map(lambda i: minimize(binary, reps[i][1], reps[i][0]),
                                           renderable)):
            reps[i] = (reps[i][0], m)
    to_test = build_to_test() if do_render else None
    lines = [f"# Findings of {os.path.basename(d)} by family", "",
             f"{len(sigs)} artifacts, {len({s for s in sigs.values()})} signatures, "
             f"{len(order)} families.", ""]
    for n, ((fam, f), (sig, rep)) in enumerate(zip(order, reps)):
        lines += [f"## {n:03d}. [{tag(sig)}] {fam} ({f['n']} artifacts, "
                  f"{len(f['sigs'])} signatures)", "",
                  f"Commands: {', '.join(sorted(f['ccs'])) or '-'}", "",
                  f"Representative: `{rep}` (`{sig}`)", ""]
        if to_test and n < top and not sig.startswith(UNRENDERABLE):
            lines += ["```rust", render(to_test, rep), "```", ""]
    with open(os.path.join(d, "families.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"{len(sigs)} artifacts -> {len(set(sigs.values()))} signatures -> {len(order)} families")
    for fam, f in order[:top]:
        print(f"{f['n']:6d} {len(f['sigs']):4d}  [{tag(max(f['sigs'], key=lambda s: len(f['sigs'][s])))}] {fam}")
    print(f"report: {os.path.join(d, 'families.md')}")


def replay(old, binary):
    if binary is None:
        target = os.path.join(os.path.dirname(old), "fuzztarget")
        subprocess.run([CARGO, "fuzz", "build", "--fuzz-dir", "testing/fuzz", "-O", "-s", "none",
                        "--features", "inproc", "--target-dir", target, "diff_conversation"],
                       cwd=R, check=True)
        binary = os.path.join(target, "x86_64-unknown-linux-gnu/release/diff_conversation")
    sigs = json.load(open(os.path.join(old, "signatures.json")))
    files = sorted(sigs)
    new = signatures(binary, files)
    json.dump(new, open(os.path.join(old, "replay.json"), "w"), indent=0)
    still = [f for f in files if not new[f].startswith("NO_REPRO")]
    same = [f for f in still if new[f] == sigs[f]]
    print(f"{len(files)} old artifacts: {len(still)} still fail "
          f"({len(same)} with the same signature), {len(files) - len(still)} fixed")
    fam, tot = collections.Counter(), collections.Counter()
    for f in files:
        k = family_of(sigs[f])[0]
        tot[k] += 1
        if not new[f].startswith("NO_REPRO"):
            fam[k] += 1
    print(f"old families: {len(tot)}, still reproducing: {len(fam)}")
    for k, n in fam.most_common(40):
        print(f"{n:6d}/{tot[k]:<6d} {k}")
    newsig = collections.Counter(family_of(new[f])[0] for f in still)
    if newsig:
        print("new families of still-failing artifacts (top 20):")
        for k, n in newsig.most_common(20):
            print(f"{n:6d} {k}")


def main():
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] == "group":
        top = int(args[args.index("--top") + 1]) if "--top" in args else 40
        group(os.path.abspath(args[1]), top, "--no-render" not in args)
    elif len(args) >= 2 and args[0] == "replay":
        replay(os.path.abspath(args[1]), os.path.abspath(args[2]) if len(args) > 2 else None)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
