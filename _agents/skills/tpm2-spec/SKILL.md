---
name: tpm2-spec
description: The TPM 2.0 spec (version 185) and where to get the C reference implementations (mstpm20 v185, ibmswtpm2)
---

# The TPM 2.0 spec and the C reference implementations

This skill provides:
1. The TPM 2.0 Library specification, version 185, as text files in
   `resources/spec`.
2. Where to get the C reference implementations `mstpm20` (version 185) and
   `ibmswtpm2`, so that you can clone and read them.

## The spec (version 185)

`resources/spec` holds the TPM 2.0 Library specification, version 185, as text:

| File | Content |
|---|---|
| `part0.tcg.txt` | Part 0: Introduction |
| `part1.tcg.txt` | Part 1: Architecture |
| `part2.tcg.txt` | Part 2: Structures (types, unmarshal tables, `#TPM_RC_*` rows) |
| `part3.tcg.txt` | Part 3: Commands (each command's description and detailed actions, command/handle/session validation, response codes) |
| `errata.tcg.txt` | Errata for version 185 |

The spec is the ground truth. Check it whenever you are unsure how the TPM
should behave. The files are large, so `grep` them for a command name
(e.g. `TPM2_ContextLoad`), a type (e.g. `TPMI_RH_HIERARCHY`) or a section title
rather than reading them whole.

## The C reference implementations

Read these to see how a TPM actually behaves, especially where the spec is
silent. `tpm-rs` follows the spec first and `mstpm20` only where the spec is
silent; `ibmswtpm2` never decides.

| Implementation | Repository |
|---|---|
| `mstpm20` v185 (TCG reference implementation) | https://github.com/TrustedComputingGroup/TPM-Internal, tag `v185.0.0` |
| `ibmswtpm2` (IBM software TPM), latest | https://github.com/kgoldman/ibmswtpm2 |

Clone them into `/tmp/` or into your artifact folder, never into the
repository:

```sh
git clone --depth 1 --branch v185.0.0 https://github.com/TrustedComputingGroup/TPM-Internal /tmp/mstpm20-v185
git clone --depth 1 https://github.com/kgoldman/ibmswtpm2 /tmp/ibmswtpm2
```

Reuse an existing clone if one is already there.

- `TPM-Internal` is a TCG-internal repository. If the clone fails for lack of
  access, use the public TCG reference implementation
  https://github.com/TrustedComputingGroup/TPM instead, and say that what you
  read is not version 185.
- The differential tests run these references at pinned commits with the
  patches in `testing/patches/<name>/` applied (see `testing/build.rs` and
  `differential.md`). The latest `ibmswtpm2` and an unpatched clone can
  therefore behave differently from the references that `tpm-rs` is
  compared against. Check the patches before you draw conclusions about a
  differential result.
