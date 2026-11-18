# TPM 2.0 Specification

tpm-rs implements the Trusted Computing Group (TCG) TPM 2.0 Library
Specification, Version 185, as amended by Errata Version 1 (Errata v1). This
directory holds a copy of that specification and tracks two kinds of problems
found while implementing it:

- **Spec bugs** ([`SpecBugs.md`](SpecBugs.md)): places where the specification
  itself is wrong or incomplete, so an implementation cannot follow it as
  written.
- **Reference spec conflicts**
  ([`ReferenceSpecConflicts.md`](ReferenceSpecConflicts.md)): places where the
  TCG reference implementation (`tcgtpm`) does something the specification
  forbids.

The two are kept apart because they are fixed in different places: a spec bug
needs a change to the specification (an erratum or a later version), while a
reference spec conflict usually needs a change to the reference implementation.
Every issue listed here should eventually be fixed in one of these ways. Until
then, each entry records what tpm-rs does.

Choices that the specification deliberately leaves to the implementation are not
tracked here, even when tpm-rs and `tcgtpm` choose differently. Neither are
obvious typos (such as `TPM_RC_NV_INITIALIZED` for `TPM_RC_NV_UNINITIALIZED`).

## Specification (`tpm2_v185/`)

The PDF files in [`tpm2_v185/`](tpm2_v185) were obtained from the TCG at
https://trustedcomputinggroup.org/resource/tpm-library-specification/.

| File | Document |
| :--- | :--- |
| [`Part-0-Introduction.pdf`](tpm2_v185/Part-0-Introduction.pdf) | Part 0: Introduction |
| [`Part-1-Architecture.pdf`](tpm2_v185/Part-1-Architecture.pdf) | Part 1: Architecture |
| [`Part-2-Structures.pdf`](tpm2_v185/Part-2-Structures.pdf) | Part 2: Structures |
| [`Part-3-Commands.pdf`](tpm2_v185/Part-3-Commands.pdf) | Part 3: Commands |
| [`Errata-v1.pdf`](tpm2_v185/Errata-v1.pdf) | Errata for Version 185, Version 1 (2026-03-12) |

Errata v1 supersedes the clauses of Version 185 that it amends. tpm-rs treats
requirements in Part 1 and in the errata as normative, like those in Parts 2
and 3. A contradiction between any of these is a spec bug.

## Spec Bugs (`SpecBugs.md`)

A spec bug is a place where the specification contradicts itself, contradicts a
standard it relies on (such as the RFC that defines a cryptographic algorithm),
or leaves out a requirement it needs, so that an implementation cannot follow it
as written.

For example, Part 1 computes an X25519 shared secret by multiplying by the
curve's cofactor, while Part 2 defines it as the X25519 function of RFC 7748,
which already accounts for the cofactor. The two give different results, so an
implementation has to pick one.

Each entry uses this template:

```markdown
### Spec Bug N: <short description>

- **Spec:** <the clauses involved, what each says, and why they cannot be
  followed as written>
- **Fix:** <the proposed change to the specification, or "Undecided" followed
  by the options>
- **Reference implementation:** <what `tcgtpm` does>
- **tpm-rs:** <what tpm-rs does>
```

## Reference Spec Conflicts (`ReferenceSpecConflicts.md`)

A reference spec conflict is a place where `tcgtpm` does something that the
specification directly forbids. The fix is a change to the reference
implementation or, if the reference behavior is the better one, to the
specification.

For example, the specification says that `TPM2_SignDigest` does not support
HMAC keys, but `tcgtpm` signs with them.

A difference that the specification permits is not a conflict. For example, the
specification lets each implementation choose the format of a saved context
(`TPM2B_CONTEXT_DATA`), so tpm-rs need not use the format that `tcgtpm` does.

Each entry uses this template:

```markdown
### Spec Conflict N: <short description>

- **Spec:** <the requirement, with its clause>
- **Fix:** <the proposed change to the reference implementation or to the
  specification, or "Undecided" followed by the options>
- **Reference implementation:** <what `tcgtpm` does instead, with the file or
  function>
- **tpm-rs:** <what tpm-rs does>
```

## Entries

Each file numbers its entries separately, in the order they are added. Numbers
are never reused. When an issue is fixed upstream, add a **Fixed in:** field
naming the errata version or reference implementation change, rather than
deleting the entry.

The **tpm-rs** field describes the current or intended behavior of tpm-rs. Parts
of it may not be implemented yet.
