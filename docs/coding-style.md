# TPM-rs Coding Style and Contribution Guide

This document outlines the coding style adopted by TPM-rs. The principles
presented here are not entirely original; they are heavily inspired by, and in
some cases directly adapted from:
1. Previous tpm-rs discussions.
2. [Rust Compiler Development Guide](https://rustc-dev-guide.rust-lang.org/)
3. [Linux kernel coding
   style](https://www.kernel.org/doc/html/v4.10/process/coding-style.html).
4. [Kernel patch submission
   guidelines](https://www.kernel.org/doc/html/v4.10/process/submitting-patches.html)
5. [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)

We have chosen to simplify the organizational aspects of contributions found in
the *Rust Compiler* and *Linux Kernel* guidelines, the overhead outweighs the
benefits for our specific context.

## Code Structure

### Formatting, Naming, and Linting

We adhere to the [the Rust standard coding
style](https://github.com/rust-lang/style-team). Code should always conform to
the latest version of `rustfmt` and the style recommendations provided by
`cargo clippy` at the time of submission.

In cases where the name of a data structure specified by the [TPM Library
Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
conflicts with *the Rust standard coding style*, we will choose a name that
aligns with *the Rust standard coding style* while remaining as close as
possible to the original name from the *TPM Library Specification*.

### Comments

Prefer `//`, `//!`, and `///` for both single-line and multi-line comments.
Please also avoid including license boilerplate at the beginning of every file.

Comments should provide sufficient information for the reader to understand how
and when to use the code, as well as any important considerations for its
correct implementation. Avoid stating the obvious or simply describing what the
code does.

Try to avoid multiple empty lines, and comment boxes. Try to limit placing
comments within a function body. If a function is complex enough to require
extensive comments, it may be a sign that it should be refactored. Small
comments can be used to highlight or caution against particularly clever (or
ugly) solutions. However, overly clever implementations should be avoided, as
`tpm-rs` aims to serve as a reference implementation.

### Traits

Public traits on public types expose APIs that users may rely on. Therefore, it
is important to consider them carefully. Limit exposure by making only
necessary methods and properties public. Keep internal helper functions
private, either by using a sealed trait or by placing them within a private
module whenever applicable.

Manual trait implementations should be placed after the `impl` blocks for a
type if they are in the same file. Whenever possible, order trait
implementations by the name of the trait being implemented. If there are
multiple implementations of the same trait for a type, further order them by
the generic arguments present.

Trait names and their corresponding derive macros should share the same name.
For example, the derive macro for the trait `Deserialize` should also be named
`Deserialize`.

### Macros

Avoid defining `macro_rules` unless absolutely necessary. If a macro is closely
related to a particular type, its invocation should be placed near the type
definition it is invoked on.

Macros should be self-contained. Be cautious about relying on implicit imports
from a parent module. Instead, prefer using fully qualified names to ensure
that your macro functions correctly in any environment.

Define macros in a way that exposes only what is necessary. If a macro
generates functions or types, ensure that they are not publicly accessible
unless explicitly intended.

### Unsafe Code

Avoid including unsafe code in [tpm-rs](https://github.com/tpm-rs/tpm-rs)
repository. When creating a new crate, add `#![forbid(unsafe_code)]` to
prohibit the use of unsafe codes.

### Preludes

Avoid using `super::*` outside of tests. It is acceptable to use the pattern
pub use `some::path::*` for re-exporting symbols.

### Modules

Prefer placing data types with business logic in their own separate submodule.
If a particular type has complex business logic, it is encoraged to separate
each independent part of the logic into smaller submodules whenever applicable.

### Tests

Prefer placing tests in their own separate files. However, if the tests are
small, it is acceptable to include them in the same file as the implementation.

## Feature Flags

When adding a new feature flag, consider including the corresponding GitHub
workflows for `cargo clippy` and `cargo test`.

### Crates

Avoid nested Crates. Define all crates at the top level root directory. This
enhances accessibility for newcomers, and prevents confusion about which crates
belong to the project.

Ensure that all crate names start with the `tpm2-rs-` prefix, and organize the
folder structure in the root directory by their full crate name, excluding the
`tpm2-rs-` prefix.

Each crate must include a `README.md` file. In that file, provide a concise
description of the crate's purpose and functionality. Whenever possible,
include usage examples that demonstrate how to use the crate, as well as a list
of all feature flags and their functionalities.

Avoid introducing new dependencies within an individual crate. Instead, declare
the dependency at the top level in the `Cargo.toml` file under
`workspace.dependencies`, and reference that workspace dependency within the
crate.

### Third Party Crates.

Before adding a new third-party crate to the top-level `Cargo.toml`, ensure
that you review the crate's license for compatibility with our
[license](https://github.com/tpm-rs/tpm-rs/blob/main/LICENSE.md). After that,
please create an [issue](https://github.com/tpm-rs/tpm-rs/issues) outlining the
need for the crate. In your description, clarify the specific problems the
crate addresses and how it aligns with the project's goals. Additionally,
including small code snippets that illustrate the crate's application in our
specific use case would be greatly appreciated.

## How to Structure Your Pull Request

- **Rebase to `main` branch**: all pull requests should be submitted against
  the `main` branch, unless you know for sure that you should target a
  different branch.

- **Isolate "pure refactorings" into their own separate pull requests**: For
  example, if you rename a method, then put that rename into its own pull
  request, along with the renames of all the uses.

- **Smaller pull requests are usually better**: If you are committing a large
  change, it's almost always better to break it up into smaller steps that can
  be independently reviewed. Each pull request should be justifiable on its own
  merits.

- **Pay extra attention to the title and body of your pull requests
  (commits)**: As for the title, describe your changes using the imperative
  mood. In the body, outline the user-visible impact, quantifying any
  optimizations and trade-offs. If you claim improvements in performance,
  memory consumption, stack footprint, or binary size, include supporting
  numbers. Additionally, describe any non-obvious costs. If the patch results
  from earlier issue discussions or relevant documentation, be sure to include
  links to those sources.

  Example of good commit message from the linux kernel:
  ```
  distinguish rcv vs sent backup flag in requests

  When sending an MP_JOIN + SYN + ACK, it is possible to mark the subflow
  as 'backup' by setting the flag with the same name. Before this patch,
  the backup was set if the other peer set it in its MP_JOIN + SYN
  request.

  It is not correct: the backup flag should be set in the MPJ+SYN+ACK only
  if the host asks for it, and not mirroring what was done by the other
  peer. It is then required to have a dedicated bit for each direction,
  similar to what is done in the subflow context.

  Fixes: f296234 ("mptcp: Add handling of incoming MP_JOIN requests")
  ```

-  **Prefer squash and merge**: Squash and merge is the strongly preferred and
   default method for handling all pull requests. *Fast-forward* merges are
   exceptions and may only be allowed when absolutely necessary. If a pull
   request requires a *fast-forward* merge, it must be explicitly stated in the
   pull request description.

   When dividing your change into a series of commits for *fast-forward* merge,
   take special care to ensure that `tpm-rs` builds and runs properly after
   each commit in the series. Developers using `git bisect` to track down a
   problem can end up splitting your patch series at any point; they will not
   thank you if you introduce bugs in the middle.

   When working with *fast-forward* merges, be mindful that if you implement a
   certain design in one commit and then make significant changes to that code
   in a later commit (as opposed to simply adding to it) within the same patch
   series, it can create confusion. To maintain clarity for reviewers, it's
   best to avoid drastic shifts in implementation between commits in the same
   series, as this can make it harder to follow the evolution of your changes.

- **Do not add merge commits**: We do not allow merge commits into our history.
  If you get a merge conflict, rebase instead via a command like `git rebase -i
  origin/main` (presuming you use the name origin for your remote).

- **Developers must agree to the CLA before contributing**: All contributors
  are required to sign tpm-rs's
  [CLA](https://github.com/tpm-rs/tpm-rs/blob/main/CONTRIBUTING.md). After
  submitting your *first* pull request, you should reply to that pull request
  in github with the following message:
  ```
  I have read the CLA Document and I hereby sign the CLA
  ```
