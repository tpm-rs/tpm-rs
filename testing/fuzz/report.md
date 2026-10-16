# Differential fuzzing of tpm-rs: final report

This report covers the differential fuzzing campaign of `tpm-rs` against the
C reference TPMs `mstpm20` (TCG reference, version 185) and `ibmswtpm2` with
the `diff_conversation` target (see [README.md](README.md)): what the fuzzer
reached, every `tpm-rs` bug it found and how each was fixed, and the
discrepancies that are still deliberately ignored.

All findings were differential: a response of `tpm-rs` that differs from both
(or one) of the references, compared byte for byte with the fixed reference
seed `4242:1000000`. The fuzzer never found a `tpm-rs` panic, hang,
out-of-memory, malformed response, unparseable success response or bad
response HMAC. Bugs in the C references are out of scope here; they are fixed
by `testing/patches/**/bug-fix-*.patch` and documented in
[differential.md](../../differential.md).

## 1. Coverage

### 1.1 Campaigns

Before the campaigns, two pre-campaign smoke runs (120 s each, AddressSanitizer, reference processes, one fork) exercised the target from an empty corpus and from the first seed corpus; their findings were fixed before campaign 1.

All campaigns use the recommended build (`cargo fuzz build -O -s none
--features inproc diff_conversation`), the dictionary
[tpm2.dict](tpm2.dict), `-fork=72 -ignore_crashes=1 -max_total_time=1800`,
and start from the seed corpus of the time (campaigns 1–3: 1,049 inputs; campaigns 4 and 5: the grown corpus of 1.2). `cov` is libFuzzer's edge count and `ft`
its feature count (Rust code only: the C references are not instrumented). An
artifact is one crashing input; artifacts are grouped into signatures
(`DIVERGENCE[<impl>:round*:<cc>:<rs_rc>:<ref_rc>]`) and families (the same
references and the same `tpm-rs`/reference response-code pair, any command).

| Run | Execs | Exec/s (72 forks) | cov / ft | Corpus (start → end) | Artifacts → signatures → families |
|---|---|---|---|---|---|
| Campaign 1 | 6,836,711 | 3,798 | 11,274 / 45,733 | 1,049 → 8,229 | 23,538 → 625 → 213 |
| Campaign 2 | 9,427,468 | 5,237 | 11,154 / 44,423 | 1,049 → 7,901 | 346 → 9 → 7 |
| Campaign 3 | 10,680,854 | 5,894 | 11,161 / 44,695 | 1,049 → 7,876 | 27 → 8 → 6 |
| Campaign 4 | 7,944,395 | 4,411 | 11,343 / 45,402 | 2,067 → 6,507 | 10 → 7 → 7 |
| Campaign 5 | 7,897,970 | 4,385 | 11,343 / 45,468 | 2,067 → 6,556 | **0** (clean) |

Between campaigns, all families were triaged and fixed. Replaying the
campaign-1 artifacts on the campaign-2 binary, 23,496 of 23,538 no longer
crashed; replaying the campaign-2 artifacts on the campaign-3 binary, 325 of
346 no longer crashed; all 27 campaign-3 artifacts replay clean on the
campaign-4 binary, and all 10 campaign-4 artifacts on the campaign-5 binary.
Campaign 5 found nothing: no crash, timeout or out-of-memory input, with an
empty `known_divergences.txt`. Campaigns 4 and 5 started from the grown corpus (see 1.2), which is why they
execute fewer, longer inputs than campaign 3.

### 1.2 Seed corpus and input-model measurements

| Measurement (5-minute runs, one fork) | Execs | Exec/s | cov / ft |
|---|---|---|---|
| Empty corpus | 1,228,302 | 4,094 | 3,587 / 7,388 |
| Seed corpus (E2E and Go traces, 987 inputs) | 20,063 | 67 | 9,199 / 28,396 |
| Seed corpus before the ECC variants (987 + 2 session seeds) | 19,509 | 64 | 9,283 / 28,829 |
| Seed corpus with the ECC variants (`trace2conv --ecc-variants`) | 43,028 | 134 | 9,420 / 29,992 |

The seed corpus (converted from the E2E and Go-parity suites with
`trace2conv`) reaches 2.6 times the edges and 3.8 times the features of an
empty corpus in the same time. Rewriting RSA key templates to ECC P-256
doubled the executions per second without losing coverage. In-process
references (`--features inproc`) are 12% faster than reference processes on
an empty corpus and about the same on the real corpus, where `tpm-rs`'s own key
generation dominates.

The final seed corpus `corpus/diff_conversation/` (2,067 files,
1.4 MB; generated locally and gitignored, see
[README.md](README.md#the-seed-corpus) for how to regenerate it) holds the 1,049 seed inputs (trace conversions, ECC
variants, and the HMAC, salted-session and policy seeds of the session
engine) plus an edge-preserving set-cover minimization (`-set_cover_merge=1
-use_counters=0`) of the campaign-2 and campaign-3 corpora, which keeps all
11,369 edges they reached.

### 1.3 `tpm2-impl` handler coverage

Source-based coverage (`cargo fuzz coverage`, then `llvm-cov report`) of
replaying the final seed corpus once, over
[crates/tpm2-impl/src/handler/](../../crates/tpm2-impl/src/handler/):

Files are sorted by line coverage, lowest first.

| Handler file | Lines | Line coverage | Region coverage | Function coverage |
|---|---|---|---|---|
| [policy_counter_timer.rs](../../crates/tpm2-impl/src/handler/policy_counter_timer.rs) | 151 | 58.28% | 53.73% | 66.67% |
| [mod.rs](../../crates/tpm2-impl/src/handler/mod.rs) | 769 | 65.93% | 63.92% | 76.00% |
| [startup.rs](../../crates/tpm2-impl/src/handler/startup.rs) | 391 | 73.40% | 65.60% | 90.48% |
| [policy_nv.rs](../../crates/tpm2-impl/src/handler/policy_nv.rs) | 177 | 73.45% | 71.78% | 80.00% |
| [duplicate.rs](../../crates/tpm2-impl/src/handler/duplicate.rs) | 407 | 73.96% | 75.99% | 80.00% |
| [policy_authorize.rs](../../crates/tpm2-impl/src/handler/policy_authorize.rs) | 141 | 75.89% | 70.21% | 100.00% |
| [encrypt_decrypt.rs](../../crates/tpm2-impl/src/handler/encrypt_decrypt.rs) | 171 | 78.36% | 75.81% | 100.00% |
| [load_external.rs](../../crates/tpm2-impl/src/handler/load_external.rs) | 504 | 80.56% | 79.07% | 80.00% |
| [commit.rs](../../crates/tpm2-impl/src/handler/commit.rs) | 380 | 82.63% | 80.42% | 85.71% |
| [quote.rs](../../crates/tpm2-impl/src/handler/quote.rs) | 77 | 83.12% | 76.97% | 100.00% |
| [policy_signed.rs](../../crates/tpm2-impl/src/handler/policy_signed.rs) | 287 | 83.97% | 84.02% | 33.33% |
| [set_primary_policy.rs](../../crates/tpm2-impl/src/handler/set_primary_policy.rs) | 59 | 86.44% | 81.61% | 100.00% |
| [create_loaded.rs](../../crates/tpm2-impl/src/handler/create_loaded.rs) | 1012 | 86.96% | 85.63% | 87.88% |
| [object_change_auth.rs](../../crates/tpm2-impl/src/handler/object_change_auth.rs) | 90 | 87.78% | 81.91% | 66.67% |
| [get_time.rs](../../crates/tpm2-impl/src/handler/get_time.rs) | 233 | 87.98% | 87.26% | 83.33% |
| [import.rs](../../crates/tpm2-impl/src/handler/import.rs) | 361 | 88.37% | 82.48% | 71.43% |
| [crypt_ops.rs](../../crates/tpm2-impl/src/handler/crypt_ops.rs) | 660 | 90.45% | 88.04% | 66.67% |
| [shutdown.rs](../../crates/tpm2-impl/src/handler/shutdown.rs) | 32 | 90.62% | 86.27% | 100.00% |
| [hierarchy_change_auth.rs](../../crates/tpm2-impl/src/handler/hierarchy_change_auth.rs) | 47 | 91.49% | 84.15% | 50.00% |
| [certify.rs](../../crates/tpm2-impl/src/handler/certify.rs) | 189 | 91.53% | 86.70% | 100.00% |
| [policy_ticket.rs](../../crates/tpm2-impl/src/handler/policy_ticket.rs) | 136 | 91.91% | 89.04% | 100.00% |
| [ecdh.rs](../../crates/tpm2-impl/src/handler/ecdh.rs) | 65 | 92.31% | 89.51% | 100.00% |
| [session.rs](../../crates/tpm2-impl/src/handler/session.rs) | 506 | 92.69% | 88.47% | 86.67% |
| [policy_secret.rs](../../crates/tpm2-impl/src/handler/policy_secret.rs) | 170 | 92.94% | 90.07% | 75.00% |
| [load.rs](../../crates/tpm2-impl/src/handler/load.rs) | 213 | 92.96% | 89.54% | 66.67% |
| [nv_storage.rs](../../crates/tpm2-impl/src/handler/nv_storage.rs) | 1100 | 93.00% | 87.14% | 91.11% |
| [context_load.rs](../../crates/tpm2-impl/src/handler/context_load.rs) | 422 | 93.60% | 88.27% | 85.71% |
| [rewrap.rs](../../crates/tpm2-impl/src/handler/rewrap.rs) | 392 | 93.62% | 90.84% | 78.95% |
| [create.rs](../../crates/tpm2-impl/src/handler/create.rs) | 132 | 93.94% | 88.41% | 33.33% |
| [get_session_audit_digest.rs](../../crates/tpm2-impl/src/handler/get_session_audit_digest.rs) | 84 | 94.05% | 91.84% | 100.00% |
| [da.rs](../../crates/tpm2-impl/src/handler/da.rs) | 68 | 94.12% | 85.93% | 100.00% |
| [get_command_audit_digest.rs](../../crates/tpm2-impl/src/handler/get_command_audit_digest.rs) | 72 | 94.44% | 92.31% | 100.00% |
| [create_primary.rs](../../crates/tpm2-impl/src/handler/create_primary.rs) | 163 | 94.48% | 89.05% | 50.00% |
| [sequence.rs](../../crates/tpm2-impl/src/handler/sequence.rs) | 362 | 94.48% | 91.01% | 83.33% |
| [policy_template.rs](../../crates/tpm2-impl/src/handler/policy_template.rs) | 73 | 94.52% | 89.57% | 100.00% |
| [evict_control.rs](../../crates/tpm2-impl/src/handler/evict_control.rs) | 203 | 94.58% | 88.93% | 71.43% |
| [hierarchy_control.rs](../../crates/tpm2-impl/src/handler/hierarchy_control.rs) | 75 | 94.67% | 90.18% | 100.00% |
| [policy_or.rs](../../crates/tpm2-impl/src/handler/policy_or.rs) | 78 | 94.87% | 91.79% | 100.00% |
| [policy_authorize_nv.rs](../../crates/tpm2-impl/src/handler/policy_authorize_nv.rs) | 99 | 94.95% | 88.94% | 33.33% |
| [read_public.rs](../../crates/tpm2-impl/src/handler/read_public.rs) | 41 | 95.12% | 86.30% | 50.00% |
| [policy_duplication_select.rs](../../crates/tpm2-impl/src/handler/policy_duplication_select.rs) | 83 | 95.18% | 90.83% | 100.00% |
| [policy_locality.rs](../../crates/tpm2-impl/src/handler/policy_locality.rs) | 67 | 95.52% | 90.38% | 100.00% |
| [random.rs](../../crates/tpm2-impl/src/handler/random.rs) | 47 | 95.74% | 92.54% | 100.00% |
| [policy_auth_value.rs](../../crates/tpm2-impl/src/handler/policy_auth_value.rs) | 51 | 96.08% | 88.24% | 100.00% |
| [policy_password.rs](../../crates/tpm2-impl/src/handler/policy_password.rs) | 51 | 96.08% | 88.24% | 100.00% |
| [activate_credential.rs](../../crates/tpm2-impl/src/handler/activate_credential.rs) | 131 | 96.18% | 89.61% | 75.00% |
| [flush_context.rs](../../crates/tpm2-impl/src/handler/flush_context.rs) | 80 | 96.25% | 93.33% | 100.00% |
| [capability.rs](../../crates/tpm2-impl/src/handler/capability.rs) | 922 | 96.42% | 89.85% | 93.33% |
| [clear_control.rs](../../crates/tpm2-impl/src/handler/clear_control.rs) | 28 | 96.43% | 89.29% | 100.00% |
| [policy_nv_written.rs](../../crates/tpm2-impl/src/handler/policy_nv_written.rs) | 60 | 96.67% | 90.53% | 100.00% |
| [context_save.rs](../../crates/tpm2-impl/src/handler/context_save.rs) | 395 | 96.71% | 93.13% | 77.78% |
| [policy_pcr.rs](../../crates/tpm2-impl/src/handler/policy_pcr.rs) | 95 | 96.84% | 92.68% | 100.00% |
| [policy_name_hash.rs](../../crates/tpm2-impl/src/handler/policy_name_hash.rs) | 70 | 97.14% | 91.07% | 100.00% |
| [policy_cp_hash.rs](../../crates/tpm2-impl/src/handler/policy_cp_hash.rs) | 73 | 97.26% | 91.30% | 100.00% |
| [reference_ops.rs](../../crates/tpm2-impl/src/handler/reference_ops.rs) | 193 | 97.41% | 90.31% | 100.00% |
| [change_eps.rs](../../crates/tpm2-impl/src/handler/change_eps.rs) | 44 | 97.73% | 87.78% | 100.00% |
| [change_pps.rs](../../crates/tpm2-impl/src/handler/change_pps.rs) | 44 | 97.73% | 87.78% | 100.00% |
| [unseal.rs](../../crates/tpm2-impl/src/handler/unseal.rs) | 47 | 97.87% | 89.19% | 100.00% |
| [set_command_code_audit_status.rs](../../crates/tpm2-impl/src/handler/set_command_code_audit_status.rs) | 54 | 98.15% | 93.62% | 100.00% |
| [pcr.rs](../../crates/tpm2-impl/src/handler/pcr.rs) | 383 | 98.17% | 91.02% | 95.83% |
| [clear.rs](../../crates/tpm2-impl/src/handler/clear.rs) | 137 | 98.54% | 91.67% | 100.00% |
| [make_credential.rs](../../crates/tpm2-impl/src/handler/make_credential.rs) | 116 | 99.14% | 90.43% | 100.00% |
| [clock_ops.rs](../../crates/tpm2-impl/src/handler/clock_ops.rs) | 66 | 100.00% | 91.85% | 100.00% |
| [read_clock.rs](../../crates/tpm2-impl/src/handler/read_clock.rs) | 17 | 100.00% | 89.19% | 100.00% |
| [testing.rs](../../crates/tpm2-impl/src/handler/testing.rs) | 93 | 100.00% | 92.76% | 100.00% |
| **Total** | 13939 | **88.75%** | 84.92% | 83.96% |

Every one of the 104 commands `tpm-rs` implements is sent by the corpus, and
102 of them succeed at least once. The two that never succeed are
`TPM2_Startup` (the TPM is always started; it needs a reset or restart, which
are platform signals outside the fuzzer's scope) and the deprecated
`TPM2_EncryptDecrypt` (sent 77 times, always rejected;
`TPM2_EncryptDecrypt2` succeeds). The least covered handler files are those
whose remaining code needs state the conversations rarely build (clock and
timer policy values in `policy_counter_timer.rs`, startup/shutdown state in
`startup.rs`, and the shared helpers in `mod.rs` for algorithms outside the
profile).

### 1.4 C-side coverage

With `FUZZ_C_COVERAGE=1` the C references are compiled with
`-fsanitize=fuzzer-no-link`, so their paths count too: libFuzzer's counters
grow from 37,088 to 54,553, and replaying the same 2,781 inputs reaches 4,939
edges instead of 2,594. The campaigns above did not use it (it slows the
references down); it is meant for occasional runs that look for reference
paths the corpus misses.

## 2. Bugs found in tpm-rs

Each entry names the campaign (C1–C3) and family or the smoke run that found
it, the root cause, the fix with a link to the fixed code (which quotes the
specification verbatim at the fix), the specification text, and the
regression test in `testing/tests/e2e/`. Repro inputs are in each campaign's
`families.md` report; every regression test reproduces its finding as a plain
E2E test.

### 2.1 Handle, session and header validation order

1. **Handle area validated per handle while unmarshaling** — *C1 family 000 (0x29a vs 0x184, 15,883 artifacts) and the pre-campaign smoke runs.*
   Root cause: `tpm-rs` read the authorization size before validating the handles and interleaved each handle's type check with its presence check, so an invalid later handle or a missing authorization size was reported before an invalid first handle; several positions had no interface-type check at all (e.g. `TPM2_PolicySecret` `TPMI_DH_ENTITY`, `TPM2_NV_ReadPublic` `TPMI_RH_NV_INDEX`).
   Fix: two passes before the authorization area is parsed, first every handle against its Part 3 interface type in order, then the load status — [engine.rs `validate_command_handles`](../../crates/tpm2-impl/src/engine.rs#L5078-L5100), with the per-command table [handle_checks.rs `command_handle_types`](../../crates/tpm2-impl/src/handle_checks.rs#L257-L270).
   Spec: Part 3, "Handle Area Validation": "1. The TPM shall successfully unmarshal the number of handles required by the command and validate that the value of the handle is consistent with the command syntax. If not, the TPM shall return TPM_RC_VALUE." … "These checks may be performed in any order" (the order of the TCG reference is followed).
   Tests: [handle_validation.rs](../tests/e2e/handle_validation.rs) (`invalid_handle_type_is_reported_before_unloaded_handle`, `handles_outside_their_interface_type_are_value_errors`), [authorization_area.rs](../tests/e2e/authorization_area.rs) (`invalid_handle_is_reported_before_missing_authorization_size`).

2. **Truncated handle area reported as a whole** — *C1 families 000/007.*
   Root cause: a command with fewer handle octets than its command code needs was rejected without checking the handles that were present, so a missing second handle (`TPM_RC_INSUFFICIENT`) hid an invalid first handle (`TPM_RC_VALUE + H1`).
   Fix: per-handle `TPM_RC_INSUFFICIENT`/`TPM_RC_VALUE` in handle order — [engine.rs `handle_area_unmarshal_error`](../../crates/tpm2-impl/src/engine.rs#L6305-L6320).
   Spec: Part 3, "Handle Area Validation" item 1 (quoted above) and Part 2, "Unmarshaling Errors": "the input buffer did not contain enough octets to allow unmarshaling of the expected data type".
   Test: [authorization_area.rs](../tests/e2e/authorization_area.rs) (`invalid_first_handle_reported_before_missing_second_handle`).

3. **Sessions validated after all of them were unmarshaled** — *pre-campaign smoke run (`TPM2_EncryptDecrypt` 0x164, `TPM2_Create` `REFERENCE_S0`).*
   Root cause: a syntax-only pass over all sessions ran before the per-session checks, so an error in a later session (or the encrypt-session mode) hid `TPM_RC_REFERENCE_Sx`/`TPM_RC_HANDLE + Sx` of an earlier one.
   Fix: each session is checked as it is unmarshaled — [engine.rs `validate_session`](../../crates/tpm2-impl/src/engine.rs#L3040-L3065); the encrypt-session mode once all sessions are valid — [engine.rs `validate_encrypt_session_mode`](../../crates/tpm2-impl/src/engine.rs#L3145-L3148).
   Spec: Part 3, "Session Area Validation": "If the handle is not a handle for a loaded session, then the TPM will return the warning TPM_RC_REFERENCE_S0 + N where N is the number of the session. The first session is session zero, N = 0." (the specification does not order one session's checks against the next session's unmarshaling; the reference's order is followed).
   Tests: [authorization_area.rs](../tests/e2e/authorization_area.rs), [encrypt_decrypt.rs](../tests/e2e/encrypt_decrypt.rs) (`mistyped_session_handle_reported_before_decrypt_attribute`).

4. **`MAX_COMMAND_SIZE` larger than the profile's** — *C1 families 003 and every "ref 0x142" family (about 1,400 artifacts).*
   Root cause: `tpm-rs` accepted commands up to 4096 bytes and reported that as `TPM_PT_MAX_COMMAND_SIZE`, while the profile's `MAX_COMMAND_SIZE` is `4096 - 0x80`; larger commands failed later with parameter errors instead of `TPM_RC_COMMAND_SIZE`.
   Fix: [engine.rs `MAX_COMMAND_SIZE`](../../crates/tpm2-impl/src/engine.rs#L145-L151), also reported by [capability.rs](../../crates/tpm2-impl/src/handler/capability.rs).
   Spec: Part 2, `TPM_PT_MAX_COMMAND_SIZE`: "the maximum value for *commandSize* in a command"; Part 3, "Command Header Validation": "2. The TPM shall successfully unmarshal a UINT32 as the *commandSize*. If the TPM has an interface buffer that is loaded by some hardware process, the number of octets in the input buffer for the command reported by the hardware process shall exactly match the value in *commandSize* (TPM_RC_COMMAND_SIZE)." (the value itself is implementation-defined; the reference profile's `MAX_COMMAND_SIZE` is used).
   Test: [authorization_area.rs](../tests/e2e/authorization_area.rs) (`command_larger_than_max_command_size_rejected`).

5. **Sequence objects not treated as loaded objects** — *C1 family 027.*
   Root cause: a sequence object as `tpmKey` or `bind` of `TPM2_StartAuthSession` failed the load check (`TPM_RC_REFERENCE_H0/H1`).
   Fix: a loaded sequence object passes the load check of `TPM2_StartAuthSession`'s handles and then fails in the handler with `TPM_RC_KEY` — [engine.rs](../../crates/tpm2-impl/src/engine.rs#L5294-L5303).
   Spec: Part 3, "Handle Area Validation": "If the handle references a transient object, the handle shall reference a loaded object (TPM_RC_REFERENCE_H0 + N …)"; Part 1, "transient object": "object or sequence object that can be explicitly loaded and unloaded from TPM memory by the TRM".
   Test: [start_auth_session_tpm_key.rs](../tests/e2e/start_auth_session_tpm_key.rs) (`sequence_object_bind_is_loaded`).

6. **External and permanent NV handles rejected as the wrong type** — *C1 family 145.*
   Root cause: `0x11xxxxxx`/`0x12xxxxxx` handles are valid `TPMI_RH_NV_INDEX` values but were rejected with `TPM_RC_VALUE + H2` during unmarshaling.
   Fix: they unmarshal, and the load status reports `TPM_RC_VALUE` in handle order — [engine.rs](../../crates/tpm2-impl/src/engine.rs#L5163-L5170).
   Spec: Part 2, `TPMI_RH_NV_INDEX` rows (the specification is silent on their load status; the reference's `EntityGetLoadStatus` is followed: "case TPM_HT_EXTERNAL_NV: case TPM_HT_PERMANENT_NV: // Not yet supported. result = TPM_RC_VALUE;").
   Test: [handle_validation.rs](../tests/e2e/handle_validation.rs) (`external_and_permanent_nv_indexes_are_unmarshaled_but_not_implemented`).

7. **`TPM2_PolicyPCR` checked the hash before the selection count** — *pre-campaign smoke run (0x17f).*
   Root cause: a hand-written fallback parser reported `TPM_RC_HASH + P2` for the first selection even when `count` exceeded the number of banks.
   Fix: the plain profile-aware unmarshal — [policy_pcr.rs](../../crates/tpm2-impl/src/handler/policy_pcr.rs#L47).
   Spec: Part 2, `TPML_PCR_SELECTION`: "#TPM_RC_SIZE | response code when *count* is greater than the possible number of banks".
   Test: [policy_pcr.rs](../tests/e2e/policy_pcr.rs) (`oversized_selection_count_rejected_before_hash`).

8. **`TPM2_SetCommandCodeAuditStatus` reported an unimplemented `auditAlg` after later parameters** — *pre-campaign smoke run (0x140).*
   Root cause: the check ran after all parameters were unmarshaled, so `TPM_RC_SIZE + P3` of `clearList` won over `TPM_RC_HASH + P1`.
   Fix: [set_command_code_audit_status.rs](../../crates/tpm2-impl/src/handler/set_command_code_audit_status.rs#L58-L66).
   Spec: Part 2, `TPMI_ALG_HASH`: "TPMI_ALG_HASH is an interface type of all the hash algorithms implemented on a specific TPM" … "#TPM_RC_HASH"; Part 3: "TPMI_ALG_HASH+ | auditAlg" is the first parameter.
   Test: [set_command_code_audit_status.rs](../tests/e2e/set_command_code_audit_status.rs) (`unimplemented_audit_alg_rejected_before_later_parameters`).

9. **`TPM2_PolicyAuthorize` `checkTicket` with a wrong tag was `TPM_RC_VALUE`** — *C1.*
   Root cause: a `checkTicket` whose tag is not `TPM_ST_VERIFIED` was rejected with `TPM_RC_VALUE` instead of the tag error that `TPMT_TK_VERIFIED` defines.
   Fix: `TPM_RC_TAG + P4` — [policy_authorize.rs](../../crates/tpm2-impl/src/handler/policy_authorize.rs#L45-L64).
   Spec: Part 2, `TPMT_TK_VERIFIED`: "#TPM_RC_TAG | | error returned when *tag* is not one of the values in…".
   Test: [policy_authorize.rs](../tests/e2e/policy_authorize.rs) (`digest_verified_ticket_rejected_with_tag`).

10. **`TPM2_IncrementalSelfTest` accepted algorithms the TPM does not implement** — *C1 family D.*
    Root cause: the entries of `toTest` were not checked against the algorithms the TPM implements, so an unimplemented algorithm was accepted.
    Fix: `TPM_RC_VALUE + P1` for algorithms outside `TPM_CAP_ALGS` — [testing.rs](../../crates/tpm2-impl/src/handler/testing.rs#L136-L148).
    Spec: Part 3, TPM2_IncrementalSelfTest: "This command causes the TPM to perform a test of the selected algorithms." (silent on unimplemented ones; the reference is followed).
    Test: [self_test_commands.rs](../tests/e2e/self_test_commands.rs) (`unimplemented_algorithm_in_to_test_rejected`).

11. **XOR parameter obfuscation limited to 2048 bytes** — *C1 family E (`TPM2_Load` `TPM_RC_SIZE` vs `TPM_RC_SIZE + P1`).*
    Root cause: the XOR mask had a fixed 2048-byte size, and a longer decrypted parameter returned a bare `TPM_RC_SIZE` instead of reaching the parameter's own unmarshal.
    Fix: a mask of `MAX_COMMAND_SIZE` — [engine.rs `xor_obfuscation`](../../crates/tpm2-impl/src/engine.rs#L6665-L6690).
    Spec: Part 1, "XOR Parameter Obfuscation": "The obfuscated size of parameter is the same as the size of the underlying parameter."
    Test: [load_validation.rs](../tests/e2e/load_validation.rs) (`oversized_private_under_xor_decrypt_session_is_a_parameter_size_error`).

12. **`TPM2_ActivateCredential` resolved `activateHandle` before checking `keyHandle`** — *C1 family 031.*
    Root cause: an unusable `activateHandle` (e.g. a sequence object) was rejected before the protector key's type check and the seed decryption, which the reference performs first.
    Fix: the activated object is used only for its Name, after the key checks — [activate_credential.rs](../../crates/tpm2-impl/src/handler/activate_credential.rs#L99-L107).
    Spec: Part 3, TPM2_ActivateCredential: "The key associated with *keyHandle* is used to recover a seed from *secret*, which is the encrypted seed. The Name of the object associated with *activateHandle*, and the recovered seed are used in a KDF to recover the symmetric key."
    Test: [activate_credential_secret.rs](../tests/e2e/activate_credential_secret.rs) (`sequence_object_protector_is_type_error`).

13. **Sequence objects in key positions turned into `TPM_RC_KEY + H1` before each command's own checks** — *C1 families B/C, 008/027/040/045.*
    Root cause: the shared object resolution rejected a sequence object before the command-specific checks, which report other errors first.
    Fix: `TPM2_MAC_Start`/`TPM2_MAC` give `TPM_RC_TYPE + H1` ([sequence.rs](../../crates/tpm2-impl/src/handler/sequence.rs#L473), [crypt_ops.rs](../../crates/tpm2-impl/src/handler/crypt_ops.rs#L757)); `TPM2_VerifySignature` `TPM_RC_ATTRIBUTES + H1` ([crypt_ops.rs](../../crates/tpm2-impl/src/handler/crypt_ops.rs#L54-L66)); `TPM2_PolicySigned` `TPM_RC_SCHEME + P5` after the policy checks ([policy_signed.rs](../../crates/tpm2-impl/src/handler/policy_signed.rs#L134)); `TPM2_StartAuthSession` `tpmKey` `TPM_RC_KEY + H1` ([session.rs](../../crates/tpm2-impl/src/handler/session.rs#L263-L268)); `TPM2_Certify`/`TPM2_CertifyCreation` check `signHandle` and the scheme first ([certify.rs](../../crates/tpm2-impl/src/handler/certify.rs#L46-L57)).
    Spec: Part 3, TPM2_MAC_Start: "If the key type is not TPM_ALG_KEYEDHASH or TPM_ALG_SYMCIPHER then the TPM shall return TPM_RC_TYPE."; TPM2_StartAuthSession: "The TPM shall return TPM_RC_KEY if tpmKey does not reference an asymmetric key."; TPM2_Certify: "The object may be any object that is loaded with TPM2_Load() or TPM2_CreatePrimary()".
    Tests: [sequence_object_as_key.rs](../tests/e2e/sequence_object_as_key.rs), [start_auth_session_tpm_key.rs](../tests/e2e/start_auth_session_tpm_key.rs).

14. **`TPM2_RSA_Decrypt` with a ciphertext not smaller than the modulus** — *C1 family R.*
    Root cause: a modulus-sized ciphertext that is not below the modulus was not reported with the reference's `TPM_RC_SIZE` (no position), which it uses for every ciphertext the decryption primitive rejects.
    Fix: bare `TPM_RC_SIZE`, like a ciphertext of the wrong size — [crypt_ops.rs](../../crates/tpm2-impl/src/handler/crypt_ops.rs#L656-L662).
    Spec: Part 3, TPM2_RSA_Decrypt: "It will then validate the padding according to the selected scheme. If the padding checks fail, TPM_RC_VALUE is returned." (silent on an out-of-range ciphertext; the reference's code is followed).
    Test: [rsa_decrypt_ciphertext.rs](../tests/e2e/rsa_decrypt_ciphertext.rs).

15. **`TPM2_StartAuthSession` checked the `symmetric` mode before the salt and bind** — *C4 family 2 (0x4c9 vs 0x2c4).*
    Root cause: the CFB-mode check ran right after unmarshaling, so an invalid `encryptedSalt` (e.g. not a point of an ECC `tpmKey`) was reported as `TPM_RC_MODE + P4` instead of `TPM_RC_VALUE + P2`.
    Fix: the mode check after the salt and bind checks — [session.rs](../../crates/tpm2-impl/src/handler/session.rs#L102-L112).
    Spec: Part 3, TPM2_StartAuthSession: "If *symmetric* specifies a block cipher, then TPM_ALG_CFB is the only allowed value for the *mode* field in the *symmetric* parameter (TPM_RC_MODE)." (the order is not specified; the reference's is used).
    Test: [start_auth_session_validation.rs](../tests/e2e/start_auth_session_validation.rs) (`salt_checked_before_symmetric_mode`).

### 2.2 Profile and unmarshaling

16. **`tpm2` unmarshaled every compiled-in algorithm instead of the TPM profile** — *pre-campaign smoke run (`TPM2_LoadExternal`, `TPM2_Rewrap`, `TPM2_StartAuthSession`, `TPM2_Import`) and C1 families 006/010.*
    Root cause: Cargo enables every `tpm2` algorithm feature in the workspace (the crypto tests need SM3 and RSA-4096), so `tpm-rs` accepted hashes, curves, RSA sizes and RSA-sized `TPM2B`s that its TPM does not implement and failed later with other errors.
    Fix: the runtime unmarshal profile `tpm2::profile` ([profile.rs](../../crates/tpm2/src/profile.rs)), installed once by `TpmEngine::new` with [capability.rs `TPM_PROFILE`](../../crates/tpm2-impl/src/handler/capability.rs#L113-L131), whose capacities are derived from the Part 2 definitions.
    Spec: Part 2, `TPMI_ALG_HASH`: "TPMI_ALG_HASH is an interface type of all the hash algorithms implemented on a specific TPM"; `TPMI_RSA_KEY_BITS`: "#TPM_RC_VALUE | error when key size is not supported"; `TPM2B_PRIVATE`: "buffer[size] {:sizeof(_PRIVATE)}".
    Tests: [crates/tpm2/tests/profile.rs](../../crates/tpm2/tests/profile.rs), [create_primary_validation.rs](../tests/e2e/create_primary_validation.rs), [import_validation.rs](../tests/e2e/import_validation.rs), [rewrap.rs](../tests/e2e/rewrap.rs).

17. **Symmetric key sizes outside the profile (AES-192) accepted** — *C1 (`TPM2_TestParms` 0x1c3/0x1d2 vs 0x1c4).*
    Root cause: the profile gated algorithms but not their key sizes, so AES-192 passed unmarshaling and failed later with another error.
    Fix: `Profile::sym_key_bits` and the `AlgSym` unmarshal — [tpmt.rs](../../crates/tpm2/src/structures/tpmt.rs#L488).
    Spec: Part 2, "Definition of Types for Symmetric Cipher Key Sizes" (`TPMI_AES_KEY_BITS` "$AES_KEY_SIZES_BITS", "#TPM_RC_VALUE").
    Test: [crates/tpm2/tests/profile.rs](../../crates/tpm2/tests/profile.rs).

18. **`TPM2B_TEMPLATE`, `TPM2B_ECC_PARAMETER` and `HASH_COUNT` list bounds** — *C1 families 006/010.*
    Root cause: these capacities came from the compiled-in features (and, for `TPM2B_TEMPLATE`, a padded size) instead of the TPM profile, so oversized buffers and lists were accepted.
    Fix: `TPM2B_TEMPLATE` is bounded by the unpadded `sizeof(TPMT_PUBLIC)` (350), `TPM2B_ECC_PARAMETER` by 66, and `TPML_PCR_SELECTION`/`TPML_DIGEST_VALUES` by `HASH_COUNT` — [limits.rs](../../crates/tpm2/src/limits.rs#L156-L228), [tpml.rs](../../crates/tpm2/src/structures/tpml.rs#L177).
    Spec: Part 2, `TPM2B_TEMPLATE`: "buffer[size]{:sizeof(TPMT_PUBLIC)}" and "Data Alignment" ("returns the octet-aligned size of the structure, with no padding"); `TPML_PCR_SELECTION`: "#TPM_RC_SIZE | response code when count is greater than the possible number of banks".
    Test: [profile_limits.rs](../tests/e2e/profile_limits.rs).

19. **`TPM2_TestParms` used fallback heuristics** — *C1 family 3 (0x1c9 vs 0x1c4, 1,025 artifacts).*
    Root cause: hand-written checks guessed the failing field instead of unmarshaling `TPMT_PUBLIC_PARMS` in wire order, so a later field's error could be reported before an earlier one's.
    Fix: the plain profile-aware unmarshal — [capability.rs](../../crates/tpm2-impl/src/handler/capability.rs#L950-L957).
    Spec: Part 3, TPM2_TestParms: "The TPM will unmarshal the provided TPMT_PUBLIC_PARMS. If the parameters unmarshal correctly, then the TPM will return TPM_RC_SUCCESS, indicating that the parameters are valid for the TPM. The TPM will return the appropriate unmarshaling error if a parameter is not valid."
    Test: [testparms_validation.rs](../tests/e2e/testparms_validation.rs) (`first_invalid_field_in_wire_order_is_reported`).

20. **`TPM2_GetCapability` checked an unimplemented capability after the later parameters** — *C1.*
    Root cause: the capability value was validated only after `property`, `propertyCount` and the trailing size, so their errors were reported instead of `TPM_RC_VALUE + P1`.
    Fix: `TPM_CAP` validated while unmarshaled (`TPM_RC_VALUE + P1`) — [capability.rs](../../crates/tpm2-impl/src/handler/capability.rs#L265-L280).
    Spec: Part 2, "Definition of (UINT32) TPM_CAP Constants" ends with "#TPM_RC_VALUE".
    Test: [get_capability.rs](../tests/e2e/get_capability.rs) (`unimplemented_capability_rejected_while_unmarshaling`).

21. **`TPM2_Create` reported parameter errors out of order** — *pre-campaign smoke run and C1 family 053.*
    Root cause: a hand-written fallback parser of `inPublic` skipped `objectAttributes` and a heuristic masked a `P1` error with a `P2` one, so errors were not reported in unmarshaling order.
    Fix: the plain profile-aware unmarshal — [create.rs](../../crates/tpm2-impl/src/handler/create.rs#L54-L61).
    Spec: Part 3, "Unmarshaling Errors": "When an error is encountered while unmarshaling a command parameter, an error response code is returned, and no command processing occurs."; Part 2: "When any reserved bit in an attribute is SET, the TPM shall return TPM_RC_RESERVED_BITS".
    Tests: [create_public_unmarshal_order.rs](../tests/e2e/create_public_unmarshal_order.rs), [create_validation.rs](../tests/e2e/create_validation.rs).

### 2.3 Object creation, loading and import

22. **Unsupported RSA exponents accepted** — *pre-campaign smoke run.*
    Root cause: `tpm-rs` generated keys for any public exponent, while its crypto provider (like the reference) only supports 2^16+1.
    Fix: any other exponent fails key generation with `TPM_RC_RANGE` (`TPM2_CreatePrimary`, `TPM2_Create`, `TPM2_CreateLoaded`) — [handler/mod.rs](../../crates/tpm2-impl/src/handler/mod.rs#L861-L871).
    Spec: Part 1, RSA: "A TPM is required only to support a public exponent (e) of 2^16+1. Support for other exponents is allowed but discouraged." (the response code is not specified; the reference's is used).
    Tests: [create_primary_validation.rs](../tests/e2e/create_primary_validation.rs) (`unsupported_rsa_exponent_fails_key_generation_with_range`), [create_validation.rs](../tests/e2e/create_validation.rs) (`unsupported_rsa_exponent_fails_child_key_generation_with_range`).

23. **Symmetric algorithm IDs beyond the algorithm range were not `TPM_RC_SYMMETRIC`** — *pre-campaign smoke run (`TPM2_StartAuthSession`, `TPM2_Import`).*
    Root cause: a `symmetric`/`symmetricAlg` value above 0x80 failed later with another error.
    Fix: [session.rs](../../crates/tpm2-impl/src/handler/session.rs#L61-L68), [import.rs](../../crates/tpm2-impl/src/handler/import.rs#L56-L64).
    Spec: Part 2, "Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type" and "TPMI_ALG_SYM_OBJECT Type": "#TPM_RC_SYMMETRIC".
    Tests: [start_auth_session_validation.rs](../tests/e2e/start_auth_session_validation.rs) (`oversized_salt_and_unknown_symmetric_algorithm_rejected_at_unmarshal`), [start_auth_session_tpm_key.rs](../tests/e2e/start_auth_session_tpm_key.rs) (`symmetric_unmarshal_error_precedes_tpm_key_check`).

24. **`TPM2_Import` checked `fixedTPM`/`fixedParent` of `objectPublic` late** — *pre-campaign smoke run.*
    Root cause: the parent and the encryption key were checked first.
    Fix: the attribute check comes first — [import.rs](../../crates/tpm2-impl/src/handler/import.rs#L90-L99).
    Spec: Part 3, TPM2_Import: "If *fixedTPM* or *fixedParent* is SET in *objectPublic*, the TPM shall return TPM_RC_ATTRIBUTES." (the order is not specified; the reference's is used).
    Test: [import_validation.rs](../tests/e2e/import_validation.rs) (`fixed_tpm_attribute_precedence`).

25. **ECC keys with a sensitive area: public point checked on its own** — *C1 families 004/060.*
    Root cause: `TPM_RC_ECC_POINT + P2` before the private key size and the binding, and (C3 family 3) a zero-padded private key counted its leading zero octets against the key size.
    Fix: `TPM_RC_KEY_SIZE` first (on the number, without leading zeros), then `[d]G` against the public point (`TPM_RC_BINDING`) — [load_external.rs `validate_and_import_sensitive`](../../crates/tpm2-impl/src/handler/load_external.rs#L384-L410).
    Spec: Part 3, TPM2_Load: "If the parts of the object are not properly linked, the TPM shall return TPM_RC_BINDING."
    Spec (key size): Part 3, TPM2_Load: "For all objects, the size of the key in the sensitive area shall be consistent with the key size indicated in the public area or the TPM shall return TPM_RC_KEY_SIZE."
    Tests: [ecc_key_binding.rs](../tests/e2e/ecc_key_binding.rs), [import_check_order.rs](../tests/e2e/import_check_order.rs) (`zero_padded_ecc_private_key_reaches_binding_check`).

26. **Public `unique` and ECC coordinate sizes checked even with a sensitive area** — *C3 families 3/4/5.*
    Root cause: `validate_public_parameters` (shared by `TPM2_Load`, `TPM2_Import` and `TPM2_LoadExternal`) rejected a SYMCIPHER/KEYEDHASH `unique` of the wrong size or an oversized ECC coordinate with `TPM_RC_KEY + P2`, before the seed size and the binding.
    Fix: those checks only for public-only objects (`validate_public_only`) — [load_external.rs](../../crates/tpm2-impl/src/handler/load_external.rs#L574-L610); `TPM2_Import` drops its own pre-check of the `unique` sizes ([import.rs](../../crates/tpm2-impl/src/handler/import.rs#L429-L438)).
    Spec: Part 3, TPM2_LoadExternal: "If *nameAlg* is not TPM_ALG_NULL, then the same consistency checks between *inPublic* and *inPrivate* are made as for TPM2_Load()."; TPM2_Load: "If the parts of the object are not properly linked, the TPM shall return TPM_RC_BINDING."
    Tests: [load_external_sensitive_validation.rs](../tests/e2e/load_external_sensitive_validation.rs) (`keyed_hash_seed_size_checked_before_unique_size`), [import_check_order.rs](../tests/e2e/import_check_order.rs) (`oversized_ecc_coordinate_is_binding_error`).

27. **`TPM2_Import` validated `objectPublic` before recovering the seed; a symmetric parent with `inSymSeed`** — *C1 family 004, C3 family 3.*
    Root cause: `objectPublic` errors were reported before seed-recovery errors, and with a SYMCIPHER parent `tpm-rs` tried to decrypt `inSymSeed` with the symmetric key.
    Fix: the seed is recovered first, and a SYMCIPHER parent with a non-empty `inSymSeed` is `TPM_RC_TYPE + H1` — [import.rs](../../crates/tpm2-impl/src/handler/import.rs#L151-L185).
    Spec: Part 3, TPM2_Import: "Recovery of the sensitive data … in the following order: 1. If inSymSeed has a non-zero size: 2. The asymmetric parameters and private key of parentHandle are used to recover the seed".
    Tests: [import_validation.rs](../tests/e2e/import_validation.rs), [import_check_order.rs](../tests/e2e/import_check_order.rs) (`outer_wrapper_under_symmetric_parent_is_parent_type_error`).

28. **Non-specified rule for objects under a NULL-hierarchy parent** — *C1 family Q (`TPM2_Create` 0x2c2 vs 0x2c3).*
    Root cause: `tpm-rs` required `fixedTPM`/`fixedParent` CLEAR for such objects.
    Fix: rule removed — [create_loaded.rs `validate_object_attributes`](../../crates/tpm2-impl/src/handler/create_loaded.rs#L860-L873).
    Spec: Part 2, `TPMA_OBJECT` `fixedTPM`: "If fixedTPM is SET in the object's parent, then fixedTPM shall equal fixedParent in template".
    Test: [create_null_hierarchy_parent.rs](../tests/e2e/create_null_hierarchy_parent.rs).

29. **`TPM2_CreateLoaded` under a derivation parent: `sensitiveDataOrigin` error carried a parameter number** — *C1 family L.*
    Root cause: the attribute error was qualified with the position of `inPublic`, while the derivation rule has no position.
    Fix: bare `TPM_RC_ATTRIBUTES` — [create_loaded.rs](../../crates/tpm2-impl/src/handler/create_loaded.rs#L1166-L1173).
    Spec: Part 3, TPM2_CreateLoaded: "when *parentHandle* references a Derivation Parent, then *sensitiveDataOrigin* in *inPublic* is required to be CLEAR."
    Test: [create_loaded_derivation.rs](../tests/e2e/create_loaded_derivation.rs) (`derived_template_with_sensitive_data_origin_rejected`).

30. **`TPM2_Create` without a free object slot** — *C1 family 019 (`TPM2_Create` success vs `TPM_RC_OBJECT_MEMORY`).*
    Root cause: `tpm-rs` created the child even when all object slots were in use (a persistent parent's RAM copy included).
    Fix: [create.rs](../../crates/tpm2-impl/src/handler/create.rs#L86-L98).
    Spec: Part 3, "Response Code Details", `TPM_RC_OBJECT_MEMORY`: "In the Reference Code, the TPM copies a referenced persistent object into RAM for the duration of the command. If all the slots are previously occupied, the TPM may return this value."
    Test: [create_object_slots.rs](../tests/e2e/create_object_slots.rs).

31. **Public-only objects could not be made persistent** — *C2 families 1/3/5 (`TPM2_EvictControl`).*
    Root cause: `tpm-rs` kept the pre-185 rule rejecting public-only objects with `TPM_RC_ATTRIBUTES`.
    Fix: [evict_control.rs](../../crates/tpm2-impl/src/handler/evict_control.rs#L87-L98); the persistent record keeps the public-only flag ([engine.rs](../../crates/tpm2-impl/src/engine.rs#L1518-L1527)).
    Spec: Part 3, TPM2_EvictControl: "Older versions of the specification did not allow an object to be persisted when only the public portion of the object was loaded (for NV space efficiency). Support for persisting public-only objects was added in version 185."
    Test: [evict_control_public_only.rs](../tests/e2e/evict_control_public_only.rs).

32. **`TPM2_Create`/`TPM2_CreatePrimary` checked the `userAuth` size before the attributes** — *C4 family 5 (0x1d5 vs 0x2c2).*
    Root cause: the shared parameter validation checked the size of `inSensitive.userAuth` (`TPM_RC_SIZE + P1`) first for all three creation commands; the reference does that first only in `TPM2_CreateLoaded`, and `TPM2_Create`/`TPM2_CreatePrimary` report the attribute checks (`TPM_RC_ATTRIBUTES + P2`) first.
    Fix: an `auth_size_first` argument, set only for `TPM2_CreateLoaded`; the others check the size after the template checks — [create_loaded.rs](../../crates/tpm2-impl/src/handler/create_loaded.rs#L1149-L1157) and [#L1191-L1193](../../crates/tpm2-impl/src/handler/create_loaded.rs#L1191-L1193).
    Spec: Part 3, "Command Validation": "Unless stated otherwise, the order of the checks is not normative and different TPM may give different responses when a command has multiple errors." (the reference's order is followed).
    Test: [create_auth_size_order.rs](../tests/e2e/create_auth_size_order.rs) (`create_primary_checks_attributes_before_auth_size`, `create_loaded_checks_auth_size_before_attributes`).

### 2.4 Credentials and secrets

33. **Three diverging copies of encrypted-seed decryption** — *C1 family 4 (002/016/039/065/070).*
    Root cause: `TPM2_ActivateCredential`, `TPM2_Import` (`inSymSeed`) and `TPM2_StartAuthSession` (`encryptedSalt`) each decrypted the secret differently (OAEP hash, `TPM_RC_VALUE` vs `TPM_RC_SIZE`).
    Fix: one `crypt_secret_decrypt` ([rewrap.rs](../../crates/tpm2-impl/src/handler/rewrap.rs#L371)): the OAEP hash from the key's scheme, else its nameAlg; a ciphertext that is not modulus-sized or not smaller than the modulus is `TPM_RC_SIZE`, a padding error `TPM_RC_VALUE`; `TPM2_StartAuthSession` maps every failure to `TPM_RC_VALUE + P2` ([session.rs](../../crates/tpm2-impl/src/handler/session.rs#L305-L315)).
    Spec: Part 3, TPM2_StartAuthSession: "The TPM shall return TPM_RC_VALUE if … the size of encryptedSalt is not the same as the size of the public modulus".
    Test: [activate_credential_secret.rs](../tests/e2e/activate_credential_secret.rs).

34. **`TPM2_MakeCredential`/`TPM2_ActivateCredential` used the protector's symmetric mode** — *C2 family 6 (`TPM_RC_FAILURE`).*
    Root cause: with a CTR-mode protector, the credential was encrypted in CTR, which failed with `TPM_RC_FAILURE`.
    Fix: always CFB with the protector's algorithm — [make_credential.rs](../../crates/tpm2-impl/src/handler/make_credential.rs#L93-L111), [activate_credential.rs](../../crates/tpm2-impl/src/handler/activate_credential.rs#L109-L127).
    Spec: Part 1, "Credential Protection": "encIdentity := CFB_ekSymAlg (symKey, 0, CV)", "CFB_ekSymAlg | is symmetric encryption in CFB mode using the symmetric algorithm of the key serving as "EK"".
    Test: [activate_credential.rs](../tests/e2e/activate_credential.rs) (`credential_round_trips_under_ctr_mode_protector`).

### 2.5 Hierarchies

35. **Firmware- and SVN-limited hierarchies rejected as `TPM_RC_VALUE`** — *C1 families 054/082/112/164/182.*
    Root cause: valid `TPMI_RH_HIERARCHY` values were rejected while unmarshaling instead of failing at use for lack of a firmware secret.
    Fix: [engine.rs `limited_hierarchy_error`](../../crates/tpm2-impl/src/engine.rs#L6149-L6170), used at the handle load status (`TPM2_CreatePrimary`/`TPM2_CreateLoaded`), for tickets and contexts ([handler/mod.rs](../../crates/tpm2-impl/src/handler/mod.rs#L1173), [sequence.rs](../../crates/tpm2-impl/src/handler/sequence.rs#L57), [context_load.rs](../../crates/tpm2-impl/src/handler/context_load.rs#L93)).
    Spec: Part 2, `TPM_RC_FW_LIMITED`: "the hierarchy is firmware-limited but the Firmware Secret is unavailable"; `TPM_RC_SVN_LIMITED`: "the hierarchy is SVN-limited but the Firmware SVN Secret associated with the given SVN is unavailable".
    Test: [limited_hierarchies.rs](../tests/e2e/limited_hierarchies.rs).

36. **`TPM2_CertifyCreation` of a sequence object rejected the ticket before computing its proof** — *C4 families 1/6 (0x4e0 vs 0xa8/0xa9).*
    Root cause: `TPM_RC_TICKET` was returned for a sequence object before the ticket's hierarchy proof was obtained, so a firmware- or SVN-limited ticket hierarchy did not fail with `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED` as in the reference.
    Fix: the ticket hierarchy is checked first — [certify.rs](../../crates/tpm2-impl/src/handler/certify.rs#L227-L240).
    Spec: Part 3, TPM2_CertifyCreation: "This command is used to prove the association between an object and its creation data."; Part 2, `TPM_RC_FW_LIMITED`: "the hierarchy is firmware-limited but the Firmware Secret is unavailable".
    Test: [limited_hierarchies.rs](../tests/e2e/limited_hierarchies.rs) (`certify_creation_ticket_of_limited_hierarchy_fails`).

### 2.6 Context management

37. **Authentic context with foreign contents returned `TPM_RC_FAILURE`** — *C3 family 2.*
    Root cause: a blob that authenticates (e.g. saved by an earlier build under the same seed) but whose decrypted contents are not `tpm-rs`'s layout failed to parse, which was reported as a TPM failure.
    Fix: `TPM_RC_INTEGRITY + P1` (failure mode stays only for the fingerprint check) — [context_load.rs `malformed_context`](../../crates/tpm2-impl/src/handler/context_load.rs#L610-L629).
    Spec: Part 3, TPM2_ContextLoad: "The TPM shall perform a check on the decrypted context as described in the "Context Confidentiality Protection" clause of TPM 2.0 Part 1 and enter failure mode if the check fails."; Part 2, `TPM2B_CONTEXT_SENSITIVE`: "This is an informative table that is included in the specification only to allow calculation of the maximum size for TPM2B_CONTEXT_DATA."
    Test: [context_load_foreign_contents.rs](../tests/e2e/context_load_foreign_contents.rs).

38. **A saved object with `nameAlg = TPM_ALG_NULL` could not be loaded** — *C1 family J (`TPM_RC_FAILURE`).*
    Root cause: the saved public area was unmarshaled as `TPMT_PUBLIC` (without `+`), which rejects `TPM_ALG_NULL`, and the parse error became `TPM_RC_FAILURE`.
    Fix: the saved public area is read as `TPMT_PUBLIC+` — [context_load.rs](../../crates/tpm2-impl/src/handler/context_load.rs#L390-L395).
    Spec: Part 3, TPM2_LoadExternal: "If *nameAlg* is TPM_ALG_NULL, then the Name is the Empty Buffer."
    Test: [context_save_load_object.rs](../tests/e2e/context_save_load_object.rs) (`null_name_alg_external_object_round_trips`).

39. **`TPM2_ContextLoad`: `savedHandle` not range-checked; wrong `TPM2B_CONTEXT_DATA` capacity** — *C1 family J.*
    Root cause: `savedHandle` values outside the `TPMI_DH_SAVED` ranges were accepted, and the blob capacity did not match the profile's `MAX_CONTEXT_SIZE`, so oversized blobs failed later with other errors.
    Fix: [context_load.rs](../../crates/tpm2-impl/src/handler/context_load.rs#L79-L101), capacity [context_load.rs](../../crates/tpm2-impl/src/handler/context_load.rs#L33-L45).
    Spec: Part 2, "Definition of (TPM_HANDLE) TPMI_DH_SAVED Type" rows and "#TPM_RC_VALUE"; `TPM2B_CONTEXT_DATA`: "buffer[size] {:sizeof(TPMS_CONTEXT_DATA)}".
    Test: [context_load_blob_validation.rs](../tests/e2e/context_load_blob_validation.rs) (`context_fields_fail_in_unmarshaling_order`).

### 2.7 NV capacity and handle assignment

40. **NV space accounting** — *C1 (`TPM2_EvictControl`/`TPM2_NV_DefineSpace` `TPM_RC_NV_SPACE` vs success, and the `TPM_PT_HR_PERSISTENT_AVAIL`/`TPM_PT_NV_COUNTERS_AVAIL` values).*
    Root cause: `tpm-rs` charged its own, key-type-dependent records against a 4 KiB store.
    Fix: the ledger [nv_capacity.rs](../../crates/tpm2-impl/src/storage/nv_capacity.rs), used by [evict_control.rs](../../crates/tpm2-impl/src/handler/evict_control.rs#L118-L129), [nv_storage.rs](../../crates/tpm2-impl/src/handler/nv_storage.rs#L467-L481) and [capability.rs](../../crates/tpm2-impl/src/handler/capability.rs#L327-L334); the simulator's NV is 32 KiB ([lib.rs](../../crates/tpm2-simulator/src/lib.rs#L95)).
    Spec: Part 3, TPM2_EvictControl: "TPM_RC_NV_SPACE | no space in NV memory"; Part 2, `TPM_PT_HR_PERSISTENT_AVAIL`: "This value is an estimate".
    Test: [nv_capacity.rs](../tests/e2e/nv_capacity.rs).

41. **Transient handle numbering with persistent handles** — *C3 family 0 (`TPM2_GetCapability` `HANDLES`, 20 artifacts).*
    Root cause: the reference copies each persistent object of the handle area into the lowest free object slot for the duration of the command, so an object the command creates (`TPM2_HMAC_Start`/`TPM2_MAC_Start` with a persistent key, `TPM2_Load`/`TPM2_CreateLoaded` under a persistent parent) gets the next free slot; `tpm-rs` gave it the lowest free handle.
    Fix: `find_next_transient_handle` skips the slots of the per-command persistent copies — [engine.rs](../../crates/tpm2-impl/src/engine.rs#L1183-L1211).
    Spec: Part 1, "Transient Object Handles": "The TPM assigns Object handles when an Object is loaded [...] Transient Objects in TPM RAM have handles with an MSO of $80_{16}$." (the numbering itself is left open; the reference is followed).
    Test: [transient_handle_numbering.rs](../tests/e2e/transient_handle_numbering.rs).

42. **Unwritten bytes of a non-orderly NV index read as `0x00` instead of the erase value** — *C3 family 0 and C4 family 0 (`TPM2_NV_Read`/`TPM2_NV_Certify` behind an encrypt session or a signature).*
    Root cause: `tpm-rs` initialized the data of a new index and the rest of an ordinary index on its first partial write to `0x00`; the reference leaves the data of a non-orderly index at the NV erase value `0xFF` (`NvAdd()` writes only the header), so e.g. a zero-length first write of a PIN index read back zeros in `tpm-rs` and `0xFF` in the references.
    Fix: new non-orderly indexes start at `0xFF` ([nv_storage.rs `allocate_nv_space`](../../crates/tpm2-impl/src/handler/nv_storage.rs#L864-L919)), and the first partial write of an ordinary index clears the rest to `0xFF` (non-orderly) or `0x00` (orderly) ([nv_storage.rs](../../crates/tpm2-impl/src/handler/nv_storage.rs#L333-L387)).
    Spec: Part 3, TPM2_NV_Write: "merge the *data.size* octets …" (the value of the other octets is left open; the reference is followed).
    Tests: [nv_read_write.rs](../tests/e2e/nv_read_write.rs) (`first_partial_write_clears_rest`, `first_partial_write_of_orderly_index_clears_rest_to_zero`, `unwritten_bytes_of_non_orderly_index_read_as_erased`, `zero_length_first_write_of_pin_index_leaves_data_erased`).

### 2.8 Capability reporting

43. **`TPM_CAP_ALGS`/`TPM_CAP_ECC_CURVES` compared the whole 32-bit `property`** — *pre-campaign smoke run (0x17a).*
    Root cause: a `property` with upper bits set matched no 16-bit algorithm or curve ID and returned an empty list.
    Fix: only the low 16 bits — [capability.rs](../../crates/tpm2-impl/src/handler/capability.rs#L728-L736).
    Spec: Part 3, TPM2_GetCapability: "TPM_CAP_ALGS | TPM_ALG_ID(1) | TPML_ALG_PROPERTY" with "[1] The TPM_ALG_ID or TPM_ECC_CURVE is cast to a UINT32" (silent on the upper bits; the reference is followed).
    Test: [get_capability.rs](../tests/e2e/get_capability.rs) (`algorithm_and_curve_properties_ignore_upper_bits`).

44. **`TPM_CAP_TPM_PROPERTIES` returned properties of the next group** — *pre-campaign smoke run.*
    Root cause: the property list continued past the 256-value group of the requested property.
    Fix: [capability.rs](../../crates/tpm2-impl/src/handler/capability.rs#L491-L515).
    Spec: Part 3, TPM2_GetCapability: "The properties are returned in groups. Each property group is on a 256-value boundary (that is, the boundary occurs when the TPM_PT is evenly divisible by 256). The TPM will only return values in the same group as the property parameter in the command."
    Test: [get_capability.rs](../tests/e2e/get_capability.rs) (`tpm_properties_stay_within_the_requested_group`).

45. **`TPM_PT_LOADED_CURVES` wrong** — *C1.*
    Root cause: the property did not count the implemented (always loaded) curves.
    Fix: the number of implemented curves — [capability.rs](../../crates/tpm2-impl/src/handler/capability.rs#L482-L485).
    Spec: Part 2, `TPM_PT`: "TPM_PT_LOADED_CURVES | PT_VAR + 13 | the number of curves loaded".
    Test: [get_capability.rs](../tests/e2e/get_capability.rs) (`loaded_curves_counts_every_implemented_curve`).

46. **`TPM_PT_MAX_OBJECT_CONTEXT`/`TPM_PT_MAX_SESSION_CONTEXT` unrelated to the real context format** — *found while triaging the context families of C1.*
    Root cause: fixed values 3072/512, smaller than real saved contexts.
    Fix: computed from the serializer's field capacities, with a static check that they fit `TPM2B_CONTEXT_DATA` — [context_save.rs](../../crates/tpm2-impl/src/handler/context_save.rs#L533-L630), reported by [capability.rs](../../crates/tpm2-impl/src/handler/capability.rs#L419-L430).
    Spec: Part 2, `TPM_PT`: "TPM_PT_MAX_OBJECT_CONTEXT | PT_FIXED + 33 | the maximum size of an object context that will be returned by TPM2_ContextSave()".
    Test: [get_capability.rs](../tests/e2e/get_capability.rs) (`max_context_sizes_bound_saved_contexts`).

## 3. Remaining ignored discrepancies

### 3.1 Active `server.rs` exceptions

These are the documented exceptions of
[server.rs](../../testing/src/differential/server.rs) (`compare_differential_response`),
listed in [differential.md](../../differential.md), Part IV. Each is keyed to a
command and condition; any other difference fails the comparison.

| # | Commands | Implementation | What differs | Why it is acceptable | Code / doc |
|---|---|---|---|---|---|
| 1 | `TPM2_ContextSave` | both | The `contextBlob` contents (encrypted object/session image); `sequence`, `savedHandle`, `hierarchy` and the tag are compared exactly, and a later `TPM2_ContextLoad` of the blob must behave identically (the blob is translated to the reference's own blob). | Implementation-defined format: Part 2, `TPM2B_CONTEXT_SENSITIVE`: "This is an informative table that is included in the specification only to allow calculation of the maximum size for TPM2B_CONTEXT_DATA." | [server.rs](../../testing/src/differential/server.rs#L983), differential.md Part IV rule 1 |
| 2 | `TPM2_GetCapability` | both | `TPM_CAP_TPM_PROPERTIES` values of the implementation-specific properties `0x10F, 0x116, 0x118, 0x119, 0x11C, 0x11F, 0x121, 0x122, 0x12D`; the reference-only properties `0x12F`, `0x130` and (version 185) `0x131` with value 0, and a reference `moreData = YES` against `tpm-rs`'s `NO` when the lists are otherwise equal (the reference's list was cut by `propertyCount` before or within that reference-only tail). Tag, capability, order and every other value are compared exactly. | Capability values are TPM-specific (e.g. Part 2, `TPM_PT_HR_PERSISTENT_AVAIL`: "This value is an estimate"); `0x121`/`0x122` are the bounds of each implementation's own context format (rule 1). | [server.rs `capability_difference_is_documented`](../../testing/src/differential/server.rs#L873), differential.md rule 2 |
| 3 | `TPM2_ECC_Parameters` | both | Curve parameters equal up to leading zero bytes (`tpm-rs` pads to the curve size). | Part 1/Part 3: the parameters "may not be the same size". | [server.rs](../../testing/src/differential/server.rs#L1005), rule 3 |
| 4 | `TPM2_IncrementalSelfTest` | both | The `toDoList` contents (both must be well-formed `TPML_ALG` responses with identical headers). | Which algorithms still need testing is TPM-dependent (Part 3, TPM2_IncrementalSelfTest). | [server.rs](../../testing/src/differential/server.rs#L1034), rule 4 |
| 8 | `TPM2_PCR_Reset` | both | PCR 16 at locality 5–31: `tpm-rs` `TPM_RC_LOCALITY`, reference success. | The C simulator's platform layer maps localities 5–31 to locality 0; a platform property, not TPM behavior. | [server.rs](../../testing/src/differential/server.rs#L1048), rule 8 |
| 9 | `TPM2_ContextLoad` | both | A blob `tpm-rs` never returned (tampered, truncated, or from another run) reaches the reference with its integrity value zeroed, and both must reject it: the reference with `TPM_RC_SIZE` or `TPM_RC_INTEGRITY + P1` depending on the layout, `tpm-rs` with one of those or, for an authentic blob of another run whose decrypted fingerprint does not match, with the spec-mandated `TPM_RC_FAILURE`. **This deliberately masks** how the reference would treat the blob: all implementations share the hierarchy proofs and Part 1's integrity HMAC under the fixed seed, so the reference would otherwise authenticate a `tpm-rs` blob and interpret its implementation-defined contents. | Vendor-defined blob layout (rule 1); Part 3, TPM2_ContextLoad: "The TPM shall perform a check on the decrypted context as described in the "Context Confidentiality Protection" clause of TPM 2.0 Part 1 and enter failure mode if the check fails." and "If the integrity HMAC of the saved context is not valid, the TPM shall return TPM_RC_INTEGRITY." | [server.rs `untranslated_context_load`](../../testing/src/differential/server.rs#L268), rule 9 |
| RETRY | DA-protected commands | both | The first DA-protected access of a boot returns `TPM_RC_RETRY` in the references (`USE_DA_USED`); the identical command is re-issued to the reference once and compared exactly. | `TPM_RC_RETRY` is a warning; both behaviors meet Part 1, "Non-orderly Shutdown". | [server.rs](../../testing/src/differential/server.rs#L487), rule RETRY |

Rules 5, 6, 7, 10 and 11 are retired: the TPM profile, `MAX_LOADED_OBJECTS = 3`, the transient handle numbering (bug 41) and the NV erase value (bug 42) made `tpm-rs` and the references agree.

### 3.2 `known_divergences.txt`

[known_divergences.txt](known_divergences.txt) contains no patterns (only its
header comment): no finding signature is suppressed in the fuzz target.

### 3.3 Other intentional differences

- **`TPM_PT_MAX_OBJECT_CONTEXT`/`TPM_PT_MAX_SESSION_CONTEXT`**: `tpm-rs`
  reports the true bounds of its own context format (computed from the
  serializer's field capacities in
  [context_save.rs](../../crates/tpm2-impl/src/handler/context_save.rs)), and
  the references report 1372/404 for theirs. Part 2 defines the property as
  "the maximum size of an object context that will be returned by
  TPM2_ContextSave()", and the context format is implementation-defined
  (exception 1), so the values differ legitimately (exception 2).
- **Commands one side implements and the other does not**: there are none.
  Each reference's `profile-command-list.patch` disables exactly the commands
  `tpm-rs` does not implement (14 for `mstpm20`, 21 for `mstpm20` version
  185, 12 for `ibmswtpm2`), so every campaign signature was tagged `spec`
  (never `us-only` or `them-only`).
- **Untranslatable `TPM2_ContextLoad` blobs** (exception 9) are deliberately
  corrupted before they reach the references (see the table above).
