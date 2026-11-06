# Live Migration between `tpm-rs` and `ibmswtpm2` v974

> **Note:** the `tpm2-engine` `persistence` module (`PersistedTpmState`) this document refers to has been removed; the runtime state is now serialized by the platform (`Platform::serialize`/`deserialize`). The differences between the two TPMs listed here still apply to any converter.

This document is for whoever writes a converter between `tpm-rs`'s persisted state and the state of the google3 `ibmswtpm2` (v974, `third_party/ibmswtpm2/files/src/`, saved by the vTPM serializer as its globals plus the `s_NV` image), so that a running TPM can be live-migrated in either direction. It lists the differences between the two TPMs that **no converter can bridge** (D1-D8), the features only one side has, when each of them is harmless, and what a converter must check before it migrates.

Paths are relative to the repository (`crates/...`) or, for v974, to google3 (`third_party/ibmswtpm2/files/src/...`).

---

## Background

### `PersistedTpmState`

[`tpm2_engine::persistence::PersistedTpmState`](crates/tpm2-engine/src/persistence/types.rs) (feature `persistence`; `serde` with `serde`) is the complete state of a `tpm-rs` TPM:

- `nv`: the canonical NV image (the reserved header, the item handles in ascending order and the canonical payloads; item sizes and attributes are derived). It is the source of truth for every NV-synced field (C `gp`); restore reloads them through the records of `crates/tpm2-engine/src/storage/nv.rs`.
- `reset`/`clear`/`orderly`: C `gr`/`gc`/`go`, which run ahead of NV between shutdowns.
- `runtime`: the RAM-only globals, and the `gp` values that may be ahead of NV (`orderly_state`, `failed_tries`, `da_pending_on_nv`, `lockout_auth_enabled`), applied after the NV reload.
- `time`, `loaded` (objects, sessions, sequences, in handle order), `pcrs`, `act`, `vendor`, `self_test`: RAM-only state.
- `platform` (optional): the simulated firmware image (hash and SVN).

It holds nothing derivable: restore recomputes object Names, `isNameHashDefined`, `isBound` and the slots, and a saved session is only its slot and the low 16 bits of its sequence number. Platform-timer values are relative to the timer reading at the save (`time.pending_platform_ms`, `act.tick_phase_ms`); restore rebases them on the target's timer, and a converter to v974 rebases them on the host clock behind `s_realTimePrevious`. The free functions `try_serialize`/`try_deserialize` take that timer reading (`now_ms`), and `try_deserialize` also a hash provider for the Names; `TpmEngine::save_persisted_state`/`restore_persisted_state` (and `Simulator::save_persisted_state`/`restore_persisted_state` with the platform state) use their platform's. See `crates/tpm2-engine/src/persistence/mod.rs` for the groups and what is deliberately not persisted, and `types.rs` for the widths.

### Assumptions

The state is saved and restored **between two commands, with the TPM powered on and NV available**, as the vTPM does. Per-command scratch on both sides (`tpm-rs` parsed authorizations and audit cpHashes, `update_nv`/`clear_orderly`; v974 `s_sessionHandles`, `s_nonceCaller`, `s_cpHashForCommandAudit`, the NV index cache, `g_updateNV`, `g_clearOrderly`) is then idle and need not be converted.

### Sound migration

Two directions:

- **A**: `tpm-rs` → `PersistedTpmState` → converter → v974 (and back);
- **B**: v974 → converter → `PersistedTpmState` → `tpm-rs` (and back).

A migration is **sound** if the target TPM shows the same observable behaviour as the source would have for every future command sequence: the same responses, the same keys from the same seeds, the same tickets, counters and lockout decisions. Byte equality of the two states is not required: a converter may re-encode freely (marshalled vs. C-struct public areas, `StreamingHashState` vs. BoringSSL hash contexts) and synthesize what v974 derives (`s_evictNvEnd`, `s_freeSessionSlots`, `s_oldestSavedSession`, `g_implementedAlgorithms`, `s_tpmTime`, the NV `gc.pcrSave` copy, which equals the live PCRs 0-15 while orderly is `TPM_SU_STATE` because a change to a state-saved PCR clears orderly).

The blockers below are differences of **profile or semantics**: v974 cannot hold the value, or the two engines behave differently on the same state. A converter can only refuse such states; fixing them needs a `tpm-rs` profile that matches v974.

---

## Profile and semantic blockers

### D1. Size of the hierarchy secrets

- **What differs.** `tpm-rs` draws the Primary Seeds (EPS/SPS/PPS) and the hierarchy proofs (ph/sh/ehProof) as 64 octets each (`TpmEngine::init_storage`, `crates/tpm2-engine/src/engine.rs`), and nullSeed/nullProof as 64 octets at every TPM Reset (`crates/tpm2-engine/src/handler/startup.rs`); Clear, ChangeEPS and ChangePPS draw new 64-octet values. v974 holds seeds in `TPM2B_SEED` with `PRIMARY_SEED_SIZE 32` (`third_party/ibmswtpm2/files/src/Implementation.h`) and proofs in a `TPM2B_AUTH` (48 octets).
- **Why no converter can bridge it.** The secrets are keys of KDFs and HMACs (primary keys, tickets, context integrity, attestation obfuscation); truncating them changes every derived value.
- **When it is harmless.** A: never; every `tpm-rs` state has 64-octet secrets. B: until `tpm-rs` runs a TPM Reset, TPM2_Clear, TPM2_ChangeEPS or TPM2_ChangePPS (it accepts the shorter v974 values, so v974 → `tpm-rs` alone works).
- **Fix.** A v974 profile in `tpm-rs`: 32-octet seeds and digest-sized proofs.

### D2. Width of the session context slot

- **What differs.** `tpm-rs` tracks saved sessions with a 16-bit `ContextSlot` and `MAX_CONTEXT_GAP` = 65536 (`crates/tpm2-engine/src/engine.rs`), as the TCG reference's production profile (tcgtpm `TpmProfile_Misc.h` uses `UINT8` only with `SIMULATION && DEBUG`), and `PersistedSavedSession::sequence` holds the low 16 bits. v974 defines `CONTEXT_SLOT UINT16` in `Implementation.h`, but `Global.h` redefines it as `UINT8` whenever `SIMULATION` is defined, which `TpmBuildSwitches.h` does by default (and again inside `gr` without `NDEBUG`), so `gr.contextArray` holds one octet per session and `MAX_CONTEXT_GAP` is 256 (`Session.c`).
- **Why no converter can bridge it.** v974 stores only the low octet of a saved session's sequence number. A converter recovers the full sequence as the unique value in `[contextCounter - 256, contextCounter - 1]` with that low octet (B: then keeps its low 16 bits), which works only while the gap is below 256. A `tpm-rs` session saved 256 or more contexts ago cannot be encoded (A: the full sequence is the latest value up to `reset.context_counter` with the persisted low 16 bits). After a B migration, `tpm-rs` also lets the gap grow past 256 where v974 would return `TPM_RC_CONTEXT_GAP`, and `TPM_PT_CONTEXT_GAP_MAX` differs.
- **When it is harmless.** For the conversion: every saved session is fewer than 256 sequence numbers behind `reset.context_counter`. For the behaviour afterwards: clients never let the gap reach 256.
- **Fix.** Make the context slot a profile constant of `tpm-rs` (8 bits for v974).

The time epoch and the session epochs (`CLOCK_NONCE`) are 32-bit in both: `tpm-rs` follows `CLOCK_STOPS == NO`, as do tcgtpm and v974, so they convert without a check.

### D3. Context-integrity hash

- **What differs.** google3 v974 fixes `CONTEXT_INTEGRITY_HASH_ALG` to SHA-256 (`Implementation.h`, b/64836800). `tpm-rs` uses SHA-512, or SHA-384 without the `sha512` feature (`context_integrity_hash_alg`, `crates/tpm2-engine/src/handler/mod.rs`).
- **Why no converter can bridge it.** The hash is part of the engine, not of the state. It keys the tickets (creation, verified, hashcheck, auth), the integrity HMAC and key of saved contexts, the ECDAA commit KDF, and the obfuscation of `resetCount`/`restartCount`/`firmwareVersion` in attestations that are unsigned or signed by keys outside the endorsement and platform hierarchies. It also sets `TPM_PT_CONTEXT_HASH`, the size limit of TPM2_HierarchyChangeAuth and the digest-size properties.
- **When it is harmless.** No ticket, saved context or ECDAA commit is outstanding at migration time, and no client compares obfuscated attestation fields or the properties above across the migration.
- **Fix.** A `tpm-rs` profile option that selects SHA-256 as the context-integrity hash.

### D4. Dictionary-attack startup semantics

- **What differs.**
  - `tpm-rs` implements `USE_DA_USED`: `runtime.da_used` and the NV orderly value `0xFFFE` (`SU_DA_USED_VALUE`, `crates/tpm2-engine/src/handler/startup.rs`) make an unorderly Startup increment `failedTries` only if a DA-protected authorization happened since the last orderly shutdown. v974 is built without it (`TpmBuildSwitches.h`) and increments on every unorderly Startup (`DAStartup`, `DA.c`).
  - `tpm-rs` implements `ACCUMULATE_SELF_HEAL_TIMER`: `orderly.shutdown_time_ms` and the DA timer copies in the NV header rebase the self-heal and lockout timers after an orderly power cycle. v974 is built without it and zeroes both timers at every Startup.
- **Why no converter can bridge it.** v974 has no home for `da_used`, `shutdown_time_ms` or the NV timer copies. A converter can map v974 `TPM_SU_NONE` to the NV orderly value `0xFFFE` with `runtime.da_used` set (and `0xFFFE` back to `TPM_SU_NONE`), which preserves the next increment, but a `tpm-rs` state that is not orderly and has no DA use (NV orderly `0xFFFF`, `da_used` clear, the usual state after a Startup) becomes `TPM_SU_NONE` too, and v974 then increments where `tpm-rs` would not.
- **When it is harmless.**
  - Conversion: `runtime.da_used` is set exactly when the NV orderly state (in `nv.header`) is `0xFFFE`. It is not, e.g., after a Startup that skipped the increment because `recoveryTime` is 0 or `failedTries` was at `maxTries`, after a failed Startup (`runtime.orderly_state` already `TPM_SU_NONE`, NV still `0xFFFE`), or after a DA failure while NV was off. In addition, the NV orderly state is not orderly, i.e. the TPM is not between an orderly Shutdown and the next Startup (otherwise the NV timer copies and `shutdown_time_ms` are live).
  - Behaviour afterwards: DA protection is disabled (`recoveryTime` 0) or `failedTries` is at `maxTries`, or no unorderly power cycle follows before the next DA-protected authorization, and no power cycle relies on the accumulated self-heal time.
- **Fix.** Profile switches for `USE_DA_USED` and `ACCUMULATE_SELF_HEAL_TIMER` in `tpm-rs`.

### D5. Algorithms, commands and profile constants

- **What differs.**
  - Algorithms: the default `tpm2` features include SHA-512, ECDAA and BN P-256; v974 lacks all three and has TDES, which `tpm-rs` does not implement (`Implementation.h`).
  - Commands: v974 implements TPM2_PP_Commands, TPM2_PolicyPhysicalPresence and TPM2_SetAlgorithmSet, which are the `tpm-rs` features `cc-pp-commands`, `cc-policy-physical-presence` and `cc-set-algorithm-set`.
  - Constants: `NV_CLOCK_UPDATE_INTERVAL` is 22 in `tpm-rs` (`crates/tpm2-engine/src/engine.rs`) and 12 in v974; `MAX_CONTEXT_SIZE` is 2264 and 2474; the NV space accounting of `crates/tpm2-engine/src/storage/nv_capacity.rs` (`SIZEOF_OBJECT`, `SIZEOF_NV_INDEX`) models tcgtpm, not v974's `OBJECT`/`NV_INDEX`, so `TPM_RC_NV_SPACE` and the `TPM_PT_*_AVAIL` values differ.
- **Why no converter can bridge it.** An object, key, scheme, PCR bank, self-test bit or audit/ppList bit of an algorithm or command the other side lacks has no representation there, and the constants change responses for the same state.
- **When it is harmless.** The `tpm-rs` build matches v974's sets (`--no-default-features` without `sha512`, `ecdaa` and `bn_p256`, plus the three `cc-*` features above), no TDES entity exists on the v974 side, and no client depends on the constants above.
- **Fix.** A v974 profile (features and constants), plus TDES in `tpm-rs` if v974 states with TDES entities must migrate.

### D6. Orderly NV indices

- **What differs.** `tpm-rs` writes the data of orderly NV indices (`TPMA_NV_ORDERLY`) straight to NV (`crates/tpm2-engine/src/handler/nv_storage.rs`). v974 keeps them in `s_indexOrderlyRam` and writes that RAM to its NV copy only at TPM2_Shutdown and when a command requests an orderly update (`UT_ORDERLY`, e.g. an orderly counter rolling over its low bits, `ExecCommand.c`); every Startup reloads RAM from the NV copy, and after an unorderly power cycle sets each orderly counter to its NV value `| MAX_ORDERLY_COUNT` (`NVDynamic.c`).
- **Why no converter can bridge it.** `PersistedTpmState` holds one copy. In A the converter writes the `tpm-rs` payload to both v974 copies, which is sound. In B the stale v974 NV copy is lost, so after a later power loss `tpm-rs` (and v974 after converting back) reports the RAM values instead of v974's rolled-forward or reverted ones.
- **When it is harmless.** No orderly index changed since the last orderly shutdown (the NV copy equals RAM), or no unorderly power cycle follows. The spec permits counters to jump forward, so a counter that comes back higher is still monotonic.
- **Fix.** Model the two copies in `tpm-rs`, or carry the raw 512-octet v974 copy in `PersistedTpmState` (lossless for B only).

### D7. Client-held context blobs and primary key derivation

- **What differs.** A saved context (TPM2_ContextSave) is an engine-specific format: `tpm-rs` serializes its own structures (`crates/tpm2-engine/src/handler/context_save.rs`); v974 stores the raw C `OBJECT`/`HASH_OBJECT`/`SESSION` structs, with host pointers. Saved sessions exist only in these blobs. google3 v974 also derives RSA and ECC primary keys with its BoringSSL adapter (`third_party/ibmswtpm2/bssl_adapter/`), not with the TCG reference algorithm `tpm-rs` follows.
- **Why no converter can bridge it.** The blobs are held by clients, outside both states; TPM2_CreatePrimary from the same seed yields different keys.
- **When it is harmless.** No saved contexts at migration time, and no primary key created before the migration is re-created and compared after it.
- **Fix.** A v974 decoder in TPM2_ContextLoad, and a port of the adapter's key generation as a `tpm-rs` feature.

### D8. State-save record missing with orderly `TPM_SU_STATE`

- **What differs.** TPM2_Shutdown(STATE) in `tpm-rs` ignores a failure to write the state-save record (`crates/tpm2-engine/src/handler/shutdown.rs`) and still sets orderly to `TPM_SU_STATE`; the next Startup(STATE) then fails with `TPM_RC_NV_UNINITIALIZED`. v974's `gr`/`gc` NV regions are fixed and always present.
- **Why no converter can bridge it.** v974 has no way to say "orderly is `TPM_SU_STATE` but the saved data is missing".
- **When it is harmless.** Always, except after a failed Shutdown(STATE) NV write.
- **Fix.** None needed in practice; a converter refuses the state.

---

## Features only one side has

These are features, not mismatches: a state converts soundly while the feature is disabled or at its initial value. They still change the command surface (capabilities, handles, command codes), which a v974 profile turns off.

| Side | Feature | `tpm-rs` state | Harmless when |
|---|---|---|---|
| `tpm-rs` | F1. ACTs (`ACT_0` is always built, `IMPLEMENTED_ACTS` in `crates/tpm2-engine/src/act.rs`) | `act` | Counters idle, no pending values, policies empty, saved/preserved/updated signals zero; the tick phase is then irrelevant. |
| `tpm-rs` | F2. Firmware hash/SVN and the firmware-/SVN-limited hierarchies | `platform`, object `hierarchy` | Default hash and SVN, and no limited entity (object, primary) in use. |
| `tpm-rs` | F3. Read-only mode (`cc-read-only-control`), PolicyParameters (`cc-policy-parameters`), secure channel (`cc-policy-transport-spdm`) | `clear.read_only`, session `is_parameters_hash_defined`, `sec_channel` | `false` / empty. |
| `tpm-rs` | F4. CMAC (`cmac`), Sign and Verify sequences (`cc-sign-sequence-*`, `cc-verify-sequence-*`), ML-DSA `mu_state` | `loaded.sequences` | None loaded. |
| `tpm-rs` | F5. SHA-512, SM3 and SHA-3 PCR banks | `pcrs` | Features off. |
| `tpm-rs` | F6. Nuvoton NTC2 configuration (`ntc2-vendor-commands`) | `vendor.ntc2_config` | `None`. |
| `tpm-rs` | F7. ECDAA commit state | `reset.commit` | ECDAA unused (the counter, array and nonce are then never read). |
| `tpm-rs` | F8. Self-test bits above `0x47` (ML-KEM, ML-DSA, ...); v974's `g_toTest` covers algorithm IDs up to `0x47` | `self_test.untested_algorithms` | Features off. |
| `tpm-rs` | F9. Audit and ppList bits of commands v974 lacks | NV hierarchy and platform-settings records | Clear. |
| v974 | TDES (`ALG_TDES`) | none | No TDES object or session. |
| v974 | Orderly-index NV copy | none | See D6. |
| v974 | `s_isCanceled`, `g_forceFailureMode` | none | `FALSE` (the vTPM never cancels). |
| v974 | `g_cryptoSelfTestState` | none | Always: its `rng` bit only re-runs the DRBG known-answer test. |
| v974 | Failure-mode diagnostics `s_failFunction`/`s_failLine`/`s_failCode` (`TpmFail.c`) | none (`tpm-rs` keeps no diagnostics, see `persistence/mod.rs`) | The TPM is not in Failure mode (`s_failFunction` is a truncated host pointer, not portable even between v974 hosts). |

---

## Converter checklist

Refuse to migrate unless all of these hold.

**Both directions**

- [ ] The `tpm-rs` build has v974's algorithm and command sets (D5): no `sha512`, `ecdaa`, `bn_p256`; with `cc-pp-commands`, `cc-policy-physical-presence`, `cc-set-algorithm-set`.
- [ ] No ticket, saved context or ECDAA commit is outstanding (D3, D7), and clients will not re-create and compare primary keys (D7).
- [ ] The Rust-only features F1-F9 are at their harmless values.
- [ ] The TPM is not in Failure mode.
- [ ] The NV orderly state is not orderly (D4), or the converter is known to handle the orderly window.

**A (`tpm-rs` → v974)**

- [ ] Every seed and proof fits v974: 32 octets for seeds and nullSeed, 48 for proofs and nullProof (D1). Today this fails for every state.
- [ ] Every saved session is fewer than 256 sequence numbers behind `reset.context_counter` (D2).
- [ ] `runtime.da_used` is set exactly when the NV orderly state is `0xFFFE` (D4); map `0xFFFE` to `TPM_SU_NONE`.
- [ ] If the NV orderly state is `TPM_SU_STATE`, the state-save record is present (D8).
- [ ] Write the orderly-index payloads to both `s_indexOrderlyRam` and its NV copy (D6).
- [ ] Rebase the relative timer value on the host clock: `s_realTimePrevious` = host now − `time.pending_platform_ms`.

**B (v974 → `tpm-rs`)**

- [ ] No TDES entity (D5).
- [ ] The orderly-index NV copy equals `s_indexOrderlyRam` (D6), or the loss is accepted.
- [ ] Map `TPM_SU_NONE` to NV orderly `0xFFFE` with `runtime.da_used` set (D4).
- [ ] Expand the saved-session octets of `gr.contextArray` to full sequences and keep their low 16 bits (D2).
- [ ] Set `time.pending_platform_ms` = host now − `s_realTimePrevious`.
- [ ] For the return leg: `tpm-rs` has not run a TPM Reset, Clear, ChangeEPS or ChangePPS since the migration (D1).
