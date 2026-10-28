# Bug report: mstpm20 (TCG reference implementation, pre-185)

The bugs of the C reference `mstpm20` that the `bug-fix-*.patch` files in this directory fix for differential testing against `tpm-rs`. Security Severity is the security severity of the bug in the unpatched reference (— = no security impact).

## Contents

- [Summary](#summary)
- [Categories](#categories)
- [Bugs](#bugs)
  - [activate-credential-sequence-object](#activate-credential-sequence-object)
  - [certify-sequence-object](#certify-sequence-object)
  - [pcr-extended-locality](#pcr-extended-locality)
  - [bind-entity-public-only](#bind-entity-public-only)
  - [object-change-auth-derived-object](#object-change-auth-derived-object)
  - [rsa-prime-range](#rsa-prime-range)
  - [sequence-complete-ticket-error-state](#sequence-complete-ticket-error-state)
  - [svn-fw-limited-entity-hierarchy](#svn-fw-limited-entity-hierarchy)
  - [certify-creation-sequence-object](#certify-creation-sequence-object)
  - [expiration-absolute-value](#expiration-absolute-value)
  - [persistent-copy-handle-alias](#persistent-copy-handle-alias)
  - [svn-fw-limited-load-external](#svn-fw-limited-load-external)
  - [vendor-auth-entity-break](#vendor-auth-entity-break)
  - [act-preserve-signaled](#act-preserve-signaled)
  - [get-test-result-needs-test](#get-test-result-needs-test)
  - [hierarchy-control-base-hierarchy](#hierarchy-control-base-hierarchy)
  - [nv-certify-null-sign-handle-digest](#nv-certify-null-sign-handle-digest)
  - [persist-public-only-objects](#persist-public-only-objects)
  - [session-audit-attribute-dependency](#session-audit-attribute-dependency)
  - [svn-fw-limited-evict-control](#svn-fw-limited-evict-control)
  - [symmetric-unique](#symmetric-unique)
  - [template-size](#template-size)
  - [tk-verified-tags](#tk-verified-tags)
  - [tpmu-name-size](#tpmu-name-size)

## Summary

| Patch | Categories | Security Severity | Description |
|---|---|---|---|
| [activate-credential-sequence-object](bug-fix-activate-credential-sequence-object.patch) ([details](#activate-credential-sequence-object)) | `security`, `auth-bypass`, `memory-safety`, `spec` | high | ActivateCredential accepts a sequence object, whose stale Name lets an attacker activate credentials for any public area loaded earlier in the slot. |
| [certify-sequence-object](bug-fix-certify-sequence-object.patch) ([details](#certify-sequence-object)) | `security`, `attestation`, `memory-safety`, `spec` | high | Certify accepts a sequence object and signs the stale Name/Qualified Name of an earlier (possibly public-only) object in the slot. |
| [pcr-extended-locality](bug-fix-pcr-extended-locality.patch) ([details](#pcr-extended-locality)) | `security`, `ub`, `spec` | high | PCR reset/extend checks shift by an extended locality (UB), so localities 32+ alias localities 0-4 and can modify D-RTM PCRs. |
| [bind-entity-public-only](bug-fix-bind-entity-public-only.patch) ([details](#bind-entity-public-only)) | `security`, `dos`, `spec` | medium | A bound HMAC session authorizing a public-only object hits an assertion in the bind check (failure mode) instead of TPM_RC_AUTH_UNAVAILABLE. |
| [object-change-auth-derived-object](bug-fix-object-change-auth-derived-object.patch) ([details](#object-change-auth-derived-object)) | `security`, `memory-safety`, `dos`, `spec` | medium | TPM2_ObjectChangeAuth of a derived object uses an uninitialized symmetric definition of the Derivation Parent. |
| [rsa-prime-range](bug-fix-rsa-prime-range.patch) ([details](#rsa-prime-range)) | `security`, `dos`, `crypto`, `input-validation`, `spec` | medium | RSA key loading does not check the range of the computed prime Q, so a crafted key can put the TPM in failure mode. |
| [sequence-complete-ticket-error-state](bug-fix-sequence-complete-ticket-error-state.patch) ([details](#sequence-complete-ticket-error-state)) | `security`, `dos`, `state`, `fw-limited`, `spec` | medium | A TPM2_SequenceComplete that fails computing its ticket leaves the sequence loaded with a consumed hash state, whose reuse enters failure mode. |
| [svn-fw-limited-entity-hierarchy](bug-fix-svn-fw-limited-entity-hierarchy.patch) ([details](#svn-fw-limited-entity-hierarchy)) | `security`, `attestation`, `fw-limited`, `spec` | medium | EntityGetHierarchy() reports the base hierarchy for objects in limited hierarchies, so their creation/auth tickets use the base proof. |
| [certify-creation-sequence-object](bug-fix-certify-creation-sequence-object.patch) ([details](#certify-creation-sequence-object)) | `security`, `attestation`, `memory-safety`, `spec` | low | CertifyCreation accepts a sequence object and checks/signs the creation ticket against the stale Name of an earlier object in the slot. |
| [expiration-absolute-value](bug-fix-expiration-absolute-value.patch) ([details](#expiration-absolute-value)) | `ub`, `interop`, `spec` | low | The absolute value of expiration = INT32_MIN overflows, giving a wrong policy timeout and ticket. |
| [persistent-copy-handle-alias](bug-fix-persistent-copy-handle-alias.patch) ([details](#persistent-copy-handle-alias)) | `security`, `spec` | low | A later transient handle that names the slot of a persistent object's per-command RAM copy resolves to that persistent object instead of failing with TPM_RC_REFERENCE_Hn. |
| [svn-fw-limited-load-external](bug-fix-svn-fw-limited-load-external.patch) ([details](#svn-fw-limited-load-external)) | `security`, `input-validation`, `fw-limited`, `spec` | low | TPM2_LoadExternal accepts a public-only object with firmwareLimited or svnLimited SET. |
| [vendor-auth-entity-break](bug-fix-vendor-auth-entity-break.patch) ([details](#vendor-auth-entity-break)) | `security`, `dos`, `functional`, `spec` | low | Missing break for VENDOR_PERMANENT_AUTH_HANDLE in EntityGetAuthValue() falls into FAIL(), so using the vendor authValue puts the TPM into failure mode. |
| [act-preserve-signaled](bug-fix-act-preserve-signaled.patch) ([details](#act-preserve-signaled)) | `state`, `spec` | — | ACT preserveSignaled is cleared/merged by power loss instead of being CLEAR on TPM Reset/Restart and a copy of signaled on TPM Resume. |
| [get-test-result-needs-test](bug-fix-get-test-result-needs-test.patch) ([details](#get-test-result-needs-test)) | `self-test`, `spec` | — | TPM2_GetTestResult always returns TPM_RC_SUCCESS instead of TPM_RC_NEEDS_TEST while algorithms remain untested. |
| [hierarchy-control-base-hierarchy](bug-fix-hierarchy-control-base-hierarchy.patch) ([details](#hierarchy-control-base-hierarchy)) | `spec`, `input-validation`, `rc-only` | — | TPM2_HierarchyControl unmarshals authHandle as TPMI_RH_HIERARCHY instead of TPMI_RH_BASE_HIERARCHY. |
| [nv-certify-null-sign-handle-digest](bug-fix-nv-certify-null-sign-handle-digest.patch) ([details](#nv-certify-null-sign-handle-digest)) | `spec-185`, `functional`, `spec` | — | TPM2_NV_Certify with a NULL signHandle and size = offset = 0 returns an Empty Buffer digest (pre-185 rule) instead of a digest with inScheme's hash or TPM_RC_SCHEME. |
| [persist-public-only-objects](bug-fix-persist-public-only-objects.patch) ([details](#persist-public-only-objects)) | `spec-185`, `spec` | — | TPM2_EvictControl rejects public-only objects with TPM_RC_ATTRIBUTES (pre-185 rule) although version 185 allows persisting them. |
| [session-audit-attribute-dependency](bug-fix-session-audit-attribute-dependency.patch) ([details](#session-audit-attribute-dependency)) | `spec`, `rc-only` | — | auditExclusive/auditReset without audit are ignored on HMAC/policy sessions instead of returning TPM_RC_ATTRIBUTES. |
| [svn-fw-limited-evict-control](bug-fix-svn-fw-limited-evict-control.patch) ([details](#svn-fw-limited-evict-control)) | `spec`, `rc-only`, `fw-limited` | — | TPM2_EvictControl rejects objects of limited hierarchies with TPM_RC_HIERARCHY instead of TPM_RC_ATTRIBUTES. |
| [symmetric-unique](bug-fix-symmetric-unique.patch) ([details](#symmetric-unique)) | `interop`, `crypto`, `spec` | — | unique of symmetric/keyed-hash parents is an HMAC instead of H_nameAlg(seedValue || key), giving non-interoperable Names and binding checks. |
| [template-size](bug-fix-template-size.patch) ([details](#template-size)) | `input-validation`, `spec` | — | TPM2B_TEMPLATE is bounded by the padded C sizeof(TPMT_PUBLIC) (356) instead of the unpadded 350 bytes, so oversized templates are accepted. |
| [tk-verified-tags](bug-fix-tk-verified-tags.patch) ([details](#tk-verified-tags)) | `spec-185`, `input-validation`, `spec` | — | TPMT_TK_VERIFIED unmarshaling rejects the version 185 tags TPM_ST_MESSAGE_VERIFIED/TPM_ST_DIGEST_VERIFIED with TPM_RC_TAG. |
| [tpmu-name-size](bug-fix-tpmu-name-size.patch) ([details](#tpmu-name-size)) | `input-validation`, `spec` | — | Alignment padding of the TPM_HANDLE member makes sizeof(TPMU_NAME) 68, so 67/68-octet TPM2B_NAMEs are accepted instead of TPM_RC_SIZE. |

## Categories

Categories form a tree; a child category implies its parent.

- `security`: the bug has a security impact (see the bug's **Security** paragraph).
  - `dos`: a caller can crash the TPM or put it into failure mode (denial of service).
  - `auth-bypass`: an operation succeeds without the authorization it requires.
  - `attestation`: tickets, signatures or proofs are produced over wrong or stale data.
- `memory-safety`: reads uninitialized or stale memory, or reinterprets memory as the wrong type.
- `ub`: undefined behavior in C (e.g. oversized shifts, signed overflow).
- `spec`: the behavior deviates from the TPM 2.0 Library specification (version 185).
  - `spec-185`: the reference implements a rule from before version 185 that version 185 changed.
  - `input-validation`: unmarshaling or validation accepts input it must reject (or vice versa).
  - `rc-only`: only the response code (or its handle/parameter number) is wrong.
- `functional`: a feature does not work.
  - `state`: TPM state is wrong across commands or startups.
  - `self-test`: self-test status or bookkeeping is wrong.
- `crypto`: a cryptographic computation or key validation is wrong.
- `interop`: produces values or blobs that differ from other implementations.
- `fw-limited`: concerns the firmware-limited / SVN-limited hierarchies.

## Bugs

### activate-credential-sequence-object

**Categories:** `security`, `auth-bypass`, `memory-safety`, `spec`.

**Severity:** high

**Description:**

TPM2_ActivateCredential accepts a hash, HMAC or event sequence object as `activateHandle`. A sequence object has no public area that the TPM has validated. In this reference, `FindEmptyObjectSlot()` clears only the slot's internal attributes and `AllocateSequenceSlot()` sets neither the Name nor the Qualified Name, so the sequence object keeps the Name of whatever object last used the slot (a stale-memory read). The credential check (`name` in the decrypted credential blob vs. `activateObject->name`) therefore compares against that stale Name. A caller can load a public area chosen by them in the lowest free slot with TPM2_LoadExternal, flush it, and start a sequence (which takes the same slot) with an authValue of their own choosing. The sequence then carries the Name of that public area and satisfies the ADMIN-role authorization of `activateHandle` with the caller's own password, and TPM2_ActivateCredential releases the credential secret for that Name.

The patch returns TPM_RC_TYPE + RC_ActivateCredential_activateHandle for a sequence object, after the `keyHandle` checks. This matches the TCG reference's version 185 ("Cannot activate credential of sequence object") and tpm-rs.

**Security:**

The attacker needs only TPM2_LoadExternal (no authorization), a sequence start, and the USER-role authorization of the decrypting key `keyHandle` (typically the EK, whose default policy needs endorsement authorization, which the platform owner has and which is often empty). Neither the private key nor the authorization of the credentialed object is needed: a public-only load is enough, and its `fixedTPM`/`restricted` attributes may be set freely because no private area is loaded. The attacker can therefore pass a privacy-CA / attestation-CA enrollment for an arbitrary key, for example a software key presented as a TPM-resident, restricted AK: the CA encrypts a credential to the genuine EK, bound to the Name of the forged AK, and the attacker recovers it. This defeats the guarantee TPM2_ActivateCredential exists to provide (that the credentialed object is resident in the same TPM as the EK and that its parameters were validated), so AK certificates can be issued for non-TPM keys. The severity is high because it breaks the root of the remote-attestation enrollment protocol and needs no privileged access beyond the EK use authorization.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_ActivateCredential", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L2772-L2774)

> This command enables the association of a credential with an object in a
> way that ensures that the TPM has validated the parameters of the
> credentialed object.

---

### certify-sequence-object

**Categories:** `security`, `attestation`, `memory-safety`, `spec`.

**Severity:** high

**Description:**

TPM2_Certify accepts a hash, HMAC or event sequence object as `objectHandle` and signs a TPMS_CERTIFY_INFO over its Name and Qualified Name. A sequence object is not loaded with TPM2_Load() or TPM2_CreatePrimary(). In this reference, `FindEmptyObjectSlot()` clears only the slot's attributes and `AllocateSequenceSlot()` sets neither name field, so the attestation contains the stale Name and Qualified Name of whatever object last used the slot. A caller can load any public area (including one with `fixedTPM`/`fixedParent` set) with TPM2_LoadExternal, flush it, and start a sequence in the same slot with an authValue of their choosing. TPM2_Certify then attests the public-only object's Name, which the specification explicitly forbids certifying.

The patch returns TPM_RC_TYPE + RC_Certify_objectHandle for a sequence object, after the `signHandle` and scheme checks. This matches the TCG reference's version 185 ("Cannot certify a sequence object") and tpm-rs.

**Security:**

The caller needs TPM2_LoadExternal (no authorization), a sequence start, and the USER-role authorization of a signing key `signHandle` (for example their own restricted AK). The ADMIN-role authorization of `objectHandle` is satisfied by the sequence's caller-chosen authValue, so neither the private key nor the authorization of the certified object is needed. The resulting attestation, signed by a genuine AK, claims that an object with an arbitrary Name (e.g. the Name of a software key whose public area says `fixedTPM`) is loaded in this TPM. A verifier that relies on TPM2_Certify to establish key residency would accept a non-TPM key. The severity is high: a genuine AK signs a key-residency attestation for a key that never was in the TPM, which is what TPM2_Certify-based enrollment (e.g. a privacy CA certifying a TPM-resident key) relies on. A careful verifier could notice that the Qualified Name reflects the LoadExternal hierarchy rather than a real parent chain, but most verifiers only check the Name and attributes.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_Certify", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L6143-L6152)

> The object may be any object that is loaded with `TPM2_Load()` or
> `TPM2_CreatePrimary()`. An object that only has its public area loaded
> cannot be certified.
>
> **Note:** The restriction occurs because the Name is used to identify the
> object being certified. If the TPM has not validated that the public
> area is associated with a matched sensitive area, then the public area
> may not represent a valid object and cannot be certified.

---

### pcr-extended-locality

**Categories:** `security`, `ub`, `spec`.

**Severity:** high

**Description:**

`PCRIsResetAllowed()` and `PCRIsExtendAllowed()` (`PCR.c`) turn the command locality into a bit with `localityBits << commandLocality` and test it against the PCR's 5-bit reset/extend locality bitmap (localities 0-4). For an extended locality (32-255) the shift amount is at least the width of the promoted `int`, which is C undefined behavior. With the usual x86 code generation the shift count is taken modulo 32 and the result is truncated to the `UINT8` `localityBits`, so localities 32-36, 64-68, 96-100, ... alias localities 0-4 (e.g. locality 67 acts as locality 3 and locality 68 as locality 4). TPM2_PCR_Extend, TPM2_PCR_Event and TPM2_PCR_Reset sent from such an extended locality are then accepted on PCRs whose attributes restrict them to localities 2-4: the D-RTM PCRs 17-22 can be extended, and PCRs 20-22 (reset localities 2 and 4) can be reset. The `DRTM_PCR` check, which forbids PCR_Reset at locality 4, compares `commandLocality == 4` and so does not stop an extended locality that aliases locality 4. Other compilers or optimizations may produce different results.

An extended locality is a single integer, not a member of the 0-4 bitmap, so the patch makes both functions return FALSE for any locality above 4. The commands then fail with TPM_RC_LOCALITY.

**Security:**

To trigger this, the caller must be able to send commands at an extended locality. The platform asserts the locality (hardware or interface signaling), so software at locality 0 cannot choose it. On a platform that defines extended localities, though, any software that is given such a locality (for example a TEE or management engine assigned locality 32+) can extend or reset the D-RTM PCRs. Those PCRs are meant to be changed only by the D-RTM sequence or by localities 2-4. As a result the attacker can forge or replay a D-RTM measurement chain, and sealed data, PolicyPCR-protected keys and remote attestation that trust PCRs 17-22 would accept it. The severity is high because this breaks the locality-based integrity of the D-RTM PCRs. The behavior also depends on undefined behavior, so it can change with the compiler. It is mitigated on platforms that never assert extended localities (most PC-client systems).

**Spec:** [TPM 2.0 (version 185), Part 1, "Locality"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L12447-L12460)

> The locality value is represented as a byte and locality values have two
> separate representations. Localities 0 through 4 are represented as bits
> in the byte with 0000 0001$_{2}$ representing locality 0 and
> 0001 0000$_{2}$ representing locality 4. This representation
> allows multiple localities to be represented in a single byte as long as
> the localities are in the range of 0-4. This representation of locality
> is compatible with previous families of this specification.
>
> A second representation is for localities above 4. These are called
> *extended localities*. For extended localities, the locality byte is an
> integer value representing the locality. Because of the format for
> localities 0-4, the first extended locality is 32. The range of extended
> localities is 32-255. The locality value may indicate only one extended
> locality at a time.

---

### bind-entity-public-only

**Categories:** `security`, `dos`, `spec`.

**Severity:** medium

**Description:**

When a bound HMAC session authorizes a handle, `CheckAuthSession()` first decides whether the authorized entity is the bind entity (`IsSessionBindEntity()` -> `SessionComputeBoundEntity()`). That computation reads the entity's authValue with `EntityGetAuthValue()`. For an object whose sensitive area is not loaded (a public-only object loaded with TPM2_LoadExternal), `EntityGetAuthValue()` asserts `publicOnly == CLEAR`. The TPM therefore enters failure mode before it reaches the TPM_RC_AUTH_UNAVAILABLE check (`IsAuthValueAvailable()`) that the specification requires first.

A public-only object has no authValue, so it cannot be the bind entity. The patch makes `IsSessionBindEntity()` return FALSE for such an object, and the command then fails with TPM_RC_AUTH_UNAVAILABLE, as in tpm-rs.

**Security:**

Any caller can trigger this without knowing any authorization value. They load an arbitrary public area with TPM2_LoadExternal (no authorization, e.g. in the NULL hierarchy), start an HMAC session bound to any entity (StartAuthSession needs no authorization for the bind handle), and send any command that requires authorization of the public-only object using that session. The assertion fires before any HMAC is checked, and the TPM enters failure mode. It then refuses all commands except TPM2_GetTestResult/TPM2_GetCapability until it is reset (_TPM_Init). This is a denial of service against every user of the TPM, but it does not disclose or modify protected data. The severity is medium.

**Spec:** [TPM 2.0 (version 185), Part 3, "Authorization Checks"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L620-L627)

> After unmarshaling and validating the handles and the consistency of the
> authorization sessions, the authorizations shall be checked.
> Authorization checks only apply to handles if the handle in the command
> schematic has the "\@" decoration. Authorization checks must be performed
> in this order.
>
> 1.  The public and sensitive portions of the object shall be present on
>     the TPM (`TPM_RC_AUTH_UNAVAILABLE`).

---

### object-change-auth-derived-object

**Categories:** `security`, `memory-safety`, `dos`, `spec`.

**Severity:** medium

**Description:**

`TPM2_ObjectChangeAuth` (`command/Object/ObjectChangeAuth.c`) checks only that *parentHandle*'s Qualified Name matches the object's. It then re-protects the object's sensitive area under that parent with `SensitiveToPrivate()`. For a Derived Object, created by `TPM2_CreateLoaded` under a Derivation Parent, the "parent" is a KEYEDHASH key with *derivation* SET, which has no symmetric definition. The protection code asks for the parent's symmetric definition through `CryptoCommon_SelectSymDefObject()`, which fails for such a key, but the failure is not handled. The `TPMT_SYM_DEF_OBJECT` it was supposed to fill stays uninitialized, and its stack contents are then used as the algorithm, key size and mode for the IV size, the protection-key derivation and the symmetric encryption. This can crash the TPM or produce a garbage-protected blob. Even if it succeeds, the command returns an `outPrivate` for an object that, by Part 3, cannot be loaded and can only be re-derived. `TPM2_CreateLoaded` itself returns an Empty Buffer for *outPrivate* for this reason.

The specification gives no response code for this case. The patch returns `TPM_RC_TYPE + RC_ObjectChangeAuth_parentHandle`, the code this command already uses for a *parentHandle* that cannot be the object's parent, whenever the parent has *derivation* SET. This happens before any private area is produced.

**Security:**

The caller needs a Derived Object it controls: `TPM2_CreateLoaded` under any Derivation Parent it can use, then ADMIN authorization of the derived object, whose auth value it chose. This is available to an ordinary user, for example with a Derivation Parent made by `TPM2_CreatePrimary` in the NULL hierarchy. The command then reads an uninitialized stack structure and uses it to drive cryptographic code. Depending on the stale contents, this can crash the TPM process, assert into failure mode (DoS), or return a private blob protected with unpredictable parameters, which could reflect stale stack data. No reliable secret disclosure has been demonstrated. Severity is medium because a DoS or memory-safety problem is reachable by an unprivileged caller.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_CreateLoaded", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L3152-L3157)

> If *parentHandle* references a Derivation Parent or a Primary Seed, then
> *outPrivate* will be an Empty Buffer.
>
> ... Returning *outPrivate* would imply that the returned primary or
> derived object can be loaded, and it cannot. It can only be re-derived.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_ObjectChangeAuth", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L3050-L3051)

> This command may not be used to change the authorization value for an NV
> Index or a Primary Object.

---

### rsa-prime-range

**Categories:** `security`, `dos`, `crypto`, `input-validation`, `spec`.

**Severity:** medium

**Description:**

When an RSA key with a sensitive area is loaded (`TPM2_LoadExternal`, `TPM2_Load` under a non-fixedTPM parent, `TPM2_Import`), the key validation (`CryptValidateKeys()`) checks only the *provided* prime P: it must be half the size of the modulus with its most significant bit SET, and it must divide N. `CryptRsaLoadPrivateExponent()` (`crypt/CryptRsa.c`) then computes the second prime Q = N / P and checks only that the remainder is zero. **Q's range is never checked.** Part 1 requires both "the provided and computed prime factors" to be in range, meaning each prime squared has as many significant bits as N. A crafted modulus with a P just above 2^(k/2-1) can give a Q that is one bit longer than half the modulus, and such a key is accepted. The private exponent is then expanded into the five-value CRT form (P, Q, dP, dQ, qInv), with the larger prime determining the element size. For RSA-2048 the packed size (5 × 129 = 645 bytes) exceeds the `TPM2B_PRIVATE_KEY_RSA` buffer (`RSA_MAX_PRIME` × 5 = 640). `PackExponent()`'s size assertion fires and the TPM enters failure mode. For RSA-1024, the key under a fixedTPM parent gets a 325-byte CRT sensitive value that `TPM2_Load` later rejects.

The patch squares both P and Q after the division and requires each square to have the same number of significant bits as N. Otherwise it returns `TPM_RC_BINDING`, the function's existing code for a key whose public and private parts do not fit together.

**Security:**

Any caller can trigger this. `TPM2_LoadExternal` of an RSA-2048 key with a sensitive area into `TPM_RH_NULL` needs no authorization, and the crafted key (P a 1024-bit factor with its top bit SET, Q a 1025-bit cofactor) is easy to build offline. The result is a failure-mode denial of service until the next `_TPM_Init`. No key material is disclosed and no authorization is bypassed, so the severity is medium. The cost to the attacker is minimal, which places it at the upper end of medium.

**Spec:** [TPM 2.0 (version 185), Part 1, "RSA", "Introduction"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L15962-L15977)

> When loading an RSA key, the TPM validates that its public and private
> portions are properly paired by dividing the public modulus by the
> single private prime and requiring that the remainder be zero. The TPM
> does not validate whether input values are primes.
>
> ...
>
> The TPM will also validate that the provided and computed prime factors
> are in an acceptable range. To be acceptable, the square of the prime is
> required to have the same number of significant bits as the public
> modulus.

**Spec:** [TPM 2.0 (version 185), Part 2, "TPM2B_PRIVATE_KEY_RSA"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L9778-L9781)

> All primes are required to have exactly half the number of
> significant bits as the public modulus, and the square of each prime is
> required to have the same number of significant bits as the public
> modulus.

---

### sequence-complete-ticket-error-state

**Categories:** `security`, `dos`, `state`, `fw-limited`, `spec`.

**Severity:** medium

**Description:**

For a hash sequence, `TPM2_SequenceComplete` (`command/HashHMAC/SequenceComplete.c`) runs in this order:
1. Adds the last `buffer` with `CryptDigestUpdate2B()`.
2. Ends the hash with `CryptHashEnd()`, which consumes the state.
3. May set `ticketSafe`.
4. Only then calls `TicketComputeHashCheck()`.

Step 4 can fail. This reference accepts the firmware-limited and SVN-limited handles for `TPMI_RH_HIERARCHY+`, and `HierarchyGetProof()` returns `TPM_RC_SVN_LIMITED` for an SVN above the firmware's current SVN (or `TPM_RC_FW_LIMITED` when the Firmware Secret is unavailable). The command then returns the error, but the sequence object is **not** flushed: it stays loaded with an ended hash state and possibly an updated `ticketSafe`. This contradicts Part 3: after an error, "the state of the TPM is unchanged". In the public reference code, `HashEnd()` sets the state's type to `HASH_STATE_EMPTY`, and `CryptDigestUpdate()` on a state that is neither `HASH_STATE_HASH` nor `HASH_STATE_HMAC` calls `FAIL(FATAL_ERROR_INTERNAL)`. So a later `TPM2_SequenceUpdate` on the handle, or a retried `TPM2_SequenceComplete` (which also calls `CryptDigestUpdate2B()` first), puts the TPM into failure mode instead of continuing the sequence.

The patch checks the hierarchy's proof with `HierarchyGetProof()` (and wipes the copy) **before** changing the sequence, under exactly the conditions in which a ticket would be computed: a non-NULL hierarchy, and either `ticketSafe` already SET or this is the first block and `TicketIsSafe()` accepts it. If the proof is unavailable, the command fails with the sequence intact.

**Security:**

Any caller can trigger this without authorization. `TPM2_HashSequenceStart` needs no auth, the caller chooses the sequence's auth value, and the *hierarchy* parameter of `TPM2_SequenceComplete` is not authorized. The caller passes an SVN-limited hierarchy with a too-high SVN and then reuses the sequence handle. As traced above, the reuse reaches `FAIL(FATAL_ERROR_INTERNAL)`, a failure-mode denial of service until the next reset. No secret or forgery is involved. The severity is medium: like the 185 code base, any caller can put the TPM into failure mode (traced in the public pre-185 code, not the pinned commit).

**Spec:** [TPM 2.0 (version 185), Part 3, "Response Codes"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L922-L926)

> The normal response for any command is `TPM_RC_SUCCESS`. Any other value
> indicates that the command did not complete and the state of the TPM is
> unchanged. An exception to this general rule is that the logic
> associated with dictionary attack protection is allowed to be modified
> when an authorization failure occurs.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of (UINT32) TPM_RC Constants (Actions)"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L2503-L2507)

> TPM_RC_FW_LIMITED | RC_FMT1 + 0x028 | the hierarchy is firmware-limited but the Firmware Secret is unavailable
>
> TPM_RC_SVN_LIMITED | RC_FMT1 + 0x029 | the hierarchy is SVN-limited but the Firmware SVN Secret associated with the given SVN is unavailable

---

### svn-fw-limited-entity-hierarchy

**Categories:** `security`, `attestation`, `fw-limited`, `spec`.

**Severity:** medium

**Description:**

`EntityGetHierarchy()` (`support/Entity.c`) determines an object's hierarchy from its `ppsHierarchy`/`spsHierarchy`/`epsHierarchy` attributes, and those attributes only ever hold the *base* hierarchy. An object in a firmware-limited or SVN-limited hierarchy (a primary key created with `TPM_RH_FW_*`/`TPM_RH_SVN_*_BASE + SVN`, an external object loaded into such a hierarchy, or any descendant) is therefore treated as belonging to `TPM_RH_OWNER`/`TPM_RH_PLATFORM`/`TPM_RH_ENDORSEMENT`. As a result, `TPM2_Create`'s creation ticket and the `TPM2_PolicySigned`/`TPM2_PolicySecret` auth tickets for such an object are labelled with the base hierarchy and HMACed with the base hierarchy's proof. `TPM2_VerifySignature`, which goes through `GetHierarchy()`, already uses the object's limited hierarchy. Part 2 says the ticket hierarchy is "the hierarchy containing *name*" or "the hierarchy of the object used to produce the ticket", and Part 1 says an object is in the limited hierarchy even without *firmwareLimited*/*svnLimited* SET.

The patch makes `EntityGetHierarchy()` return `object->hierarchy` when it is firmware-limited or SVN-limited (`HierarchyIsFirmwareLimited()`/`HierarchyIsSvnLimited()`). Every other object keeps the attribute-based result.

**Security:**

Firmware-limited and SVN-limited hierarchies exist so that objects stay protected from firmware that knows the base hierarchy seeds and proofs. With this bug, the creation and policy tickets for objects in those hierarchies are protected only by the base proof. Firmware with access to the base proof (for example, an older vulnerable image after an update) can forge a creation ticket for a limited object. `TPM2_CertifyCreation` would then attest the forged creation data under a genuine AK. The same firmware can forge `TPMT_TK_AUTH` tickets that satisfy `TPM2_PolicyTicket` for the object's policies. These tickets also survive firmware/SVN changes, which should invalidate the limited hierarchy's proof. Exploiting this requires a compromised or vulnerable firmware image (or other access to the base proof), not just a TPM command, which is why the severity is medium rather than high. It still defeats the isolation guarantee the feature is meant to provide.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPMT_TK_CREATION Structure"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7442-L7447)

> hierarchy | TPMI_RH_HIERARCHY+ | the hierarchy containing *name*
>
> digest | TPM2B_DIGEST | This shall be the HMAC produced using a proof value of *hierarchy*.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPMT_TK_AUTH Structure"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7638-L7643)

> hierarchy | TPMI_RH_HIERARCHY+ | the hierarchy of the object used to produce the ticket
>
> digest | TPM2B_DIGEST | This shall be the HMAC produced using a proof value of *hierarchy*.

**Spec:** [TPM 2.0 (version 185), Part 1, "EvictControl of objects in firmware-limited and SVN-limited hierarchies"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L15520-L15529)

> Objects in a firmware-limited or SVN-limited hierarchy (including objects
> without *firmwareLimited/svnLimited* SET), cannot be made persistent by
> `TPM2_EvictControl()`.
>
> ... An object can exist within a firmware-limited (or SVN-limited)
> hierarchy and not have *firmwareLimited* (or *svnLimited*) SET. In this
> case, the object is protected by the properties of its object hierarchy,
> the root of which is a *firmwareLimited* (or *svnLimited*) hierarchy
> handle.

**Spec:** [TPM 2.0 (version 185), Part 1, "Enrollment of SVN-Limited Objects"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L15751-L15754)

> As the use-case for SVN-limited objects involves protection from
> vulnerable firmware that has access to base hierarchy seeds and proof
> values, users should certify SVN-limited objects via a firmware-limited
> or SVN-limited AK.

---

### certify-creation-sequence-object

**Categories:** `security`, `attestation`, `memory-safety`, `spec`.

**Severity:** low

**Description:**

TPM2_CertifyCreation accepts a hash, HMAC or event sequence object as `objectHandle`. A sequence object has no creation data, yet the reference recomputes the creation ticket over `certified->name`. That Name is stale, left by whatever object last used the slot, because `FindEmptyObjectSlot()` clears only the slot's attributes and `AllocateSequenceSlot()` does not set it. If the caller holds a valid creation ticket for that earlier object, the TPM signs a TPMS_CREATION_INFO for an object that is no longer loaded. Otherwise the command fails with TPM_RC_TICKET, and it also checks `signHandle` before rejecting the object.

The patch returns TPM_RC_TYPE + RC_CertifyCreation_objectHandle for a sequence object, before the `signHandle` and scheme checks. This matches the TCG reference's version 185 ("Cannot certify creation of a sequence object") and tpm-rs.

**Security:**

The caller needs a sequence object (with an authValue of their choosing, which satisfies the ADMIN role of `objectHandle`), USER-role authorization of a signing key, and a creation ticket that the TPM produced for the object whose Name is stale in the slot. Creation tickets are HMACs under a hierarchy proof, so the attacker can only reuse tickets the TPM really issued, and the signed creation data is therefore true. The main gain is skipping the certified object's own ADMIN authorization: someone who saw an object's creation ticket can get its creation certified without that object's authorization or policy. They do so by loading its public area (LoadExternal is enough) to plant the Name and then starting a sequence. The severity is low because no false statement about creation data can be produced.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_CertifyCreation", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L6228-L6231)

> This command is used to prove the association between an object and its
> creation data. The TPM will validate that the ticket was produced by the
> TPM and that the ticket validates the association between a loaded
> public area and the provided hash of the creation data (*creationHash*).

---

### expiration-absolute-value

**Categories:** `ub`, `interop`, `spec`.

**Severity:** low

**Description:**

`TPM2_PolicySigned` and `TPM2_PolicySecret` take an `INT32 expiration` in seconds. A negative value requests a ticket, and Part 3 uses the *absolute value* of *expiration* to compute the timeout. `ComputeAuthTimeout()` (`command/EA/Policy_spt.c`) computes it as `expiration = -expiration` on the `INT32`. For `expiration = INT32_MIN` (0x80000000) that negation overflows, which is undefined behavior in C. In practice the value stays `INT32_MIN`, and the cast `(UINT64)expiration` sign-extends it. The policy timeout therefore becomes `(2^64 − 2^31) × 1000` (mod 2^64) milliseconds, plus the start time or the sub-second part of Time, instead of `2^31 × 1000`. The wrong value goes into the session's *policySession→timeout*, the returned *timeout*, and the HMAC of the returned `TPMT_TK_AUTH` ticket. As a result, the timeout and the ticket differ from those of other implementations, such as tpm-rs.

The patch removes the in-place negation and takes the absolute value in `UINT64` arithmetic (`(UINT64)0 − (UINT64)expiration` for negative values) in both branches (empty and non-empty *nonceTPM*). This yields 2^31 seconds for `INT32_MIN`, as the specification requires.

**Security:**

Any caller that can run `TPM2_PolicySigned`/`TPM2_PolicySecret` can trigger it, but the caller only affects its own authorization: it chooses *expiration*, and both the specified timeout (about 68 years) and the overflowed one are effectively "never expires". The ticket remains bound to the TPM's proof, so no authorization is bypassed. The practical impact is undefined behavior (a compiler may optimize it differently) and non-interoperable timeout and ticket values. Severity is low.

**Spec:** [TPM 2.0 (version 185), Part 3, "Policy Parameter Checks"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L8818-L8827)

> 2.  *expiration* - If this parameter is not zero, then:
>
> 3.  if *nonceTPM* is not an Empty Buffer, then the absolute value of
>     *expiration* is converted to milliseconds and added to
>     *policySession→startTime* to create the *timeout* value and proceed
>     to c).
>
> 4.  If *nonceTPM* is an Empty Buffer, then the absolute value of
>     *expiration* is converted to milliseconds and used as the *timeout*
>     value and proceed to c).

**Spec:** [TPM 2.0 (version 185), Part 3, Table "TPM2_PolicySecret Command"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L9328-L9332)

> INT32 | expiration | time when authorization will expire, measured in seconds from the time that *nonceTPM* was generated. If *expiration* is non-negative, a NULL Ticket is returned (see @sec:policy-ticket-creation).

---

### persistent-copy-handle-alias

**Categories:** `security`, `spec`.

**Severity:** low

**Description:**

`EntityGetLoadStatus()` validates the command handles in order. For a persistent handle, `ObjectLoadEvict()` copies the object into the lowest free object slot for the duration of the command (marking the copy `attributes.evict`) and replaces the handle with that slot's transient handle. A later transient handle of the same command that happens to name that slot then passes `IsObjectPresent()` and silently refers to the persistent object, even though no object was loaded at that handle. For example, TPM2_Duplicate(0x81000200, 0x80000000) with no transient objects loaded uses the persistent key as both `objectHandle` and `newParentHandle`. The command should fail with TPM_RC_REFERENCE_H1.

The patch also rejects a transient handle whose slot only holds such a per-command copy (`attributes.evict` SET). An object loaded with TPM2_Load, TPM2_CreatePrimary or TPM2_ContextLoad never has that flag. The command then returns TPM_RC_REFERENCE_H0 + N, as tpm-rs does.

**Security:**

Any caller can trigger this, but the aliased handle refers to a persistent object, and any authorization required for that handle is checked against the persistent object's own authValue/policy. The caller therefore gains no access to an object they could not already use through its persistent handle. The risk is confusion: a client that names a transient handle it believes is loaded (for example after a resource manager or another client flushed it) gets the command executed on a persistent object instead of a TPM_RC_REFERENCE error. The command can then use the same key in two roles (e.g. duplicating or wrapping a key under itself) or operate on an unintended key. The severity is low because no authorization is bypassed and exploiting it requires a confused or misbehaving client.

**Spec:** [TPM 2.0 (version 185), Part 3, "Handle Area Validation"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L476-L481)

> 2.  For all handles in the handle area of the command, the TPM will
>     validate that the referenced entity is present in the TPM.
>
>     1.  If the handle references a transient object, the handle shall
>         reference a loaded object (`TPM_RC_REFERENCE_H0` + N where N is the
>         number of the handle in the command).

---

### svn-fw-limited-load-external

**Categories:** `security`, `input-validation`, `fw-limited`, `spec`.

**Severity:** low

**Description:**

Part 2 requires the *firmwareLimited* (bit 8) and *svnLimited* (bit 9) attributes to be CLEAR for an External object, without any condition. This differs from *fixedTPM*, which must be CLEAR only when both the public and sensitive portions are loaded. `TPM2_LoadExternal` (`command/Object/LoadExternal.c`) checks object attributes only through `ObjectLoad()`, and `ObjectLoad()` runs `PublicAttributesValidation()` only when a sensitive area is supplied. In that case the limited attributes are rejected indirectly, because they require *fixedTPM*, which an external object with a sensitive area must not have. A **public-only** external object with *firmwareLimited* or *svnLimited* SET is not checked at all, so it loads successfully. The TPM then holds an object whose public area claims to exist only within a firmware-limited or SVN-limited hierarchy, although it was never created in one.

The patch rejects either attribute for every external object with `TPM_RC_ATTRIBUTES + RC_LoadExternal_inPublic`. The check runs after the existing hierarchy and sensitive-area checks and before the Name is computed and the object is loaded.

**Security:**

Any caller can trigger this, because `TPM2_LoadExternal` into `TPM_RH_NULL` needs no authorization. The attacker gets a loaded public key whose attributes (and therefore its Name) carry *firmwareLimited*/*svnLimited*. A relying party that trusts these attributes as proof of limited-hierarchy confinement could be misled, for example when the object appears in TPM-produced data such as a signature verification or certification. Only a public key is involved, so no secret is exposed. A careful verifier checks the qualified name or hierarchy, which still shows the object's real hierarchy. Severity is therefore low.

**Spec:** [TPM 2.0 (version 185), Part 2, "Bit[8] - firmwareLimited"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L4706-L4730)

> If SET, the object exists only within a firmware-limited hierarchy.
>
> If CLEAR, the object can exist outside a firmware-limited hierarchy.
>
> ... **Load** | may be SET or CLEAR. **Import** | shall be CLEAR. **External** | shall be CLEAR

**Spec:** [TPM 2.0 (version 185), Part 2, "Bit[9] - svnLimited"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L4732-L4756)

> If SET, the object exists only within an SVN-limited hierarchy.
>
> If CLEAR, the object can exist outside a SVN-limited hierarchy.
>
> ... **Load** | may be SET or CLEAR. **Import** | shall be CLEAR. **External** | shall be CLEAR

---

### vendor-auth-entity-break

**Categories:** `security`, `dos`, `functional`, `spec`.

**Severity:** low

**Description:**

In `EntityGetAuthValue()`, the `VENDOR_PERMANENT_AUTH_HANDLE` case sets `pAuth = &g_platformUniqueAuth` but has no `break`, so it falls through into `default`, which calls `FAIL(FATAL_ERROR_INTERNAL)`. Any use of the authValue of the vendor-specific TPM_RH_AUTH_xx handle therefore puts the TPM into failure mode instead of being checked. This includes a password or HMAC authorization of that handle (e.g. as the `authHandle` of TPM2_PolicySecret) and using it as the bind entity of TPM2_StartAuthSession. As a result the vendor authorization value can never be used. The code is compiled only with `VENDOR_PERMANENT_AUTH_ENABLED == YES`, which is NO by default upstream. The test build enables it with `profile-enable-vendor-permanent-auth.patch`.

The patch adds the missing `break`, so the vendor authorization value is returned and checked like any other authValue.

**Security:**

This applies only where the vendor permanent authorization is enabled; with the default upstream configuration the code is not compiled and there is no impact. Where it is enabled, any caller can trigger it without knowing the vendor authValue: a TPM2_PolicySecret with `authHandle` = the vendor TPM_RH_AUTH_xx handle and a password session, or a TPM2_StartAuthSession bound to that handle, reaches `EntityGetAuthValue()` before any comparison. The TPM then enters failure mode until it is reset, which is a denial of service against all users. The feature itself (vendor-authorized policies and bound sessions) also cannot work. The severity is low because the denial of service exists only in non-default builds.

**Spec:** [TPM 2.0 (version 185), Part 1, "Permanent Resource Handles (MSO=$\text{40}_{16}$)"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L3995-L4003)

> Another type of permanent resource handle is the vendor-specific
> authorization value. These optional resources can be populated with
> authorization values that are known only by the TPM manufacturer or some
> other privileged entity. The update of these authorization values is
> TPM-manufacturer-dependent.
>
> If present, a vendor-specific authorization value can be used as a bind
> value within an authorization session or to authorize a policy using the
> `TPM2_PolicySecret()` command. ...

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of (TPM_HANDLE) TPMI_DH_ENTITY Type"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L5850-L5850)

> {TPM_RH_AUTH_00 : TPM_RH_AUTH_FF}: range of vendor-specific authorization values

---

### act-preserve-signaled

**Categories:** `state`, `spec`.

**Severity:** —

**Description:**

`ActStartup()` decides `go.preservedSignaled` by power history instead of by
startup type: it clears it only when `g_powerWasLost` is set and otherwise ORs
`go.signaledACT` into it, whatever the startup type. After a `_TPM_Init` without
power loss, a TPM Reset or TPM Restart therefore keeps a stale `preserveSignaled`
(and a TPM Restart after `TPM2_Shutdown(TPM_SU_STATE)` even sets it from the saved
`signaled` bits), a TPM Resume keeps bits of ACTs that no longer signal, and a
TPM Resume after a power loss clears it although `signaled` itself is restored by
`_ActResume()`. `TPM2_GetCapability(TPM_CAP_ACT)` then reports a
`preserveSignaled` that does not tell software whether the last system reset may
have been caused by an ACT timeout, which is the purpose of the bit.

The patch sets `go.preservedSignaled = go.signaledACT` (the `signaled` state saved
by `TPM2_Shutdown(TPM_SU_STATE)`) on TPM Resume (`SU_RESUME`) and clears it on
every other startup, as Part 2 requires.

**Spec:** [TPM 2.0 (version 185), Part 2, "TPMA_ACT"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L5639-L5646)

> The *preservedSignaled* value indicates whether a system reset may have
> been initiated due to an ACT timeout. As there is no defined
> relationship between a specific ACT and a system reset,
> *preservedSignaled* behavior is the same for all ACT.
>
> On a TPM Reset or Restart, *preservedSignaled* is CLEAR for all ACT. On a TPM Resume,
> the state of each ACT *signaled* is copied to the corresponding
> *preservedSignaled.*

---

### get-test-result-needs-test

**Categories:** `self-test`, `spec`.

**Severity:** —

**Description:**

`TPM2_GetTestResult` outside Failure mode always returns `testResult =
TPM_RC_SUCCESS` with empty `outData`: `CryptGetTestResult()` is a placeholder (its own comment
says the behavior "is NOT the correct behavior for a real TPM implementation").
After `_TPM_Init`, before any `TPM2_SelfTest`, or after `TPM2_IncrementalSelfTest`
of only some algorithms, software asking for the test status is told that all
testing is complete without failure, although `g_toTest` still has untested
algorithms (the same ones that `TPM2_IncrementalSelfTest` reports in its
`toDoList`), so it cannot use this command to decide whether a
`TPM2_SelfTest` is needed.

The self tests of this reference run synchronously (`TPM2_SelfTest` finishes all
tests before it returns and an untested algorithm is tested on first use), so
testing is never "in progress" and `TPM_RC_TESTING` cannot occur. The patch
returns `TPM_RC_NEEDS_TEST` while any bit of `g_toTest` is SET and
`TPM_RC_SUCCESS` otherwise; the Failure-mode path is unchanged.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_GetTestResult"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L1734-L1741)

> If `TPM2_SelfTest()` has not been executed and a testable function has
> not been tested, *testResult* will be `TPM_RC_NEEDS_TEST`. If
> `TPM2_SelfTest()` has been received and the tests are not complete,
> *testResult* will be `TPM_RC_TESTING`.
>
> If testing of all functions is complete without functional failures,
> *testResult* will be `TPM_RC_SUCCESS`. If any test failed, *testResult*
> will be `TPM_RC_FAILURE`.

---

### hierarchy-control-base-hierarchy

**Categories:** `spec`, `input-validation`, `rc-only`.

**Severity:** —

**Description:**

Part 3 types `TPM2_HierarchyControl`'s *authHandle* as `TPMI_RH_BASE_HIERARCHY`. That type admits only `TPM_RH_OWNER`, `TPM_RH_PLATFORM` and `TPM_RH_ENDORSEMENT`, and anything else must fail to unmarshal with `TPM_RC_VALUE`. This reference's command descriptor (`CommandDispatchData.h`) instead unmarshals *authHandle* as `TPMI_RH_HIERARCHY_H_UNMARSHAL`. That type also admits `TPM_RH_NULL` and, in this reference, the firmware-limited and SVN-limited hierarchy handles. Such a handle therefore passes unmarshaling and is rejected later, by the hierarchy load-status check or the authorization logic (for example, `TPM_RC_FW_LIMITED + H1` for `TPM_RH_FW_OWNER` when the Firmware Secret is unavailable), instead of with `TPM_RC_VALUE + H1`. The command is still refused, so only the response code differs. The patch switches the descriptor to the existing `TPMI_RH_BASE_HIERARCHY_H_UNMARSHAL` handle type, matching version 185 of the reference.

**Spec:** [TPM 2.0 (version 185), Part 3, Table "TPM2_HierarchyControl Command"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L11875-L11880)

> TPMI_RH_BASE_HIERARCHY | @authHandle | TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Index: 1 Auth Role: USER

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of (TPM_HANDLE) TPMI_RH_BASE_HIERARCHY Type"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L6106-L6112)

> TPM_RH_OWNER: Storage hierarchy. TPM_RH_PLATFORM: Platform hierarchy. TPM_RH_ENDORSEMENT: Endorsement hierarchy. #TPM_RC_VALUE: response code returned when the unmarshaling of this type fails

---

### nv-certify-null-sign-handle-digest

**Categories:** `spec-185`, `functional`, `spec`.

**Severity:** —

**Description:**

This reference implements the pre-185 rule. For `TPM2_NV_Certify` with
`signHandle = TPM_RH_NULL`, `CryptSelectSignScheme()` replaces `inScheme` with `TPM_ALG_NULL`, and
for `size = offset = 0` the digest of the Index data is then started with the hash
algorithm of that cleared scheme, i.e. `TPM_ALG_NULL`. The response is a
`TPM_ST_ATTEST_NV_DIGEST` attestation whose `nvDigest` is an Empty Buffer,
whatever scheme the caller asked for, and a caller passing a NULL scheme gets the
same Empty Buffer instead of an error. Versions 1.83 and earlier allowed this
Empty Buffer; version 185 requires the digest to be computed with the hash
algorithm of `inScheme` and `TPM_RC_SCHEME` when the scheme or its hash algorithm
is `TPM_ALG_NULL`. Without the fix, an unsigned digest attestation (used, e.g.,
to obtain the digest of an Index larger than `MAX_NV_BUFFER_SIZE` that the caller
then checks itself) never contains the digest.

The patch saves the caller's `inScheme` before the scheme selection and, in the
digest branch with a NULL `signHandle`, returns `TPM_RC_SCHEME` (+
`RC_NV_Certify_inScheme`) if that scheme or its `hashAlg` is `TPM_ALG_NULL` and
otherwise computes the digest with its `hashAlg`. The attestation stays unsigned
(NULL signature).

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_NV_Certify"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L15942-L15951)

> If *size* and *offset* are both zero (0), then *certifyInfo* in the
> response will contain a `TPMS_NV_DIGEST_CERTIFY_INFO`, otherwise, it
> will contain a `TPMS_NV_CERTIFY_INFO`. The digest in the
> `TPMS_NV_DIGEST_CERTIFY_INFO` is created using the hash algorithm of the
> selected signing scheme.
>
> If *size* and *offset* are both zero and *signHandle* is TPM_RH_NULL,
> the digest is computed using the hash algorithm provided in *inScheme*,
> unless the scheme or hash algorithm is TPM_ALG_NULL, in which case the
> TPM shall return TPM_RC_SCHEME.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_NV_Certify"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L15960-L15962)

> Versions 1.83 and earlier allowed TPM2_NV_Certify to set the digest in
> `TPMS_NV_DIGEST_CERTIFY_INFO` to an Empty Buffer if size and offset were zero
> and signHandle was TPM_RH_NULL.

---

### persist-public-only-objects

**Categories:** `spec-185`, `spec`.

**Severity:** —

**Description:**

This reference implements the pre-185 rule of `TPM2_EvictControl`: it refuses to
make a transient object persistent when `attributes.publicOnly` is SET (for
example the public-only object loaded by `TPM2_LoadExternal(hierarchy =
TPM_RH_OWNER)`) and returns `TPM_RC_ATTRIBUTES` + `RC_EvictControl_objectHandle`.
Older versions of the specification did not allow persisting public-only objects
(for NV space efficiency); version 185 removed that condition, so only objects in
the NULL, firmware-limited or SVN-limited hierarchies, and temporary or `stClear`
objects, are rejected. Without the fix, software written for version 185 cannot
persist an external public key (for example a verification key for
`TPM2_PolicyAuthorize` or `TPM2_VerifySignature`) and must reload it after every
TPM Reset.

The patch drops the `publicOnly` condition, so only temporary and `stClear`
objects are rejected, as in version 185. The persistent copy keeps
`attributes.publicOnly` (`NvAddEvictObject()` stores the whole `OBJECT`), so it
still has neither authValue nor authPolicy available. Found by differential
fuzzing.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_EvictControl"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L13748-L13761)

> If *objectHandle* references a Transient Object:
>
> 1.  The TPM shall return `TPM_RC_ATTRIBUTES` if
>
>     1.  it is in the hierarchy of `TPM_RH_NULL` or a firmware-limited or
>         SVN-limited hierarchy, or
>
>         Older versions of the specification did not allow an object to be persisted
>     when only the public portion of the object was loaded (for NV space efficiency).
>     Support for persisting public-only objects was added in version 185.
>
>     2.  the *stClear* is SET in the object or in an ancestor key.

---

### session-audit-attribute-dependency

**Categories:** `spec`, `rc-only`.

**Severity:** —

**Description:**

`RetrieveSessionData()` rejects `auditExclusive`/`auditReset` without `audit` only
for a password session (`TPM_RS_PW`); on an HMAC or policy session whose `audit`
attribute is CLEAR the two bits are silently ignored. The command then continues
and fails later with another response code (e.g. a later session's unmarshaling
error, `TPM_RC_SYMMETRIC` or `TPM_RC_BAD_AUTH`), or succeeds, instead of being
rejected with `TPM_RC_ATTRIBUTES` for that session. Part 2 allows these bits only
when `audit` is SET and reserves them for a different meaning when `audit` is
CLEAR in future versions.

The patch adds the check to `RetrieveSessionData()` right after the
duplicate-handle check, before the decrypt/encrypt/audit checks, and returns
`TPM_RC_ATTRIBUTES` + the session index when `auditExclusive` or `auditReset` is
SET while `audit` is CLEAR. Found by differential fuzzing.

**Spec:** [TPM 2.0 (version 185), Part 2, "TPMA_SESSION"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L4981-L4988)

> In this version, if *audit* is CLEAR, *auditExclusive* must be CLEAR in
> the command and will be CLEAR in the response. In a future version,
> this bit may have a different meaning if *audit* is CLEAR. See
> "Exclusive Audit Session" clause in TPM 2.0 Part 1.
>
> In this version, if *audit* is CLEAR, *auditReset* must be clear in the
> command and will be CLEAR in the response. In a future version, this
> bit may have a different meaning if *audit* is CLEAR.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of (UINT8) TPMA_SESSION Bits"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L5023-L5034)

> 1 | auditExclusive | **SET (1):** In a command, this setting indicates that
> the command should only be executed if the session is exclusive at the start of
> the command. In a response, it indicates that the session is exclusive. This
> setting is only allowed if the *audit* attribute is SET (TPM_RC_ATTRIBUTES).
> ...
> 2 | auditReset | **SET (1):** In a command, this setting indicates that the
> audit digest of the session should be initialized and the exclusive status of
> the session SET. This setting is only allowed if the *audit* attribute is SET
> (TPM_RC_ATTRIBUTES).

---

### svn-fw-limited-evict-control

**Categories:** `spec`, `rc-only`, `fw-limited`.

**Severity:** —

**Description:**

`TPM2_EvictControl` (`command/Context/EvictControl.c`) correctly refuses to make persistent a transient object that is in a firmware-limited or SVN-limited hierarchy (`HierarchyIsFirmwareLimited()`/`HierarchyIsSvnLimited()` on `evictObject->hierarchy`). However, it reports this with `TPM_RC_HIERARCHY + RC_EvictControl_objectHandle`. Part 3 (version 185) lists this case under `TPM_RC_ATTRIBUTES`, together with objects of `TPM_RH_NULL` and objects with *stClear* SET in themselves or an ancestor. `TPM_RC_HIERARCHY` is meant for an object that is not in the proper hierarchy as determined by *auth*. The object is still rejected, so only the response code differs. The patch returns `TPM_RC_ATTRIBUTES + RC_EvictControl_objectHandle` instead.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_EvictControl", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L13748-L13761)

> If *objectHandle* references a Transient Object:
>
> 1.  The TPM shall return `TPM_RC_ATTRIBUTES` if
>
>     1.  it is in the hierarchy of `TPM_RH_NULL` or a firmware-limited or
>         SVN-limited hierarchy, or
>
>     ...
>
>     2.  the *stClear* is SET in the object or in an ancestor key.

**Spec:** [TPM 2.0 (version 185), Part 1, "EvictControl of objects in firmware-limited and SVN-limited hierarchies"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L15520-L15522)

> Objects in a firmware-limited or SVN-limited hierarchy (including objects
> without *firmwareLimited/svnLimited* SET), cannot be made persistent by
> `TPM2_EvictControl()`.

---

### symmetric-unique

**Categories:** `interop`, `crypto`, `spec`.

**Severity:** —

**Description:**

`CryptComputeSymmetricUnique()` computes `unique` of a `TPM_ALG_SYMCIPHER` or
`TPM_ALG_KEYEDHASH` object as `HMAC_nameAlg(seedValue, sensitive)` when the object
is a parent (`restricted` and `decrypt` SET: a symmetric storage key or a
derivation parent) and as the digest `H_nameAlg(seedValue || sensitive)` only for
the other objects. Part 1 defines a single formula, the digest, for every
keyed-hash and symmetric object. The `unique` (and hence the Name) of every
symmetric or keyed-hash parent created by `TPM2_Create`/`TPM2_CreatePrimary`/
`TPM2_CreateLoaded` therefore differs from the one a spec-conformant TPM or
software computes for the same sensitive values, and because the same function
checks the public/sensitive binding when a sensitive area is loaded, such a parent
built by external software per the specification (for `TPM2_LoadExternal` or
`TPM2_Import`) is rejected with `TPM_RC_BINDING`, while blobs created by this TPM
fail the same check on a conformant one.

The patch disables the HMAC branch (`if(0 && ...)`), so `unique` is
`H_nameAlg(obfuscate || key)` for every keyed-hash and symmetric object, parents
included.

**Spec:** [TPM 2.0 (version 185), Part 1, "TPM_ALG_KEYEDHASH"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L10662-L10682)

> #### TPM_ALG_KEYEDHASH
>
> This type is used for an HMAC key or data block. The computation for
> *unique* for a KeyedHash object is:
>
> $$ \mathit{unique} := \mathbf{H}_{\mathit{nameAlg}} (\mathit{obfuscate} \parallel \mathit{key}) $$ {#eq:keyedhash-sym}
>
> where
>
> $\mathbf{H}_{\mathit{nameAlg}}$ is the hash using *nameAlg* from the object
> template; $\mathit{obfuscate}$ is the contents of *seedValue.buffer* in the
> object's sensitive area; $\mathit{key}$ is the contents of sensitive.bits.buffer
> in the object's sensitive area; this will be either an HMAC key, a data blob, or
> a symmetric key.

**Spec:** [TPM 2.0 (version 185), Part 1, "TPM_ALG_SYMCIPHER"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L10684-L10687)

> #### TPM_ALG_SYMCIPHER
>
> This type is used for a symmetric block cipher key. The *unique* value
> is computed as shown in @eq:keyedhash-sym.

---

### template-size

**Categories:** `input-validation`, `spec`.

**Severity:** —

**Description:**

The maximum size of a `TPM2B_TEMPLATE` is `sizeof(TPMT_PUBLIC)`, which Part 2 defines as the octet-aligned size of the structure without padding. `TPM2B_TEMPLATE_Unmarshal()` (`Marshal.c`) compares the size field with the C `sizeof(TPMT_PUBLIC)`, and the C size includes the alignment padding caused by the 4-byte alignment of the `UINT32` members (`TPMA_OBJECT` and the `exponent` of `TPMS_RSA_PARMS`): 356 bytes instead of 350 with this profile (RSA-2048, 66-byte `authPolicy` for SHA-512). A `TPM2_CreateLoaded` whose `inPublic` template is 351 to 356 bytes long is therefore accepted by the unmarshaler and processed further (so it fails later with another response code, or not at all) instead of being rejected with `TPM_RC_SIZE` for `inPublic`. This is the same kind of padding issue as `tpmu-name-size`. There is no memory-safety impact: the C buffer of `TPM2B_TEMPLATE` has the padded size, so the extra bytes still fit.

The patch computes the unpadded size `TPMT_PUBLIC_PACKED_SIZE` from the members (`type`, `nameAlg`, `objectAttributes`, `authPolicy`, the larger of the packed `TPMS_RSA_PARMS` and `TPMS_ECC_PARMS`, and `TPMU_PUBLIC_ID`) and uses it as the bound.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPM2B_TEMPLATE Structure"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L11079-L11082)

> size | UINT16 | size of publicArea; buffer[size]{:sizeof(TPMT_PUBLIC)} | BYTE | the public area

**Spec:** [TPM 2.0 (version 185), Part 2, "Data Alignment"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L1120-L1123)

> The data structures in this specification use octet alignment for all
> structures. When used in a table to indicate a maximum size, the
> sizeof() function returns the octet-aligned size of the structure, with
> no padding.

---

### tk-verified-tags

**Categories:** `spec-185`, `input-validation`, `spec`.

**Severity:** —

**Description:**

This reference was written before version 185 and unmarshals a `TPMT_TK_VERIFIED`
(the `checkTicket` of `TPM2_PolicyAuthorize`) only with `tag = TPM_ST_VERIFIED`;
any other tag fails with `TPM_RC_TAG`. Version 185 added
`TPM2_VerifySequenceComplete()` and `TPM2_VerifyDigestSignature()`, whose tickets
carry the new tags `TPM_ST_MESSAGE_VERIFIED` (0x8026) and `TPM_ST_DIGEST_VERIFIED`
(0x8027), and a tag-selected `metadata` field (`TPMU_TK_VERIFIED_META`, a
`TPMI_ALG_HASH` for `TPM_ST_DIGEST_VERIFIED`) between `hierarchy` and the HMAC.
A version 185 command carrying such a ticket (for example a NULL Verified Ticket
with one of the new tags) is rejected at unmarshaling with `TPM_RC_TAG`
(+ the parameter position) instead of being parsed and judged by
`TPM2_PolicyAuthorize`, so the response code differs from a version 185 TPM, and
a `TPM_ST_DIGEST_VERIFIED` ticket would be mis-parsed if its tag were accepted
without the metadata.

The patch accepts both new tags and, for `TPM_ST_DIGEST_VERIFIED`, unmarshals
(and discards) the `TPMI_ALG_HASH` metadata before the HMAC. No such ticket can be
valid on this TPM (it implements neither `TPM2_VerifySequenceComplete` nor
`TPM2_VerifyDigestSignature`), so `TPM2_PolicyAuthorize` still rejects it when it
checks the ticket.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPMT_TK_VERIFIED Structure"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7539-L7554)

> Table: Definition of TPMT_TK_VERIFIED Structure
>
> tag | TPM_ST | ticket structure tag
> #TPM_RC_TAG | | error returned when *tag* is not one of the values in @tbl:tpm-st-for-signatures
> hierarchy | TPMI_RH_HIERARCHY+ | the hierarchy containing *keyName*.
> \[tag\]metadata | TPMU_TK_VERIFIED_META | Additional (if any) metadata required in order to validate the ticket.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "TPM_ST Values For Signature Verification Commands"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7527-L7537)

> Table: TPM_ST Values For Signature Verification Commands
>
> `TPM_ST_VERIFIED`: `TPM2_VerifySignature()`; `TPM_ST_MESSAGE_VERIFIED`:
> `TPM2_VerifySequenceComplete()`; `TPM_ST_DIGEST_VERIFIED`:
> `TPM2_VerifyDigestSignature()`.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPMU_TK_VERIFIED_META Union"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7462-L7476)

> verified | TPMS_EMPTY | `TPM_ST_VERIFIED`; messageVerified | TPMS_EMPTY |
> `TPM_ST_MESSAGE_VERIFIED`; digestVerified | TPMI_ALG_HASH |
> `TPM_ST_DIGEST_VERIFIED` | The hash algorithm or XOF used to produce the digest
> that was verified

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_VerifySequenceComplete"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7359-L7359)

> `TPM2_VerifySequenceComplete()` was added in version 185.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_VerifyDigestSignature"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7443-L7443)

> `TPM2_VerifyDigestSignature()` was added in version 185.

---

### tpmu-name-size

**Categories:** `input-validation`, `spec`.

**Severity:** —

**Description:**

`TPM2B_NAME` is bounded by `sizeof(TPMU_NAME)`, and the largest `TPMU_NAME` member is a `TPMT_HA` of 66 octets (a 2-octet algorithm ID plus a SHA-512 digest), so a Name longer than 66 octets must be rejected with `TPM_RC_SIZE`. In `TpmTypes.h`, `TPMU_NAME` is a C union with a `TPM_HANDLE` (`UINT32`) member, whose 4-byte alignment pads the union from 66 to 68 bytes. `TPM2B_NAME` unmarshaling uses this padded C size, so 67- and 68-octet Names in command parameters (for example `objectName`/`newParentName` of `TPM2_PolicyDuplicationSelect`, `objectName` of `TPM2_MakeCredential`, or `keySign` of `TPM2_PolicyAuthorize`) are accepted and processed further instead of being rejected with `TPM_RC_SIZE`. There is no memory-safety impact: the C buffer has the padded size, so the extra bytes still fit.

The patch declares the `handle` member as `BYTE handle[sizeof(TPM_HANDLE)]` (same size, alignment 1), so `sizeof(TPMU_NAME)` is the 66 octets of `TPMT_HA`.

**Spec:** [TPM 2.0 (version 185), Part 2, "TPM2B_NAME"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7200-L7204)

> The type of Name in the structure is determined by context and the
> *size* parameter. If *size* is four, then the Name is a handle. If
> *size* is zero, then no Name is present. Otherwise, the size shall be
> the size of a `TPM_ALG_ID` plus the size of the digest produced by the
> indicated hash algorithm.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPM2B_NAME Structure"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7211-L7214)

> size | UINT16 | size of the Name structure; name[size]{:sizeof(TPMU_NAME)} | BYTE | the Name structure

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPMU_NAME Union"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7188-L7192)

> digest | TPMT_HA | when the Name is a digest; handle | TPM_HANDLE | when the Name is a handle

**Spec:** [TPM 2.0 (version 185), Part 2, "Data Alignment"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L1120-L1123)

> The data structures in this specification use octet alignment for all
> structures. When used in a table to indicate a maximum size, the
> sizeof() function returns the octet-aligned size of the structure, with
> no padding.
