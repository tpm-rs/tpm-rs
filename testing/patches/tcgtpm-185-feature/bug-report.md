# Bug report: tcgtpm-185-feature (TCG reference implementation, version 185)

The bugs of the C reference `tcgtpm-185-feature` that the `bug-fix-*.patch` files in this directory fix for differential testing against `tpm-rs`. Security Severity is the security severity of the bug in the unpatched reference (— = no security impact).

## Contents

- [Summary](#summary)
- [Categories](#categories)
- [Bugs](#bugs)
  - [bind-entity-public-only](#bind-entity-public-only)
  - [object-change-auth-derived-object](#object-change-auth-derived-object)
  - [read-public-null-name-alg](#read-public-null-name-alg)
  - [rsa-prime-range](#rsa-prime-range)
  - [sequence-complete-ticket-error-state](#sequence-complete-ticket-error-state)
  - [svn-fw-limited-entity-hierarchy](#svn-fw-limited-entity-hierarchy)
  - [verify-sequence-ticket](#verify-sequence-ticket)
  - [expiration-absolute-value](#expiration-absolute-value)
  - [nv-define-space2-external-nv](#nv-define-space2-external-nv)
  - [persistent-copy-handle-alias](#persistent-copy-handle-alias)
  - [policy-capability-session-handle](#policy-capability-session-handle)
  - [policy-capability-transient-handle](#policy-capability-transient-handle)
  - [read-only-before-authorization](#read-only-before-authorization)
  - [svn-fw-limited-load-external](#svn-fw-limited-load-external)
  - [verify-signature-mldsa-not-supported](#verify-signature-mldsa-not-supported)
  - [act-preserve-signaled](#act-preserve-signaled)
  - [cipher-mode-error-code](#cipher-mode-error-code)
  - [ecdaa-signature-context](#ecdaa-signature-context)
  - [ecc-point-coordinate-range](#ecc-point-coordinate-range)
  - [get-test-result-needs-test](#get-test-result-needs-test)
  - [nv-certify-null-sign-handle-digest](#nv-certify-null-sign-handle-digest)
  - [nv-define-space2-dispatch](#nv-define-space2-dispatch)
  - [nv-exp-index-range](#nv-exp-index-range)
  - [pcr-reset-handle-type](#pcr-reset-handle-type)
  - [policy-authorize-ticket-tags](#policy-authorize-ticket-tags)
  - [policy-capability-sec-channel](#policy-capability-sec-channel)
  - [read-only-before-startup](#read-only-before-startup)
  - [sequence-complete-flushed-attribute](#sequence-complete-flushed-attribute)
  - [session-audit-attribute-dependency](#session-audit-attribute-dependency)
  - [sign-digest-hmac-scheme](#sign-digest-hmac-scheme)
  - [sign-mldsa-not-supported](#sign-mldsa-not-supported)
  - [sm2-signature-sequence](#sm2-signature-sequence)
  - [sec-channel-property-count](#sec-channel-property-count)
  - [svn-fw-limited-evict-control](#svn-fw-limited-evict-control)
  - [symmetric-unique](#symmetric-unique)
  - [template-size](#template-size)
  - [tpmu-name-size](#tpmu-name-size)
  - [verify-digest-signature-scheme](#verify-digest-signature-scheme)
  - [verify-digest-signature-ticket](#verify-digest-signature-ticket)
  - [verify-sequence-complete-scheme](#verify-sequence-complete-scheme)
  - [cmac-self-test](#cmac-self-test)
  - [select-sym-def-object-camellia](#select-sym-def-object-camellia)
  - [zgen-2phase-mqv-sm2](#zgen-2phase-mqv-sm2)
  - [ecc-decrypt-c1-point](#ecc-decrypt-c1-point)
  - [zgen-2phase-out-z2](#zgen-2phase-out-z2)
- [Locality problems (not patched)](#locality-problems-not-patched)
  - [pcr-extended-locality](#pcr-extended-locality)

## Summary

| Patch | Categories | Security Severity | Description |
|---|---|---|---|
| [bind-entity-public-only](bug-fix-bind-entity-public-only.patch) ([details](#bind-entity-public-only)) | `security`, `dos`, `spec` | medium | A bound HMAC session authorizing a public-only object hits an assertion in the bind check (failure mode) instead of TPM_RC_AUTH_UNAVAILABLE. |
| [object-change-auth-derived-object](bug-fix-object-change-auth-derived-object.patch) ([details](#object-change-auth-derived-object)) | `security`, `memory-safety`, `dos`, `spec` | medium | TPM2_ObjectChangeAuth of a derived object uses an uninitialized symmetric definition of the Derivation Parent. |
| [read-public-null-name-alg](bug-fix-read-public-null-name-alg.patch) ([details](#read-public-null-name-alg)) | `security`, `dos`, `spec` | medium | ReadPublic of a LoadExternal object with nameAlg TPM_ALG_NULL fails response marshaling and puts the TPM into failure mode. |
| [rsa-prime-range](bug-fix-rsa-prime-range.patch) ([details](#rsa-prime-range)) | `security`, `dos`, `crypto`, `input-validation`, `spec` | medium | RSA key loading does not check the range of the computed prime Q, so a crafted key can put the TPM in failure mode. |
| [sequence-complete-ticket-error-state](bug-fix-sequence-complete-ticket-error-state.patch) ([details](#sequence-complete-ticket-error-state)) | `security`, `dos`, `state`, `fw-limited`, `spec` | medium | A TPM2_SequenceComplete that fails computing its ticket leaves the sequence loaded with a consumed hash state, whose reuse enters failure mode. |
| [svn-fw-limited-entity-hierarchy](bug-fix-svn-fw-limited-entity-hierarchy.patch) ([details](#svn-fw-limited-entity-hierarchy)) | `security`, `attestation`, `fw-limited`, `spec` | medium | EntityGetHierarchy() reports the base hierarchy for objects in limited hierarchies, so their creation/auth tickets use the base proof. |
| [verify-sequence-ticket](bug-fix-verify-sequence-ticket.patch) ([details](#verify-sequence-ticket)) | `security`, `dos`, `functional`, `state`, `spec` | medium | TPM2_VerifySequenceComplete returns a TPM_ST_VERIFIED ticket over the digest (NULL for HMAC) instead of a TPM_ST_MESSAGE_VERIFIED ticket over the message, and a failed verification consumes the running state (a later update enters failure mode). |
| [select-sym-def-object-camellia](bug-fix-select-sym-def-object-camellia.patch) ([details](#select-sym-def-object-camellia)) | `security`, `dos`, `functional`, `spec` | medium | A storage parent whose symmetric algorithm is Camellia puts the TPM into failure mode: the SM4/Camellia case labels of CryptoCommon_SelectSymDefObject() are profile switches, not algorithm IDs. |
| [expiration-absolute-value](bug-fix-expiration-absolute-value.patch) ([details](#expiration-absolute-value)) | `ub`, `interop`, `spec` | low | The absolute value of expiration = INT32_MIN overflows, giving a wrong policy timeout and ticket. |
| [nv-define-space2-external-nv](bug-fix-nv-define-space2-external-nv.patch) ([details](#nv-define-space2-external-nv)) | `memory-safety`, `ub`, `functional`, `spec` | low | TPM2_NV_DefineSpace2 of an external NV Index defines an Index at an uninitialized handle, and external NV handles can never be loaded. |
| [persistent-copy-handle-alias](bug-fix-persistent-copy-handle-alias.patch) ([details](#persistent-copy-handle-alias)) | `security`, `spec` | low | A later transient handle that names the slot of a persistent object's per-command RAM copy resolves to that persistent object instead of failing with TPM_RC_REFERENCE_Hn. |
| [policy-capability-session-handle](bug-fix-policy-capability-session-handle.patch) ([details](#policy-capability-session-handle)) | `security`, `auth-bypass`, `spec` | low | TPM2_PolicyCapability(TPM_CAP_HANDLES) reports a saved session as loaded and a loaded session as saved. |
| [policy-capability-transient-handle](bug-fix-policy-capability-transient-handle.patch) ([details](#policy-capability-transient-handle)) | `security`, `auth-bypass`, `spec` | low | TPM2_PolicyCapability(TPM_CAP_HANDLES) reports a transient handle as existing whenever any object with a larger handle is loaded. |
| [read-only-before-authorization](bug-fix-read-only-before-authorization.patch) ([details](#read-only-before-authorization)) | `security`, `spec`, `state` | low | In Read-Only mode, TPM2_NV_Write/Extend/SetBits/WriteLock/ReadLock on other than ORDERLY+CLEAR_STCLEAR Indexes and TPM2_PolicySecret with a PIN Index are rejected only after authorization, so a wrong authorization updates the DA counter or pinCount. |
| [svn-fw-limited-load-external](bug-fix-svn-fw-limited-load-external.patch) ([details](#svn-fw-limited-load-external)) | `security`, `input-validation`, `fw-limited`, `spec` | low | TPM2_LoadExternal accepts a public-only object with firmwareLimited or svnLimited SET. |
| [verify-signature-mldsa-not-supported](bug-fix-verify-signature-mldsa-not-supported.patch) ([details](#verify-signature-mldsa-not-supported)) | `security`, `attestation`, `memory-safety`, `input-validation`, `spec` | low | TPM2_VerifySignature with an external-mu ML-DSA key ("Not supported") verifies the digest as an external mu, without checking the signature algorithm, and returns a TPMT_TK_VERIFIED ticket. |
| [cmac-self-test](bug-fix-cmac-self-test.patch) ([details](#cmac-self-test)) | `self-test`, `spec` | — | TPM2_MAC/TPM2_MAC_Start compute a CMAC with the block cipher of the key without testing it, leaving it untested. |
| [act-preserve-signaled](bug-fix-act-preserve-signaled.patch) ([details](#act-preserve-signaled)) | `state`, `spec` | — | ACT preserveSignaled is cleared/merged by power loss instead of being CLEAR on TPM Reset/Restart and a copy of signaled on TPM Resume. |
| [cipher-mode-error-code](bug-fix-cipher-mode-error-code.patch) ([details](#cipher-mode-error-code)) | `rc-only`, `spec` | — | TPMI_ALG_CIPHER_MODE values are rejected with TPM_RC_SYMMETRIC instead of TPM_RC_MODE. |
| [ecdaa-signature-context](bug-fix-ecdaa-signature-context.patch) ([details](#ecdaa-signature-context)) | `spec-185`, `functional`, `spec` | — | TPM2B_SIGNATURE_CTX is limited to 0 octets without ML-DSA, and TPM2_SignDigest/TPM2_SignSequenceStart reject keys whose scheme is TPM_ALG_ECDAA instead of taking the commit counter from context. |
| [ecc-point-coordinate-range](bug-fix-ecc-point-coordinate-range.patch) ([details](#ecc-point-coordinate-range)) | `spec`, `input-validation`, `crypto` | — | BnIsPointOnCurve() checks only the curve equation modulo p, so ECC points with a coordinate not below p (x + p) are accepted as valid points. |
| [get-test-result-needs-test](bug-fix-get-test-result-needs-test.patch) ([details](#get-test-result-needs-test)) | `self-test`, `spec` | — | TPM2_GetTestResult always returns TPM_RC_SUCCESS instead of TPM_RC_NEEDS_TEST while algorithms remain untested. |
| [nv-certify-null-sign-handle-digest](bug-fix-nv-certify-null-sign-handle-digest.patch) ([details](#nv-certify-null-sign-handle-digest)) | `spec-185`, `functional`, `spec` | — | TPM2_NV_Certify with a NULL signHandle and size = offset = 0 always returns TPM_RC_SCHEME because the caller's inScheme is cleared before its hash is used. |
| [nv-define-space2-dispatch](bug-fix-nv-define-space2-dispatch.patch) ([details](#nv-define-space2-dispatch)) | `functional`, `spec` | — | TPM2_NV_DefineSpace2 unmarshals publicInfo into the auth member, so the command never defines an Index (TPM_RC_HANDLE + publicInfo). |
| [nv-exp-index-range](bug-fix-nv-exp-index-range.patch) ([details](#nv-exp-index-range)) | `spec`, `input-validation` | — | TPMI_RH_NV_EXP_INDEX admits the ordinary NV Index range instead of the external NV Index range. |
| [pcr-reset-handle-type](bug-fix-pcr-reset-handle-type.patch) ([details](#pcr-reset-handle-type)) | `input-validation`, `rc-only`, `spec` | — | TPM2_PCR_Reset unmarshals pcrHandle as TPMI_DH_PCR+, accepting TPM_RH_NULL instead of TPM_RC_VALUE + H1. |
| [policy-authorize-ticket-tags](bug-fix-policy-authorize-ticket-tags.patch) ([details](#policy-authorize-ticket-tags)) | `spec-185`, `functional`, `spec` | — | TPM2_PolicyAuthorize recomputes every ticket as TPM_ST_VERIFIED, so valid TPM_ST_MESSAGE_VERIFIED and TPM_ST_DIGEST_VERIFIED tickets are rejected with TPM_RC_VALUE. |
| [policy-capability-sec-channel](bug-fix-policy-capability-sec-channel.patch) ([details](#policy-capability-sec-channel)) | `spec`, `functional` | — | With SEC_CHANNEL_SUPPORT, TPM2_PolicyCapability rejects TPM_CAP_PUB_KEYS and TPM_CAP_SPDM_SESSION_INFO with TPM_RC_VALUE although its Capability Contents table lists them. |
| [read-only-before-startup](bug-fix-read-only-before-startup.patch) ([details](#read-only-before-startup)) | `spec`, `rc-only` | — | Before TPM2_Startup, a command not permitted in Read-Only mode can fail with TPM_RC_READ_ONLY (from a stale or unestablished gc.readOnly) instead of TPM_RC_INITIALIZE. |
| [sequence-complete-flushed-attribute](bug-fix-sequence-complete-flushed-attribute.patch) ([details](#sequence-complete-flushed-attribute)) | `spec` | — | TPMA_CC of TPM2_VerifySequenceComplete and TPM2_SignSequenceComplete has flushed CLEAR although Part 3 marks both {F}. |
| [session-audit-attribute-dependency](bug-fix-session-audit-attribute-dependency.patch) ([details](#session-audit-attribute-dependency)) | `spec`, `rc-only` | — | auditExclusive/auditReset without audit are ignored on HMAC/policy sessions instead of returning TPM_RC_ATTRIBUTES. |
| [sign-digest-hmac-scheme](bug-fix-sign-digest-hmac-scheme.patch) ([details](#sign-digest-hmac-scheme)) | `input-validation`, `spec` | — | TPM2_SignDigest signs with a key whose scheme is TPM_ALG_HMAC instead of returning TPM_RC_SCHEME. |
| [sign-mldsa-not-supported](bug-fix-sign-mldsa-not-supported.patch) ([details](#sign-mldsa-not-supported)) | `rc-only`, `spec` | — | TPM2_Sign with an ML-DSA key ("Not supported") selects the NULL scheme and fails later with TPM_RC_SIZE, TPM_RC_EXT_MU or TPM_RC_VALUE instead of TPM_RC_SCHEME + inScheme. |
| [sm2-signature-sequence](bug-fix-sm2-signature-sequence.patch) ([details](#sm2-signature-sequence)) | `spec-185`, `functional`, `spec` | — | TPM2_SignSequenceStart/TPM2_VerifySequenceStart reject SM2 keys (185TODO) instead of signing/verifying the message with context as ID_A, and TPMU_SIGNATURE_CTX lacks the SM2 id member. |
| [sec-channel-property-count](bug-fix-sec-channel-property-count.patch) ([details](#sec-channel-property-count)) | `spec` | — | TPM_CAP_PUB_KEYS and TPM_CAP_SPDM_SESSION_INFO return their entry even with propertyCount = 0 (moreData NO) instead of an empty list with moreData YES. |
| [svn-fw-limited-evict-control](bug-fix-svn-fw-limited-evict-control.patch) ([details](#svn-fw-limited-evict-control)) | `spec`, `rc-only`, `fw-limited` | — | TPM2_EvictControl rejects objects of limited hierarchies with TPM_RC_HIERARCHY instead of TPM_RC_ATTRIBUTES. |
| [symmetric-unique](bug-fix-symmetric-unique.patch) ([details](#symmetric-unique)) | `interop`, `crypto`, `spec` | — | unique of symmetric/keyed-hash parents is an HMAC instead of H_nameAlg(seedValue || key), giving non-interoperable Names and binding checks. |
| [template-size](bug-fix-template-size.patch) ([details](#template-size)) | `input-validation`, `spec` | — | TPM2B_TEMPLATE is bounded by the padded C sizeof(TPMT_PUBLIC) (356) instead of the unpadded 350 bytes, so oversized templates are accepted. |
| [tpmu-name-size](bug-fix-tpmu-name-size.patch) ([details](#tpmu-name-size)) | `input-validation`, `spec` | — | Alignment padding of the TPM_HANDLE member makes sizeof(TPMU_NAME) 68, so 67/68-octet TPM2B_NAMEs are accepted instead of TPM_RC_SIZE. |
| [verify-digest-signature-scheme](bug-fix-verify-digest-signature-scheme.patch) ([details](#verify-digest-signature-scheme)) | `input-validation`, `spec` | — | TPM2_VerifyDigestSignature accepts keys without a digest-signing scheme (or HMAC), digests of any size and signatures of another scheme/hash than the key's. |
| [verify-digest-signature-ticket](bug-fix-verify-digest-signature-ticket.patch) ([details](#verify-digest-signature-ticket)) | `spec-185`, `functional`, `interop`, `spec` | — | TPM2_VerifyDigestSignature returns a TPM_ST_VERIFIED ticket instead of a TPM_ST_DIGEST_VERIFIED ticket with the hash algorithm as metadata. |
| [verify-sequence-complete-scheme](bug-fix-verify-sequence-complete-scheme.patch) ([details](#verify-sequence-complete-scheme)) | `input-validation`, `spec` | — | TPM2_VerifySequenceComplete verifies a signature of another scheme or hash than the sequence's (digest-signing schemes) instead of returning TPM_RC_SCHEME. |
| [zgen-2phase-mqv-sm2](bug-fix-zgen-2phase-mqv-sm2.patch) ([details](#zgen-2phase-mqv-sm2)) | `security`, `dos`, `crypto`, `spec` | low | TPM2_ZGen_2Phase: Full MQV never sets the curve order and the x coordinate of Q_e,B (division by zero puts the TPM into failure mode), the associated values mask the wrong bits and avfSM2() uses an f one too small, and a Z at infinity is TPM_RC_NO_RESULT instead of an Empty Point. |
| [ecc-decrypt-c1-point](bug-fix-ecc-decrypt-c1-point.patch) ([details](#ecc-decrypt-c1-point)) | `input-validation`, `spec` | — | TPM2_ECC_Decrypt does not check that C1 is on the curve of the key; it continues with C1 itself as [d]C1 and fails later with TPM_RC_VALUE instead of TPM_RC_ECC_POINT. |
| [zgen-2phase-out-z2](bug-fix-zgen-2phase-out-z2.patch) ([details](#zgen-2phase-out-z2)) | `functional`, `spec` | — | The dispatch table of TPM2_ZGen_2Phase marshals outZ1 twice, so the response never contains outZ2 (Ze for ECDH, the Empty Point for MQV/SM2). |

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

### read-public-null-name-alg

**Categories:** `security`, `dos`, `spec`.

**Severity:** medium

**Description:**

Version 185 validates values while marshaling responses. Its dispatch table marshals the `outPublic` of TPM2_ReadPublic as a TPM2B_PUBLIC whose `nameAlg` is a TPMI_ALG_HASH without the "+" (TPM_ALG_NULL not allowed). TPM2_LoadExternal, however, may load a public area with `nameAlg` = TPM_ALG_NULL (the Name is then the Empty Buffer), as Part 3 permits. A TPM2_ReadPublic of such an object fails the TPMI_ALG_HASH check during response marshaling, which the reference treats as an internal error, and the TPM enters failure mode instead of returning the public area.

The patch marshals the response with `MARSHAL_ID_TPM2B_PUBLIC_Plus`, i.e. as TPM2B_PUBLIC+ (the public area exactly as it was loaded), so TPM2_ReadPublic returns it with `nameAlg` = TPM_ALG_NULL.

**Security:**

Any caller can trigger this without authorization: TPM2_LoadExternal of a public area with `nameAlg` = TPM_ALG_NULL (e.g. in the NULL hierarchy) needs no authorization, and neither does TPM2_ReadPublic. The TPM then enters failure mode and refuses all commands except TPM2_GetTestResult/TPM2_GetCapability until it is reset. This is a denial of service against every user of the TPM, but it does not disclose or modify protected data. The severity is medium.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPMT_PUBLIC Structure"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L11002-L11008)

> nameAlg: +TPMI_ALG_HASH: algorithm used for computing the Name of the object
> ... The "+" indicates that the instance of a TPMT_PUBLIC may have a "+" to
> indicate that the *nameAlg* may be TPM_ALG_NULL.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_LoadExternal", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L2633-L2634)

> If *hierarchy* is `TPM_RH_NULL` or *nameAlg* is `TPM_ALG_NULL`, a ticket
> produced using the object shall be a NULL Ticket.

**Spec:** [TPM 2.0 (version 185), Part 3, "Type Decoration +"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L171-L179)

> When appended to a value in the Type column of a command, this symbol
> indicates that the parameter is allowed to use the optional value of the
> data type (see TPM 2.0 Part 2, *Conditional Types*). The optional value
> is usually `TPM_RH_NULL` for a handle or `TPM_ALG_NULL` for an algorithm
> selector.
>
> **Note:** This decoration is not appended to response parameters

---

### rsa-prime-range

**Categories:** `security`, `dos`, `crypto`, `input-validation`, `spec`.

**Severity:** medium

**Description:**

When an RSA key with a sensitive area is loaded (`TPM2_LoadExternal`, `TPM2_Load` under a non-fixedTPM parent, `TPM2_Import`), the key validation (`CryptoCommon_ValidateKeys()`) checks only the *provided* prime P: it must be half the size of the modulus with its most significant bit SET, and it must divide N. `CryptoRsa_LoadPrivateExponent()` (`cryptolibs/implementations/RsaRef/CryptRsa.c`) then computes the second prime Q = N / P and checks only that the remainder is zero. **Q's range is never checked.** Part 1 requires both "the provided and computed prime factors" to be in range, meaning each prime squared has as many significant bits as N. A crafted modulus with a P just above 2^(k/2-1) can give a Q that is one bit longer than half the modulus, and such a key is accepted. The private exponent is then expanded into the five-value CRT form (P, Q, dP, dQ, qInv), with the larger prime determining the element size. For RSA-2048 the packed size (5 × 129 = 645 bytes) exceeds the `TPM2B_PRIVATE_KEY_RSA` buffer (`RSA_MAX_PRIME` × 5 = 640). `PackExponent()`'s size assertion fires and the TPM enters failure mode. For RSA-1024, the key under a fixedTPM parent gets a 325-byte CRT sensitive value that `TPM2_Load` later rejects.

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
1. Adds the last `buffer` to the hash state.
2. Ends the hash with `TpmHash_HashEnd`, which consumes the state.
3. May set `ticketSafe`.
4. Only then computes the `TPMT_TK_HASHCHECK` ticket.

Step 4 can fail. `HierarchyGetProof()` returns `TPM_RC_SVN_LIMITED` for an SVN-limited *hierarchy* whose SVN is above the firmware's current SVN, and `TPM_RC_FW_LIMITED` when the Firmware Secret is unavailable. The command then returns the error, but the sequence object is **not** flushed: it stays loaded with an ended hash state and possibly an updated `ticketSafe`. This contradicts Part 3: after an error, "the state of the TPM is unchanged". A later `TPM2_SequenceUpdate` or `TPM2_SequenceComplete` on that handle operates on the consumed hash state, and the TPM enters failure mode.

The patch checks the hierarchy's proof with `HierarchyGetProof()` (and wipes the copy) **before** changing the sequence, under exactly the conditions in which a ticket would be computed: a non-NULL hierarchy, and either `ticketSafe` already SET or this is the first block and `CryptoCommon_TicketIsSafe()` accepts it. If the proof is unavailable, the command fails with the sequence intact, so it can be retried with another hierarchy.

**Security:**

Any caller can trigger this without authorization. `TPM2_HashSequenceStart` needs no auth, the caller chooses the sequence's auth value, and the *hierarchy* parameter of `TPM2_SequenceComplete` is not authorized. It is enough to pass an SVN-limited hierarchy handle with an SVN above the current firmware SVN, send safe data, and then call `TPM2_SequenceUpdate`/`TPM2_SequenceComplete` again. The TPM then enters failure mode, a denial of service that lasts until the next `_TPM_Init` (reset). The attacker gains no secrets and cannot forge anything, so the severity is medium.

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

`EntityGetHierarchy()` (`support/Entity.c`, version 185 code base) determines an object's hierarchy from its `ppsHierarchy`/`spsHierarchy`/`epsHierarchy` attributes, and those attributes only ever hold the *base* hierarchy. An object in a firmware-limited or SVN-limited hierarchy (a primary key created with `TPM_RH_FW_*`/`TPM_RH_SVN_*_BASE + SVN`, an external object loaded into such a hierarchy, or any descendant) is therefore treated as belonging to `TPM_RH_OWNER`/`TPM_RH_PLATFORM`/`TPM_RH_ENDORSEMENT`. As a result, `TPM2_Create`'s creation ticket and the `TPM2_PolicySigned`/`TPM2_PolicySecret` auth tickets for such an object are labelled with the base hierarchy and HMACed with the base hierarchy's proof. `TPM2_VerifySignature`, which goes through `GetHierarchy()`, already uses the object's limited hierarchy. Part 2 says the ticket hierarchy is "the hierarchy containing *name*" or "the hierarchy of the object used to produce the ticket", and Part 1 says an object is in the limited hierarchy even without *firmwareLimited*/*svnLimited* SET.

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

### verify-sequence-ticket

**Categories:** `security`, `dos`, `functional`, `state`, `spec`.

**Severity:** medium

**Description:**

`TPM2_VerifySequenceComplete` (`command/Signature/VerifySequenceComplete.c`) has two problems.

1. **Wrong ticket.** Part 3 requires a `TPM_ST_MESSAGE_VERIFIED` ticket, and Part 2 defines it as an HMAC over the tag, the *message* and the key's Name. The reference ends the running hash of the message and returns the `TPM_ST_VERIFIED` ticket of `TPM2_VerifySignature` over that *digest* (`CryptoCommon_TicketComputeVerified()`). For the HMAC (and ML-DSA) schemes, which have no digest, it returns a NULL `TPM_ST_VERIFIED` ticket even for a key in a real hierarchy. So no `TPM_ST_MESSAGE_VERIFIED` ticket is ever produced, and the ticket it does produce looks like a `TPM2_VerifySignature` ticket for a digest the caller never supplied.
2. **A failed verification consumes the sequence.** The running hash (or HMAC) is ended in place (`CryptoHash_HashEnd()`/`CryptoHash_HmacEnd()` set the state to `HASH_STATE_EMPTY`) before the signature is checked. When the signature is not genuine, the command returns `TPM_RC_SIGNATURE` but leaves the sequence object loaded, so the TPM state did change. A later `TPM2_SequenceUpdate` on it reaches `FAIL_VOID(FATAL_ERROR_INTERNAL)` in `CryptoHash_DigestUpdate()`, and a retried `TPM2_VerifySequenceComplete` reaches `pAssert_ZERO` in `CryptoHash_HashEnd()`: the TPM enters failure mode.

The patch makes the ticket a running HMAC alongside the sequence:
- `TPM2_VerifySequenceStart` obtains the proof of the key's hierarchy (`GetHierarchy()`; none for `TPM_RH_NULL` or a key with nameAlg `TPM_ALG_NULL`) before the sequence object is allocated, so `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED` leave the TPM unchanged. After `ObjectCreateVerifySequence()` it starts HMAC<sub>contextAlg</sub>(proof, ...) with the tag `TPM_ST_MESSAGE_VERIFIED`.
- The running HMAC is kept in a new member of the `state` union of `SEQUENCE_OBJECT` (`state.verify.ticket`, after the running state of the message, which aliases `hashState[0]`/`hmacState`), because a `SEQUENCE_OBJECT` has to fit in an `OBJECT` slot (`MUST_BE(sizeof(SEQUENCE_OBJECT) <= sizeof(OBJECT))`). Its hierarchy is a new field `ticketHierarchy` before `state`. `SequenceDataExport()`/`SequenceDataImport()` export and import the running HMAC, so a context save/load preserves it.
- `ObjectVerifySequenceUpdate()` (`TPM2_SequenceUpdate`) adds the message to it.
- `TPM2_VerifySequenceComplete` ends the message's running hash or HMAC on a copy, so a failed verification leaves the sequence unchanged. After a successful verification, for every scheme, it checks that the proof is still available, adds the key's Name to a copy of the running HMAC and returns `<TPM_ST_MESSAGE_VERIFIED, hierarchy, HMAC>`, or `<TPM_ST_MESSAGE_VERIFIED, TPM_RH_NULL, Empty Buffer>` without a running HMAC. Only then is the sequence marked for flushing.

For ML-DSA, the message's library-owned state is completed on a copy made with `CryptoMldsa_VerifySequenceExport()`/`CryptoMldsa_VerifySequenceImport()`. The running ticket HMAC follows the largest form of the message state (including the exported ML-DSA state), and it is exported/imported before the early return of an ML-DSA sequence in `SequenceDataExport()`/`SequenceDataImport()`. This matches tpm-rs.

**Security:**

Any caller can trigger the failure mode without knowing any authorization value. They load any public key with `TPM2_LoadExternal` (no authorization needed; e.g. in the NULL hierarchy), start a verification sequence with `TPM2_VerifySequenceStart` (no authorization of the key, and the caller chooses the sequence's authValue), send `TPM2_VerifySequenceComplete` with a wrong signature, and then send `TPM2_SequenceUpdate` (or `TPM2_VerifySequenceComplete` again) on the sequence. The TPM enters failure mode until the next `_TPM_Init`, a denial of service for every user of the TPM. No secret is disclosed and no ticket can be forged, so the severity is medium.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_VerifySequenceComplete", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7325-L7331)

> This command is like `TPM2_VerifySignature()` with the following differences:
>
> - Verifying with *context* (provided in `TPM2_VerifySequenceStart()`) is
>   supported (requires a supporting signing scheme, e.g., TPM\_ALG\_MLDSA).
> - Verifying takes a message (provided via `TPM2_SequenceUpdate()`) rather than a
>   digest.
> - The ticket's *tag* is `TPM_ST_MESSAGE_VERIFIED`.

**Spec:** [TPM 2.0 (version 185), Part 2, "TPMT_TK_VERIFIED"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7497-L7525)

> $$ \mathbf{HMAC}_{\mathit{contextAlg}}(\mathit{proof}, (\mathit{tag} \parallel
>     \mathit{digestOrMessage} \parallel \mathit{keyName} \parallel \mathit{metadata})) $$
>
> ...
>
> The *metadata* is the serialized
> [TPMU_TK_VERIFIED_META](#sec:TPMU-TK-VERIFIED-META) contents according to the
> *tag* value. For some cases, *metadata* is zero-length.

**Spec:** [TPM 2.0 (version 185), Part 3, "Response Codes"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L922-L926)

> The normal response for any command is `TPM_RC_SUCCESS`. Any other value
> indicates that the command did not complete and the state of the TPM is
> unchanged. An exception to this general rule is that the logic
> associated with dictionary attack protection is allowed to be modified
> when an authorization failure occurs.

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

### nv-define-space2-external-nv

**Categories:** `memory-safety`, `ub`, `functional`, `spec`.

**Severity:** low

**Description:**

With `EXTERNAL_NV YES` (the default profile), TPM2_NV_DefineSpace2 accepts a `TPM2B_NV_PUBLIC_2` whose `handleType` is `TPM_HT_EXTERNAL_NV` and converts its `TPMS_NV_PUBLIC_EXP_ATTR` to the legacy `TPMS_NV_PUBLIC` with `NvPublicFromNvPublic2()`. That function copies the attributes, `authPolicy`, `dataSize` and `nameAlg`, but not `nvIndex`, so `NvDefineSpace()` checks (`NvIndexIsDefined()`) and defines an Index whose handle is whatever the uninitialized stack variable `legacyPublic` holds; the external Index the caller named is not created. Even with the handle copied, the Index could not be used: `EntityGetLoadStatus()` rejects every `TPM_HT_EXTERNAL_NV` handle ("Not yet supported", `TPM_RC_VALUE`), so it could neither be read, written nor undefined. The patch compiles the external NV case out, so TPM2_NV_DefineSpace2 rejects the handle type like every other one it does not support (`TPM_RC_HANDLE` + `publicInfo`).

**Security:**

A caller with owner or platform authorization (needed to define any Index) gets an Index at an unpredictable handle derived from stack contents, consuming NV space under a handle it did not choose. The severity is low because the caller is already authorized to define Indexes.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_NV_DefineSpace2"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L16041-L16052)

> This command is identical to `TPM2_NV_DefineSpace()`, except that the *publicInfo* parameter is a `TPM2B_NV_PUBLIC_2`, allowing all types of NV indices that support DefineSpace to be defined. The following types of NV indices are supported by this command: `TPM_HT_NV_INDEX` (the legacy NV index type), `TPM_HT_EXTERNAL_NV`

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPMS_NV_PUBLIC_EXP_ATTR Structure"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L11824-L11835)

> nvIndex | TPMI_RH_NV_EXP_INDEX | the handle of the data area

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

### policy-capability-session-handle

**Categories:** `security`, `auth-bypass`, `spec`.

**Severity:** low

**Description:**

For `TPM_CAP_HANDLES`, `TPM_HT_LOADED_SESSION` (0x02) handles name loaded sessions and `TPM_HT_SAVED_SESSION` (0x03) handles saved session contexts, as `TPM2_GetCapability` lists them. `SessionCapGetOneLoaded()` and `SessionCapGetOneSaved()`, which `TPM2_PolicyCapability` uses, only check that the session slot is in use (`gr.contextArray[slot] != 0`), not whether the session is loaded (`contextArray[slot] <= MAX_LOADED_SESSIONS`) or saved (`> MAX_LOADED_SESSIONS`) as `SessionCapGetLoaded()`/`SessionCapGetSaved()` do. A saved session therefore exists as a loaded one and a loaded session as a saved one.

**Security:** a policy that gates an authorization on a session being loaded (or saved) with `TPM2_PolicyCapability` is satisfied by a session in the other state (low).

The patch adds the check of the slot's state.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_GetCapability"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L14307-L14314)

> For this capability, use of `TPM_HT_LOADED_SESSION` and
> `TPM_HT_SAVED_SESSION` is allowed. Requesting handles with a handle
> type of `TPM_HT_LOADED_SESSION` will return handles for loaded
> sessions. [...] If saved sessions are requested, all returned values
> will have the `TPM_HT_HMAC_SESSION` handle type because the TPM does
> not track the session type of saved sessions.

**Spec:** [TPM 2.0 (version 185), Part 2, "TPM_HT"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L3865-L3876)

> TPM_HT_LOADED_SESSION | 0x02 | **Loaded Authorization Session** - loaded sessions of type `TPM_HT_HMAC_SESSION` or `TPM_HT_POLICY_SESSION`
>
> TPM_HT_SAVED_SESSION | 0x03 | **Saved Authorization Session** - [...] This type references saved authorization session contexts for which the TPM is maintaining tracking information.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_PolicyCapability"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L11252-L11253)

> If the requested TPM *property* does not exist, the TPM will return
> `TPM_RC_POLICY` unless the *operation* is `TPM_EO_NEQ`.

---

### policy-capability-transient-handle

**Categories:** `security`, `auth-bypass`, `spec`.

**Severity:** low

**Description:**

`TPM2_PolicyCapability` asserts a condition on one property of a capability; for `TPM_CAP_HANDLES` the property is a handle, which exists if the TPM has an entity under it, and a property that does not exist satisfies only `TPM_EO_NEQ`. For a transient handle the reference calls `ObjectCapGetOneLoaded()`, which loops over every object slot from the handle's slot to `MAX_LOADED_OBJECTS` and returns TRUE for the first occupied one. A transient handle whose object was flushed (or never loaded) therefore "exists" as long as any object with a larger handle is loaded, and the comparison is made against the queried handle value itself, so an assertion such as "handle 0x80000000 is loaded" (`TPM_EO_EQ` with that handle as operandB) holds although no such object exists.

**Security:** a policy that gates an authorization on a loaded transient object with `TPM2_PolicyCapability` is satisfied by loading any other object (low: the condition is under the caller's control anyway).

The patch checks only the handle's own slot.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_PolicyCapability"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L11252-L11265)

> If the requested TPM *property* does not exist, the TPM will return
> `TPM_RC_POLICY` unless the *operation* is `TPM_EO_NEQ`.
>
> TPM_CAP_HANDLES | TPM_HANDLE | TPM_HANDLE

---

### read-only-before-authorization

**Categories:** `security`, `spec`, `state`.

**Severity:** low

**Description:**

In Read-Only mode (`TPM2_ReadOnlyControl`), the commands that are never permitted (`RO_DISALLOW`) are rejected by `ExecuteCommand()` right after the command code, but the commands that are permitted only on some entities are checked in their actions: `NvReadOnlyModeChecks()` for TPM2_NV_Write, TPM2_NV_Extend, TPM2_NV_SetBits, TPM2_NV_WriteLock and TPM2_NV_ReadLock on an Index without both `TPMA_NV_ORDERLY` and `TPMA_NV_CLEAR_STCLEAR`, and `TPM2_PolicySecret()` for a PIN Pass/PIN Fail `authHandle`. These run after the authorization area has been processed, so a command with a wrong authorization reports `TPM_RC_AUTH_FAIL`/`TPM_RC_BAD_AUTH` instead of `TPM_RC_READ_ONLY`, and its failed authorization is accounted: the DA failure counter increments, and for a PIN Index authorizing TPM2_PolicySecret its `pinCount` (NV data) is updated, although Read-Only mode must not change NV. The patch runs the same checks in `ExecuteCommand()` once the handles are validated (`EntityGetLoadStatus()`) and before the authorization area.

**Security:**

Read-Only mode is meant to freeze the TPM's persistent state (Part 1: it "prevents making persistent changes, including object eviction, NV update operations, authorization changes"). With the upstream order, any caller can still change NV in Read-Only mode by sending a not-permitted command with a wrong authorization: each attempt increments the DA failure counter (eventually locking out the TPM's DA-protected entities) or a PIN Index's `pinCount` (exhausting a PIN Fail Index's `pinLimit`). The severity is low: the affected values are the ones failed authorizations always update, and the caller must know an Index of the right kind.

**Spec:** [TPM 2.0 (version 185), Part 1, "Read-Only Mode of Operation"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L15801-L15806)

> The error code `TPM_RC_READ_ONLY`, which indicates that an operation was rejected because the operation required a change to TPM state that is unsupported while in Read-Only mode. A device supporting Read-Only mode must reject any affected command before performing authorization checks which would be evaluated during the execution of the command.

**Spec:** [TPM 2.0 (version 185), Part 3, Table "Commands Permitted in Read-Only Mode"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L12568-L12572)

> TPM2_PolicySecret | Permitted | Not permitted when used with a PIN Pass/Fail NV index. ... TPM2_NV_Write | Permitted | Permitted only when the NV index is defined with `TPMA_NV_ORDERLY` and `TPMA_NV_CLEAR_STCLEAR`.

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

### verify-signature-mldsa-not-supported

**Categories:** `security`, `attestation`, `memory-safety`, `input-validation`, `spec`.

**Severity:** low

**Description:**

`TPM2_VerifySignature()` does not support (pure) ML-DSA keys: an external mu is verified with `TPM2_VerifyDigestSignature()`, a message with `TPM2_VerifySequenceComplete()`. Version 185's `CryptoCommon_ValidateDigestSignature()` verifies the `TPM2_VerifySignature()` digest as an external mu for a key with *allowExternalMu* and returns a `TPMT_TK_VERIFIED` ticket over it; it reads `signature.mldsa` without checking that `sigAlg` is `TPM_ALG_MLDSA`, so any signature type is interpreted as an ML-DSA signature (the union member of another algorithm).

**Security:** a `TPMT_TK_VERIFIED` ticket is produced for a combination the specification does not support, over an external mu that a later `TPM2_PolicyAuthorize()` cannot relate to a message (version 185 errata, "Ticket produced by `TPM2_VerifyDigestSignature()` for ML-DSA", recommends a NULL ticket for exactly this reason), and the signature union is read as the wrong type.

The patch returns `TPM_RC_SCHEME + RC_VerifySignature_signature` for an ML-DSA key after the *sign* attribute check.

**Spec:** [TPM 2.0 (version 185), Part 3, Table "Signing commands overview"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7191-L7196)

> (Pure) ML-DSA | Message (see Note) | Not supported | Signs/verifies the provided (external) Mu value for the message | Signs/verifies the message

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

### cipher-mode-error-code

**Categories:** `rc-only`, `spec`.

**Severity:** —

**Description:**

The error code of the `TPMI_ALG_CIPHER_MODE` interface type is `TPM_RC_MODE`. In version 185, `TPMI_ALG_CIPHER_MODE_MarshalUnmarshal()` and `TPMI_ALG_CIPHER_MODE_Plus_MarshalUnmarshal()` (`Marshal.c`) pass `TPM_RC_SYMMETRIC` as the error of the table-driven value check, so a mode that is not an implemented block cipher mode (e.g. `TPM_ALG_CMAC` as `mode` of `TPM2_EncryptDecrypt`) is rejected with `TPM_RC_SYMMETRIC` instead of `TPM_RC_MODE`. Only the response code differs; the value is still rejected.

The patch passes `TPM_RC_MODE` in both functions.

**Spec:** [TPM 2.0 (version 185), Part 2, "TPMI_ALG_CIPHER_MODE"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L6693-L6695)

> ... `TPMI_ALG_CIPHER_MODE` is an interface type of all the
> symmetric block cipher, encryption/decryption modes that are listed in
> the TCG algorithm registry.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of (TPM_ALG_ID) TPMI_ALG_CIPHER_MODE Type"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L6702-L6714)

> TPM_ALG_CTR; TPM_ALG_OFB; TPM_ALG_CBC; TPM_ALG_CFB; TPM_ALG_ECB; +TPM_ALG_NULL | required; #TPM_RC_MODE

---

### ecdaa-signature-context

**Categories:** `spec-185`, `functional`, `spec`.

**Severity:** —

**Description:**

The version 185 signing commands have no *inScheme*. The counter of a split signing scheme (ECDAA), which `TPM2_Sign` takes from *inScheme*, is passed in *context* instead: `TPMU_SIGNATURE_CTX` defines `commitCount[sizeof(UINT16)]` for `TPM_ALG_ECDAA`, and Part 3 requires *context* to carry the counter from `TPM2_Commit()`. The reference's `TPM2_SignDigest` and `TPM2_SignSequenceStart` select the key's scheme with a NULL selector, which `CryptoCommon_SelectSignScheme()` rejects for a split scheme, and accept *context* only for ML-DSA. A key whose scheme is `TPM_ALG_ECDAA` therefore can never sign: it gets `TPM_RC_VALUE` (*context*) with its counter, and `TPM_RC_SCHEME` without one. Moreover, without ML-DSA, the reference unmarshals *context* with the limit `MAX_SIG_CTX_SIZE` = 0 (`TpmAlgorithmDefines.h`, "185TODO: Incorporate DAA context size"), although `TPM2B_SIGNATURE_CTX` holds up to sizeof(`TPMU_SIGNATURE_CTX`) octets and its `TPMU_SIGNATURE_CTX` has the 2-octet `commitCount`, so any non-empty *context* is `TPM_RC_SIZE` in every command that takes one.

The patch sets `MAX_SIG_CTX_SIZE` to 2 with ECDAA (still `MLDSA_CTX_MAX_SIZE` with ML-DSA).

For a key whose scheme is `TPM_ALG_ECDAA`, it requires *context* to be exactly the 2-octet big-endian counter (otherwise `TPM_RC_VALUE + RC_<command>_context`). It selects the key's scheme with that counter through `CryptoCommon_SelectSignScheme()`, whose failure is `TPM_RC_VALUE + RC_<command>_context`. `TPM2_SignDigest` signs with that scheme, and a signing sequence keeps it, so that `TPM2_SignSequenceComplete` signs with it, consuming the commit (an unknown or used counter is the `TPM_RC_VALUE` of the ECDAA signing, as in `TPM2_Sign`). Other keys are unchanged, and the verification commands still reject ECDAA keys with `TPM_RC_SCHEME`. This matches tpm-rs.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPMU_SIGNATURE_CTX Union"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L10414-L10416)

> commitCount\[sizeof(UINT16)\] | BYTE | `TPM_ALG_ECDAA` | the counter value that is used between `TPM2_Commit()` and the sign operation

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPM2B_SIGNATURE_CTX Structure"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L10446-L10456)

> size | UINT16 | size of *context*; context\[size\]{:sizeof(TPMU_SIGNATURE_CTX)} | BYTE

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_SignSequenceStart", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L5586-L5588)

> If the scheme of *keyHandle* uses a counter value (e.g., TPM\_ALG\_ECDAA), then
> *context* shall contain the counter value from `TPM2_Commit()` to use for the
> signature.

---

### ecc-point-coordinate-range

**Categories:** `spec`, `input-validation`, `crypto`.

**Severity:** —

**Description:**

`BnIsPointOnCurve()` (`BnMath.c`), which validates every ECC point the TPM receives (public keys of `TPM2_LoadExternal`/`TPM2_Load`, `inPoint` of `TPM2_ECDH_ZGen`, `P1`/`(x2, y2)` of `TPM2_Commit`, ...), evaluates the curve equation modulo p but never checks that the coordinates are field elements. A coordinate `x + p` (or `y + p`) passes whenever the integer still fits the `TPM2B_ECC_PARAMETER` of the curve: for every point of BN P-638 (p is about 2^637.2 in 80 bytes) and for points with small coordinates of the curves whose p is not close to 2^(8n) (e.g. NIST P-224). The TPM then accepts and keeps a non-canonical encoding of the point, so the same public key has several Names.

The patch rejects a coordinate that is not below p, as `tpm-rs` does (`TPM_RC_ECC_POINT`/`TPM_RC_KEY` like any other point off the curve).

**Spec:** [TPM 2.0 (version 185), Part 1, "ECDH"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L2085-L2085)

> "(Cofactor) One-Pass Diffie-Hellman, C(1e, 1s, ECC CDH)" from SP 800-56A

**Spec:** NIST SP 800-56A Rev. 3, 5.6.2.3.3 "ECC Full Public-Key Validation Routine", step 2

> Verify that xQ and yQ are integers in the interval [0, p - 1] in the case that q is an odd prime p

---

### get-test-result-needs-test

**Categories:** `self-test`, `spec`.

**Severity:** —

**Description:**

`TPM2_GetTestResult` outside Failure mode always returns `testResult =
TPM_RC_SUCCESS` with empty `outData`: `CryptoCommon_GetTestResult()` is a placeholder (its own comment
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

### nv-certify-null-sign-handle-digest

**Categories:** `spec-185`, `functional`, `spec`.

**Severity:** —

**Description:**

This reference targets version 185 but implements the new rule incorrectly. For
`TPM2_NV_Certify` with `signHandle = TPM_RH_NULL`, `SelectAttestSignScheme()`
(`CryptoCommon_SelectSignScheme()`) replaces `inScheme` with `TPM_ALG_NULL`, and
for `size = offset = 0` the digest's hash algorithm is then taken from that
cleared scheme by `AttestHashAlg()`. It is always `TPM_ALG_NULL`, so the command
always fails with `TPM_RC_SCHEME`, even when the caller supplied a valid scheme
such as `TPM_ALG_RSASSA`/`TPM_ALG_SHA256`. The unsigned NV digest attestation that
version 185 introduced as the replacement of the pre-185 Empty Buffer (versions
1.83 and earlier allowed an Empty Buffer digest here) is therefore unusable.

The patch saves the caller's `inScheme` before the scheme selection and passes it
to `AttestHashAlg()` when `signHandle` is NULL, so the digest is computed with the
hash algorithm of `inScheme` and `TPM_RC_SCHEME` is returned only when that scheme
or its hash algorithm is `TPM_ALG_NULL`. The attestation stays unsigned (NULL
signature).

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

### nv-define-space2-dispatch

**Categories:** `functional`, `spec`.

**Severity:** —

**Description:**

The dispatch table of TPM2_NV_DefineSpace2 (`CommandDispatch.inl`) unmarshals its second parameter, the `TPM2B_NV_PUBLIC_2`, at the offset of the `auth` member instead of `publicInfo`. `publicInfo` therefore stays zero, so its `handleType` (0) fails the handle-type check of every well-formed command with `TPM_RC_HANDLE` + `publicInfo`, and the authValue just unmarshaled is overwritten: the command can never define an Index. The patch makes the entry target `publicInfo`, as in the public `tcgtpm` and `ibmswtpm2`.

**Spec:** [TPM 2.0 (version 185), Part 3, Table "TPM2_NV_DefineSpace2 Command"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L16061-L16086)

> TPM2B_AUTH | auth | the authorization value. TPM2B_NV_PUBLIC_2 | publicInfo | the public parameters of the NV area

---

### nv-exp-index-range

**Categories:** `spec`, `input-validation`.

**Severity:** —

**Description:**

Part 2 defines `TPMI_RH_NV_EXP_INDEX`, the type of the `nvIndex` of a `TPMS_NV_PUBLIC_EXP_ATTR` (the `TPM_HT_EXTERNAL_NV` member of a `TPM2B_NV_PUBLIC_2`), as `{EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST}`. This reference's `TPMI_RH_NV_EXP_INDEX_RANGES` (`Marshal.c`) hold `{NV_INDEX_FIRST, NV_INDEX_LAST}` instead, so the member accepts ordinary NV Index handles and rejects every external NV handle with `TPM_RC_VALUE` (the public `tcgtpm`, `ibmswtpm2` and `tpm-rs` use the external range). The patch uses the external NV Index range.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of (TPM_HANDLE) TPMI_RH_NV_EXP_INDEX Type"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L6318-L6333)

> {EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST}: range of external NV Indexes. #TPM_RC_VALUE: error returned if the handle is out of range

---

### pcr-reset-handle-type

**Categories:** `input-validation`, `rc-only`, `spec`.

**Severity:** —

**Description:**

The `pcrHandle` of `TPM2_PCR_Reset` is a `TPMI_DH_PCR` without the `+` decoration, so its conditional value `TPM_RH_NULL` is not allowed and must be rejected while unmarshaling the handle area with `TPM_RC_VALUE + TPM_RC_H + TPM_RC_1`. In version 185, the dispatch table (`CommandDispatch.inl`) unmarshals `pcrHandle` as `TPMI_DH_PCR+` (`MARSHAL_ID_TPMI_DH_PCR_Plus`), so `TPM_RH_NULL` is accepted and the command fails only later with another response code (e.g. `TPM_RC_AUTH_MISSING` in the authorization checks). Only the response code differs.

The patch changes the dispatch entry to `MARSHAL_ID_TPMI_DH_PCR`, so `TPM_RH_NULL` is rejected with `TPM_RC_VALUE + TPM_RC_H + TPM_RC_1`.

**Spec:** [TPM 2.0 (version 185), Part 3, Table "TPM2_PCR_Reset Command"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L8636-L8636)

> TPMI_DH_PCR | @pcrHandle | the PCR to reset

**Spec:** [TPM 2.0 (version 185), Part 3, "Type Decoration +"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L171-L175)

> When appended to a value in the Type column of a command, this symbol
> indicates that the parameter is allowed to use the optional value of the
> data type (see TPM 2.0 Part 2, *Conditional Types*). The optional value
> is usually `TPM_RH_NULL` for a handle or `TPM_ALG_NULL` for an algorithm
> selector.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of (TPM_HANDLE) TPMI_DH_PCR Type"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L5874-L5878)

> {PCR_FIRST:PCR_LAST}; +TPM_RH_NULL | conditional value; #TPM_RC_VALUE

---

### policy-authorize-ticket-tags

**Categories:** `spec-185`, `functional`, `spec`.

**Severity:** —

**Description:**

Version 185 adds two `TPMT_TK_VERIFIED` tags: `TPM_ST_MESSAGE_VERIFIED` (`TPM2_VerifySequenceComplete`, an HMAC over the message) and `TPM_ST_DIGEST_VERIFIED` (`TPM2_VerifyDigestSignature`, an HMAC over the digest followed by its hash algorithm as metadata). Part 3 says that each of the three verification commands produces a ticket that `TPM2_PolicyAuthorize` accepts. The reference's `TPM2_PolicyAuthorize` (`command/EA/PolicyAuthorize.c`) unmarshals all three tags, but recomputes every *checkTicket* as a `TPM_ST_VERIFIED` ticket over aHash = H<sub>nameAlg(keySign)</sub>(*approvedPolicy* || *policyRef*). A valid ticket with either new tag therefore never matches, and the command fails with `TPM_RC_VALUE`.

The patch recomputes the ticket according to its tag:
- `TPM_ST_VERIFIED`: unchanged.
- `TPM_ST_MESSAGE_VERIFIED`: HMAC(proof, (tag || *approvedPolicy* || *policyRef* || *keySign*)), the message being *toBeSigned*.
- `TPM_ST_DIGEST_VERIFIED`: HMAC(proof, (tag || aHash || *keySign* || hashAlg)), with aHash computed with the hash algorithm hashAlg of the ticket's metadata.

This matches tpm-rs.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_PolicyAuthorize", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L10586-L10590)

> This signature over *toBeSigned* is verified using `TPM2_VerifySignature()`,
> `TPM2_VerifySequenceComplete()`, or `TPM2_VerifyDigestSignature()`. Each of
> these commands produces a `TPMT_TK_VERIFIED` ticket.
>
> The ticket is then used in `TPM2_PolicyAuthorize()` to satisfy the policy.

**Spec:** [TPM 2.0 (version 185), Part 2, "TPMT_TK_VERIFIED"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7497-L7525)

> $$ \mathbf{HMAC}_{\mathit{contextAlg}}(\mathit{proof}, (\mathit{tag} \parallel
>     \mathit{digestOrMessage} \parallel \mathit{keyName} \parallel \mathit{metadata})) $$
>
> ...
>
> The *metadata* is the serialized
> [TPMU_TK_VERIFIED_META](#sec:TPMU-TK-VERIFIED-META) contents according to the
> *tag* value. For some cases, *metadata* is zero-length.

---

### policy-capability-sec-channel

**Categories:** `spec`, `functional`.

**Severity:** —

**Description:**

Version 184 added `TPM_CAP_PUB_KEYS` (the TPM SPDM public keys) and `TPM_CAP_SPDM_SESSION_INFO` (the key Names of the SPDM session protecting the command) to `TPM2_GetCapability`, and to the "Capability Contents" table of `TPM2_PolicyCapability` with the property types `TPM2B_PUBLIC` and `TPMS_SPDM_SESSION_INFO`. The reference implements both in `TPM2_GetCapability` (with `SEC_CHANNEL_SUPPORT`), but its `TPM2_PolicyCapability` switch has no case for them, so a policy assertion on an SPDM key or on the SPDM session fails with `TPM_RC_VALUE` (capability) instead of comparing.

The patch adds both cases: `TPM_CAP_PUB_KEYS` compares against the `TPM2B_PUBLIC` of the TPM SPDM key (the reference has only `TPM_PUB_KEY_TPM_SPDM_00`; another key of the `TPM_PUB_KEY` range does not exist, a property beyond `TPM_PUB_KEY_TPM_SPDM_FF` is `TPM_RC_VALUE`), `TPM_CAP_SPDM_SESSION_INFO` against the `TPMS_SPDM_SESSION_INFO` of the current SPDM session (property 0, else `TPM_RC_VALUE` as in `TPM2_GetCapability`).

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_PolicyCapability"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L11252-L11288)

> If the requested TPM *property* does not exist, the TPM will return
> `TPM_RC_POLICY` unless the *operation* is `TPM_EO_NEQ`.
>
> TPM_CAP_PUB_KEYS | TPM_PUB_KEY | TPM2B_PUBLIC
>
> TPM_CAP_SPDM_SESSION_INFO | reserved | TPMS_SPDM_SESSION_INFO

**Spec:** [TPM 2.0 (version 185), Part 2, "TPM_PUB_KEY"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L3801-L3811)

> TPM_PUB_KEY_TPM_SPDM_00 | 0x00000000 | Start of the property range for TPM SPDM authentication public keys
>
> TPM_PUB_KEY_TPM_SPDM_FF | 0x000000FF | End of the property range for TPM SPDM authentication public keys

---

### read-only-before-startup

**Categories:** `spec`, `rc-only`.

**Severity:** —

**Description:**

`ExecuteCommand()` rejects the commands that are never permitted in Read-Only mode (`RO_DISALLOW`) when `gc.readOnly` is set, before it checks whether the TPM has been started. `gc` is only established by TPM2_Startup (`HierarchyStartup()` for TPM Reset/Restart, `NvRead(&gc, NV_STATE_CLEAR_DATA, ...)` for TPM Resume), so between `_TPM_Init` and TPM2_Startup `gc.readOnly` holds whatever is left in memory, and such a command can fail with `TPM_RC_READ_ONLY` instead of `TPM_RC_INITIALIZE`. The command is refused either way, so only the response code differs. The patch applies the Read-Only check only to a started TPM.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_Startup"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L1162-L1168)

> `TPM2_Startup()` is only valid after `_TPM_Init`. ... If a TPM requires `TPM2_Startup()` and another command is received, or if the TPM receives `TPM2_Startup()` when it is not required, the TPM shall return `TPM_RC_INITIALIZE`.

---

### sequence-complete-flushed-attribute

**Categories:** `spec`.

**Severity:** —

**Description:**

Part 3 marks the command codes of `TPM2_VerifySequenceComplete` and `TPM2_SignSequenceComplete` with `{F}`, so the *flushed* attribute of their `TPMA_CC` is SET: both commands flush the sequence object they complete, as `TPM2_SequenceComplete` does. The reference's `s_ccAttr` table (`CommandAttributeData.h`) has *flushed* CLEAR for `TPM_CC` 0x1A3 and 0x1A4, so `TPM2_GetCapability(TPM_CAP_COMMANDS)` reports them without it. The patch sets *flushed* for both, as in tpm-rs. Command execution does not change.

**Spec:** [TPM 2.0 (version 185), Part 3, "Description Modifier {F}"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L215-L218)

> This modifier indicates that the "flushed" attribute will be SET in the
> `TPMA_CC` for the command. The modifier may follow the *commandCode* in
> the "Description" column to indicate that any transient handle context
> used by the command will be flushed from the TPM when the command
> completes.

**Spec:** [TPM 2.0 (version 185), Part 3, Table "TPM2_VerifySequenceComplete Command"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7375-L7375)

> TPM_CC | commandCode | TPM_CC_VerifySequenceComplete {F}

**Spec:** [TPM 2.0 (version 185), Part 3, Table "TPM2_SignSequenceComplete Command"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7699-L7699)

> TPM_CC | commandCode | TPM_CC_SignSequenceComplete {F}

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

### sec-channel-property-count

**Categories:** `spec`.

**Severity:** —

**Description:**

With `SEC_CHANNEL_SUPPORT`, `TPM2_GetCapability(TPM_CAP_PUB_KEYS)` returns the reference's TPM SPDM public key (`SpdmCapGetTpmPubKeys()` ignores its `count` argument) and `TPM2_GetCapability(TPM_CAP_SPDM_SESSION_INFO)` returns the entry of the current SPDM session (`SpdmCapGetSessionInfo()` takes no count) whatever `propertyCount` is: with `propertyCount = 0` the list still holds one entry and `moreData` is NO. The specification bounds every capability list by `propertyCount` and reports the values left out with `moreData`, as the reference's other capabilities do (e.g. `PCRCapGetAllocation()` for `TPM_CAP_PCRS`, `ActGetCapabilityData()` for `TPM_CAP_ACT`).

The patch leaves the entry out and sets `moreData = YES` when `propertyCount` is 0 (tests `e2e::secure_channel_capabilities::pub_keys_with_zero_count_returns_no_key`, `e2e::secure_channel_capabilities::spdm_session_info_with_zero_count_returns_no_entry`).

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_GetCapability"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L14152-L14155)

> The *propertyCount* parameter indicates the number of capabilities in
> the indicated group that are requested. The TPM will return no more than
> the number of requested values (*propertyCount*) or until the last
> property of the requested type has been returned.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_GetCapability"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L14406-L14407)

> The *moreData* parameter will have a value of YES if there are more
> values of the requested type that were not returned.

---

### sign-digest-hmac-scheme

**Categories:** `input-validation`, `spec`.

**Severity:** —

**Description:**

`TPM2_SignDigest` (`command/Signature/SignDigest.c`) takes the scheme of the key from `CryptoCommon_SelectSignScheme()` with a NULL selector and signs with any scheme it returns. For a keyed-hash signing key with scheme `TPM_ALG_HMAC`, it returns an HMAC of *digest*, although Part 3 excludes HMAC from `TPM2_SignDigest` (HMAC signs a message, not a digest; HMAC keys sign with `TPM2_SignSequenceComplete`, or with the deprecated `TPM2_Sign`). The patch returns `TPM_RC_SCHEME + RC_SignDigest_keyHandle` for such a key, at the scheme check, as in tpm-rs.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_SignDigest", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7749-L7752)

> The scheme of *keyHandle* must be a signing scheme that supports signing a
> digest (e.g., TPM\_ALG\_ECDSA, but not TPM\_ALG\_HMAC).
> The size of *digest* must match the size of the hash algorithm of the signing
> scheme.

**Spec:** [TPM 2.0 (version 185), Part 3, Table "Signing commands overview"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7150-L7158)

> Signing algorithm: HMAC | Signs message, or digest?: Message | `TPM2_SignDigest()`/`TPM2_VerifyDigestSignature()`: Not supported

---

### sign-mldsa-not-supported

**Categories:** `rc-only`, `spec`.

**Severity:** —

**Description:**

`TPM2_Sign()` does not support (pure) ML-DSA keys (they sign with `TPM2_SignSequenceComplete()`, or an external mu with `TPM2_SignDigest()`), so no signing scheme is valid for such a key and the command must fail with `TPM_RC_SCHEME`. Version 185's `CryptoCommon_SelectSignScheme()` selects the NULL scheme for an ML-DSA key and accepts it; the command then checks the digest against the (zero) size of the NULL hash (`TPM_RC_SIZE + RC_Sign_digest` for any non-empty digest), computes a hash-check ticket with the NULL hash for a restricted key, and finally treats the digest as an external mu (`TPM_RC_EXT_MU` without *allowExternalMu*, `TPM_RC_VALUE` for its size). It never signs, so only the response code differs.

The patch returns `TPM_RC_SCHEME + RC_Sign_inScheme` for an ML-DSA key after the *x509sign* check (test `e2e::mldsa_attestation`/`e2e::mldsa_keys` TPM2_Sign cases).

**Spec:** [TPM 2.0 (version 185), Part 3, Table "Signing commands overview"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7191-L7196)

> (Pure) ML-DSA | Message (see Note) | Not supported | Signs/verifies the provided (external) Mu value for the message | Signs/verifies the message

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_Sign"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7547-L7548)

> If *inScheme* is not a valid signing scheme for the type of keyHandle
> (or `TPM_ALG_NULL`), then the TPM shall return `TPM_RC_SCHEME`.

---

### sm2-signature-sequence

**Categories:** `spec-185`, `functional`, `spec`.

**Severity:** —

**Description:**

Version 185 makes SM2 a message-signing scheme for the signing and verification sequences: `TPM2_SignSequenceComplete`/`TPM2_VerifySequenceComplete` sign or verify the message "using the provided *context* as *ID$_A$*". Per Part 1, that means computing Z<sub>A</sub> from ID<sub>A</sub>, the curve and the public key, and then the internal digest e = H(Z<sub>A</sub> || M). The reference does not implement this: `SelectSignSequenceScheme()`/`SelectVerifySequenceScheme()` reject a key whose scheme is `TPM_ALG_SM2` with `TPM_RC_SCHEME` ("185TODO"). Its `TPMU_SIGNATURE_CTX` also lacks the `id[MAX_SM2_ID_BYTES]` member of Part 2, so a `TPM2B_SIGNATURE_CTX` could not carry an ID<sub>A</sub>.

The patch:
- accepts SM2 in both `TPM2_*SequenceStart` commands, with any *context* (`Sign/VerifySequenceSchemeTakesContext()`);
- in `ObjectCreateSignSequence()`/`ObjectCreateVerifySequence()`, starts the running hash of the scheme with Z<sub>A</sub> = H(ENTL<sub>A</sub> || ID<sub>A</sub> || a || b || x<sub>G</sub> || y<sub>G</sub> || x<sub>A</sub> || y<sub>A</sub>), where ENTL<sub>A</sub> is the length of ID<sub>A</sub> in octets (2 octets, big-endian), a, b and G come from the curve (`CryptoEcc_GetParameters()`), and every field element is left-padded to the size of the field. The complete commands therefore sign or verify e with the existing digest-based SM2 code;
- adds `id[MAX_SM2_ID_BYTES]` (`MAX_SM2_ID_BYTES` = 255) to `TPMU_SIGNATURE_CTX`, and uses it as `MAX_SIG_CTX_SIZE` with SM2 and without ML-DSA.

This matches tpm-rs. `TPM2_SignDigest`/`TPM2_VerifyDigestSignature` are unchanged: with SM2, their *digest* is e and their *context* must be empty.

**Spec:** [TPM 2.0 (version 185), Part 3, Table "Signing commands overview"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7178-L7182)

> SM2 | Message (see Note) | Signs/verifies the internal digest *e* | Signs/verifies the internal digest *e*, *context* must be empty | Signs/verifies the message using the provided *context* as *ID$_A$*

**Spec:** [TPM 2.0 (version 185), Part 1, "SM2 Sign"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L17369-L17410)

> $$ {\mathit{Z}}_{\mathit{A}} := {\mathbf{H}}( {\mathit{ENTL}}_{\mathit{A}}
>     \parallel {\mathit{ID}}_{\mathit{A}} \parallel {\mathit{a}} \parallel
>     {\mathit{b}} \parallel {\mathit{x}}_{\mathit{G}} \parallel
>     {\mathit{y}}_{\mathit{G}} \parallel {\mathit{x}}_{\mathit{A}}
>     \parallel {\mathit{y}}_{\mathit{A}}) $$
>
> ...
>
> *ENTL$_A$* is two octets containing the length of *ID$_A$* in octets
>
> ...
>
> $$ {\mathit{e}} := {\mathbf{H}}({\mathit{Z}}_{\mathit{A}} \parallel {\mathit{M}}) $$

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPMU_SIGNATURE_CTX Union"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L10418-L10420)

> id\[MAX_SM2_ID_BYTES\] | BYTE | `TPM_ALG_SM2` | Value for *ID$_A$* "identifying an entity's identity"

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

The maximum size of a `TPM2B_TEMPLATE` is `sizeof(TPMT_PUBLIC)`, which Part 2 defines as the octet-aligned size of the structure without padding. `TPM2B_TEMPLATE_MarshalUnmarshal()` (`Marshal.c`) passes the C `sizeof(TPMT_PUBLIC)` to `TPM2B_MarshalUnmarshal()` as the maximum size, and the C size includes the alignment padding caused by the 4-byte alignment of the `UINT32` members (`TPMA_OBJECT` and the `exponent` of `TPMS_RSA_PARMS`): 356 bytes instead of 350 with this profile (RSA-2048, 66-byte `authPolicy` for SHA-512). A `TPM2_CreateLoaded` whose `inPublic` template is 351 to 356 bytes long is therefore accepted by the unmarshaler and processed further (so it fails later with another response code, or not at all) instead of being rejected with `TPM_RC_SIZE` for `inPublic`. This is the same kind of padding issue as `tpmu-name-size`. There is no memory-safety impact: the C buffer of `TPM2B_TEMPLATE` has the padded size, so the extra bytes still fit.

The patch computes the unpadded size `TPMT_PUBLIC_PACKED_SIZE` from the members (`type`, `nameAlg`, `objectAttributes`, `authPolicy`, the larger of the packed `TPMS_RSA_PARMS` and `TPMS_ECC_PARMS`, and `TPMU_PUBLIC_ID`) and uses it as the bound.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPM2B_TEMPLATE Structure"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L11079-L11082)

> size | UINT16 | size of publicArea; buffer[size]{:sizeof(TPMT_PUBLIC)} | BYTE | the public area

**Spec:** [TPM 2.0 (version 185), Part 2, "Data Alignment"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L1120-L1123)

> The data structures in this specification use octet alignment for all
> structures. When used in a table to indicate a maximum size, the
> sizeof() function returns the octet-aligned size of the structure, with
> no padding.

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

---

### verify-digest-signature-scheme

**Categories:** `input-validation`, `spec`.

**Severity:** —

**Description:**

For keys other than ML-DSA, `TPM2_VerifyDigestSignature` (`command/Signature/VerifyDigestSignature.c`) passes *digest* and *signature* straight to `CryptoCommon_ValidateDigestSignature()`, like `TPM2_VerifySignature`. That function verifies with the scheme and hash algorithm of the *signature*, not those of the key. So the command accepts:
- a key without a signing scheme of its own (scheme `TPM_ALG_NULL`), or with `TPM_ALG_HMAC`, which Part 3 excludes;
- a *digest* of any size;
- a signature whose scheme or hash algorithm differs from the key's (e.g. an RSAPSS signature for an RSASSA key, or a SHA-1 signature for a SHA-256 scheme).

The patch adds the checks in this order, after the *context* check:
1. The key's scheme (`CryptoCommon_SelectSignScheme()` with a NULL selector) fails or is `TPM_ALG_HMAC`: `TPM_RC_SCHEME + RC_VerifyDigestSignature_keyHandle`.
2. The size of *digest* is not the digest size of the scheme's hash: `TPM_RC_SIZE + RC_VerifyDigestSignature_digest`.
3. The *signature*'s sigAlg or hash algorithm is not the key scheme's: `TPM_RC_SCHEME + RC_VerifyDigestSignature_signature`.

The signature is then validated as before. This matches tpm-rs.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_VerifyDigestSignature", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7424-L7434)

> This command is like `TPM2_VerifySequenceComplete()`, except that it verifies a digest of
> a message instead of the raw message, and the produced ticket has *tag*
> `TPM_ST_DIGEST_VERIFIED`.
>
> The scheme of *keyHandle* must be a signing scheme that supports signing a
> digest (e.g., TPM\_ALG\_ECDSA). The size of *digest* must match the size of the
> hash algorithm of the signing scheme.
>
> The TPM will verify that the signing scheme (including the hash or XOF
> algorithm) in *signature* matches the signing scheme of *keyHandle*
> (TPM_RC_SCHEME).

**Spec:** [TPM 2.0 (version 185), Part 3, Table "Signing commands overview"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7150-L7158)

> Signing algorithm: HMAC | Signs message, or digest?: Message | `TPM2_SignDigest()`/`TPM2_VerifyDigestSignature()`: Not supported

---

### verify-digest-signature-ticket

**Categories:** `spec-185`, `functional`, `interop`, `spec`.

**Severity:** —

**Description:**

`TPM2_VerifyDigestSignature` returns the ticket of `TPM2_VerifySignature`: `TPM_ST_VERIFIED`, HMAC(proof, (`TPM_ST_VERIFIED` || *digest* || keyName)), and a NULL Ticket with tag `TPM_ST_VERIFIED`. Version 185 requires tag `TPM_ST_DIGEST_VERIFIED`, whose metadata (`TPMU_TK_VERIFIED_META.digestVerified`) is the hash algorithm that produced the digest and is included in the HMAC. The reference's `TPMT_TK_VERIFIED` and its marshaling already support the metadata; only the command does not produce it.

The patch returns `<TPM_ST_DIGEST_VERIFIED, hierarchy, hashAlg, HMAC(proof, (TPM_ST_DIGEST_VERIFIED || digest || keyName || hashAlg))>`, where hashAlg is the hash algorithm of the key's scheme. For a key in `TPM_RH_NULL` or with nameAlg `TPM_ALG_NULL`, it returns the NULL Ticket `<TPM_ST_DIGEST_VERIFIED, TPM_RH_NULL, hashAlg, Empty Buffer>`. For an ML-DSA key (an external mu), the ticket is always the NULL Ticket, as the version 185 errata recommend, with the key's nameAlg as metadata (SHAKE256 is not a `TPMI_ALG_HASH`). This matches tpm-rs, and `TPM2_PolicyAuthorize` accepts the ticket with `bug-fix-policy-authorize-ticket-tags.patch`.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_VerifyDigestSignature", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L7424-L7434)

> This command is like `TPM2_VerifySequenceComplete()`, except that it verifies a digest of
> a message instead of the raw message, and the produced ticket has *tag*
> `TPM_ST_DIGEST_VERIFIED`.
>
> The scheme of *keyHandle* must be a signing scheme that supports signing a
> digest (e.g., TPM\_ALG\_ECDSA). The size of *digest* must match the size of the
> hash algorithm of the signing scheme.
>
> The TPM will verify that the signing scheme (including the hash or XOF
> algorithm) in *signature* matches the signing scheme of *keyHandle*
> (TPM_RC_SCHEME).

**Spec:** [TPM 2.0 (version 185), Part 2, "TPMT_TK_VERIFIED"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7497-L7525)

> $$ \mathbf{HMAC}_{\mathit{contextAlg}}(\mathit{proof}, (\mathit{tag} \parallel
>     \mathit{digestOrMessage} \parallel \mathit{keyName} \parallel \mathit{metadata})) $$
>
> ...
>
> The *metadata* is the serialized
> [TPMU_TK_VERIFIED_META](#sec:TPMU-TK-VERIFIED-META) contents according to the
> *tag* value. For some cases, *metadata* is zero-length.

**Spec:** [TPM 2.0 (version 185), Part 2, Table "Definition of TPMU_TK_VERIFIED_META Union"](../../../_agents/skills/tpm2-spec/resources/spec/part2.tcg.txt#L7473-L7475)

> digestVerified | TPMI_ALG_HASH | `TPM_ST_DIGEST_VERIFIED` | The hash algorithm or XOF used to produce the digest that was verified

**Spec:** [TPM 2.0 (version 185), Errata, "Ticket produced by `TPM2_VerifyDigestSignature()` for ML-DSA"](../../../_agents/skills/tpm2-spec/resources/spec/errata.tcg.txt#L145-L160)

> To avoid returning a nonviable ticket to the user, it is preferable for the TPM
> to return a NULL `TPMT_TK_VERIFIED` ticket instead.

---

### verify-sequence-complete-scheme

**Categories:** `input-validation`, `spec`.

**Severity:** —

**Description:**

A verification sequence is bound to the scheme of the key that started it (`signScheme`; `TPM2_VerifySequenceComplete` has no scheme parameter). `TPM2_VerifySequenceComplete` checks the *signature*'s scheme for the HMAC and ML-DSA schemes (`TPM_RC_SCHEME`). For a scheme that signs a digest, however, it calls `CryptoCommon_ValidateDigestSignature()`, which verifies with the scheme and hash algorithm of the *signature*, as `TPM2_VerifySignature` does. It therefore accepts, e.g., an RSAPSS signature for an RSASSA key, or a signature with another hash algorithm over the digest of the sequence's hash. The patch returns `TPM_RC_SCHEME + RC_VerifySequenceComplete_signature` when the *signature*'s sigAlg or hash algorithm is not the sequence's, before the hash is ended. This matches tpm-rs.

**Spec:** [TPM 2.0 (version 185), Part 3, "TPM2_PolicyAuthorize", "General Description"](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L10593-L10598)

> If this signature is verified using `TPM2_VerifySignature()`, the key is not
> used according to its public parameters. Instead, the signature scheme is
> modified as discussed in @sec:policy-authorize-edge-cases.
>
> In all other cases, the signature scheme is as determined by the public
> parameters of the key.

---

### cmac-self-test

**Categories:** `self-test`, `spec`.

**Severity:** —

**Description:**

`TPM2_MAC` and `TPM2_MAC_Start` with a SYMCIPHER signing key compute a CMAC
(`TPM_ALG_CMAC`) with the block cipher of the key. `CryptCmacStart()` and the
CMAC data/end functions use the key schedule of the block cipher directly
(`ENCRYPT()`), which bypasses the `TEST()` of `CryptSymmetricEncrypt()`, so on
a TPM where AES has not been tested yet (after `_TPM_Init`, before
`TPM2_SelfTest`) the command returns a MAC computed with untested AES, and AES
stays in the `toDoList` of `TPM2_IncrementalSelfTest` (and
`TPM2_GetTestResult` keeps reporting `TPM_RC_NEEDS_TEST`). The HMAC path tests
its hash in `CryptHashStart()` (`TPM_DO_SELF_TEST(hashAlg)`). The patch runs
`TPM_DO_SELF_TEST()` on the block cipher in `CryptCmacStart()`, i.e. when
`TPM2_MAC`/`TPM2_MAC_Start` start the CMAC (Camellia has no test vectors in the
reference and is never in `g_toTest`, so it is unaffected).

**Spec:** [TPM 2.0 (version 185), Part 1, "Self-Test Modes"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L2926-L2929)

> If a command requires use of an untested algorithm or functional module,
> the TPM performs the test and then completes the command actions.

---

### select-sym-def-object-camellia

**Categories:** `security`, `dos`, `functional`, `spec`.

**Severity:** medium

**Description:**

`CryptoCommon_SelectSymDefObject()` (`CryptUtil.c`) copies the symmetric definition of a parent (RSA, ECC, SYMCIPHER or ML-KEM) for the protection of its children (`ComputeProtectionKeyParms()`, the IV size of a private area, credential protection). It switches on the algorithm ID, but its SM4 and Camellia case labels are `ALG_SM4` and `ALG_CAMELLIA`, the profile switches (value 1 when enabled, i.e. `TPM_ALG_RSA`), instead of `TPM_ALG_SM4` and `TPM_ALG_CAMELLIA`. A parent with a Camellia symmetric definition (which `TPM2_CreatePrimary` accepts) therefore reaches the `default` case, `FAIL_BOOL(FATAL_ERROR_INTERNAL)`: the first `TPM2_Create`, `TPM2_Load`, `TPM2_Import`, `TPM2_Duplicate`, `TPM2_MakeCredential` or `TPM2_ActivateCredential` using it puts the TPM into failure mode, so Camellia storage keys are unusable.

The patch uses the algorithm IDs `TPM_ALG_SM4` and `TPM_ALG_CAMELLIA` as the case labels.

**Security:**

Any caller who may create a storage key (a primary object under an enabled hierarchy, or a child of any storage parent) can put the TPM into failure mode with a Camellia symmetric definition, so every later command fails until the next `_TPM_Init` (denial of service). No data is disclosed and no authorization is bypassed. Severity is medium, as for the other caller-triggered failure-mode bugs.

**Spec:** [TPM 2.0 (version 185), Part 1, "Symmetric Encryption"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L8651-L8652)

> The block cipher used for encrypting the object's sensitive area is the
> symmetric cipher of the Storage Parent.

---

### zgen-2phase-mqv-sm2

**Categories:** `security`, `dos`, `crypto`, `spec`.

**Severity:** low

**Description:**

`C_2_2_MQV()` declares the curve order `bnN` and the coordinate `bnXeB` with
`CRYPT_ECC_NUM()` but never sets them. `avf1()` therefore uses
`f = (SizeInBits(0) + 1) / 2 = 0`, and the following
`ModMult(bnTa, bnDsA, bnTa, bnN)` divides by zero (`FATAL_ERROR_DIVIDE_ZERO`):
every `TPM2_ZGen_2Phase` with `TPM_ALG_ECMQV` puts the TPM into failure mode
(denial of service by any user of an ECC decryption key). Even with `bnN` set,
`avf(Q_e,B)` would be the constant `2^f` instead of a function of the x
coordinate of `Q_e,B`. `avf1()` and `avfSm2()` reduce `x` modulo `2^f` with
`MaskBits()`, whose mask keeps `64 - (f mod 64)` bits of the last word instead of
`f mod 64` (80 instead of 112 bits for NIST P-224), so the associated value is
wrong whenever `f` is not a multiple of 64. `ComputeWForSM2()` returns
`MostSigBitNum(n) / 2 - 1`, but the most significant bit number is zero-based,
one less than `ceil(log2(n))`, so `avfSM2()` uses `f` one smaller than Part 1's
`ceil(ceil(log2(n)) / 2) - 1` and the SM2 Z value does not match a conformant
peer. Both key exchanges return `TPM_RC_NO_RESULT` when Z is the point at
infinity (which the caller can force for MQV with
`Q_s,B := -[avf(Q_e,B)^-1]Q_e,B`), where Part 3 requires an Empty Point.

The patch sets `bnN` to the curve order and `bnXeB` to the x coordinate of
`Q_e,B`, reduces `x` modulo `2^f` with a modular reduction (`MaskBits()` itself is
left alone: the random-number code uses it), computes `f` from the size of `n` in bits, and returns success with
the Empty Point (the caller initializes `outZ1` empty) for a Z at infinity.

**Security:** an authorized user of any ECC decryption key puts the TPM into
failure mode with one `TPM2_ZGen_2Phase(TPM_ALG_ECMQV)` (until the next
`_TPM_Init`).

**Spec:** [TPM 2.0 (version 185), Part 1, "Full MQV"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L17261-L17304)

> 1.  Set $\mathit{f} := \lceil \frac{\lceil {\mathit{log}}_2(n)\rceil}{2} \rceil$
>
> 2.  Set *x'* = 2*$^f$* + (*x* mod 2*$^f$* )
>
> ...
>
> 7.  set *t$_A$* $:=$ (*d$_{e,A}$* + *d$_{s,A}$* $·$ **avf**(*Q$_{e,A}$*)) (mod *n*)
>
> 8.  set *outZ1* $:=$ \[*h* $·$ *t$_A$*\] (*Q$_{e,B}$* + \[**avf**(*Q$_{e,B}$*)\](*Q$_{s,B}$*))

**Spec:** [TPM 2.0 (version 185), Part 1, "SM2 Key Exchange"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L17589-L17628)

> 1.  set $\mathit{f} := \lceil \frac{\lceil log_2(\mathit{n}) \rceil}{2} \rceil - 1$
>
> 2.  set *x'* $:=$ 2$^f$ + (*x* (mod 2$^f$))

**Spec:** [TPM 2.0 (version 185), Part 3, TPM2_ZGen_2Phase](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L4221-L4222)

> If a computation of either Z produces the point at infinity, then the
> corresponding Z value will be an Empty Point.

Part 1, "SM2 Key Exchange Protocol", step 6 reads "if Z is the point at infinity, return
failure". Part 3 defines the response of `TPM2_ZGen_2Phase` for every scheme it supports
(`TPM_ALG_ECDH`, `TPM_ALG_ECMQV` and `TPM_ALG_SM2`), while Part 1 describes the protocol
without a response code, so the Empty Point of Part 3 applies to SM2 as well.

**Spec:** [TPM 2.0 (version 185), Part 1, "SM2 Key Exchange Protocol"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L17630-L17672)

> 6.  if *Z* is the point at infinity, return failure

---

### ecc-decrypt-c1-point

**Categories:** `input-validation`, `spec`.

**Severity:** —

**Description:**

`TPM2_ECC_Decrypt` passes `C1` to `CryptEccDecrypt()`, which ignores the
result of `TpmEcc_PointMult(C1, C1, D, ...)`: for a `C1` that is not on the
curve the multiplication fails with `TPM_RC_ECC_POINT`, `C1` is left unchanged
and used as `P2 = (x2, y2)`, so the command fails with `TPM_RC_VALUE` at the
`C3` check (or, for a `C3` the caller computed over `C1`, returns a "plaintext"
unmasked with a value unrelated to the key). The decryption of
GB/T 32918.4-2016, which Part 1 implements, starts by verifying that `C1` is on
the curve. The patch checks `C1` after the scheme selection and returns
`TPM_RC_ECC_POINT + RC_ECC_Decrypt_C1`, as `TPM2_ECDH_ZGen` does for its input
point.

**Spec:** [TPM 2.0 (version 185), Part 1, "SM2 Encryption and Decryption"](../../../_agents/skills/tpm2-spec/resources/spec/part1.tcg.txt#L17674-L17680)

> These clauses describe the encryption and decryption process of GB/T
> 32918.4-2016 as implemented in the TPM.

---

### zgen-2phase-out-z2

**Categories:** `functional`, `spec`.

**Severity:** —

**Description:**

The response dispatch table of `TPM2_ZGen_2Phase` in `CommandDispatch.inl` lists
`MAKE_OUTPUT_DISPATCH_ENTRY(MARSHAL_ID_TPM2B_ECC_POINT, outZ1)` for both response
parameters, so the second parameter repeats `outZ1`: with `TPM_ALG_ECDH` the
caller gets `Zs` twice and never `Ze`, and with `TPM_ALG_ECMQV`/`TPM_ALG_SM2` it
gets `Z` instead of the Empty Point. The patch marshals `outZ2` as the second
parameter.

**Spec:** [TPM 2.0 (version 185), Part 3, TPM2_ZGen_2Phase](../../../_agents/skills/tpm2-spec/resources/spec/part3.tcg.txt#L4195-L4214)

> For `TPM_ALG_ECDH` *outZ1* will be Zs and *outZ2* will be Ze as defined in
> clause 6.1.1.2 of SP 800-56A [@{sp800-56a}].
>
> ...
>
> For `TPM_ALG_ECMQV` or `TPM_ALG_SM2` *outZ1* will be *Z* and *outZ2*
> will be an Empty Point.

## Locality problems (not patched)

The differential tests run every command at locality 0: the harness entry point `difftest_run_command()` (`harness-difftest-entry-points.patch`) has no locality parameter and always calls `_rpc__Send_Command(0, ...)`, `testing::tpm::Tpm` mirrors only locality-0 commands to the reference, and the fuzzer has no locality step. Problems that need a command at another locality can therefore not be reached by the differential tests, and this directory ships no patch for them. They are listed here for the record; `tpm-rs` behaves as described in the specification, which its own (unmirrored, `Tpm::new_unmirrored`) E2E tests check.

### pcr-extended-locality

Not patched (previously `bug-fix-pcr-extended-locality.patch`, `PCR.c` `PCRIsResetAllowed`/`PCRIsExtendAllowed`); `tpm-rs` test: `e2e::platform_signals::extended_locality_cannot_extend_or_reset_pcrs`.

**Categories:** `security`, `ub`, `spec`.

**Severity:** high

**Description:**

`PCRIsResetAllowed()` and `PCRIsExtendAllowed()` (`PCR.c`) turn the command locality into a bit with `localityBits << commandLocality` and test it against the PCR's 5-bit reset/extend locality bitmap (localities 0-4). For an extended locality (32-255) the shift amount is at least the width of the promoted `int`, which is C undefined behavior. With the usual x86 code generation the shift count is taken modulo 32 and the result is truncated to the `UINT8` `localityBits`, so localities 32-36, 64-68, 96-100, ... alias localities 0-4 (e.g. locality 67 acts as locality 3 and locality 68 as locality 4). TPM2_PCR_Extend, TPM2_PCR_Event and TPM2_PCR_Reset sent from such an extended locality are then accepted on PCRs whose attributes restrict them to localities 2-4: the D-RTM PCRs 17-22 can be extended, and PCRs 20-22 (reset localities 2 and 4) can be reset. The `DRTM_PCR` check, which forbids PCR_Reset at locality 4, compares `commandLocality == 4` and so does not stop an extended locality that aliases locality 4. Other compilers or optimizations may produce different results.

An extended locality is a single integer, not a member of the 0-4 bitmap, so both functions should return FALSE for any locality above 4 and the commands should fail with TPM_RC_LOCALITY, as they do in `tpm-rs`.

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
