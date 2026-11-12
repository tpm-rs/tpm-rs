//! The saved contexts of the TCG reference TPM: `TPM2_ContextSave` returns, and
//! `TPM2_ContextLoad` takes, byte for byte the `contextBlob` of the reference implementation
//! (`ContextSave.c`, `ContextLoad.c`, `Context_spt.c`; version 185, the `185-feature` branch), so
//! that the differential tests compare saved contexts exactly. The C references of the other
//! differential targets (the public TCG reference and `ibmswtpm2`) use the same format with their
//! own structure definitions and profiles, which this module follows (see below).
//!
//! The context data is implementation-defined (TPM 2.0 Part 2, `TPMS_CONTEXT_DATA`: "This is an
//! informative table"); the reference's is:
//!
//! - `contextBlob = integrity || encContext`, where `integrity` is a `TPM2B_DIGEST` (an HMAC with
//!   `CONTEXT_INTEGRITY_HASH_ALG`, [`crate::handler::context_integrity_hash_alg`]) and
//!   `encContext` is *not* a sized buffer ("the size field of the TPM2B_CONTEXT_DATA is used to
//!   determine the amount of data in the encrypted data").
//! - `encContext = CFB(AES-256, sequence || entity)`, keyed with `KDFa(CONTEXT_INTEGRITY_HASH_ALG,
//!   hProof, "CONTEXT", sequence, savedHandle, 384)` (key || IV). The `sequence` fingerprint and the
//!   KDF's `sequence` and `savedHandle` are the octets of the reference's in-memory
//!   `UINT64`/`UINT32` (`MemoryCopy`), i.e. little-endian.
//! - `integrity = HMAC(hProof, totalResetCount || {clearCount} || sequence || savedHandle ||
//!   encContext)` (TPM 2.0 Part 1, "Context Integrity Protection"), with the big-endian
//!   integers of `CryptoCommon_DigestUpdateInt` and `clearCount` only for `savedHandle`
//!   `0x80000002`.
//! - `entity` is the reference's in-memory structure of the saved entity (x86-64 layout): an
//!   `OBJECT` ([`OBJECT_SIZE`] octets), a `SEQUENCE_OBJECT` ([`SEQUENCE_OBJECT_SIZE`]) whose
//!   running hash, HMAC, CMAC and SHAKE256 states are in their exported form
//!   (`SequenceDataExport()`: the OpenSSL contexts of the reference's `Ossl` crypto library), or a
//!   `SESSION` ([`SESSION_SIZE`]).
//!
//! The sizes and offsets of the structures follow from the profile, as in the C code: the
//! capacities of the `TPM2B` buffers (`sizeof(TPMU_HA)`, `MAX_RSA_KEY_BYTES`, `MAX_ECC_KEY_BYTES`,
//! the ML-KEM/ML-DSA key sizes), `HASH_COUNT`, `SEC_CHANNEL_SUPPORT` (`SESSION.scKeyNameHash`, the
//! `sec-channel` feature) and the sequence object: version 185's `SEQUENCE_OBJECT` (with
//! `signScheme`, `associatedName` and `ticketHierarchy`). With the `context-format-pre-v185`
//! feature, the structures are those of the earlier versions (the public TCG reference,
//! `ibmswtpm2`): the `HASH_OBJECT` sequence object, the 6-octet `TPMT_RSA_SCHEME` (whose details
//! are a `TPMU_ASYM_SCHEME` with the 4-octet ECDAA member) and the packed RSA private key without
//! `RSA_CRT_flag`.
//!
//! This module converts between those structures and the state of `tpm-rs` with free functions
//! ([`object_image`], [`object_from_image`], [`sequence_image`], [`sequence_from_image`],
//! [`session_image`], [`session_from_image`]) that need no `CommandHandler`. An image is the
//! entity as the reference keeps it in memory (its object slot or session), which
//! `TPM2_ContextSave()` copies unchanged, except that the exported hash states of a sequence have
//! a zero `HASH_STATE.def` (see below). Every octet the reference does not write is zero: object
//! slots and sessions are zeroed when they are allocated (`ObjectFlush()`, `SessionCreate()`),
//! the command buffers before every command (`MemoryGetInBuffer()`), the differential build
//! compiles the references with `-ftrivial-auto-var-init=zero` (their local structures are copied
//! into objects, e.g. the `TPMT_SENSITIVE` of `TPM2_Load`), and the pointers to the reference's
//! code and data in an exported hash state (`HASH_STATE.def`, `SMAC_STATE.smacMethods`) are
//! zeroed by the `harness-context-no-pointers.patch` of each reference.

use crate::Platform;
use crate::handler::{CommandHandler, SecChannelPolicy, SessionState, TransientObject};
use crate::hash_state::StreamingHashState;
use crate::owned::{OwnedAuth, OwnedName, OwnedNonce, OwnedPublic, OwnedSensitiveData};
use crate::req_resp::RequestThenResponse;
use crate::self_test::kdfa_bits;
use crate::{ActiveSequence, SequenceType, SignatureSequence};
use tpm2::crypto::{Crypto, Direction};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, AlgSym, Handle, Marshal, TpmHt, TpmSe, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode,
    TpmsAuthResponse, TpmtSymDefObject, Unmarshal,
};

// The `HASH_OBJECT` of the earlier references has no place for the state of a signing or
// verification sequence (`TPM2_SignSequenceStart`, `TPM2_VerifySequenceStart`, version 185).
#[cfg(all(
    feature = "context-format-pre-v185",
    any(
        feature = "cc-sign-sequence-start",
        feature = "cc-verify-sequence-start"
    )
))]
compile_error!(
    "`context-format-pre-v185` (the sequence objects of TCG reference versions before 185) excludes \
     the signature sequence commands `cc-sign-sequence-start` and `cc-verify-sequence-start`"
);

// ---------------------------------------------------------------------------------------------
// The layout of the reference's structures (x86-64; the sizes follow from the profile).
// ---------------------------------------------------------------------------------------------

/// `x` rounded up to a multiple of `a`.
const fn align(x: usize, a: usize) -> usize {
    x.div_ceil(a) * a
}

/// The larger of `a` and `b`.
const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// The capacity of a `TPM2B_DIGEST` buffer (`sizeof(TPMU_HA)`).
const DIGEST_CAP: usize = crate::owned::OwnedDigest::CAP;
/// The capacity of a `TPM2B_NAME` buffer: the largest Name, a `TPMT_HA` (the TCG references and
/// `ibmswtpm2` with their `bug-fix-tpmu-name-size.patch`, which shrinks `TPMU_NAME` to it).
const NAME_CAP: usize = crate::owned::OwnedName::CAP;
/// `sizeof(TPM2B_NAME)`: the size and the buffer.
const NAME_STRUCT: usize = 2 + NAME_CAP;
/// `sizeof(HASH_STATE)`: the type, the hash, the descriptor pointer and the largest library
/// context (`SHA512_CTX`, 216 octets in OpenSSL, also the context of SHA-384, which every
/// profile implements).
const HASH_STATE_SIZE: usize = 232;
/// `sizeof(HMAC_STATE)`: a `HASH_STATE` and the key block (`TPM2B_HASH_BLOCK`, 128 octets for
/// SHA-384/512), aligned to 8.
const HMAC_STATE_SIZE: usize = align(HASH_STATE_SIZE + 2 + HMAC_KEY_CAP, 8);
/// The capacity of the HMAC key block (`TPM2B_HASH_BLOCK`).
const HMAC_KEY_CAP: usize = 128;
/// `sizeof(CRYPTO_MLDSA_EXPORTED_SIGN_SEQUENCE_STATE)` (`OPENSSL_EXPORTED_SHAKE_STATE`) with
/// ML-DSA (the `mldsa` feature), else 0.
const MLDSA_EXPORT_SIZE: usize = if cfg!(feature = "mldsa") { 372 } else { 0 };

/// `sizeof(OBJECT)`.
pub(crate) const OBJECT_SIZE: usize = obj::SIZE;
/// `sizeof(SEQUENCE_OBJECT)` (`sizeof(HASH_OBJECT)` with `context-format-pre-v185`).
pub(crate) const SEQUENCE_OBJECT_SIZE: usize = seq::SIZE;
/// `sizeof(SESSION)`.
pub(crate) const SESSION_SIZE: usize = sess::SIZE;
/// The size of the `sequence` fingerprint (`sizeof(UINT64)`).
const FINGERPRINT_SIZE: usize = 8;
/// The size of the context integrity value (`sizeof(UINT16)` + the integrity digest).
const INTEGRITY_SIZE: usize = 2 + crate::handler::CONTEXT_INTEGRITY_DIGEST_SIZE;
/// `SIZE_OF_CONTEXT_OVERHEAD` (`PropertyCap.c`): `sequence`, `savedHandle`, `hierarchy`, the size
/// of `contextBlob`, the integrity value and the fingerprint.
const CONTEXT_OVERHEAD: usize = 8 + 4 + 4 + 2 + INTEGRITY_SIZE + FINGERPRINT_SIZE;
/// `TPM_PT_MAX_OBJECT_CONTEXT`: `SIZE_OF_CONTEXT_OVERHEAD + sizeof(OBJECT)`.
pub(crate) const MAX_OBJECT_CONTEXT_SIZE: usize = CONTEXT_OVERHEAD + OBJECT_SIZE;
/// `TPM_PT_MAX_SESSION_CONTEXT`: `SIZE_OF_CONTEXT_OVERHEAD + sizeof(SESSION)`.
pub(crate) const MAX_SESSION_CONTEXT_SIZE: usize = CONTEXT_OVERHEAD + SESSION_SIZE;
/// `CONTEXT_ENCRYPT_KEY_BITS` (`TPM_PT_CONTEXT_SYM_SIZE`).
pub(crate) const CONTEXT_ENCRYPT_KEY_BITS: u32 = 256;

/// `CONTEXT_ENCRYPT_ALG` in CFB mode.
const CONTEXT_ENCRYPTION_ALG: TpmtSymDefObject = TpmtSymDefObject {
    alg: AlgSym::Aes256,
    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
};

// Every context fits the profile: the `contextBlob` of an object fits `TPM2B_CONTEXT_DATA`, its
// encrypted part `MAX_CONTEXT_SIZE`, and the other entities are not larger than an `OBJECT`.
const _: () = {
    assert!(
        INTEGRITY_SIZE + FINGERPRINT_SIZE + OBJECT_SIZE
            <= super::context_load::CONTEXT_DATA_CAPACITY
    );
    assert!(FINGERPRINT_SIZE + OBJECT_SIZE <= super::context_load::MAX_CONTEXT_SIZE);
    assert!(SEQUENCE_OBJECT_SIZE <= OBJECT_SIZE && SESSION_SIZE <= OBJECT_SIZE);
};

/// `OBJECT_ATTRIBUTES` (a bit field `UINT32`).
mod attr {
    pub const PUBLIC_ONLY: u32 = 1 << 0;
    pub const EPS_HIERARCHY: u32 = 1 << 1;
    pub const PPS_HIERARCHY: u32 = 1 << 2;
    pub const SPS_HIERARCHY: u32 = 1 << 3;
    pub const PRIMARY: u32 = 1 << 5;
    pub const TEMPORARY: u32 = 1 << 6;
    pub const ST_CLEAR: u32 = 1 << 7;
    pub const HMAC_SEQ: u32 = 1 << 8;
    pub const HASH_SEQ: u32 = 1 << 9;
    pub const EVENT_SEQ: u32 = 1 << 10;
    pub const TICKET_SAFE: u32 = 1 << 11;
    pub const FIRST_BLOCK: u32 = 1 << 12;
    pub const IS_PARENT: u32 = 1 << 13;
    pub const OCCUPIED: u32 = 1 << 15;
    pub const DERIVATION: u32 = 1 << 16;
    pub const EXTERNAL: u32 = 1 << 17;
    pub const SIGN_SEQ: u32 = 1 << 18;
    pub const VERIFY_SEQ: u32 = 1 << 19;
    /// The kinds of sequence objects (`ObjectIsSequence()`; the references before version 185
    /// have neither signing nor verification sequences).
    pub const ANY_SEQ: u32 = if cfg!(feature = "context-format-pre-v185") {
        HMAC_SEQ | HASH_SEQ | EVENT_SEQ
    } else {
        HMAC_SEQ | HASH_SEQ | EVENT_SEQ | SIGN_SEQ | VERIFY_SEQ
    };
}

/// `OBJECT` member offsets.
mod obj {
    use super::*;
    pub const ATTRIBUTES: usize = 0;
    pub const PUBLIC: usize = 4;
    pub const SENSITIVE: usize = align(PUBLIC + public::SIZE, 2);
    pub const QUALIFIED_NAME: usize = SENSITIVE + sensitive::SIZE;
    pub const EVICT_HANDLE: usize = align(QUALIFIED_NAME + NAME_STRUCT, 4);
    pub const NAME: usize = EVICT_HANDLE + 4;
    pub const HIERARCHY: usize = align(NAME + NAME_STRUCT, 4);
    pub const SIZE: usize = HIERARCHY + 4;
}

/// `TPMT_PUBLIC` member offsets.
mod public {
    use super::*;
    pub const TYPE: usize = 0;
    pub const NAME_ALG: usize = 2;
    pub const ATTRIBUTES: usize = 4;
    pub const AUTH_POLICY: usize = 8;
    /// `TPMU_PUBLIC_PARMS` is aligned like `TPMS_RSA_PARMS` (its `UINT32` exponent).
    pub const PARAMETERS: usize = align(AUTH_POLICY + 2 + DIGEST_CAP, 4);
    /// `sizeof(TPMU_PUBLIC_PARMS)`: the largest member, `TPMS_ECC_PARMS` (18 octets), aligned
    /// to 4.
    pub const PARAMETERS_SIZE: usize = 20;
    pub const UNIQUE: usize = PARAMETERS + PARAMETERS_SIZE;
    pub const ECC_PARAMETER_CAP: usize = crate::owned::OwnedEccParameter::CAP;
    /// `TPMS_ECC_POINT.y` relative to `x`.
    pub const ECC_Y: usize = 2 + ECC_PARAMETER_CAP;
    pub const RSA_CAP: usize = crate::owned::OwnedPublicKeyRsa::CAP;
    pub const MLKEM_CAP: usize = crate::owned::OwnedPublicKeyMlkem::CAP;
    pub const MLDSA_CAP: usize = crate::owned::OwnedPublicKeyMldsa::CAP;
    /// `TPMS_RSA_PARMS.keyBits` and `.exponent` (relative to `parameters`) after the
    /// `TPMT_RSA_SCHEME` of 4 octets (version 185) or 6 octets (`context-format-pre-v185`).
    pub const RSA_KEY_BITS: usize = if cfg!(feature = "context-format-pre-v185") {
        12
    } else {
        10
    };
    pub const RSA_EXPONENT: usize = if cfg!(feature = "context-format-pre-v185") {
        16
    } else {
        12
    };
    /// `sizeof(TPMU_PUBLIC_ID)`: digests, RSA modulus, ECC point, ML-KEM/ML-DSA keys and
    /// `TPMS_DERIVE` (two 32-octet labels).
    pub const UNIQUE_SIZE: usize = max(
        max(
            max(2 + DIGEST_CAP, 2 + RSA_CAP),
            max(2 * ECC_Y, 2 + MLKEM_CAP),
        ),
        max(2 + MLDSA_CAP, 2 * (2 + 32)),
    );
    /// `sizeof(TPMT_PUBLIC)`.
    pub const SIZE: usize = align(UNIQUE + UNIQUE_SIZE, 4);
}

/// `TPMT_SENSITIVE` member offsets.
mod sensitive {
    use super::*;
    pub const TYPE: usize = 0;
    pub const AUTH: usize = 2;
    pub const SEED: usize = AUTH + 2 + DIGEST_CAP;
    pub const VALUE: usize = SEED + 2 + DIGEST_CAP;
    /// The capacity of the largest member of `TPMU_SENSITIVE_COMPOSITE`.
    pub const VALUE_CAP: usize = max(
        max(
            crate::owned::OwnedPrivateKeyRsa::CAP,
            crate::owned::OwnedEccParameter::CAP,
        ),
        max(
            max(
                crate::owned::OwnedSensitiveData::CAP,
                crate::owned::OwnedSymKey::CAP,
            ),
            max(
                crate::owned::OwnedPrivateKeyMlkem::CAP,
                crate::owned::OwnedPrivateKeyMldsa::CAP,
            ),
        ),
    );
    /// `sizeof(TPMT_SENSITIVE)`.
    pub const SIZE: usize = VALUE + 2 + VALUE_CAP;
    /// `RSA_prime_flag` in the size of a packed RSA private key.
    pub const RSA_PRIME_FLAG: u16 = 0x8000;
    /// The flags in the size of a packed RSA private key: `RSA_prime_flag | RSA_CRT_flag`
    /// (version 185), `RSA_prime_flag` (`context-format-pre-v185`).
    pub const RSA_CRT_FLAGS: u16 = if cfg!(feature = "context-format-pre-v185") {
        RSA_PRIME_FLAG
    } else {
        RSA_PRIME_FLAG | 0x4000
    };
    /// The flags that are never part of the size of a packed RSA private key.
    pub const RSA_SIZE_FLAGS: u16 = 0x8000 | 0x4000;
}

/// `SEQUENCE_OBJECT` member offsets.
mod seq {
    use super::*;
    pub const ATTRIBUTES: usize = 0;
    pub const TYPE: usize = 4;
    pub const NAME_ALG: usize = 6;
    pub const OBJECT_ATTRIBUTES: usize = 8;
    pub const AUTH: usize = 12;
    /// `signScheme` (version 185's `SEQUENCE_OBJECT`).
    pub const SIGN_SCHEME: usize = AUTH + 2 + DIGEST_CAP;
    pub const ASSOCIATED_NAME: usize = SIGN_SCHEME + 6;
    pub const TICKET_HIERARCHY: usize = align(ASSOCIATED_NAME + 2 + NAME_CAP, 4);
    /// `state` (aligned like a `HASH_STATE`).
    pub const STATE: usize = if cfg!(feature = "context-format-pre-v185") {
        align(AUTH + 2 + DIGEST_CAP, 8)
    } else {
        align(TICKET_HIERARCHY + 4, 8)
    };
    /// `state.verify.message`: an `HMAC_STATE` or the exported ML-DSA state.
    const MESSAGE_SIZE: usize = align(max(HMAC_STATE_SIZE, MLDSA_EXPORT_SIZE), 8);
    /// `state.verify.ticket`.
    pub const TICKET: usize = STATE + MESSAGE_SIZE;
    /// `sizeof(state)`: `hashState[HASH_COUNT]`, `hmacState` and (version 185) `verify` and the
    /// ML-DSA states.
    const STATE_SIZE: usize = {
        let hashes = ActiveSequence::EVENT_HASH_COUNT * HASH_STATE_SIZE;
        let size = max(hashes, HMAC_STATE_SIZE);
        if cfg!(feature = "context-format-pre-v185") {
            size
        } else {
            align(max(size, MESSAGE_SIZE + HMAC_STATE_SIZE), 8)
        }
    };
    pub const SIZE: usize = STATE + STATE_SIZE;
    /// `HMAC_STATE.hmacKey`.
    pub const HMAC_KEY: usize = HASH_STATE_SIZE;
    /// `HASH_STATE.type` and `HASH_STATE.hashAlg` (`{ type; hashAlg; def; state }`).
    pub const HASH_TYPE: usize = 0;
    pub const HASH_ALG: usize = 2;
    /// `HASH_STATE.def`, the pointer to the hash descriptor (zero in an exported state).
    #[cfg_attr(not(test), allow(dead_code))]
    pub const HASH_DEF: usize = 8;
    /// `HASH_STATE.state`.
    pub const HASH_CONTEXT: usize = 16;
    /// `HASH_STATE.state.smac.state.cmac`.
    #[cfg_attr(not(feature = "cmac"), allow(dead_code))]
    pub const CMAC: usize = 32;
    /// `HASH_STATE_HASH`, `HASH_STATE_HMAC`, `HASH_STATE_SMAC`.
    pub const TYPE_HASH: u8 = 1;
    pub const TYPE_HMAC: u8 = 2;
    #[cfg_attr(not(feature = "cmac"), allow(dead_code))]
    pub const TYPE_SMAC: u8 = 3;
    /// `OPENSSL_EXPORTED_SHAKE_STATE` members (relative to `state`).
    pub const SHAKE_SIZE: usize = 200;
    pub const SHAKE_BUF: usize = 204;
    pub const SHAKE_BUF_CAP: usize = 168;
}

/// `SESSION` member offsets.
mod sess {
    use super::*;
    pub const ATTRIBUTES: usize = 0;
    pub const PCR_COUNTER: usize = 4;
    pub const START_TIME: usize = 8;
    pub const TIMEOUT: usize = 16;
    pub const EPOCH: usize = 24;
    pub const COMMAND_CODE: usize = 28;
    pub const AUTH_HASH_ALG: usize = 32;
    /// `commandLocality`: a `TPMA_LOCALITY` (one octet).
    pub const COMMAND_LOCALITY: usize = 34;
    pub const SYMMETRIC: usize = 36;
    pub const SESSION_KEY: usize = SYMMETRIC + 6;
    pub const NONCE_TPM: usize = SESSION_KEY + 2 + DIGEST_CAP;
    pub const U1: usize = NONCE_TPM + 2 + DIGEST_CAP;
    /// `u1` is a `TPM2B_NAME` or a `TPM2B_DIGEST`.
    pub const U2: usize = U1 + NAME_STRUCT;
    /// `scKeyNameHash` (`SEC_CHANNEL_SUPPORT`, the `sec-channel` feature).
    pub const SC_KEY_NAME_HASH: usize = U2 + 2 + DIGEST_CAP;
    const END: usize = if cfg!(feature = "sec-channel") {
        SC_KEY_NAME_HASH + 2 + DIGEST_CAP
    } else {
        SC_KEY_NAME_HASH
    };
    /// `sizeof(SESSION)` (aligned like its `UINT64` members).
    pub const SIZE: usize = align(END, 8);
}

/// `SESSION_ATTRIBUTES` (a bit field `UINT32`).
mod sattr {
    pub const IS_POLICY: u32 = 1 << 0;
    pub const IS_AUDIT: u32 = 1 << 1;
    pub const IS_BOUND: u32 = 1 << 2;
    pub const IS_CP_HASH_DEFINED: u32 = 1 << 3;
    pub const IS_NAME_HASH_DEFINED: u32 = 1 << 4;
    pub const IS_PARAMETERS_HASH_DEFINED: u32 = 1 << 5;
    pub const IS_TEMPLATE_HASH_DEFINED: u32 = 1 << 6;
    pub const IS_AUTH_VALUE_NEEDED: u32 = 1 << 7;
    pub const IS_PASSWORD_NEEDED: u32 = 1 << 8;
    pub const IS_PP_REQUIRED: u32 = 1 << 9;
    pub const IS_TRIAL_POLICY: u32 = 1 << 10;
    pub const IS_DA_BOUND: u32 = 1 << 11;
    pub const IS_LOCKOUT_BOUND: u32 = 1 << 12;
    pub const INCLUDE_AUTH: u32 = 1 << 13;
    pub const CHECK_NV_WRITTEN: u32 = 1 << 14;
    pub const NV_WRITTEN_STATE: u32 = 1 << 15;
    pub const CHECK_SECURE_CHANNEL: u32 = 1 << 16;
    pub const CHECK_REQ_KEY: u32 = 1 << 17;
    pub const CHECK_TPM_KEY: u32 = 1 << 18;
}

/// Algorithm identifiers the conversions need.
mod alg {
    pub const RSA: u16 = 0x0001;
    pub const KEYEDHASH: u16 = 0x0008;
    pub const XOR: u16 = 0x000A;
    pub const NULL: u16 = 0x0010;
    pub const RSAES: u16 = 0x0015;
    pub const ECDAA: u16 = 0x001A;
    pub const ECC: u16 = 0x0023;
    pub const SYMCIPHER: u16 = 0x0025;
    pub const EDDSA: u16 = 0x0060;
    pub const HASH_EDDSA: u16 = 0x0061;
    pub const MLKEM: u16 = 0x00A0;
    pub const MLDSA: u16 = 0x00A1;
    pub const HASH_MLDSA: u16 = 0x00A2;
}

/// `TPMA_OBJECT.noDA`, the `objectAttributes` of every sequence object (`AllocateSequenceSlot()`).
const TPMA_OBJECT_NO_DA: u32 = 1 << 10;

// ---------------------------------------------------------------------------------------------
// Octet helpers: the structures hold native (little-endian) integers, the marshaled TPM
// structures big-endian ones.
// ---------------------------------------------------------------------------------------------

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn get_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn get_u32(b: &[u8], at: usize) -> u32 {
    let mut v = [0u8; 4];
    v.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(v)
}

fn get_u64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

/// Writes a `TPM2B` (size and buffer) of capacity `cap` at `at`, or `None` if `data` exceeds it.
fn put_tpm2b(b: &mut [u8], at: usize, cap: usize, data: &[u8]) -> Option<()> {
    if data.len() > cap {
        return None;
    }
    put_u16(b, at, data.len() as u16);
    b[at + 2..at + 2 + data.len()].copy_from_slice(data);
    Some(())
}

/// The buffer of the `TPM2B` of capacity `cap` at `at`, or `None` if its size exceeds it.
fn get_tpm2b(b: &[u8], at: usize, cap: usize) -> Option<&[u8]> {
    let size = usize::from(get_u16(b, at));
    (size <= cap).then(|| &b[at + 2..at + 2 + size])
}

/// A reader of marshaled (big-endian) TPM structures.
struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn tpm2b(&mut self) -> Option<&'a [u8]> {
        let size = usize::from(self.u16()?);
        self.bytes(size)
    }
}

/// A writer of marshaled (big-endian) TPM structures.
struct WireOut<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> WireOut<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn bytes(&mut self, data: &[u8]) -> Option<()> {
        let end = self.len.checked_add(data.len())?;
        self.buf.get_mut(self.len..end)?.copy_from_slice(data);
        self.len = end;
        Some(())
    }

    fn u8(&mut self, v: u8) -> Option<()> {
        self.bytes(&[v])
    }

    fn u16(&mut self, v: u16) -> Option<()> {
        self.bytes(&v.to_be_bytes())
    }

    fn u32(&mut self, v: u32) -> Option<()> {
        self.bytes(&v.to_be_bytes())
    }

    fn tpm2b(&mut self, data: &[u8]) -> Option<()> {
        self.u16(u16::try_from(data.len()).ok()?)?;
        self.bytes(data)
    }
}

/// The number of `UINT16` members a scheme's details marshal (the selected member of
/// `TPMU_ASYM_SCHEME`, `TPMU_SCHEME_KEYEDHASH`, `TPMU_KDF_SCHEME` or `TPMU_SIG_SCHEME`): none for
/// `TPM_ALG_NULL` and the schemes with empty details, a `hashAlg` and a `count` for ECDAA, a
/// `hashAlg` and a `kdf` for XOR, a `hashAlg` otherwise.
fn scheme_detail_words(scheme: u16) -> usize {
    match scheme {
        alg::NULL | alg::RSAES | alg::MLDSA | alg::EDDSA | alg::HASH_EDDSA => 0,
        alg::ECDAA | alg::XOR => 2,
        _ => 1,
    }
}

/// Converts a marshaled scheme (`scheme` and its details) to the structure at `at` (the details
/// union follows the `scheme` member).
fn scheme_to_c(r: &mut Wire<'_>, img: &mut [u8], at: usize) -> Option<()> {
    let scheme = r.u16()?;
    put_u16(img, at, scheme);
    for i in 0..scheme_detail_words(scheme) {
        put_u16(img, at + 2 + 2 * i, r.u16()?);
    }
    Some(())
}

/// Converts the scheme structure at `at` to its marshaled form ([`scheme_to_c`]).
fn scheme_from_c(img: &[u8], at: usize, w: &mut WireOut<'_>) -> Option<()> {
    let scheme = get_u16(img, at);
    w.u16(scheme)?;
    for i in 0..scheme_detail_words(scheme) {
        w.u16(get_u16(img, at + 2 + 2 * i))?;
    }
    Some(())
}

/// Converts a marshaled `TPMT_SYM_DEF_OBJECT` (or `TPMT_SYM_DEF`) to the structure at `at`
/// (`algorithm`, `keyBits`, `mode`; XOR has only a hash in `keyBits`).
fn sym_def_to_c(r: &mut Wire<'_>, img: &mut [u8], at: usize) -> Option<()> {
    let algorithm = r.u16()?;
    put_u16(img, at, algorithm);
    match algorithm {
        alg::NULL => {}
        alg::XOR => put_u16(img, at + 2, r.u16()?),
        _ => {
            put_u16(img, at + 2, r.u16()?);
            put_u16(img, at + 4, r.u16()?);
        }
    }
    Some(())
}

/// Converts the symmetric definition at `at` to its marshaled form ([`sym_def_to_c`]).
fn sym_def_from_c(img: &[u8], at: usize, w: &mut WireOut<'_>) -> Option<()> {
    let algorithm = get_u16(img, at);
    w.u16(algorithm)?;
    match algorithm {
        alg::NULL => {}
        alg::XOR => w.u16(get_u16(img, at + 2))?,
        _ => {
            w.u16(get_u16(img, at + 2))?;
            w.u16(get_u16(img, at + 4))?;
        }
    }
    Some(())
}

/// Converts a marshaled `TPMT_PUBLIC` to the reference's `TPMT_PUBLIC` structure `img`
/// ([`public::SIZE`] octets, zero on entry).
fn public_to_c(wire: &[u8], img: &mut [u8]) -> Option<()> {
    let mut r = Wire(wire);
    let ty = r.u16()?;
    put_u16(img, public::TYPE, ty);
    put_u16(img, public::NAME_ALG, r.u16()?);
    put_u32(img, public::ATTRIBUTES, r.u32()?);
    put_tpm2b(img, public::AUTH_POLICY, DIGEST_CAP, r.tpm2b()?)?;
    let p = public::PARAMETERS;
    match ty {
        alg::KEYEDHASH => scheme_to_c(&mut r, img, p)?,
        alg::SYMCIPHER => sym_def_to_c(&mut r, img, p)?,
        alg::RSA => {
            sym_def_to_c(&mut r, img, p)?;
            scheme_to_c(&mut r, img, p + 6)?;
            put_u16(img, p + public::RSA_KEY_BITS, r.u16()?);
            put_u32(img, p + public::RSA_EXPONENT, r.u32()?);
        }
        alg::ECC => {
            sym_def_to_c(&mut r, img, p)?;
            scheme_to_c(&mut r, img, p + 6)?;
            put_u16(img, p + 12, r.u16()?);
            scheme_to_c(&mut r, img, p + 14)?;
        }
        alg::MLKEM => {
            sym_def_to_c(&mut r, img, p)?;
            put_u16(img, p + 6, r.u16()?);
        }
        alg::MLDSA => {
            put_u16(img, p, r.u16()?);
            img[p + 2] = r.u8()?;
        }
        alg::HASH_MLDSA => {
            put_u16(img, p, r.u16()?);
            put_u16(img, p + 2, r.u16()?);
        }
        _ => return None,
    }
    let u = public::UNIQUE;
    match ty {
        alg::KEYEDHASH | alg::SYMCIPHER => put_tpm2b(img, u, DIGEST_CAP, r.tpm2b()?)?,
        alg::RSA => put_tpm2b(img, u, public::RSA_CAP, r.tpm2b()?)?,
        alg::ECC => {
            put_tpm2b(img, u, public::ECC_PARAMETER_CAP, r.tpm2b()?)?;
            put_tpm2b(
                img,
                u + public::ECC_Y,
                public::ECC_PARAMETER_CAP,
                r.tpm2b()?,
            )?;
        }
        alg::MLKEM => put_tpm2b(img, u, public::MLKEM_CAP, r.tpm2b()?)?,
        _ => put_tpm2b(img, u, public::MLDSA_CAP, r.tpm2b()?)?,
    }
    r.0.is_empty().then_some(())
}

/// Converts the reference's `TPMT_PUBLIC` structure `img` to its marshaled form in `out` and
/// returns its length ([`public_to_c`]).
fn public_from_c(img: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut w = WireOut::new(out);
    let ty = get_u16(img, public::TYPE);
    w.u16(ty)?;
    w.u16(get_u16(img, public::NAME_ALG))?;
    w.u32(get_u32(img, public::ATTRIBUTES))?;
    w.tpm2b(get_tpm2b(img, public::AUTH_POLICY, DIGEST_CAP)?)?;
    let p = public::PARAMETERS;
    match ty {
        alg::KEYEDHASH => scheme_from_c(img, p, &mut w)?,
        alg::SYMCIPHER => sym_def_from_c(img, p, &mut w)?,
        alg::RSA => {
            sym_def_from_c(img, p, &mut w)?;
            scheme_from_c(img, p + 6, &mut w)?;
            w.u16(get_u16(img, p + public::RSA_KEY_BITS))?;
            w.u32(get_u32(img, p + public::RSA_EXPONENT))?;
        }
        alg::ECC => {
            sym_def_from_c(img, p, &mut w)?;
            scheme_from_c(img, p + 6, &mut w)?;
            w.u16(get_u16(img, p + 12))?;
            scheme_from_c(img, p + 14, &mut w)?;
        }
        alg::MLKEM => {
            sym_def_from_c(img, p, &mut w)?;
            w.u16(get_u16(img, p + 6))?;
        }
        alg::MLDSA => {
            w.u16(get_u16(img, p))?;
            w.u8(img[p + 2])?;
        }
        alg::HASH_MLDSA => {
            w.u16(get_u16(img, p))?;
            w.u16(get_u16(img, p + 2))?;
        }
        _ => return None,
    }
    let u = public::UNIQUE;
    match ty {
        alg::KEYEDHASH | alg::SYMCIPHER => w.tpm2b(get_tpm2b(img, u, DIGEST_CAP)?)?,
        alg::RSA => w.tpm2b(get_tpm2b(img, u, public::RSA_CAP)?)?,
        alg::ECC => {
            w.tpm2b(get_tpm2b(img, u, public::ECC_PARAMETER_CAP)?)?;
            w.tpm2b(get_tpm2b(
                img,
                u + public::ECC_Y,
                public::ECC_PARAMETER_CAP,
            )?)?;
        }
        alg::MLKEM => w.tpm2b(get_tpm2b(img, u, public::MLKEM_CAP)?)?,
        _ => w.tpm2b(get_tpm2b(img, u, public::MLDSA_CAP)?)?,
    }
    Some(w.len)
}

/// The algorithm identifier of a hash.
fn hash_id(alg: TpmiAlgHash) -> u16 {
    Alg::from(alg).id()
}

/// The hash with the identifier `id`.
fn hash_from_id(id: u16) -> Option<TpmiAlgHash> {
    TpmiAlgHash::try_from(id).ok()
}

/// The size of the OpenSSL context of `alg` in a `HASH_STATE` (`sizeof(SHA_CTX)` etc.).
const fn openssl_md_len(alg: TpmiAlgHash) -> u32 {
    alg.digest_size() as u32
}

/// Writes the running hash `st` as an exported `HASH_STATE` of type `ty` (`hashAlg` and the
/// OpenSSL context: `SHA_CTX`, `SHA256_CTX` or `SHA512_CTX`) to `img` (zero on entry; `def`
/// stays zero).
///
/// OpenSSL keeps the unprocessed octets of SHA-1 and SHA-256 at the start of a zeroed block
/// (`md32_common.h`: \"keep it zeroed\"); SHA-384/512 leave the rest of the last complete block in
/// the buffer (`sha512.c`), as [`StreamingHashState::update`] does with its `block_buf`. OpenSSL's
/// `SHA512_CTX` is `{ h[8]; Nl, Nh (bits); p[128]; num, md_len }`.
fn hash_state_to_c(st: &StreamingHashState, ty: u8, img: &mut [u8]) {
    img[seq::HASH_TYPE] = ty;
    put_u16(img, seq::HASH_ALG, hash_id(st.alg));
    let c = &mut img[seq::HASH_CONTEXT..];
    let bits = u128::from(st.total_len) * 8;
    match st.block_size() {
        64 => {
            let (words, data) = if st.alg == TpmiAlgHash::Sha1 {
                (5, 28)
            } else {
                (8, 40)
            };
            for (i, h) in st.h[..words].iter().enumerate() {
                put_u32(c, 4 * i, *h as u32);
            }
            put_u32(c, 4 * words, bits as u32);
            put_u32(c, 4 * words + 4, (bits >> 32) as u32);
            c[data..data + st.block_len].copy_from_slice(&st.block_buf[..st.block_len]);
            put_u32(c, data + 64, st.block_len as u32);
            if st.alg != TpmiAlgHash::Sha1 {
                put_u32(c, data + 68, openssl_md_len(st.alg));
            }
        }
        _ => {
            for (i, h) in st.h.iter().enumerate() {
                put_u64(c, 8 * i, *h);
            }
            put_u64(c, 64, bits as u64);
            put_u64(c, 72, (bits >> 64) as u64);
            c[80..208].copy_from_slice(&st.block_buf);
            put_u32(c, 208, st.block_len as u32);
            put_u32(c, 212, openssl_md_len(st.alg));
        }
    }
}

/// Reads an exported `HASH_STATE` ([`hash_state_to_c`]): its type and running hash.
fn hash_state_from_c(img: &[u8]) -> Option<(u8, StreamingHashState)> {
    let ty = img[seq::HASH_TYPE];
    let alg = hash_from_id(get_u16(img, seq::HASH_ALG))?;
    let c = &img[seq::HASH_CONTEXT..];
    let mut st = StreamingHashState::new(alg);
    let bits: u128;
    match st.block_size() {
        64 => {
            let (words, data) = if alg == TpmiAlgHash::Sha1 {
                (5, 28)
            } else {
                (8, 40)
            };
            for (i, h) in st.h[..words].iter_mut().enumerate() {
                *h = u64::from(get_u32(c, 4 * i));
            }
            bits =
                u128::from(get_u32(c, 4 * words)) | (u128::from(get_u32(c, 4 * words + 4)) << 32);
            st.block_len = get_u32(c, data + 64) as usize;
            if st.block_len >= 64 {
                return None;
            }
            st.block_buf = [0; 128];
            st.block_buf[..st.block_len].copy_from_slice(&c[data..data + st.block_len]);
        }
        _ => {
            for (i, h) in st.h.iter_mut().enumerate() {
                *h = get_u64(c, 8 * i);
            }
            bits = u128::from(get_u64(c, 64)) | (u128::from(get_u64(c, 72)) << 64);
            st.block_buf.copy_from_slice(&c[80..208]);
            st.block_len = get_u32(c, 208) as usize;
            if st.block_len >= 128 {
                return None;
            }
        }
    }
    st.total_len = u64::try_from(bits / 8).ok()?;
    if !bits.is_multiple_of(8) || st.total_len % st.block_size() as u64 != st.block_len as u64 {
        return None;
    }
    Some((ty, st))
}

/// Reads an exported SHAKE256 state (`OPENSSL_EXPORTED_SHAKE_STATE`) at the start of `img`.
fn shake_from_c(img: &[u8]) -> Option<crate::shake256::Shake256> {
    let lanes: [u8; 200] = img.get(..seq::SHAKE_SIZE)?.try_into().ok()?;
    let bufsz = get_u32(img, seq::SHAKE_SIZE) as usize;
    if bufsz > seq::SHAKE_BUF_CAP {
        return None;
    }
    let pending = img.get(seq::SHAKE_BUF..seq::SHAKE_BUF + bufsz)?;
    crate::shake256::Shake256::from_openssl(&lanes, pending)
}

/// The HMAC key block of an `HMAC_STATE` (`hmacKey`, `CryptoHash_HmacStart()`): the key (its
/// digest if it is longer than a block), zero-padded to the block size and XORed with the outer
/// pad `0x5c`.
fn hmac_key_block(digest: Option<&[u8]>, key: &[u8], block: usize, out: &mut [u8]) {
    let key = digest.unwrap_or(key);
    out[..block].fill(0x5c);
    for (o, k) in out.iter_mut().zip(key) {
        *o ^= k;
    }
}

/// The HMAC key that [`hmac_key_block`] turned into `block_bytes`: the key block XORed with the
/// outer pad, without its zero padding (an HMAC with the zero-padded key is the same HMAC).
fn hmac_key_from_block(block_bytes: &[u8]) -> Option<OwnedSensitiveData> {
    let mut key = [0u8; 128];
    for (k, b) in key.iter_mut().zip(block_bytes) {
        *k = b ^ 0x5c;
    }
    let len = key[..block_bytes.len()]
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i + 1);
    OwnedSensitiveData::new(&key[..len])
}

impl<P: Platform> CommandHandler<'_, P> {
    // -----------------------------------------------------------------------------------------
    // Protection.
    // -----------------------------------------------------------------------------------------

    /// The context encryption key and IV: `KDFa(CONTEXT_INTEGRITY_HASH_ALG, hProof, "CONTEXT",
    /// sequence, savedHandle, 384)` with the little-endian `sequence` and `savedHandle`
    /// (`ComputeContextProtectionKey()`).
    fn tcg_protection_key(
        &self,
        proof: &[u8],
        sequence: u64,
        saved_handle: u32,
    ) -> Result<([u8; 32], [u8; 16]), TpmRc> {
        let mut key_iv = [0u8; 48];
        kdfa_bits(
            &self.crypto(),
            crate::handler::context_integrity_hash_alg(),
            proof,
            b"CONTEXT",
            &sequence.to_le_bytes(),
            &saved_handle.to_le_bytes(),
            384,
            &mut key_iv,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_iv[..32]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&key_iv[32..]);
        Ok((key, iv))
    }

    /// Encrypts (`dir`) or decrypts `data` in place with the context protection key.
    fn tcg_crypt(
        &self,
        proof: &[u8],
        sequence: u64,
        saved_handle: u32,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), TpmRc> {
        let (key, mut iv) = self.tcg_protection_key(proof, sequence, saved_handle)?;
        self.sym_encrypt_decrypt(CONTEXT_ENCRYPTION_ALG, &key, &mut iv, dir, data)
            .map_err(|_| TpmRc::FAILURE)
    }

    /// The context integrity HMAC (`ComputeContextIntegrity()`) over `encrypted` into `out`;
    /// returns its length.
    fn tcg_integrity(
        &self,
        proof: &[u8],
        sequence: u64,
        saved_handle: u32,
        encrypted: &[u8],
        out: &mut [u8; 64],
    ) -> Result<usize, TpmRc> {
        let mut mac = self
            .crypto()
            .hmac_stream(crate::handler::context_integrity_hash_alg(), proof)
            .map_err(|_| TpmRc::FAILURE)?;
        let reset_count = self.context.state.nv.persistent.total_reset_count;
        mac.update(&reset_count.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        if saved_handle == 0x8000_0002 {
            mac.update(&self.context.state.nv.reset.clear_count.to_be_bytes())
                .map_err(|_| TpmRc::FAILURE)?;
        }
        mac.update(&sequence.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        mac.update(&saved_handle.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        mac.update(encrypted).map_err(|_| TpmRc::FAILURE)?;
        let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = mac.finalize(&mut buf).map_err(|_| TpmRc::FAILURE)?;
        let len = digest.digest().len();
        out[..len].copy_from_slice(&buf[..len]);
        Ok(len)
    }

    // -----------------------------------------------------------------------------------------
    // TPM2_ContextSave.
    // -----------------------------------------------------------------------------------------

    /// `TPM2_ContextSave` of `save_handle` after the handle, session and parameter checks and
    /// `RETURN_IF_ORDERLY`, producing the reference's context.
    pub(super) fn tcg_context_save(
        &mut self,
        request: RequestThenResponse<'_, '_>,
        save_handle: u32,
        session_responses: &[TpmsAuthResponse],
    ) -> Result<(), TpmRc> {
        // `contextBlob`: integrity || fingerprint || entity (the fingerprint and the entity are
        // encrypted in place).
        let mut blob = [0u8; INTEGRITY_SIZE + FINGERPRINT_SIZE + OBJECT_SIZE];
        let entity_at = INTEGRITY_SIZE + FINGERPRINT_SIZE;
        let (hierarchy, saved_handle, entity_len, is_session) =
            if let Some(obj) = self.context.state.find_transient_object(save_handle) {
                let obj = obj.clone();
                object_image::<P::Crypto>(&obj, &mut blob[entity_at..])?;
                let st_clear = obj.st_clear
                    || obj
                        .public
                        .object_attributes
                        .contains(tpm2::TpmaObject::ST_CLEAR);
                let saved = if st_clear { 0x8000_0002 } else { 0x8000_0000 };
                (obj.hierarchy, saved, OBJECT_SIZE, false)
            } else if let Some(sess) = self.context.state.session(save_handle) {
                session_image(sess, &mut blob[entity_at..])?;
                (Handle::RH_NULL.0, save_handle, SESSION_SIZE, true)
            } else if let Some(seq) = self.context.state.find_active_sequence(save_handle) {
                let seq = seq.clone();
                sequence_image::<P::Crypto>(&seq, &mut blob[entity_at..], |h| {
                    self.resolve_hierarchy_proof(h).map(|(proof, _)| proof)
                })?;
                // `fixed-size-context`: padded with zeros to an `OBJECT`.
                let len = if cfg!(feature = "fixed-size-context") {
                    OBJECT_SIZE
                } else {
                    SEQUENCE_OBJECT_SIZE
                };
                (Handle::RH_NULL.0, 0x8000_0001, len, false)
            } else {
                return Err(TpmRc::REFERENCE_H0);
            };

        let (proof, _) = self.resolve_hierarchy_proof(hierarchy)?;
        let sequence = if is_session {
            self.context.state.save_session_context(save_handle)?
        } else {
            let state = &mut self.context.state.nv.reset;
            state.object_context_counter = state
                .object_context_counter
                .checked_add(1)
                .ok_or(TpmRc::FAILURE)?;
            state.object_context_counter
        };
        blob[INTEGRITY_SIZE..entity_at].copy_from_slice(&sequence.to_le_bytes());
        let end = entity_at + entity_len;
        self.tcg_crypt(
            proof.as_bytes(),
            sequence,
            saved_handle,
            Direction::Encrypt,
            &mut blob[INTEGRITY_SIZE..end],
        )?;
        let mut integrity = [0u8; 64];
        let len = self.tcg_integrity(
            proof.as_bytes(),
            sequence,
            saved_handle,
            &blob[INTEGRITY_SIZE..end],
            &mut integrity,
        )?;
        if len + 2 != INTEGRITY_SIZE {
            return Err(TpmRc::FAILURE);
        }
        blob[..2].copy_from_slice(&(len as u16).to_be_bytes());
        blob[2..INTEGRITY_SIZE].copy_from_slice(&integrity[..len]);

        let rsp = TcgContextSaveRsp {
            sequence,
            saved_handle,
            hierarchy,
            blob: &blob[..end],
        };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, session_responses)
    }

    // -----------------------------------------------------------------------------------------
    // TPM2_ContextLoad.
    // -----------------------------------------------------------------------------------------

    /// `TPM2_ContextLoad` of the reference's context `blob` (after the `TPMS_CONTEXT` parameter
    /// unmarshaling); returns the handle of the loaded context.
    pub(super) fn tcg_context_load(
        &mut self,
        sequence: u64,
        saved_handle: Handle,
        hierarchy: Handle,
        blob: &[u8],
    ) -> Result<u32, TpmRc> {
        let mut slice = blob;
        let integrity = tpm2::Tpm2bDigest::unmarshal(&mut slice).map_err(|e| e.to_rc())?;
        if integrity.get_size() as usize
            != crate::handler::context_integrity_hash_alg().digest_size()
        {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        if slice.len() < FINGERPRINT_SIZE {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        let (proof, _) = self.resolve_hierarchy_proof(hierarchy.0)?;
        let mut expected = [0u8; 64];
        let len = self.tcg_integrity(
            proof.as_bytes(),
            sequence,
            saved_handle.0,
            slice,
            &mut expected,
        )?;
        if integrity.get_buffer() != &expected[..len] {
            return Err(TpmRc::INTEGRITY.with(Position::parameter(1)));
        }
        let mut plain = [0u8; INTEGRITY_SIZE + FINGERPRINT_SIZE + OBJECT_SIZE];
        let plain = plain.get_mut(..slice.len()).ok_or(TpmRc::FAILURE)?;
        plain.copy_from_slice(slice);
        self.tcg_crypt(
            proof.as_bytes(),
            sequence,
            saved_handle.0,
            Direction::Decrypt,
            plain,
        )?;
        if plain[..FINGERPRINT_SIZE] != sequence.to_le_bytes() {
            return Err(TpmRc::FAILURE);
        }
        let entity = &plain[FINGERPRINT_SIZE..];

        let loaded_handle = match Handle(saved_handle.0).handle_type() {
            Some(TpmHt::HMACSession | TpmHt::PolicySession) => {
                if entity.len() != SESSION_SIZE {
                    return Err(TpmRc::FAILURE);
                }
                self.nv_clear_orderly()?;
                if !self
                    .context
                    .state
                    .saved_session_sequence_is_valid(saved_handle.0, sequence)
                {
                    return Err(TpmRc::HANDLE.with(Position::parameter(1)));
                }
                let free_slots = self
                    .context
                    .state
                    .active_sessions
                    .iter()
                    .filter(|s| s.is_none())
                    .count();
                if free_slots == 0 {
                    return Err(TpmRc::SESSION_MEMORY);
                }
                let slot = (saved_handle.0 & 0x00FF_FFFF) as usize;
                if free_slots == 1
                    && self.context.state.context_gap_exhausted()
                    && self.context.state.oldest_saved_session_slot() != Some(slot)
                {
                    return Err(TpmRc::CONTEXT_GAP);
                }
                let sess = session_from_image(entity, saved_handle.0)
                    .ok_or(TpmRc::INTEGRITY.with(Position::parameter(1)))?;
                self.context.state.remove_saved_session(saved_handle.0);
                self.context.state.add_session(sess)?;
                saved_handle.0
            }
            _ => {
                if entity.len() > OBJECT_SIZE {
                    return Err(TpmRc::FAILURE);
                }
                if !self.context.hierarchy_is_enabled(hierarchy.0) {
                    return Err(TpmRc::HIERARCHY.with(Position::parameter(1)));
                }
                // The reference reads a whole `OBJECT` from the buffer (zero beyond the
                // context).
                let mut img = [0u8; OBJECT_SIZE];
                img[..entity.len()].copy_from_slice(entity);
                if image_is_sequence(&img) {
                    let mut seq = sequence_from_image(&img)
                        .ok_or(TpmRc::INTEGRITY.with(Position::parameter(1)))?;
                    let (slot, handle) = self.context.state.find_empty_sequence_slot()?;
                    seq.handle = handle;
                    self.context.state.active_sequences[slot] = Some(seq);
                    handle
                } else {
                    let mut obj = object_from_image::<P::Crypto>(&img)
                        .ok_or(TpmRc::INTEGRITY.with(Position::parameter(1)))?;
                    let (slot, handle) = self.context.state.find_empty_transient_slot(true)?;
                    obj.handle = handle;
                    self.context.state.transient_objects[slot] = Some(obj);
                    handle
                }
            }
        };
        Ok(loaded_handle)
    }
}

// ---------------------------------------------------------------------------------------------
// The conversions between the loaded entities and the reference's structures.
// ---------------------------------------------------------------------------------------------

/// Whether `obj` is a primary object (`OBJECT_ATTRIBUTES.primary`): loaded without a parent
/// (`TPM2_CreatePrimary`, `TPM2_CreateLoaded` of a primary object, `TPM2_LoadExternal`)
/// into a hierarchy other than `TPM_RH_NULL` (`ObjectSetLoadedAttributes()`). An external
/// object always has no parent; any other object has none if its qualified name is that of
/// a child of its hierarchy (`ComputeQualifiedName()`: `H(hierarchy || name)`).
///
/// The digest is computed with the backend `C` directly, without the self test of a
/// [`crate::self_test::Tested`] backend: the reference does not compute it (its `OBJECT` keeps the
/// attribute), so it must not run a self test the reference does not run.
fn is_primary<C: Crypto>(obj: &TransientObject) -> Result<bool, TpmRc> {
    if crate::hierarchy::normalize(obj.hierarchy) == Handle::RH_NULL.0 {
        return Ok(false);
    }
    if obj.external {
        return Ok(true);
    }
    let alg = obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
    let mut digest = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash::<C>(
        alg,
        &[&obj.hierarchy.to_be_bytes(), obj.name.get_buffer()],
        &mut digest,
    )
    .map_err(|_| TpmRc::FAILURE)?;
    let qn = obj.qualified_name.get_buffer();
    Ok(qn.len() == 2 + digest.digest().len()
        && qn[..2] == hash_id(alg).to_be_bytes()
        && qn[2..] == *digest.digest())
}

/// Writes the reference's `OBJECT` structure of the loaded object `obj` to `img[..OBJECT_SIZE]`
/// (zeroed first): the image the reference keeps in its object slot (`s_objects[]`) and copies
/// into a saved context (`TPM2_ContextSave()` copies the slot as it is). `evictHandle` is zero
/// and `evict` clear (a transient object).
///
/// Fails with `TPM_RC_FAILURE` if `img` is shorter than an `OBJECT` or a value of `obj` does not
/// fit the reference's structure.
pub(crate) fn object_image<C: Crypto>(obj: &TransientObject, img: &mut [u8]) -> Result<(), TpmRc> {
    let img = img.get_mut(..OBJECT_SIZE).ok_or(TpmRc::FAILURE)?;
    img.fill(0);
    let attributes = obj.public.object_attributes;
    let mut a = attr::OCCUPIED;
    if obj.public_only {
        a |= attr::PUBLIC_ONLY;
    }
    if obj.external {
        a |= attr::EXTERNAL;
    }
    if obj.st_clear || attributes.contains(tpm2::TpmaObject::ST_CLEAR) {
        a |= attr::ST_CLEAR;
    }
    let base = crate::hierarchy::normalize(obj.hierarchy);
    a |= match base {
        h if h == Handle::RH_ENDORSEMENT.0 => attr::EPS_HIERARCHY,
        h if h == Handle::RH_OWNER.0 => attr::SPS_HIERARCHY,
        h if h == Handle::RH_PLATFORM.0 => attr::PPS_HIERARCHY,
        _ => attr::TEMPORARY,
    };
    if is_primary::<C>(obj)? {
        a |= attr::PRIMARY;
    }
    if !obj.external
        && !obj.public_only
        && attributes.contains(tpm2::TpmaObject::RESTRICTED)
        && attributes.contains(tpm2::TpmaObject::DECRYPT)
        && obj.public.name_alg.is_some()
    {
        a |= if obj.public.algorithm() == Alg::KEYEDHASH {
            attr::DERIVATION
        } else {
            attr::IS_PARENT
        };
    }
    put_u32(img, obj::ATTRIBUTES, a);

    let mut wire = [0u8; tpm2::TpmtPublic::MAX_SIZE];
    let len = obj.public.as_tpmt().marshal(&mut wire);
    public_to_c(
        &wire[..len],
        &mut img[obj::PUBLIC..obj::PUBLIC + public::SIZE],
    )
    .ok_or(TpmRc::FAILURE)?;

    if !obj.public_only {
        let s = obj::SENSITIVE;
        put_u16(img, s + sensitive::TYPE, obj.public.algorithm().id());
        put_tpm2b(img, s + sensitive::AUTH, DIGEST_CAP, obj.auth.get_buffer())
            .ok_or(TpmRc::FAILURE)?;
        put_tpm2b(img, s + sensitive::SEED, DIGEST_CAP, obj.seed_bytes()).ok_or(TpmRc::FAILURE)?;
        let value = s + sensitive::VALUE;
        if obj.public.algorithm() == Alg::RSA && obj.private_len > 0 {
            // The packed CRT form of `CryptoRsa_LoadPrivateExponent()`, which every RSA
            // object with a private key has once loaded (and `TPM2_ContextSave` ensures).
            let key = obj
                .rsa_private_key::<C>()
                .ok()
                .flatten()
                .ok_or(TpmRc::FAILURE)?;
            let mut crt = [0u8; crate::handler::rsa_sensitive::RSA_PRIVATE_SIZE];
            let len = key
                .crt(&mut crt)
                .map_err(|_| TpmRc::FAILURE)?
                .as_slice()
                .len();
            if !crate::handler::rsa_sensitive::order_crt_for_prime(
                obj.private_bytes(),
                &mut crt[..len],
            ) {
                return Err(TpmRc::FAILURE);
            }
            put_tpm2b(img, value, sensitive::VALUE_CAP, &crt[..len]).ok_or(TpmRc::FAILURE)?;
            let size = get_u16(img, value) | sensitive::RSA_CRT_FLAGS;
            put_u16(img, value, size);
        } else {
            put_tpm2b(img, value, sensitive::VALUE_CAP, obj.private_bytes())
                .ok_or(TpmRc::FAILURE)?;
        }
    }
    put_tpm2b(
        img,
        obj::QUALIFIED_NAME,
        NAME_CAP,
        obj.qualified_name.get_buffer(),
    )
    .ok_or(TpmRc::FAILURE)?;
    put_tpm2b(img, obj::NAME, NAME_CAP, obj.name.get_buffer()).ok_or(TpmRc::FAILURE)?;
    put_u32(img, obj::HIERARCHY, obj.hierarchy);
    Ok(())
}

/// Writes the reference's `SESSION` structure of `s` to `img[..SESSION_SIZE]` (zeroed first):
/// the session in the reference's session slot (`s_sessions[].session`), which
/// `TPM2_ContextSave()` copies into a saved context as it is.
///
/// Fails with `TPM_RC_FAILURE` if `img` is shorter than a `SESSION` or a value of `s` does not
/// fit the reference's structure.
pub(crate) fn session_image(s: &SessionState, img: &mut [u8]) -> Result<(), TpmRc> {
    let img = img.get_mut(..SESSION_SIZE).ok_or(TpmRc::FAILURE)?;
    img.fill(0);
    let is_policy = s.session_type != TpmSe::HMAC;
    let flags = [
        (is_policy, sattr::IS_POLICY),
        (s.audit_digest.is_some(), sattr::IS_AUDIT),
        (s.bound_entity.get_size() > 0, sattr::IS_BOUND),
        (s.is_cp_hash_defined, sattr::IS_CP_HASH_DEFINED),
        (
            is_policy && s.is_name_hash_defined(),
            sattr::IS_NAME_HASH_DEFINED,
        ),
        (
            s.is_parameters_hash_defined,
            sattr::IS_PARAMETERS_HASH_DEFINED,
        ),
        (s.is_template_hash_defined, sattr::IS_TEMPLATE_HASH_DEFINED),
        (s.is_auth_value_needed, sattr::IS_AUTH_VALUE_NEEDED),
        (s.is_password_needed, sattr::IS_PASSWORD_NEEDED),
        (s.is_pp_required, sattr::IS_PP_REQUIRED),
        (s.session_type == TpmSe::Trial, sattr::IS_TRIAL_POLICY),
        (s.is_da_bound, sattr::IS_DA_BOUND),
        (s.is_lockout_bound, sattr::IS_LOCKOUT_BOUND),
        (s.include_auth, sattr::INCLUDE_AUTH),
        (s.check_nv_written, sattr::CHECK_NV_WRITTEN),
        (s.nv_written_state, sattr::NV_WRITTEN_STATE),
        (
            s.sec_channel.check_secure_channel,
            sattr::CHECK_SECURE_CHANNEL,
        ),
        (s.sec_channel.check_req_key, sattr::CHECK_REQ_KEY),
        (s.sec_channel.check_tpm_key, sattr::CHECK_TPM_KEY),
    ];
    let a = flags
        .iter()
        .filter(|(set, _)| *set)
        .fold(0, |a, (_, bit)| a | bit);
    put_u32(img, sess::ATTRIBUTES, a);
    put_u32(img, sess::PCR_COUNTER, s.pcr_counter.unwrap_or(0));
    put_u64(img, sess::START_TIME, s.start_time);
    put_u64(img, sess::TIMEOUT, s.timeout);
    put_u32(img, sess::EPOCH, s.epoch);
    put_u32(img, sess::COMMAND_CODE, s.command_code);
    put_u16(img, sess::AUTH_HASH_ALG, hash_id(s.auth_hash));
    img[sess::COMMAND_LOCALITY] = s.command_locality;
    let mut wire = [0u8; <Option<tpm2::TpmtSymDef>>::MAX_SIZE];
    let len = s.symmetric.marshal(&mut wire);
    sym_def_to_c(&mut Wire(&wire[..len]), img, sess::SYMMETRIC).ok_or(TpmRc::FAILURE)?;
    put_tpm2b(
        img,
        sess::SESSION_KEY,
        DIGEST_CAP,
        &s.session_key[..s.session_key_len],
    )
    .ok_or(TpmRc::FAILURE)?;
    put_tpm2b(img, sess::NONCE_TPM, DIGEST_CAP, s.nonce_tpm.get_buffer()).ok_or(TpmRc::FAILURE)?;
    if is_policy {
        // `u1` holds the cpHash, nameHash, templateHash or pHash; `SessionResetPolicyData()`
        // only zeroes its size, so the whole buffer is kept.
        put_u16(img, sess::U1, s.policy_hash_len as u16);
        img[sess::U1 + 2..sess::U1 + 2 + DIGEST_CAP].copy_from_slice(&s.policy_hash[..DIGEST_CAP]);
        put_tpm2b(
            img,
            sess::U2,
            DIGEST_CAP,
            &s.policy_digest[..s.policy_digest_len],
        )
        .ok_or(TpmRc::FAILURE)?;
    } else {
        put_tpm2b(img, sess::U1, NAME_CAP, s.bound_entity.get_buffer()).ok_or(TpmRc::FAILURE)?;
        if let Some(digest) = &s.audit_digest {
            put_tpm2b(img, sess::U2, DIGEST_CAP, &digest[..s.audit_digest_len])
                .ok_or(TpmRc::FAILURE)?;
        }
    }
    // `scKeyNameHash` (`SEC_CHANNEL_SUPPORT`).
    if cfg!(feature = "sec-channel") {
        let sc = &s.sec_channel;
        put_tpm2b(
            img,
            sess::SC_KEY_NAME_HASH,
            DIGEST_CAP,
            &sc.sc_key_name_hash[..sc.sc_key_name_hash_len],
        )
        .ok_or(TpmRc::FAILURE)?;
    }
    Ok(())
}

/// Writes an `HMAC_STATE` (the running inner hash `inner` and the key block of `key`) to
/// `img` (zero on entry). A key longer than a block is hashed with the backend `C` directly (see
/// [`is_primary`]).
fn hmac_state_to_c<C: Crypto>(
    inner: &StreamingHashState,
    key: &[u8],
    img: &mut [u8],
) -> Result<(), TpmRc> {
    hash_state_to_c(inner, seq::TYPE_HMAC, img);
    let block = inner.block_size();
    let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = if key.len() > block {
        let digest = tpm2::crypto::hash::<C>(inner.alg, &[key], &mut digest_buf)
            .map_err(|_| TpmRc::FAILURE)?;
        Some(digest.digest())
    } else {
        None
    };
    put_u16(img, seq::HMAC_KEY, block as u16);
    hmac_key_block(
        digest,
        key,
        block,
        &mut img[seq::HMAC_KEY + 2..seq::HMAC_KEY + 2 + block],
    );
    Ok(())
}

/// Writes the reference's `SEQUENCE_OBJECT` structure of `s` (with its states exported,
/// `SequenceDataExport()`) to `img[..SEQUENCE_OBJECT_SIZE]` (zeroed first). The exported states
/// are the states in the reference's object slot (it copies its OpenSSL hash contexts
/// with `memcpy`), except that the export zeroes the pointer `HASH_STATE.def`
/// (`harness-context-no-pointers.patch`; the slot holds the address of the hash descriptor in
/// the reference's process) and the SMAC dispatch pointers.
///
/// `ticket_proof` returns the proof of a hierarchy, the key of the ticket HMAC of a verification
/// sequence (version 185's `SEQUENCE_OBJECT` only).
///
/// Fails with `TPM_RC_FAILURE` if `img` is shorter than a sequence object or a value of `s` does
/// not fit the reference's structure.
pub(crate) fn sequence_image<C: Crypto>(
    s: &ActiveSequence,
    img: &mut [u8],
    ticket_proof: impl Fn(u32) -> Result<crate::hierarchy::HierarchySecret, TpmRc>,
) -> Result<(), TpmRc> {
    let img = img.get_mut(..SEQUENCE_OBJECT_SIZE).ok_or(TpmRc::FAILURE)?;
    img.fill(0);
    let mut a = attr::OCCUPIED | attr::TEMPORARY;
    if s.first_block {
        a |= attr::FIRST_BLOCK;
    }
    if s.ticket_safe {
        a |= attr::TICKET_SAFE;
    }
    a |= match s.sequence_type {
        SequenceType::Hash { .. } => attr::HASH_SEQ,
        SequenceType::Hmac { .. } => attr::HMAC_SEQ,
        #[cfg(feature = "cmac")]
        SequenceType::Cmac { .. } => attr::HMAC_SEQ,
        SequenceType::Event => attr::EVENT_SEQ,
        SequenceType::Sign(_) => attr::SIGN_SEQ,
        SequenceType::Verify(_) => attr::VERIFY_SEQ,
    };
    put_u32(img, seq::ATTRIBUTES, a);
    put_u16(img, seq::TYPE, alg::NULL);
    put_u16(img, seq::NAME_ALG, alg::NULL);
    put_u32(img, seq::OBJECT_ATTRIBUTES, TPMA_OBJECT_NO_DA);
    put_tpm2b(img, seq::AUTH, DIGEST_CAP, s.auth.get_buffer()).ok_or(TpmRc::FAILURE)?;
    let state = seq::STATE;
    match &s.sequence_type {
        SequenceType::Hash { .. } => {
            hash_state_to_c(&s.hash_states[0], seq::TYPE_HASH, &mut img[state..]);
        }
        SequenceType::Hmac { key, .. } => {
            hmac_state_to_c::<C>(&s.hash_states[0], key.get_buffer(), &mut img[state..])?;
        }
        #[cfg(feature = "cmac")]
        SequenceType::Cmac { state: cmac } => {
            // `CryptSmacStart()`: an SMAC `HASH_STATE` (no `hashAlg`) with the
            // `tpmCmacState_t`.
            let h = &mut img[state..];
            h[seq::HASH_TYPE] = seq::TYPE_SMAC;
            let c = seq::CMAC;
            let (key, iv, bcount) = cmac.parts();
            put_u16(h, c, cmac.alg.algorithm().id());
            put_u16(h, c + 2, cmac.alg.key_bits());
            put_u16(h, c + 4, u16::from(bcount));
            put_tpm2b(h, c + 6, 16, iv).ok_or(TpmRc::FAILURE)?;
            put_tpm2b(h, c + 24, 32, key).ok_or(TpmRc::FAILURE)?;
        }
        SequenceType::Event => {
            for (i, st) in s.event_hash_states().iter().enumerate() {
                let at = state + i * HASH_STATE_SIZE;
                hash_state_to_c(st, seq::TYPE_HASH, &mut img[at..]);
            }
        }
        // The `HASH_OBJECT` of the earlier references has no signing or verification
        // sequences (`context-format-pre-v185` excludes their commands).
        SequenceType::Sign(_) | SequenceType::Verify(_)
            if cfg!(feature = "context-format-pre-v185") =>
        {
            return Err(TpmRc::FAILURE);
        }
        SequenceType::Sign(sig) | SequenceType::Verify(sig) => {
            let mut wire = [0u8; tpm2::TpmtSigScheme::MAX_SIZE];
            let len = sig.scheme.marshal(&mut wire);
            scheme_to_c(&mut Wire(&wire[..len]), img, seq::SIGN_SCHEME).ok_or(TpmRc::FAILURE)?;
            put_tpm2b(
                img,
                seq::ASSOCIATED_NAME,
                NAME_CAP,
                sig.key_name.get_buffer(),
            )
            .ok_or(TpmRc::FAILURE)?;
            match (sig.scheme, &s.mu_state) {
                (tpm2::TpmtSigScheme::Mldsa, Some(mu)) => {
                    let (lanes, bufsz, pending) = mu.to_openssl();
                    img[state..state + seq::SHAKE_SIZE].copy_from_slice(&lanes);
                    put_u32(img, state + seq::SHAKE_SIZE, bufsz as u32);
                    let buf = state + seq::SHAKE_BUF;
                    img[buf..buf + pending.len()].copy_from_slice(pending);
                }
                (tpm2::TpmtSigScheme::Hmac(_), _) => {
                    hmac_state_to_c::<C>(
                        &s.hash_states[0],
                        sig.hmac_key.get_buffer(),
                        &mut img[state..],
                    )?;
                }
                (tpm2::TpmtSigScheme::HashMldsa, Some(mu)) => {
                    // Not in the references' profiles (`hash_mldsa`): the pre-hash in the
                    // reference's place (`hashState[0]`) and, as a `tpm-rs` extension, the
                    // running `mu` prefix in the unused `hashState[1]`.
                    hash_state_to_c(&s.hash_states[0], seq::TYPE_HASH, &mut img[state..]);
                    let at = state + HASH_STATE_SIZE;
                    let (lanes, bufsz, pending) = mu.to_openssl();
                    img[at..at + seq::SHAKE_SIZE].copy_from_slice(&lanes);
                    put_u32(img, at + seq::SHAKE_SIZE, bufsz as u32);
                    img[at + seq::SHAKE_BUF..at + seq::SHAKE_BUF + pending.len()]
                        .copy_from_slice(pending);
                }
                (tpm2::TpmtSigScheme::Mldsa | tpm2::TpmtSigScheme::HashMldsa, None) => {
                    return Err(TpmRc::FAILURE);
                }
                _ => hash_state_to_c(&s.hash_states[0], seq::TYPE_HASH, &mut img[state..]),
            }
            if let SequenceType::Verify(_) = s.sequence_type {
                match sig.ticket_hierarchy {
                    Some(hierarchy) => {
                        put_u32(img, seq::TICKET_HIERARCHY, hierarchy);
                        // The ticket HMAC is keyed with the hierarchy proof
                        // (`TPM2_VerifySequenceStart`).
                        let proof = ticket_proof(hierarchy)?;
                        hmac_state_to_c::<C>(
                            &s.hash_states[SignatureSequence::TICKET_INNER_STATE],
                            proof.as_bytes(),
                            &mut img[seq::TICKET..],
                        )?;
                    }
                    None => put_u32(img, seq::TICKET_HIERARCHY, Handle::RH_NULL.0),
                }
            }
        }
    }
    Ok(())
}

/// Whether the object slot image `img` holds a sequence object (`ObjectIsSequence()`).
fn image_is_sequence(img: &[u8]) -> bool {
    img.len() >= 4 && get_u32(img, obj::ATTRIBUTES) & attr::ANY_SEQ != 0
}

/// The loaded object of the reference's `OBJECT` structure `img` ([`object_image`]), or `None`
/// if `img` is shorter than an `OBJECT` or not an object this TPM can load (its RSA private key
/// is validated against its public key, as the reference's `CryptoRsa_LoadPrivateExponent()`
/// does). Octets the reference does not define (padding, the unused ends of buffers) are ignored.
/// The object's hierarchy is the reference's `hierarchy` member. The returned object's `handle`
/// is 0.
pub(crate) fn object_from_image<C: Crypto>(img: &[u8]) -> Option<TransientObject> {
    let img = img.get(..OBJECT_SIZE)?;
    let a = get_u32(img, obj::ATTRIBUTES);
    let mut wire = [0u8; tpm2::TpmtPublic::MAX_SIZE];
    let len = public_from_c(&img[obj::PUBLIC..obj::PUBLIC + public::SIZE], &mut wire)?;
    let public = OwnedPublic::unmarshal_nullable(&mut &wire[..len]).ok()?;
    let public_only = a & attr::PUBLIC_ONLY != 0;
    let s = obj::SENSITIVE;
    let (auth, seed, mut private, mut private_len) = if public_only {
        (
            OwnedAuth::default(),
            &[][..],
            [0u8; super::MAX_PRIVATE_KEY_SIZE],
            0,
        )
    } else {
        let auth = OwnedAuth::new(get_tpm2b(img, s + sensitive::AUTH, DIGEST_CAP)?)?;
        let seed = get_tpm2b(img, s + sensitive::SEED, DIGEST_CAP)?;
        let value_at = s + sensitive::VALUE;
        let size = get_u16(img, value_at);
        let value = if public.algorithm() == Alg::RSA && size & sensitive::RSA_PRIME_FLAG != 0 {
            // The packed CRT form: its first value is the prime.
            let packed = usize::from(size & !sensitive::RSA_SIZE_FLAGS);
            if packed > sensitive::VALUE_CAP
                || !packed.is_multiple_of(crate::handler::rsa_sensitive::CRT_VALUES)
            {
                return None;
            }
            &img[value_at + 2..value_at + 2 + packed / crate::handler::rsa_sensitive::CRT_VALUES]
        } else {
            get_tpm2b(img, value_at, sensitive::VALUE_CAP)?
        };
        let mut private = [0u8; super::MAX_PRIVATE_KEY_SIZE];
        private.get_mut(..value.len())?.copy_from_slice(value);
        (auth, seed, private, value.len())
    };
    if public.algorithm() == Alg::RSA && private_len > 0 {
        let crate::owned::OwnedPublicParmsAndId::Rsa(parms, unique) = &public.parms_and_id else {
            return None;
        };
        let key = crate::handler::rsa_private_key::<C>(
            parms,
            unique.get_buffer(),
            &private[..private_len],
        )
        .ok()??;
        private_len = crate::handler::rsa_private_prime(&key, &mut private).ok()?;
    }
    let (seed, seed_len) = TransientObject::seed_from_bytes(seed);
    Some(TransientObject {
        handle: 0,
        seed,
        seed_len,
        external: a & attr::EXTERNAL != 0,
        public_only,
        name: OwnedName::new(get_tpm2b(img, obj::NAME, NAME_CAP)?)?,
        auth,
        public,
        private,
        private_len,
        qualified_name: OwnedName::new(get_tpm2b(img, obj::QUALIFIED_NAME, NAME_CAP)?)?,
        hierarchy: get_u32(img, obj::HIERARCHY),
        st_clear: a & attr::ST_CLEAR != 0,
    })
}

/// The session of the reference's `SESSION` structure `img` ([`session_image`]) with the
/// session handle `handle`, or `None` if `img` is shorter than a `SESSION`, the type of `handle`
/// does not match the session's (an HMAC or a policy session) or a value does not fit this TPM.
pub(crate) fn session_from_image(img: &[u8], handle: u32) -> Option<SessionState> {
    let img = img.get(..SESSION_SIZE)?;
    let a = get_u32(img, sess::ATTRIBUTES);
    let flag = |bit: u32| a & bit != 0;
    let is_policy = flag(sattr::IS_POLICY);
    let session_type = match (is_policy, flag(sattr::IS_TRIAL_POLICY)) {
        (false, _) => TpmSe::HMAC,
        (true, false) => TpmSe::Policy,
        (true, true) => TpmSe::Trial,
    };
    // A session handle's type must match the session (`HandleGetType` of `savedHandle`).
    let expected = if is_policy {
        TpmHt::PolicySession
    } else {
        TpmHt::HMACSession
    };
    if Handle(handle).handle_type() != Some(expected) {
        return None;
    }
    let auth_hash = hash_from_id(get_u16(img, sess::AUTH_HASH_ALG))?;
    let mut wire = [0u8; 6];
    let mut w = WireOut::new(&mut wire);
    sym_def_from_c(img, sess::SYMMETRIC, &mut w)?;
    let len = w.len;
    let symmetric = <Option<tpm2::TpmtSymDef>>::unmarshal(&mut &wire[..len]).ok()?;
    let key = get_tpm2b(img, sess::SESSION_KEY, DIGEST_CAP)?;
    let mut session_key = [0u8; 128];
    session_key[..key.len()].copy_from_slice(key);
    let u1_size = usize::from(get_u16(img, sess::U1));
    let mut policy_hash = [0u8; 64];
    let mut policy_hash_len = 0;
    let mut bound_entity = OwnedName::default();
    let mut audit_digest = None;
    let mut audit_digest_len = 0;
    let mut policy_digest = [0u8; 64];
    let mut policy_digest_len = auth_hash.digest_size();
    if is_policy {
        if u1_size > DIGEST_CAP {
            return None;
        }
        policy_hash[..DIGEST_CAP].copy_from_slice(&img[sess::U1 + 2..sess::U1 + 2 + DIGEST_CAP]);
        policy_hash_len = u1_size;
        let digest = get_tpm2b(img, sess::U2, DIGEST_CAP)?;
        policy_digest[..digest.len()].copy_from_slice(digest);
        policy_digest_len = digest.len();
    } else {
        if flag(sattr::IS_BOUND) {
            bound_entity = OwnedName::new(get_tpm2b(img, sess::U1, NAME_CAP)?)?;
        }
        if flag(sattr::IS_AUDIT) {
            let digest = get_tpm2b(img, sess::U2, DIGEST_CAP)?;
            let mut d = [0u8; 64];
            d[..digest.len()].copy_from_slice(digest);
            audit_digest = Some(d);
            audit_digest_len = digest.len();
        }
    }
    let sc_hash = if cfg!(feature = "sec-channel") {
        get_tpm2b(img, sess::SC_KEY_NAME_HASH, DIGEST_CAP)?
    } else {
        &[]
    };
    let mut sec_channel = SecChannelPolicy {
        check_secure_channel: flag(sattr::CHECK_SECURE_CHANNEL),
        check_req_key: flag(sattr::CHECK_REQ_KEY),
        check_tpm_key: flag(sattr::CHECK_TPM_KEY),
        ..SecChannelPolicy::default()
    };
    sec_channel.sc_key_name_hash[..sc_hash.len()].copy_from_slice(sc_hash);
    sec_channel.sc_key_name_hash_len = sc_hash.len();
    let pcr_counter = get_u32(img, sess::PCR_COUNTER);
    Some(SessionState {
        session_handle: handle,
        session_type,
        auth_hash,
        nonce_tpm: OwnedNonce::new(get_tpm2b(img, sess::NONCE_TPM, DIGEST_CAP)?)?,
        session_key,
        session_key_len: key.len(),
        symmetric,
        bound_entity,
        audit_digest,
        audit_digest_len,
        policy_hash,
        policy_hash_len,
        is_cp_hash_defined: flag(sattr::IS_CP_HASH_DEFINED),
        is_template_hash_defined: flag(sattr::IS_TEMPLATE_HASH_DEFINED),
        is_parameters_hash_defined: flag(sattr::IS_PARAMETERS_HASH_DEFINED),
        is_pp_required: flag(sattr::IS_PP_REQUIRED),
        policy_digest,
        policy_digest_len,
        command_code: get_u32(img, sess::COMMAND_CODE),
        start_time: get_u64(img, sess::START_TIME),
        timeout: get_u64(img, sess::TIMEOUT),
        epoch: get_u32(img, sess::EPOCH),
        is_auth_value_needed: flag(sattr::IS_AUTH_VALUE_NEEDED),
        is_password_needed: flag(sattr::IS_PASSWORD_NEEDED),
        pcr_counter: (pcr_counter != 0).then_some(pcr_counter),
        check_nv_written: flag(sattr::CHECK_NV_WRITTEN),
        nv_written_state: flag(sattr::NV_WRITTEN_STATE),
        command_locality: img[sess::COMMAND_LOCALITY],
        include_auth: flag(sattr::INCLUDE_AUTH),
        is_da_bound: flag(sattr::IS_DA_BOUND),
        is_lockout_bound: flag(sattr::IS_LOCKOUT_BOUND),
        sec_channel,
    })
}

/// Reads an `HMAC_STATE` ([`hmac_state_to_c`]): the running inner hash and the key.
fn hmac_state_from_c(img: &[u8]) -> Option<(StreamingHashState, OwnedSensitiveData)> {
    let (ty, inner) = hash_state_from_c(img)?;
    let block = inner.block_size();
    if ty != seq::TYPE_HMAC || usize::from(get_u16(img, seq::HMAC_KEY)) != block {
        return None;
    }
    let key = hmac_key_from_block(&img[seq::HMAC_KEY + 2..seq::HMAC_KEY + 2 + block])?;
    Some((inner, key))
}

/// The sequence of the reference's `SEQUENCE_OBJECT` structure `img` (with exported states,
/// [`sequence_image`]; `HASH_STATE.def` is ignored), or `None` if `img` is shorter than a
/// sequence object or not a sequence this TPM can load. The returned sequence's `handle` is 0.
pub(crate) fn sequence_from_image(img: &[u8]) -> Option<ActiveSequence> {
    let img = img.get(..SEQUENCE_OBJECT_SIZE)?;
    let a = get_u32(img, seq::ATTRIBUTES);
    let auth = OwnedAuth::new(get_tpm2b(img, seq::AUTH, DIGEST_CAP)?)?;
    let state = &img[seq::STATE..SEQUENCE_OBJECT_SIZE];
    let mut hash_states = [StreamingHashState::default(); 4];
    let mut mu_state = None;
    let sequence_type = if a & attr::HASH_SEQ != 0 {
        let (ty, st) = hash_state_from_c(state)?;
        if ty != seq::TYPE_HASH {
            return None;
        }
        hash_states[0] = st;
        SequenceType::Hash { alg: st.alg }
    } else if a & attr::EVENT_SEQ != 0 {
        for (i, slot) in hash_states
            .iter_mut()
            .enumerate()
            .take(ActiveSequence::EVENT_HASH_COUNT)
        {
            let (ty, st) = hash_state_from_c(&state[i * HASH_STATE_SIZE..])?;
            if ty != seq::TYPE_HASH {
                return None;
            }
            *slot = st;
        }
        SequenceType::Event
    } else if a & attr::HMAC_SEQ != 0 {
        #[cfg(feature = "cmac")]
        let smac = state[seq::HASH_TYPE] == seq::TYPE_SMAC;
        #[cfg(not(feature = "cmac"))]
        let smac = false;
        if smac {
            #[cfg(not(feature = "cmac"))]
            return None;
            #[cfg(feature = "cmac")]
            {
                let c = seq::CMAC;
                let alg =
                    AlgSym::from_parts(Alg::new(get_u16(state, c)), get_u16(state, c + 2)).ok()?;
                let bcount = u8::try_from(get_u16(state, c + 4)).ok()?;
                let iv: [u8; 16] = get_tpm2b(state, c + 6, 16)?.try_into().ok()?;
                let key = get_tpm2b(state, c + 24, 32)?;
                SequenceType::Cmac {
                    state: crate::cmac::CmacState::from_parts(alg, key, iv, bcount)?,
                }
            }
        } else {
            let (inner, key) = hmac_state_from_c(state)?;
            hash_states[0] = inner;
            SequenceType::Hmac {
                hash_alg: inner.alg,
                key,
            }
        }
    } else if a & (attr::SIGN_SEQ | attr::VERIFY_SEQ) != 0
        && !cfg!(feature = "context-format-pre-v185")
    {
        let mut wire = [0u8; tpm2::TpmtSigScheme::MAX_SIZE];
        let mut w = WireOut::new(&mut wire);
        scheme_from_c(img, seq::SIGN_SCHEME, &mut w)?;
        let len = w.len;
        let scheme = tpm2::TpmtSigScheme::unmarshal(&mut &wire[..len]).ok()?;
        let mut hmac_key = OwnedSensitiveData::default();
        let mut pre_hash = None;
        match scheme {
            tpm2::TpmtSigScheme::Mldsa => mu_state = Some(shake_from_c(state)?),
            tpm2::TpmtSigScheme::HashMldsa => {
                let (ty, st) = hash_state_from_c(state)?;
                if ty != seq::TYPE_HASH {
                    return None;
                }
                hash_states[0] = st;
                pre_hash = Some(st.alg);
                mu_state = Some(shake_from_c(&state[HASH_STATE_SIZE..])?);
            }
            tpm2::TpmtSigScheme::Hmac(_) => {
                let (inner, key) = hmac_state_from_c(state)?;
                hash_states[0] = inner;
                hmac_key = key;
            }
            _ => {
                let (ty, st) = hash_state_from_c(state)?;
                if ty != seq::TYPE_HASH {
                    return None;
                }
                hash_states[0] = st;
            }
        }
        let ticket_hierarchy = get_u32(img, seq::TICKET_HIERARCHY);
        let is_verify = a & attr::VERIFY_SEQ != 0;
        let ticket_hierarchy = if is_verify && ticket_hierarchy != Handle::RH_NULL.0 {
            let ticket = &img[seq::TICKET..seq::TICKET + HASH_STATE_SIZE + 2 + HMAC_KEY_CAP];
            let (inner, _) = hmac_state_from_c(ticket)?;
            let block = inner.block_size();
            let mut outer = StreamingHashState::new(inner.alg);
            outer.update(&ticket[seq::HMAC_KEY + 2..seq::HMAC_KEY + 2 + block]);
            hash_states[SignatureSequence::TICKET_INNER_STATE] = inner;
            hash_states[SignatureSequence::TICKET_OUTER_STATE] = outer;
            Some(ticket_hierarchy)
        } else {
            None
        };
        let sig = SignatureSequence {
            scheme,
            key_name: OwnedName::new(get_tpm2b(img, seq::ASSOCIATED_NAME, NAME_CAP)?)?,
            hmac_key,
            ticket_hierarchy,
            pre_hash,
        };
        if is_verify {
            SequenceType::Verify(sig)
        } else {
            SequenceType::Sign(sig)
        }
    } else {
        return None;
    };
    Some(ActiveSequence {
        handle: 0,
        auth,
        sequence_type,
        first_block: a & attr::FIRST_BLOCK != 0,
        ticket_safe: a & attr::TICKET_SAFE != 0,
        hash_states,
        mu_state,
    })
}

/// The parameters of a `TPM2_ContextSave` response with the reference's `contextBlob`.
struct TcgContextSaveRsp<'a> {
    sequence: u64,
    saved_handle: u32,
    hierarchy: u32,
    blob: &'a [u8],
}

/// The largest marshaled [`TcgContextSaveRsp`].
const TCG_CONTEXT_SAVE_RSP_MAX_SIZE: usize =
    8 + 4 + 4 + 2 + INTEGRITY_SIZE + FINGERPRINT_SIZE + OBJECT_SIZE;

impl Marshal for TcgContextSaveRsp<'_> {
    const MAX_SIZE: usize = TCG_CONTEXT_SAVE_RSP_MAX_SIZE;
    type MaxBuffer = [u8; TCG_CONTEXT_SAVE_RSP_MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        dst[..8].copy_from_slice(&self.sequence.to_be_bytes());
        dst[8..12].copy_from_slice(&self.saved_handle.to_be_bytes());
        dst[12..16].copy_from_slice(&self.hierarchy.to_be_bytes());
        dst[16..18].copy_from_slice(&(self.blob.len() as u16).to_be_bytes());
        dst[18..18 + self.blob.len()].copy_from_slice(self.blob);
        18 + self.blob.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A marshaled `TPMT_PUBLIC` of every type survives the conversion to the reference's
    /// structure and back, and lands at the reference's offsets.
    #[test]
    fn public_area_round_trips() {
        // ECC P-256 with AES-128-CFB, ECDAA(SHA-256, count 7), KDF1_SP800_56A(SHA-256).
        let mut ecc = alloc::vec::Vec::new();
        ecc.extend_from_slice(&[0x00, 0x23, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x72]);
        ecc.extend_from_slice(&[0x00, 0x02, 0xAA, 0xBB]);
        ecc.extend_from_slice(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x43]);
        ecc.extend_from_slice(&[0x00, 0x1A, 0x00, 0x0B, 0x00, 0x07]);
        ecc.extend_from_slice(&[0x00, 0x03]);
        ecc.extend_from_slice(&[0x00, 0x20, 0x00, 0x0B]);
        ecc.extend_from_slice(&[0x00, 0x01, 0x11, 0x00, 0x02, 0x22, 0x33]);
        let mut img = [0u8; public::SIZE];
        public_to_c(&ecc, &mut img).unwrap();
        assert_eq!(get_u16(&img, public::TYPE), alg::ECC);
        assert_eq!(get_u32(&img, public::ATTRIBUTES), 0x0003_0072);
        assert_eq!(get_u16(&img, public::PARAMETERS + 6), alg::ECDAA);
        assert_eq!(get_u16(&img, public::PARAMETERS + 10), 7);
        assert_eq!(get_u16(&img, public::PARAMETERS + 12), 3);
        assert_eq!(get_u16(&img, public::UNIQUE + public::ECC_Y), 2);
        let mut out = [0u8; 4096];
        let len = public_from_c(&img, &mut out).unwrap();
        assert_eq!(&out[..len], &ecc[..]);

        // RSA-2048 with RSAES (empty details) and a NULL symmetric.
        let mut rsa = alloc::vec::Vec::new();
        rsa.extend_from_slice(&[0x00, 0x01, 0x00, 0x0B, 0x00, 0x04, 0x00, 0x60, 0x00, 0x00]);
        rsa.extend_from_slice(&[0x00, 0x10, 0x00, 0x15, 0x08, 0x00, 0x00, 0x01, 0x00, 0x01]);
        rsa.extend_from_slice(&[0x00, 0x01, 0x5A]);
        let mut img = [0u8; public::SIZE];
        public_to_c(&rsa, &mut img).unwrap();
        assert_eq!(
            get_u32(&img, public::PARAMETERS + public::RSA_EXPONENT),
            0x0001_0001
        );
        let len = public_from_c(&img, &mut out).unwrap();
        assert_eq!(&out[..len], &rsa[..]);

        // Trailing octets and unknown types are rejected.
        let mut long = rsa.clone();
        long.push(0);
        assert!(public_to_c(&long, &mut [0u8; public::SIZE]).is_none());
        assert!(public_to_c(&[0x00, 0x42, 0, 0, 0, 0, 0, 0, 0, 0], &mut img).is_none());
    }

    /// A running hash of every algorithm survives the conversion to the OpenSSL context of an
    /// exported `HASH_STATE` and back, and the restored state finishes to the same digest.
    #[test]
    fn hash_state_round_trips() {
        let data: [u8; 300] = core::array::from_fn(|i| (i * 13 + 1) as u8);
        let algs = [
            Some(TpmiAlgHash::Sha1),
            Some(TpmiAlgHash::Sha256),
            Some(TpmiAlgHash::Sha384),
            crate::handler::capability::sha512(),
        ];
        for alg in algs.into_iter().flatten() {
            for split in [0, 1, 63, 64, 65, 127, 128, 200] {
                let mut st = StreamingHashState::new(alg);
                st.update(&data[..split]);
                let mut img = [0u8; HASH_STATE_SIZE];
                hash_state_to_c(&st, seq::TYPE_HASH, &mut img);
                let (ty, mut restored) = hash_state_from_c(&img).unwrap();
                assert_eq!(ty, seq::TYPE_HASH);
                st.update(&data[split..]);
                restored.update(&data[split..]);
                assert_eq!(restored.finalize(), st.finalize(), "{alg:?} {split}");
            }
        }
        // SHA-256 after 3 octets: h, the bit count, the buffered octets and md_len in place.
        let mut st = StreamingHashState::new(TpmiAlgHash::Sha256);
        st.update(b"abc");
        let mut img = [0u8; HASH_STATE_SIZE];
        hash_state_to_c(&st, seq::TYPE_HASH, &mut img);
        let c = seq::HASH_CONTEXT;
        assert_eq!(get_u32(&img, c), 0x6a09_e667);
        assert_eq!(get_u32(&img, c + 32), 24);
        assert_eq!(&img[c + 40..c + 43], b"abc");
        assert_eq!(get_u32(&img, c + 104), 3);
        assert_eq!(get_u32(&img, c + 108), 32);
    }

    /// The HMAC key block keeps the key: XORed with the outer pad and zero-padded.
    #[test]
    fn hmac_key_block_round_trips() {
        let mut block = [0u8; 64];
        hmac_key_block(None, &[1, 2, 3], 64, &mut block);
        assert_eq!(block[..4], [0x5d, 0x5e, 0x5f, 0x5c]);
        assert_eq!(
            hmac_key_from_block(&block).unwrap().get_buffer(),
            &[1, 2, 3]
        );
    }

    #[cfg(feature = "dev_crypto_bssl")]
    use tpm2_crypto_bssl::BsslCryptoProvider as TestCrypto;
    #[cfg(feature = "dev_crypto_crux")]
    use tpm2_crypto_crux::CruxCryptoProvider as TestCrypto;
    #[cfg(feature = "dev_crypto_rust")]
    use tpm2_crypto_rust::RustCryptoProvider as TestCrypto;

    /// `nameAlg || H(data...)` with SHA-256.
    fn sha256_name(data: &[&[u8]]) -> OwnedName {
        let mut digest = [0u8; 64];
        let d = tpm2::crypto::hash::<TestCrypto>(TpmiAlgHash::Sha256, data, &mut digest).unwrap();
        let mut name = alloc::vec![0x00, 0x0B];
        name.extend_from_slice(d.digest());
        OwnedName::new(&name).unwrap()
    }

    /// A loaded primary KEYEDHASH (sealed data) object in hierarchy `hierarchy` with
    /// `attributes` (`TPMA_OBJECT`).
    fn keyedhash_object(hierarchy: u32, attributes: u32) -> TransientObject {
        // KEYEDHASH, SHA-256, `attributes`, an empty authPolicy, the NULL scheme and a 32-octet
        // unique.
        let mut wire = alloc::vec![0x00, 0x08, 0x00, 0x0B];
        wire.extend_from_slice(&attributes.to_be_bytes());
        wire.extend_from_slice(&[0x00, 0x00, 0x00, 0x10, 0x00, 0x20]);
        wire.extend_from_slice(&[0x5A; 32]);
        let public = OwnedPublic::unmarshal_nullable(&mut &wire[..]).unwrap();
        let name = sha256_name(&[&wire]);
        let qualified_name = sha256_name(&[&hierarchy.to_be_bytes(), name.get_buffer()]);
        let (seed, seed_len) = TransientObject::seed_from_bytes(&[0x11; 32]);
        let mut private = [0u8; super::super::MAX_PRIVATE_KEY_SIZE];
        private[..5].copy_from_slice(b"hello");
        TransientObject {
            handle: 0x8000_0000,
            seed,
            seed_len,
            external: false,
            public_only: false,
            name,
            auth: OwnedAuth::new(&[0xAA; 32]).unwrap(),
            public,
            private,
            private_len: 5,
            qualified_name,
            hierarchy,
            st_clear: false,
        }
    }

    /// Asserts that two loaded objects are the same (but for their handles).
    fn assert_same_object(a: &TransientObject, b: &TransientObject) {
        assert_eq!(a.seed_bytes(), b.seed_bytes());
        assert_eq!(a.external, b.external);
        assert_eq!(a.public_only, b.public_only);
        assert_eq!(a.name.get_buffer(), b.name.get_buffer());
        assert_eq!(a.auth.get_buffer(), b.auth.get_buffer());
        assert_eq!(a.private_bytes(), b.private_bytes());
        assert_eq!(a.qualified_name.get_buffer(), b.qualified_name.get_buffer());
        assert_eq!(a.hierarchy, b.hierarchy);
        assert_eq!(a.st_clear, b.st_clear);
        let (mut wa, mut wb) = (
            [0u8; tpm2::TpmtPublic::MAX_SIZE],
            [0u8; tpm2::TpmtPublic::MAX_SIZE],
        );
        let la = a.public.as_tpmt().marshal(&mut wa);
        let lb = b.public.as_tpmt().marshal(&mut wb);
        assert_eq!(&wa[..la], &wb[..lb]);
    }

    /// An object survives the conversion to the reference's `OBJECT` and back; the image has
    /// the reference's attributes and members at their offsets.
    #[test]
    fn object_image_round_trips() {
        // fixedTPM | fixedParent | userWithAuth.
        let obj = keyedhash_object(Handle::RH_OWNER.0, 0x0000_0052);
        let mut img = [0xEEu8; OBJECT_SIZE + 4];
        object_image::<TestCrypto>(&obj, &mut img).unwrap();
        // Only the `OBJECT` is written.
        assert_eq!(img[OBJECT_SIZE..], [0xEE; 4]);
        let img = &img[..OBJECT_SIZE];
        assert_eq!(
            get_u32(img, obj::ATTRIBUTES),
            attr::OCCUPIED | attr::SPS_HIERARCHY | attr::PRIMARY
        );
        assert_eq!(get_u16(img, obj::PUBLIC + public::TYPE), alg::KEYEDHASH);
        assert_eq!(get_u16(img, obj::SENSITIVE + sensitive::AUTH), 32);
        assert_eq!(get_u16(img, obj::SENSITIVE + sensitive::VALUE), 5);
        assert_eq!(get_u16(img, obj::QUALIFIED_NAME), 34);
        assert_eq!(get_u32(img, obj::EVICT_HANDLE), 0);
        assert_eq!(get_u16(img, obj::NAME), 34);
        assert_eq!(get_u32(img, obj::HIERARCHY), Handle::RH_OWNER.0);
        assert!(!image_is_sequence(img));
        assert_same_object(&object_from_image::<TestCrypto>(img).unwrap(), &obj);
        // A short buffer is rejected both ways.
        assert!(object_image::<TestCrypto>(&obj, &mut [0u8; OBJECT_SIZE - 1]).is_err());
        assert!(object_from_image::<TestCrypto>(&img[..OBJECT_SIZE - 1]).is_none());

        // A child (its qualified name is not that of a child of the hierarchy) is not primary;
        // an object of the null hierarchy is temporary.
        let mut child = keyedhash_object(Handle::RH_ENDORSEMENT.0, 0x0000_0052);
        child.qualified_name = sha256_name(&[b"parent", child.name.get_buffer()]);
        let mut img = [0u8; OBJECT_SIZE];
        object_image::<TestCrypto>(&child, &mut img).unwrap();
        assert_eq!(
            get_u32(&img, obj::ATTRIBUTES),
            attr::OCCUPIED | attr::EPS_HIERARCHY
        );
        assert_same_object(&object_from_image::<TestCrypto>(&img).unwrap(), &child);
        let null = keyedhash_object(Handle::RH_NULL.0, 0x0000_0052);
        object_image::<TestCrypto>(&null, &mut img).unwrap();
        assert_eq!(
            get_u32(&img, obj::ATTRIBUTES),
            attr::OCCUPIED | attr::TEMPORARY
        );
        assert_same_object(&object_from_image::<TestCrypto>(&img).unwrap(), &null);
    }

    /// A session survives the conversion to the reference's `SESSION` and back, with the
    /// attributes and members of the reference's layout.
    #[test]
    fn session_image_round_trips() {
        let mut policy = crate::test_support::make_test_session_state(
            0x0300_0001,
            TpmSe::Policy,
            TpmiAlgHash::Sha256,
            tpm2::Tpm2bNonce::from_bytes(&[7u8; 16]).unwrap(),
            &[9u8; 32],
            None,
        );
        policy.policy_digest[..32].copy_from_slice(&[3; 32]);
        policy.policy_digest_len = 32;
        policy.policy_hash[..32].copy_from_slice(&[4; 32]);
        policy.policy_hash_len = 32;
        policy.is_cp_hash_defined = true;
        policy.is_auth_value_needed = true;
        policy.command_locality = 0x03;
        policy.command_code = 0x0000_0153;
        policy.start_time = 0x1122_3344_5566;
        policy.timeout = 77;
        policy.pcr_counter = Some(5);
        let mut img = [0xEEu8; SESSION_SIZE];
        session_image(&policy, &mut img).unwrap();
        assert_eq!(
            get_u32(&img, sess::ATTRIBUTES),
            sattr::IS_POLICY | sattr::IS_CP_HASH_DEFINED | sattr::IS_AUTH_VALUE_NEEDED
        );
        assert_eq!(img[sess::COMMAND_LOCALITY], 0x03);
        assert_eq!(img[sess::COMMAND_LOCALITY + 1], 0);
        assert_eq!(get_u16(&img, sess::SESSION_KEY), 32);
        assert_eq!(get_u16(&img, sess::NONCE_TPM), 16);
        assert_eq!(get_u16(&img, sess::U1), 32);
        assert_eq!(get_u16(&img, sess::U2), 32);
        let back = session_from_image(&img, 0x0300_0001).unwrap();
        let mut again = [0u8; SESSION_SIZE];
        session_image(&back, &mut again).unwrap();
        assert_eq!(img, again);
        assert_eq!(back.session_type, TpmSe::Policy);
        assert_eq!(back.start_time, policy.start_time);
        assert_eq!(back.pcr_counter, Some(5));
        assert!(back.is_cp_hash_defined && !back.is_name_hash_defined());
        // The handle type must match the session.
        assert!(session_from_image(&img, 0x0200_0001).is_none());
        assert!(session_from_image(&img[..SESSION_SIZE - 1], 0x0300_0001).is_none());

        // A bound, audited HMAC session.
        let mut hmac = crate::test_support::make_test_session_state(
            0x0200_0002,
            TpmSe::HMAC,
            TpmiAlgHash::Sha384,
            tpm2::Tpm2bNonce::from_bytes(&[1u8; 48]).unwrap(),
            &[2u8; 48],
            None,
        );
        hmac.bound_entity = sha256_name(&[b"bound"]);
        hmac.audit_digest = Some([6; 64]);
        hmac.audit_digest_len = 48;
        hmac.is_da_bound = true;
        session_image(&hmac, &mut img).unwrap();
        assert_eq!(
            get_u32(&img, sess::ATTRIBUTES),
            sattr::IS_AUDIT | sattr::IS_BOUND | sattr::IS_DA_BOUND
        );
        assert_eq!(get_u16(&img, sess::U1), 34);
        assert_eq!(get_u16(&img, sess::U2), 48);
        let back = session_from_image(&img, 0x0200_0002).unwrap();
        assert_eq!(
            back.bound_entity.get_buffer(),
            hmac.bound_entity.get_buffer()
        );
        assert_eq!(back.audit_digest_len, 48);
        session_image(&back, &mut again).unwrap();
        assert_eq!(img, again);
    }

    /// A sequence of `ty` with the running states `states` and the given `auth`.
    fn sequence(ty: SequenceType, states: &[StreamingHashState]) -> ActiveSequence {
        let mut hash_states = [StreamingHashState::default(); 4];
        hash_states[..states.len()].copy_from_slice(states);
        ActiveSequence {
            handle: 0x8000_0001,
            auth: OwnedAuth::new(b"seq").unwrap(),
            sequence_type: ty,
            first_block: true,
            ticket_safe: true,
            hash_states,
            mu_state: None,
        }
    }

    /// Asserts that two sequences finish to the same digests after the same further data.
    fn assert_same_sequence(a: &ActiveSequence, b: &ActiveSequence, count: usize) {
        assert_eq!(a.auth.get_buffer(), b.auth.get_buffer());
        assert_eq!(
            (a.first_block, a.ticket_safe),
            (b.first_block, b.ticket_safe)
        );
        for i in 0..count {
            let (mut x, mut y) = (a.hash_states[i], b.hash_states[i]);
            x.update(b"more");
            y.update(b"more");
            assert_eq!(x.finalize(), y.finalize());
        }
    }

    /// Hash, HMAC and event sequences survive the conversion to the reference's sequence object
    /// and back; the hash states have the reference's type, algorithm and a zero `def`.
    #[test]
    fn sequence_image_round_trips() {
        let data: [u8; 150] = core::array::from_fn(|i| i as u8);
        let mut sha384 = StreamingHashState::new(TpmiAlgHash::Sha384);
        sha384.update(&data);
        let hash = sequence(
            SequenceType::Hash {
                alg: TpmiAlgHash::Sha384,
            },
            &[sha384],
        );
        let mut img = [0xEEu8; SEQUENCE_OBJECT_SIZE];
        sequence_image::<TestCrypto>(&hash, &mut img, |_| Err(TpmRc::FAILURE)).unwrap();
        assert_eq!(
            get_u32(&img, seq::ATTRIBUTES),
            attr::OCCUPIED
                | attr::TEMPORARY
                | attr::HASH_SEQ
                | attr::FIRST_BLOCK
                | attr::TICKET_SAFE
        );
        assert_eq!(get_u32(&img, seq::OBJECT_ATTRIBUTES), TPMA_OBJECT_NO_DA);
        let st = seq::STATE;
        assert_eq!(img[st + seq::HASH_TYPE], seq::TYPE_HASH);
        assert_eq!(get_u16(&img, st + seq::HASH_ALG), 0x000C);
        assert_eq!(get_u64(&img, st + seq::HASH_DEF), 0);
        assert!(image_is_sequence(&img));
        let back = sequence_from_image(&img).unwrap();
        assert!(matches!(
            back.sequence_type,
            SequenceType::Hash {
                alg: TpmiAlgHash::Sha384
            }
        ));
        assert_same_sequence(&hash, &back, 1);

        // HMAC with a short and with a long key (the reference keeps the key block only).
        for key in [&b"short key"[..], &[0x42u8; 100][..]] {
            let mut inner = StreamingHashState::new(TpmiAlgHash::Sha256);
            let mut block = [0x36u8; 64];
            let mut digest = [0u8; 64];
            let key_bytes = if key.len() > 64 {
                tpm2::crypto::hash::<TestCrypto>(TpmiAlgHash::Sha256, &[key], &mut digest).unwrap();
                &digest[..32]
            } else {
                key
            };
            for (b, k) in block.iter_mut().zip(key_bytes) {
                *b ^= k;
            }
            inner.update(&block);
            inner.update(&data[..70]);
            let hmac = sequence(
                SequenceType::Hmac {
                    hash_alg: TpmiAlgHash::Sha256,
                    key: OwnedSensitiveData::new(key).unwrap(),
                },
                &[inner],
            );
            sequence_image::<TestCrypto>(&hmac, &mut img, |_| Err(TpmRc::FAILURE)).unwrap();
            assert_eq!(img[st + seq::HASH_TYPE], seq::TYPE_HMAC);
            assert_eq!(get_u16(&img, st + seq::HMAC_KEY), 64);
            let back = sequence_from_image(&img).unwrap();
            assert_same_sequence(&hmac, &back, 1);
            // The restored key is the block's key (the digest of a long key).
            let SequenceType::Hmac { key: restored, .. } = &back.sequence_type else {
                panic!("not an HMAC sequence");
            };
            assert_eq!(restored.get_buffer(), key_bytes);
        }

        // Event: one state per implemented hash.
        let mut states = [StreamingHashState::default(); ActiveSequence::EVENT_HASH_COUNT];
        let algs = [TpmiAlgHash::Sha1, TpmiAlgHash::Sha256, TpmiAlgHash::Sha384];
        for (i, st) in states.iter_mut().enumerate() {
            *st = StreamingHashState::new(
                algs.get(i)
                    .copied()
                    .or(crate::handler::capability::sha512())
                    .unwrap(),
            );
            st.update(&data[..i * 40 + 1]);
        }
        let event = sequence(SequenceType::Event, &states);
        sequence_image::<TestCrypto>(&event, &mut img, |_| Err(TpmRc::FAILURE)).unwrap();
        for i in 0..ActiveSequence::EVENT_HASH_COUNT {
            assert_eq!(
                img[st + i * HASH_STATE_SIZE + seq::HASH_TYPE],
                seq::TYPE_HASH
            );
        }
        let back = sequence_from_image(&img).unwrap();
        assert!(matches!(back.sequence_type, SequenceType::Event));
        assert_same_sequence(&event, &back, ActiveSequence::EVENT_HASH_COUNT);
        assert!(sequence_from_image(&img[..SEQUENCE_OBJECT_SIZE - 1]).is_none());
    }
}
