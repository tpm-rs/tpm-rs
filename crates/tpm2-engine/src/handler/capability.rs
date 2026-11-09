use crate::Platform;
use crate::storage::IndexState;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{ECCParameters, GetCapability, TestParms};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, TpmCap, TpmEccCurve, TpmPt};
use tpm2::{
    Tpm2bEccParameter, TpmaAlgorithm, TpmaCc, TpmlAlgProperty, TpmlCca, TpmlEccCurve, TpmlHandle,
    TpmlTaggedTpmProperty, TpmsAlgProperty, TpmsCapabilityData, TpmsTaggedProperty,
};

/// The firmware-limited and SVN-limited hierarchy handles reported by `TPM_CAP_HANDLES`
/// (`TPM_HT_PERMANENT`) and, except for those of `TPM_RH_NULL`, `TPM_CAP_AUTH_POLICIES`, on a TPM
/// that supports them. TPM 2.0 Part 3, TPM2_GetCapability: "For this capability,
/// `TPM_RH_SVN_OWNER_BASE`, `TPM_RH_SVN_ENDORSEMENT_BASE`, `TPM_RH_SVN_PLATFORM_BASE`, and
/// `TPM_RH_NULL_BASE` handles may be returned. There are separate handles for each SVN from 0 to
/// the firmware's current SVN (up to `UINT16_MAX`), which are not returned. Instead, only the
/// handles associated with SVN 0 are returned".
const LIMITED_HIERARCHY_HANDLES: [u32; 8] = [
    tpm2::Handle::RH_FW_OWNER.0,
    tpm2::Handle::RH_FW_ENDORSEMENT.0,
    tpm2::Handle::RH_FW_PLATFORM.0,
    tpm2::Handle::RH_FW_NULL.0,
    tpm2::Handle::RH_SVN_OWNER_BASE.0,
    tpm2::Handle::RH_SVN_ENDORSEMENT_BASE.0,
    tpm2::Handle::RH_SVN_PLATFORM_BASE.0,
    tpm2::Handle::RH_SVN_NULL_BASE.0,
];

/// ECC curves implemented by this TPM in ascending `TPM_ECC_CURVE` order (`TPM_CAP_ECC_CURVES`;
/// the curve features of `tpm2` (`nist_p256`, `bn_p256`, ...), the optional ones forwarded by
/// the features of the same name of this crate).
pub(crate) const IMPLEMENTED_CURVES: &[TpmEccCurve] = &[
    #[cfg(feature = "nist_p192")]
    TpmEccCurve::NistP192,
    TpmEccCurve::NistP224,
    TpmEccCurve::NistP256,
    TpmEccCurve::NistP384,
    TpmEccCurve::NistP521,
    TpmEccCurve::BNP256,
    #[cfg(feature = "bn_p638")]
    TpmEccCurve::BNP638,
    #[cfg(feature = "sm2_p256")]
    TpmEccCurve::SM2P256,
];

/// Whether the `tpm2` features of this build enable `alg`: SHA-512 is optional (the `sha512`
/// feature of `tpm2`; without it the TPM is like a C reference built without `ALG_SHA512`), and so
/// are Camellia and CMAC (the `camellia*` and `cmac` features of `tpm2`, forwarded by those of
/// this crate), as are SM2, EC-Schnorr and ECMQV (`sm2`, `ecschnorr`, `ecmqv`); every other
/// algorithm of [`IMPLEMENTED_ALGORITHMS`] is a default feature.
pub(crate) fn is_enabled_by_features(alg: Alg) -> bool {
    match alg {
        Alg::SHA1 | Alg::SHA256 | Alg::SHA384 | Alg::SHA512 => {
            tpm2::TpmiAlgHash::try_from(alg).is_ok()
        }
        Alg::SM2 => cfg!(feature = "sm2"),
        Alg::ECSCHNORR => cfg!(feature = "ecschnorr"),
        Alg::ECMQV => cfg!(feature = "ecmqv"),
        // Camellia with any key size (the `camellia128`/`camellia192`/`camellia256` features).
        Alg::CAMELLIA => [128, 192, 256]
            .iter()
            .any(|&bits| tpm2::AlgSym::from_parts(Alg::CAMELLIA, bits).is_ok()),
        // CMAC (the `cmac` feature).
        Alg::CMAC => tpm2::TpmiAlgMacScheme::try_from(Alg::CMAC).is_ok(),
        Alg::MLKEM => cfg!(feature = "mlkem"),
        Alg::MLDSA => cfg!(feature = "mldsa"),
        Alg::HASH_MLDSA => cfg!(feature = "hash_mldsa"),
        _ => true,
    }
}

/// Whether `alg` is implemented by this TPM: listed in [`IMPLEMENTED_ALGORITHMS`] and enabled by
/// the `tpm2` features of the build ([`is_enabled_by_features`]).
pub(crate) fn is_implemented_algorithm(alg: Alg) -> bool {
    IMPLEMENTED_ALGORITHMS
        .iter()
        .any(|&(implemented, _)| implemented == alg)
        && is_enabled_by_features(alg)
}

/// Whether this TPM implements SHA-512 (the `sha512` feature of `tpm2`): the largest digest of
/// `TpmiAlgHash` is then 64 octets.
const SHA512: bool = tpm2::TpmiAlgHash::MAX_DIGEST_BYTES == 64;

/// Whether `hash` is SHA-512, compared by its algorithm ID: the `TpmiAlgHash::Sha512` variant exists
/// only with the `sha512` feature of `tpm2`.
pub(crate) fn is_sha512(hash: tpm2::TpmiAlgHash) -> bool {
    Alg::from(hash) == Alg::SHA512
}

/// SHA-512, if this TPM implements it (the `sha512` feature of `tpm2`).
pub(crate) fn sha512() -> Option<tpm2::TpmiAlgHash> {
    tpm2::TpmiAlgHash::try_from(Alg::SHA512).ok()
}

/// The largest RSA key of this TPM's profile, in bits: 2048 (`RSA_1024` and `RSA_2048`), 3072 with
/// the `rsa3072` feature or 4096 with the `rsa4096` feature (the `rsa*` features of `tpm2`, which
/// size `TPM2B_PUBLIC_KEY_RSA`).
const MAX_RSA_KEY_BITS: usize = tpm2::TpmiRsaKeyBits::MAX_PUB_KEY_BITS as usize;
/// `MAX_RSA_KEY_BYTES`: the bytes of the largest RSA modulus.
const MAX_RSA_KEY_BYTES: usize = MAX_RSA_KEY_BITS / 8;
/// `RSA_PRIVATE_SIZE`. TPM 2.0 Part 2, TPM2B_PRIVATE_KEY_RSA: "`RSA_PRIVATE_SIZE` is a vendor
/// specific value that can be (`MAX_RSA_KEY_BYTES` / 2) or ((`MAX_RSA_KEY_BYTES` \* 5) / 2)."
/// This TPM (like the TCG reference profile) uses the larger value.
const RSA_PRIVATE_SIZE: usize = (MAX_RSA_KEY_BYTES * 5) / 2;
/// The largest digest of the implemented hashes, in bytes: SHA-512, or SHA-384 without SHA-512
/// (`sha512`, the `sha512` feature of `tpm2`).
const fn max_digest_size(sha512: bool) -> usize {
    if sha512 { 64 } else { 48 }
}
/// `sizeof(TPM2B_DIGEST)` (and `sizeof(TPM2B_AUTH)`): a `UINT16` size and the largest digest.
const fn sizeof_tpm2b_digest(sha512: bool) -> usize {
    2 + max_digest_size(sha512)
}
/// `MAX_ECC_KEY_BYTES`: the bytes of the largest implemented curve (NIST P-521, or BN P-638 with
/// `bn_p638`).
const MAX_ECC_KEY_BYTES: usize = tpm2::TpmEccCurve::MAX_ECC_KEY_BYTES;
/// `MAX_SYM_DATA`: the largest `TPM2B_SENSITIVE_DATA` (Part 2: "For interoperability,
/// `MAX_SYM_DATA` should be 128.").
const MAX_SYM_DATA: usize = 128;
/// `MAX_SYM_KEY_BYTES`: the bytes of the largest symmetric key (AES-256).
const MAX_SYM_KEY_BYTES: usize = 32;
/// `PRIVATE_VENDOR_SPECIFIC_BYTES`. Part 2: "The value for `PRIVATE_VENDOR_SPECIFIC_BYTES` is
/// determined by the vendor." This TPM (like the TCG reference) uses `RSA_PRIVATE_SIZE`.
const PRIVATE_VENDOR_SPECIFIC_BYTES: usize = RSA_PRIVATE_SIZE;

/// The larger of `a` and `b`.
const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// `sizeof(TPMU_SENSITIVE_COMPOSITE)`. Part 2, Table "Definition of TPMU_SENSITIVE_COMPOSITE
/// Union": "rsa | TPM2B_PRIVATE_KEY_RSA", "ecc | TPM2B_ECC_PARAMETER", "bits |
/// TPM2B_SENSITIVE_DATA", "sym | TPM2B_SYM_KEY", "any | TPM2B_PRIVATE_VENDOR_SPECIFIC" (the
/// ML-DSA and ML-KEM members, seeds of 32 and 64 octets, are smaller).
const SIZEOF_TPMU_SENSITIVE_COMPOSITE: usize = max(
    max(2 + RSA_PRIVATE_SIZE, 2 + MAX_ECC_KEY_BYTES),
    max(
        max(2 + MAX_SYM_DATA, 2 + MAX_SYM_KEY_BYTES),
        2 + PRIVATE_VENDOR_SPECIFIC_BYTES,
    ),
);
/// `sizeof(TPMT_SENSITIVE)`. Part 2, Table "Definition of TPMT_SENSITIVE Structure":
/// "sensitiveType | TPMI_ALG_PUBLIC", "authValue | TPM2B_AUTH", "seedValue | TPM2B_DIGEST",
/// "\[sensitiveType\]sensitive | TPMU_SENSITIVE_COMPOSITE".
const fn sizeof_tpmt_sensitive(sha512: bool) -> usize {
    2 + sizeof_tpm2b_digest(sha512) + sizeof_tpm2b_digest(sha512) + SIZEOF_TPMU_SENSITIVE_COMPOSITE
}
/// `sizeof(_PRIVATE)`. Part 2, Table "Definition of _PRIVATE Structure": "integrityOuter |
/// TPM2B_DIGEST", "integrityInner | TPM2B_DIGEST", "sensitive | TPM2B_SENSITIVE" (Table
/// "Definition of TPM2B_SENSITIVE Structure": "size | UINT16", "sensitiveArea |
/// TPMT_SENSITIVE").
const fn sizeof_private(sha512: bool) -> usize {
    sizeof_tpm2b_digest(sha512) + sizeof_tpm2b_digest(sha512) + 2 + sizeof_tpmt_sensitive(sha512)
}
/// `sizeof(TPMU_ENCRYPTED_SECRET)`. Part 2, Table "Definition of TPMU_ENCRYPTED_SECRET Union":
/// "ecc\[sizeof(TPMS_ECC_POINT)\]", "rsa\[MAX_RSA_KEY_BYTES\]",
/// "symmetric\[sizeof(TPM2B_DIGEST)\]", "keyedHash\[sizeof(TPM2B_DIGEST)\]" and, with ML-KEM
/// (`mlkem`), "mlkem\[MAX_MLKEM_CT_SIZE\]"; a `TPMS_ECC_POINT` is two `TPM2B_ECC_PARAMETER`s.
const fn sizeof_tpmu_encrypted_secret(sha512: bool, mlkem: bool) -> usize {
    max(
        max(
            max(2 * (2 + MAX_ECC_KEY_BYTES), MAX_RSA_KEY_BYTES),
            sizeof_tpm2b_digest(sha512),
        ),
        if mlkem { MAX_MLKEM_CT_SIZE } else { 0 },
    )
}
/// Whether this TPM implements ML-KEM (`mlkem`).
const MLKEM: bool = cfg!(feature = "mlkem");
/// Whether this TPM implements ML-DSA (`mldsa`).
const MLDSA: bool = cfg!(feature = "mldsa");
/// `MAX_MLKEM_CT_SIZE`: the largest ML-KEM ciphertext (ML-KEM-1024).
const MAX_MLKEM_CT_SIZE: usize = 1568;
/// `MAX_MLKEM_PUB_SIZE`: the largest ML-KEM encapsulation key (ML-KEM-1024).
const MAX_MLKEM_PUB_SIZE: usize = 1568;
/// `MAX_MLDSA_PUB_SIZE`: the largest ML-DSA verification key (ML-DSA-87).
const MAX_MLDSA_PUB_SIZE: usize = 2592;
/// `sizeof(TPMU_PUBLIC_PARMS)`: the largest member of Part 2, Table "Definition of
/// TPMU_PUBLIC_PARMS Union" in this profile, `eccDetail` (`TPMS_ECC_PARMS`: "symmetric |
/// TPMT_SYM_DEF_OBJECT+" (algorithm, keyBits and mode: 6), "scheme | TPMT_ECC_SCHEME+" (scheme
/// and its largest details, `TPMS_SCHEME_ECDAA` "hashAlg | TPMI_ALG_HASH" and "count |
/// UINT16": 6), "curveID | TPMI_ECC_CURVE" (2) and "kdf | TPMT_KDF_SCHEME+" (4)); `rsaDetail`
/// (`TPMS_RSA_PARMS`: symmetric 6, scheme 6, keyBits 2 and exponent 4) is as large,
/// `keyedHashDetail` and `symDetail` are 6, `asymDetail` is 12.
const SIZEOF_TPMU_PUBLIC_PARMS: usize = 6 + 6 + 2 + 4;
/// `sizeof(TPMU_PUBLIC_ID)`: the largest member of Part 2, Table "Definition of TPMU_PUBLIC_ID
/// Union", `rsa` ("TPM2B_PUBLIC_KEY_RSA") or, with ML-KEM (`mlkem`) or ML-DSA (`mldsa`), `mlkem`
/// ("TPM2B_PUBLIC_KEY_MLKEM") or `mldsa` ("TPM2B_PUBLIC_KEY_MLDSA"); `ecc` (`TPMS_ECC_POINT`, two
/// `TPM2B_ECC_PARAMETER`s: 136), `keyedHash`/`sym` (`TPM2B_DIGEST`: 66) and `derive`
/// (`TPMS_DERIVE`, two `TPM2B_LABEL`s: 68) are smaller. (The `TPMS_MLKEM_PARMS` and
/// `TPMS_MLDSA_PARMS` members of `TPMU_PUBLIC_PARMS`, 8 and 3 octets, are smaller than
/// `eccDetail`.)
const fn sizeof_tpmu_public_id(mlkem: bool, mldsa: bool) -> usize {
    max(
        2 + MAX_RSA_KEY_BYTES,
        max(
            if mlkem { 2 + MAX_MLKEM_PUB_SIZE } else { 0 },
            if mldsa { 2 + MAX_MLDSA_PUB_SIZE } else { 0 },
        ),
    )
}
/// `sizeof(TPMT_PUBLIC)`. Part 2, Table "Definition of TPMT_PUBLIC Structure": "type |
/// TPMI_ALG_PUBLIC", "nameAlg | +TPMI_ALG_HASH", "objectAttributes | TPMA_OBJECT", "authPolicy
/// | TPM2B_DIGEST", "\[type\]parameters | TPMU_PUBLIC_PARMS", "\[type\]unique |
/// TPMU_PUBLIC_ID". Part 2, "Data Alignment": "When used in a table to indicate a maximum size,
/// the sizeof() function returns the octet-aligned size of the structure, with no padding."
/// (The C references use the padded C `sizeof`, 356; their `bug-fix-template-size.patch`
/// fixes that.)
const fn sizeof_tpmt_public(sha512: bool, mlkem: bool, mldsa: bool) -> usize {
    2 + 2
        + 4
        + sizeof_tpm2b_digest(sha512)
        + SIZEOF_TPMU_PUBLIC_PARMS
        + sizeof_tpmu_public_id(mlkem, mldsa)
}
/// `sizeof(TPMT_PUBLIC)` of this TPM (350 octets, or 334 without SHA-512; 1662 with ML-KEM and
/// 2686 with ML-DSA).
pub(crate) const SIZEOF_TPMT_PUBLIC: usize = sizeof_tpmt_public(SHA512, MLKEM, MLDSA);

/// The expected profile-dependent sizes for the largest RSA key `rsa_bits`, with and without
/// SHA-512: `(sizeof(_PRIVATE), sizeof(TPMU_ENCRYPTED_SECRET), sizeof(TPMT_PUBLIC))` (the values of
/// the C references' `TpmTypes.h` structures for the same profile, without padding).
const fn expected_sizes(rsa_bits: usize, sha512: bool) -> (usize, usize, usize) {
    match (rsa_bits, sha512) {
        (2048, true) => (910, 256, 350),
        (2048, false) => (846, 256, 334),
        (3072, true) => (1230, 384, 478),
        (3072, false) => (1166, 384, 462),
        (4096, true) => (1550, 512, 606),
        (4096, false) => (1486, 512, 590),
        _ => (0, 0, 0),
    }
}

const _: () = {
    let (private, secret, public) = expected_sizes(MAX_RSA_KEY_BITS, true);
    assert!(
        sizeof_private(true) == private
            && sizeof_tpmu_encrypted_secret(true, false) == secret
            && sizeof_tpmt_public(true, false, false) == public
    );
    let (private, secret, public) = expected_sizes(MAX_RSA_KEY_BITS, false);
    assert!(
        sizeof_private(false) == private
            && sizeof_tpmu_encrypted_secret(false, false) == secret
            && sizeof_tpmt_public(false, false, false) == public
    );
    // ML-KEM-1024 ciphertexts and encapsulation keys and ML-DSA-87 verification keys are larger
    // than any RSA member (the values of the tcgtpm v185 reference's `TpmTypes.h` with ML-KEM and
    // ML-DSA).
    assert!(
        sizeof_tpmu_encrypted_secret(true, true) == 1568
            && sizeof_tpmt_public(true, true, false) == 1662
            && sizeof_tpmt_public(true, true, true) == 2686
    );
};

// The capacities of the profile-dependent buffers of `tpm2`, which follow from its features, are
// those of this TPM's profile (TPM 2.0 Part 2): `TPM2B_PRIVATE` "buffer\[size\]
// {:sizeof(_PRIVATE)}", `TPM2B_ENCRYPTED_SECRET` "secret\[size\]{:sizeof(TPMU_ENCRYPTED_SECRET)}"
// and `TPM2B_TEMPLATE` "buffer\[size\]{:sizeof(TPMT_PUBLIC)}".
const _: () = assert!(
    tpm2::Tpm2bPrivate::CAP == sizeof_private(SHA512)
        && tpm2::Tpm2bEncryptedSecret::CAP == sizeof_tpmu_encrypted_secret(SHA512, MLKEM)
        && tpm2::Tpm2bTemplate::CAP == SIZEOF_TPMT_PUBLIC
);

/// `TPM_PT_ML_PARAMETER_SETS` (`TPMA_ML_PARAMETER_SET`): every parameter set of the implemented
/// ML-KEM (`mlkem`) and ML-DSA (`mldsa`), and external-mu support with ML-DSA.
#[cfg(any(feature = "mlkem", feature = "mldsa"))]
fn ml_parameter_sets() -> tpm2::TpmaMlParameterSet {
    let mut sets = tpm2::TpmaMlParameterSet::empty();
    if MLKEM {
        sets |= tpm2::TpmaMlParameterSet::ML_KEM_512
            | tpm2::TpmaMlParameterSet::ML_KEM_768
            | tpm2::TpmaMlParameterSet::ML_KEM_1024;
    }
    if MLDSA {
        sets |= tpm2::TpmaMlParameterSet::ML_DSA_44
            | tpm2::TpmaMlParameterSet::ML_DSA_65
            | tpm2::TpmaMlParameterSet::ML_DSA_87
            | tpm2::TpmaMlParameterSet::EXT_MU;
    }
    sets
}

/// Algorithms implemented by this TPM together with their attributes (`s_algorithms` in the C
/// reference `AlgorithmCap.c`). This single table backs both `TPM2_GetCapability(TPM_CAP_ALGS)`
/// and the implemented-algorithm check of `TPM2_IncrementalSelfTest` (`g_implementedAlgorithms`).
pub(crate) const IMPLEMENTED_ALGORITHMS: [(Alg, TpmaAlgorithm); 35] = [
    (
        Alg::RSA,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::OBJECT),
    ),
    (Alg::SHA1, TpmaAlgorithm::HASH),
    (Alg::HMAC, TpmaAlgorithm::HASH.union(TpmaAlgorithm::SIGNING)),
    (Alg::AES, TpmaAlgorithm::SYMMETRIC),
    (Alg::MGF1, TpmaAlgorithm::HASH.union(TpmaAlgorithm::METHOD)),
    (
        Alg::KEYEDHASH,
        TpmaAlgorithm::HASH
            .union(TpmaAlgorithm::OBJECT)
            .union(TpmaAlgorithm::SIGNING)
            .union(TpmaAlgorithm::ENCRYPTING),
    ),
    (
        Alg::XOR,
        TpmaAlgorithm::SYMMETRIC.union(TpmaAlgorithm::HASH),
    ),
    (Alg::SHA256, TpmaAlgorithm::HASH),
    (Alg::SHA384, TpmaAlgorithm::HASH),
    (Alg::SHA512, TpmaAlgorithm::HASH),
    (
        Alg::RSASSA,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::SIGNING),
    ),
    (
        Alg::RSAES,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::ENCRYPTING),
    ),
    (
        Alg::RSAPSS,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::SIGNING),
    ),
    (
        Alg::OAEP,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::ENCRYPTING),
    ),
    (
        Alg::ECDSA,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::SIGNING),
    ),
    (
        Alg::ECDH,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::METHOD),
    ),
    (
        Alg::ECDAA,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::SIGNING),
    ),
    // SM2 is a signing and a key-exchange scheme (`AlgorithmCap.c`).
    (
        Alg::SM2,
        TpmaAlgorithm::ASYMMETRIC
            .union(TpmaAlgorithm::SIGNING)
            .union(TpmaAlgorithm::METHOD),
    ),
    (
        Alg::ECSCHNORR,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::SIGNING),
    ),
    (
        Alg::ECMQV,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::METHOD),
    ),
    (
        Alg::KDF1_SP800_56A,
        TpmaAlgorithm::HASH.union(TpmaAlgorithm::METHOD),
    ),
    (Alg::KDF2, TpmaAlgorithm::HASH.union(TpmaAlgorithm::METHOD)),
    (
        Alg::KDF1_SP800_108,
        TpmaAlgorithm::HASH.union(TpmaAlgorithm::METHOD),
    ),
    (
        Alg::ECC,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::OBJECT),
    ),
    (Alg::SYMCIPHER, TpmaAlgorithm::OBJECT),
    (Alg::CAMELLIA, TpmaAlgorithm::SYMMETRIC),
    (
        Alg::CMAC,
        TpmaAlgorithm::SYMMETRIC.union(TpmaAlgorithm::SIGNING),
    ),
    (
        Alg::CTR,
        TpmaAlgorithm::SYMMETRIC.union(TpmaAlgorithm::ENCRYPTING),
    ),
    (
        Alg::OFB,
        TpmaAlgorithm::SYMMETRIC.union(TpmaAlgorithm::ENCRYPTING),
    ),
    (
        Alg::CBC,
        TpmaAlgorithm::SYMMETRIC.union(TpmaAlgorithm::ENCRYPTING),
    ),
    (
        Alg::CFB,
        TpmaAlgorithm::SYMMETRIC.union(TpmaAlgorithm::ENCRYPTING),
    ),
    (
        Alg::ECB,
        TpmaAlgorithm::SYMMETRIC.union(TpmaAlgorithm::ENCRYPTING),
    ),
    // `mlkem`: ML-KEM keys are asymmetric object types (version 185 `AlgorithmCap.c`).
    (
        Alg::MLKEM,
        TpmaAlgorithm::ASYMMETRIC.union(TpmaAlgorithm::OBJECT),
    ),
    // `mldsa`: ML-DSA keys are asymmetric signing object types.
    (
        Alg::MLDSA,
        TpmaAlgorithm::ASYMMETRIC
            .union(TpmaAlgorithm::OBJECT)
            .union(TpmaAlgorithm::SIGNING),
    ),
    // `hash_mldsa`: HashML-DSA keys, likewise.
    (
        Alg::HASH_MLDSA,
        TpmaAlgorithm::ASYMMETRIC
            .union(TpmaAlgorithm::OBJECT)
            .union(TpmaAlgorithm::SIGNING),
    ),
];

/// Whether `capability` unmarshals as a `TPM_CAP` of this TPM (see `get_capability`):
/// `TPM_CAP_FIRST`..`TPM_CAP_ACT`, the two SPDM capabilities with the `sec-channel` feature,
/// and `TPM_CAP_VENDOR_PROPERTY`, as the TCG reference's `TPM_CAP` unmarshaler accepts.
pub(crate) fn is_unmarshalable_capability(capability: u32) -> bool {
    /// `TPM_CAP_VENDOR_PROPERTY`.
    const CAP_VENDOR_PROPERTY: u32 = 0x100;
    /// The last implemented capability before `TPM_CAP_VENDOR_PROPERTY`.
    const LAST_CAP: TpmCap = if cfg!(feature = "sec-channel") {
        TpmCap::SpdmSessionInfo
    } else {
        TpmCap::ACT
    };
    capability <= LAST_CAP as u32 || capability == CAP_VENDOR_PROPERTY
}

impl<'b, P: Platform> CommandHandler<'b, P> {
    /// Handles the [TpmCc::GetCapability] (`0x17A`) command.
    ///
    /// # Description
    /// This command returns various information about the TPM, including its properties,
    /// supported algorithms, current PCR allocations, and handles of loaded entities.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 30.1 (TPM2_GetCapability).
    ///
    /// # Relationships
    /// - Clients query [TpmCc::GetCapability] to check capabilities before running commands that might depend on them.
    /// - Can be used to list handles of objects loaded by [TpmCc::Load](load.rs)
    ///   or active sessions created by [TpmCc::StartAuthSession](session.rs).
    pub fn get_capability(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        // TPM 2.0 Part 2, TPM_CAP, Table "Definition of (UINT32) TPM_CAP Constants" ends with
        // "#TPM_RC_VALUE": the capability is validated while it is unmarshaled, before the
        // later parameters and the trailing-bytes check. The table also lists
        // `TPM_CAP_PUB_KEYS` and `TPM_CAP_SPDM_SESSION_INFO` (added in version 184), which are
        // implemented with secure channel support (the `sec-channel` feature); the spec is
        // silent on capabilities a TPM does not implement, so like the TCG reference (whose
        // `TPM_CAP` unmarshaler accepts `TPM_CAP_FIRST`..`TPM_CAP_ACT`, the two SPDM
        // capabilities with `SEC_CHANNEL_SUPPORT`, and `TPM_CAP_VENDOR_PROPERTY`) they fail
        // here without it.
        if let Some(b) = request.remaining_slice().get(..4)
            && !is_unmarshalable_capability(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let cmd = request.try_unmarshal_command::<GetCapability>([])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let response = request.into_response();
        self.with_capability_data(
            &cmd,
            Position::parameter(2),
            |this, capability_data, more_data| {
                let rsp = responses::GetCapability {
                    more_data,
                    capability_data,
                };
                this.write_response_message(response, &rsp, &session_responses[..num_sessions])
            },
        )
    }

    /// Computes the capability data `TPM2_GetCapability(cmd.capability, cmd.property,
    /// cmd.propertyCount)` reports and its `moreData`, and passes them to `f` (the data may
    /// borrow from the TPM state). Errors about `property` are reported at `property_pos`
    /// (parameter 2 of `TPM2_GetCapability`; `TPM2_PolicyCapability` reuses this with its own
    /// position).
    pub(crate) fn with_capability_data<Res>(
        &mut self,
        cmd: &GetCapability,
        property_pos: Position,
        f: impl FnOnce(&Self, TpmsCapabilityData<'_>, bool) -> Result<Res, TpmRc>,
    ) -> Result<Res, TpmRc> {
        let mut more_data = false;

        // The key Names of the SPDM session protecting this command, for
        // `TPM_CAP_SPDM_SESSION_INFO` (with its reserved property 0).
        #[cfg(feature = "sec-channel")]
        let spdm_session_names = if cmd.capability == TpmCap::SpdmSessionInfo && cmd.property == 0 {
            self.context.spdm_session_names()?
        } else {
            None
        };

        let capability_data = match cmd.capability {
            TpmCap::TPMProperties => {
                let active_sessions_count =
                    (self.context.state.active_sessions.iter().flatten().count()
                        + self
                            .context
                            .state
                            .nv
                            .reset
                            .saved_sessions
                            .iter()
                            .flatten()
                            .count()) as u32;
                // Authorization sessions currently held in TPM RAM (`SessionCapGetLoadedNumber`).
                let loaded_session_count =
                    self.context.state.active_sessions.iter().flatten().count() as u32;
                // Free object slots, shared by transient objects and sequence objects
                // (`ObjectCapGetTransientAvail`).
                let transient_avail = (crate::engine::MAX_LOADED_OBJECTS as u32).saturating_sub(
                    (self
                        .context
                        .state
                        .transient_objects
                        .iter()
                        .flatten()
                        .count()
                        + self.context.state.active_sequences.iter().flatten().count())
                        as u32,
                );
                let (persistent_count, nv_index_count) = {
                    let storage = &mut self.context.state.nv.index;
                    if let Ok(toc) = storage.items() {
                        let p = toc
                            .iter()
                            .filter(|item| item.in_use != 0 && (item.handle >> 24) == 0x81)
                            .count() as u32;
                        let n = toc
                            .iter()
                            .filter(|item| item.in_use != 0 && (item.handle >> 24) == 0x01)
                            .count() as u32;
                        (p, n)
                    } else {
                        (0, 0)
                    }
                };
                // The reference's NV space ledger (`NvCapGetPersistentAvail()`,
                // `NvCapGetCounterNumber()`, `NvCapGetCounterAvail()`), see
                // `storage::nv_capacity`.
                let nv_usage = crate::storage::nv_capacity::scan(&self.context.state.nv.index)
                    .unwrap_or_default();

                let mut permanent_attr = tpm2::TpmaPermanent::empty();
                if self.context.state.nv.persistent.owner_auth.get_size() > 0 {
                    permanent_attr |= tpm2::TpmaPermanent::OWNER_AUTH_SET;
                }
                if self.context.state.nv.persistent.endorsement_auth.get_size() > 0 {
                    permanent_attr |= tpm2::TpmaPermanent::ENDORSEMENT_AUTH_SET;
                }
                if self.context.state.nv.persistent.lockout_auth.get_size() > 0 {
                    permanent_attr |= tpm2::TpmaPermanent::LOCKOUT_AUTH_SET;
                }
                if self.context.state.nv.persistent.disable_clear {
                    permanent_attr |= tpm2::TpmaPermanent::DISABLE_CLEAR;
                }
                // `gp.failedTries >= gp.maxTries`: with `maxTries == 0` the TPM is in lockout.
                if self.context.state.nv.persistent.failed_tries
                    >= self.context.state.nv.persistent.max_tries
                {
                    permanent_attr |= tpm2::TpmaPermanent::IN_LOCKOUT;
                }
                // In this implementation the EPS is always generated by the TPM.
                permanent_attr |= tpm2::TpmaPermanent::TPM_GENERATED_EPS;

                let mut startup_clear_attr = tpm2::TpmaStartupClear::empty();
                // `orderly` is set iff the previous shutdown was orderly
                // (`g_prevOrderlyState != SU_NONE_VALUE`).
                if self.context.state.prev_orderly_state != 0xFFFF {
                    startup_clear_attr |= tpm2::TpmaStartupClear::ORDERLY;
                }
                if self.context.state.ph_enable {
                    startup_clear_attr |= tpm2::TpmaStartupClear::PH_ENABLE;
                }
                if self.context.state.nv.clear.sh_enable {
                    startup_clear_attr |= tpm2::TpmaStartupClear::SH_ENABLE;
                }
                if self.context.state.nv.clear.eh_enable {
                    startup_clear_attr |= tpm2::TpmaStartupClear::EH_ENABLE;
                }
                if self.context.state.nv.clear.ph_enable_nv {
                    startup_clear_attr |= tpm2::TpmaStartupClear::PH_ENABLE_NV;
                }
                // Part 2, TPMA_STARTUP_CLEAR: "readOnly | SET (1): All enabled hierarchies,
                // including the NULL hierarchy, are Read-Only." (`TPM2_ReadOnlyControl`).
                if self.context.state.nv.clear.read_only {
                    startup_clear_attr |= tpm2::TpmaStartupClear::READ_ONLY;
                }

                let info = *self.context.platform.info();
                let (firmware_svn, firmware_max_svn) = (
                    u32::from(info.firmware.svn),
                    u32::from(info.firmware.max_svn),
                );
                let all_properties = [
                    (TpmPt::FAMILY_INDICATOR, tpm2::TPM_SPEC_FAMILY), // "2.0\0"
                    (TpmPt::LEVEL, tpm2::TPM_SPEC_LEVEL),
                    (TpmPt::REVISION, tpm2::TPM_SPEC_VERSION),
                    (TpmPt::DAY_OF_YEAR, tpm2::TPM_SPEC_DAY_OF_YEAR),
                    (TpmPt::YEAR, tpm2::TPM_SPEC_YEAR),
                    // The vendor and firmware identification of the platform's `Info`.
                    (TpmPt::MANUFACTURER, info.manufacturer),
                    (TpmPt::VENDOR_STRING_1, info.vendor_strings[0]),
                    (TpmPt::VENDOR_STRING_2, info.vendor_strings[1]),
                    (TpmPt::VENDOR_STRING_3, info.vendor_strings[2]),
                    (TpmPt::VENDOR_STRING_4, info.vendor_strings[3]),
                    (TpmPt::VENDOR_TPM_TYPE, info.vendor_tpm_type),
                    (TpmPt::FIRMWARE_VERSION_1, info.firmware.version_1),
                    (TpmPt::FIRMWARE_VERSION_2, info.firmware.version_2),
                    (TpmPt::INPUT_BUFFER, 1024),
                    (
                        TpmPt::HR_TRANSIENT_MIN,
                        crate::engine::MAX_LOADED_OBJECTS as u32,
                    ),
                    (TpmPt::HR_PERSISTENT_MIN, 7),
                    (TpmPt::HR_LOADED_MIN, 3),
                    (TpmPt::ACTIVE_SESSIONS_MAX, 64),
                    // The PCR count for PC Client profile platforms (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
                    (TpmPt::PCR_COUNT, 24),
                    (TpmPt::PCR_SELECT_MIN, 3),
                    // `(1 << (8 * sizeof(CONTEXT_SLOT))) - 1` (`PropertyCap.c`).
                    (
                        TpmPt::CONTEXT_GAP_MAX,
                        (crate::engine::MAX_CONTEXT_GAP - 1) as u32,
                    ),
                    (TpmPt::NV_COUNTERS_MAX, 8),
                    (
                        TpmPt::NV_INDEX_MAX,
                        crate::handler::nv_storage::MAX_NV_INDEX_SIZE as u32,
                    ),
                    (TpmPt::MEMORY, tpm2::TpmaMemory::SHARED_NV.bits()),
                    (TpmPt::CLOCK_UPDATE, 8192),
                    (
                        TpmPt::CONTEXT_HASH,
                        tpm2::Alg::from(crate::handler::context_integrity_hash_alg()).id() as u32,
                    ),
                    (TpmPt::CONTEXT_SYM, tpm2::Alg::AES.id() as u32),
                    (
                        TpmPt::CONTEXT_SYM_SIZE,
                        crate::handler::context_format::CONTEXT_ENCRYPT_KEY_BITS,
                    ),
                    (TpmPt::ORDERLY_COUNT, 255),
                    (
                        TpmPt::MAX_COMMAND_SIZE,
                        crate::engine::MAX_COMMAND_SIZE as u32,
                    ),
                    (
                        TpmPt::MAX_RESPONSE_SIZE,
                        crate::engine::MAX_RESPONSE_SIZE as u32,
                    ),
                    // The size of the largest digest this TPM produces (`sizeof(TPMU_HA)`), also
                    // when the context integrity hash is a smaller one (`context-hash-sha256`).
                    (
                        TpmPt::MAX_DIGEST,
                        tpm2::TpmiAlgHash::MAX_DIGEST_BYTES as u32,
                    ),
                    // Part 2, TPM_PT: "the maximum size of an object context that will be
                    // returned by TPM2_ContextSave()" / "the maximum size of a session context
                    // that will be returned by TPM2_ContextSave()": the bounds of this TPM's
                    // (implementation-defined) context serialization.
                    (
                        TpmPt::MAX_OBJECT_CONTEXT,
                        crate::handler::context_save::MAX_OBJECT_CONTEXT_SIZE as u32,
                    ),
                    (
                        TpmPt::MAX_SESSION_CONTEXT,
                        crate::handler::context_save::MAX_SESSION_CONTEXT_SIZE as u32,
                    ),
                    (TpmPt::PS_FAMILY_INDICATOR, 0),
                    (TpmPt::PS_LEVEL, 0),
                    (TpmPt::PS_REVISION, 0),
                    (TpmPt::PS_DAY_OF_YEAR, 0),
                    (TpmPt::PS_YEAR, 0),
                    (TpmPt::SPLIT_MAX, 128),
                    (
                        TpmPt::TOTAL_COMMANDS,
                        self.context.implemented_commands().total() as u32,
                    ),
                    (
                        TpmPt::LIBRARY_COMMANDS,
                        crate::engine::SUPPORTED_COMMANDS.len() as u32,
                    ),
                    (
                        TpmPt::VENDOR_COMMANDS,
                        self.context.implemented_commands().vendor().len() as u32,
                    ),
                    (TpmPt::NV_BUFFER_MAX, tpm2::TPM2_MAX_NV_BUFFER_SIZE),
                    (TpmPt::MODES, tpm2::TpmaModes::empty().bits()),
                    (TpmPt::MAX_CAP_BUFFER, tpm2::limits::MAX_CAP_BUFFER as u32),
                    // TPM 2.0 Part 2, TPM_PT: "TPM_PT_FIRMWARE_SVN | PT_FIXED + 47 | the TPM
                    // vendor-specific value indicating the SVN of the firmware" and
                    // "TPM_PT_FIRMWARE_MAX_SVN | PT_FIXED + 48 | ... the maximum value that
                    // TPM_PT_FIRMWARE_SVN may take in the future", from the platform's firmware
                    // (0 on a platform without one, which has no SVN-limited hierarchies).
                    (TpmPt::FIRMWARE_SVN, firmware_svn),
                    (TpmPt::FIRMWARE_MAX_SVN, firmware_max_svn),
                    // TPM 2.0 Part 2, TPM_PT: "TPM_PT_ML_PARAMETER_SETS | PT_FIXED + 49 |
                    // TPMA_ML_PARAMETER_SET indicating the supported parameter sets for ML-KEM
                    // and ML-DSA" (version 185; reported by a TPM that implements either).
                    #[cfg(any(feature = "mlkem", feature = "mldsa"))]
                    (TpmPt::ML_PARAMETER_SETS, ml_parameter_sets().0),
                    (TpmPt::PERMANENT, permanent_attr.bits()),
                    (TpmPt::STARTUP_CLEAR, startup_clear_attr.bits()),
                    (TpmPt::HR_NV_INDEX, nv_index_count),
                    (TpmPt::HR_LOADED, loaded_session_count),
                    (
                        TpmPt::HR_LOADED_AVAIL,
                        (crate::engine::MAX_LOADED_SESSIONS as u32)
                            .saturating_sub(loaded_session_count),
                    ),
                    (TpmPt::HR_ACTIVE, active_sessions_count),
                    (
                        TpmPt::HR_ACTIVE_AVAIL,
                        64u32.saturating_sub(active_sessions_count),
                    ),
                    (TpmPt::HR_TRANSIENT_AVAIL, transient_avail),
                    (TpmPt::HR_PERSISTENT, persistent_count),
                    (TpmPt::HR_PERSISTENT_AVAIL, nv_usage.persistent_avail()),
                    (TpmPt::NV_COUNTERS, nv_usage.counters),
                    (TpmPt::NV_COUNTERS_AVAIL, nv_usage.counter_avail()),
                    (
                        TpmPt::LOCKOUT_COUNTER,
                        self.context.state.nv.persistent.failed_tries,
                    ),
                    (
                        TpmPt::MAX_AUTH_FAIL,
                        self.context.state.nv.persistent.max_tries,
                    ),
                    (
                        TpmPt::LOCKOUT_INTERVAL,
                        self.context.state.nv.persistent.recovery_time,
                    ),
                    (
                        TpmPt::LOCKOUT_RECOVERY,
                        self.context.state.nv.persistent.lockout_recovery,
                    ),
                    (TpmPt::NV_WRITE_RECOVERY, 0),
                    (
                        TpmPt::AUDIT_COUNTER_0,
                        (self.context.state.nv.persistent.audit_counter >> 32) as u32,
                    ),
                    (
                        TpmPt::AUDIT_COUNTER_1,
                        self.context.state.nv.persistent.audit_counter as u32,
                    ),
                    (
                        TpmPt::ALGORITHM_SET,
                        self.context.state.nv.persistent.algorithm_set,
                    ),
                    // TPM 2.0 Part 2, TPM_PT: "TPM_PT_LOADED_CURVES | PT_VAR + 13 | the number
                    // of loaded ECC curves". Every implemented curve is always loaded (as in
                    // the TCG reference, which reports `ECC_CURVE_COUNT`).
                    (TpmPt::LOADED_CURVES, IMPLEMENTED_CURVES.len() as u32),
                ];

                let mut all_sorted = all_properties;
                all_sorted.sort_unstable_by_key(|&(pt, _)| pt.tag());

                // TPM 2.0 Part 3, TPM2_GetCapability: "`TPM_CAP_TPM_PROPERTIES` - Returns a list
                // of tagged properties. The tag is a `TPM_PT` and the property is a 32-bit
                // value. The properties are returned in groups. Each property group is on a
                // 256-value boundary (that is, the boundary occurs when the `TPM_PT` is evenly
                // divisible by 256). The TPM will only return values in the same group as the
                // *property* parameter in the command."
                // A `property` below `PT_FIXED` starts at `PT_FIXED` (as in the TCG reference's
                // `TPMCapGetProperties()`).
                const PT_GROUP: u32 = 0x100;
                let starting_prop = cmd.property.max(PT_GROUP);
                let group_end = (starting_prop / PT_GROUP)
                    .saturating_mul(PT_GROUP)
                    .saturating_add(PT_GROUP);

                let mut tpm_property =
                    [TpmsTaggedProperty::default(); tpm2::TPM2_MAX_TPM_PROPERTIES];
                let mut count = 0;

                for &(pt, val) in all_sorted.iter() {
                    if (starting_prop..group_end).contains(&pt.tag()) {
                        if count < cmd.property_count as usize
                            && count < tpm2::TPM2_MAX_TPM_PROPERTIES
                        {
                            tpm_property[count] = TpmsTaggedProperty {
                                property: pt,
                                value: val,
                            };
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }

                TpmsCapabilityData::TpmProperties(
                    TpmlTaggedTpmProperty::from_slice(&tpm_property[..count])
                        .ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::Handles => {
                let mso = cmd.property >> 24;
                let mut handles = [tpm2::Handle::default(); tpm2::TPM2_MAX_CAP_HANDLES];
                let mut count = 0;

                // Unsupported handle types: `TPM_RCS_HANDLE + RC_GetCapability_property`.
                if !matches!(mso, 0x00 | 0x01 | 0x02 | 0x03 | 0x40 | 0x80 | 0x81) {
                    return Err(TpmRc::HANDLE.with(property_pos));
                }

                if mso == 0x80 {
                    if cmd.property > 0x80FFFFFF {
                        return Err(TpmRc::VALUE.with(property_pos));
                    }
                    let mut matching = [0u32; 272];
                    let mut match_count = 0;
                    for obj in self.context.state.transient_objects.iter().flatten() {
                        if obj.handle >= cmd.property && match_count < matching.len() {
                            matching[match_count] = obj.handle;
                            match_count += 1;
                        }
                    }
                    for seq in self.context.state.active_sequences.iter().flatten() {
                        if seq.handle >= cmd.property && match_count < matching.len() {
                            matching[match_count] = seq.handle;
                            match_count += 1;
                        }
                    }
                    matching[..match_count].sort_unstable();
                    for &item in matching.iter().take(match_count) {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_CAP_HANDLES
                        {
                            handles[count] = tpm2::Handle(item);
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                } else if mso == tpm2::TpmHt::LOADED_SESSION as u32
                    || mso == tpm2::TpmHt::SAVED_SESSION as u32
                {
                    if cmd.property > 0x03FFFFFF {
                        return Err(TpmRc::VALUE.with(property_pos));
                    }
                    let mut matching = [0u32; tpm2::TPM2_MAX_CAP_HANDLES];
                    let mut match_count = 0;
                    if mso == tpm2::TpmHt::LOADED_SESSION as u32 {
                        for sess in self.context.state.active_sessions.iter().flatten() {
                            if (sess.session_handle & 0x00FF_FFFF) >= (cmd.property & 0x00FF_FFFF)
                                && match_count < matching.len()
                            {
                                matching[match_count] = sess.session_handle;
                                match_count += 1;
                            }
                        }
                    } else if mso == tpm2::TpmHt::SAVED_SESSION as u32 {
                        for saved_handle in
                            self.context.state.nv.reset.saved_sessions.iter().flatten()
                        {
                            if (*saved_handle & 0x00FF_FFFF) >= (cmd.property & 0x00FF_FFFF)
                                && match_count < matching.len()
                            {
                                matching[match_count] =
                                    (*saved_handle & 0x00FF_FFFF) | tpm2::Handle::HR_HMAC_SESSION.0;
                                match_count += 1;
                            }
                        }
                    }
                    // Sessions are reported in ascending session-slot order (the low 24 bits),
                    // regardless of their HMAC/policy type, as `SessionCapGetLoaded` /
                    // `SessionCapGetSaved` iterate the context array.
                    matching[..match_count].sort_unstable_by_key(|&h| h & 0x00FF_FFFF);
                    for &item in matching.iter().take(match_count) {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_CAP_HANDLES
                        {
                            handles[count] = tpm2::Handle(item);
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                } else if mso == 0x81 || mso == 0x01 {
                    if (mso == 0x81 && cmd.property > 0x81FFFFFF)
                        || (mso == 0x01 && cmd.property > 0x01FFFFFF)
                    {
                        return Err(TpmRc::VALUE.with(property_pos));
                    }
                    let storage = &mut self.context.state.nv.index;
                    if let Ok(toc) = storage.items() {
                        let mut matching = [0u32; crate::storage::manager::MAX_ITEMS];
                        let mut match_count = 0;
                        for item in toc.iter() {
                            if item.in_use != 0
                                && item.handle >= cmd.property
                                && (item.handle >> 24) == mso
                                && match_count < matching.len()
                            {
                                matching[match_count] = item.handle;
                                match_count += 1;
                            }
                        }
                        matching[..match_count].sort_unstable();
                        for &item in matching.iter().take(match_count) {
                            if count < cmd.property_count as usize
                                && count < tpm2::TPM2_MAX_CAP_HANDLES
                            {
                                handles[count] = tpm2::Handle(item);
                                count += 1;
                            } else {
                                more_data = true;
                            }
                        }
                    }
                } else if mso == 0x00 {
                    // A start handle beyond `PCR_LAST` simply yields an empty list
                    // (`PCRCapGetHandles`).
                    let pcr_count = self.context.state.pcrs.sha256.len() as u32;
                    let mut item = if cmd.property < pcr_count {
                        cmd.property
                    } else {
                        pcr_count
                    };
                    while item < pcr_count {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_CAP_HANDLES
                        {
                            handles[count] = tpm2::Handle(item);
                            count += 1;
                        } else {
                            more_data = true;
                        }
                        item += 1;
                    }
                } else if mso == 0x40 {
                    let permanent = [
                        tpm2::Handle::RH_OWNER.0,
                        tpm2::Handle::RH_NULL.0,
                        tpm2::Handle::RS_PW.0,
                        tpm2::Handle::RH_LOCKOUT.0,
                        tpm2::Handle::RH_ENDORSEMENT.0,
                        tpm2::Handle::RH_PLATFORM.0,
                        tpm2::Handle::RH_PLATFORM_NV.0,
                        #[cfg(feature = "vendor-permanent-auth")]
                        tpm2::Handle::RH_AUTH_00.0,
                        // The implemented ACTs (`NextPermanentHandle`), see `crate::act`.
                        crate::act::act_handle(0).0,
                        #[cfg(feature = "act-a")]
                        crate::act::act_handle(0xA).0,
                    ];
                    // The firmware-limited and SVN-limited hierarchies of a TPM that supports
                    // them follow (in ascending handle order).
                    let limited: &[u32] = if self.context.supports_limited_hierarchies() {
                        &LIMITED_HIERARCHY_HANDLES
                    } else {
                        &[]
                    };
                    for &h in permanent.iter().chain(limited) {
                        if h >= cmd.property {
                            if count < cmd.property_count as usize
                                && count < tpm2::TPM2_MAX_CAP_HANDLES
                            {
                                handles[count] = tpm2::Handle(h);
                                count += 1;
                            } else {
                                more_data = true;
                            }
                        }
                    }
                } else {
                    return Err(TpmRc::HANDLE.with(property_pos));
                }

                TpmsCapabilityData::Handles(
                    TpmlHandle::from_slice(&handles[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::PCRs => {
                if cmd.property != 0 {
                    return Err(TpmRc::VALUE.with(property_pos));
                }
                // `PCRCapGetAllocation`: a zero `propertyCount` returns an empty list with
                // `moreData = YES`.
                if cmd.property_count == 0 {
                    more_data = true;
                    TpmsCapabilityData::AssignedPcr(tpm2::TpmlPcrSelection::default())
                } else {
                    TpmsCapabilityData::AssignedPcr(self.context.state.pcrs.pcr_allocation)
                }
            }
            TpmCap::Commands => {
                let mut command_attributes = [TpmaCc::default(); tpm2::TPM2_MAX_CAP_CC];
                let mut count = 0;
                // `CommandCapGetCCList`: the library commands, then the vendor commands, from
                // the first one at or after `property` (see `command_list_start`).
                let first = crate::engine::command_list_start(cmd.property);
                for cc in self.context.implemented_commands().in_order() {
                    if first.is_some_and(|first| cc.code() >= first) {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_CAP_CC {
                            command_attributes[count] = self.context.command_attributes(cc);
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }
                TpmsCapabilityData::Command(
                    TpmlCca::from_slice(&command_attributes[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::Algs => {
                let mut algs = IMPLEMENTED_ALGORITHMS;
                algs.sort_unstable_by_key(|&(alg, _)| alg.id() as u32);
                // Without the algorithms the `tpm2` features of the build exclude (SHA-512).
                let algs = algs.iter().filter(|&&(alg, _)| is_enabled_by_features(alg));
                let mut alg_properties = [TpmsAlgProperty::default(); tpm2::TPM2_MAX_CAP_ALGS];
                let mut count = 0;
                // TPM 2.0 Part 3, TPM2_GetCapability, capability table: "TPM_CAP_ALGS |
                // TPM_ALG_ID(1) | TPML_ALG_PROPERTY" with note "[1] The TPM_ALG_ID or
                // TPM_ECC_CURVE is cast to a UINT32". The spec is silent on a `property` with
                // upper bits set; like the TCG reference (`(TPM_ALG_ID)in->property`), only
                // its low 16 bits count.
                let first = cmd.property as u16;
                for &(alg, props) in algs {
                    if alg.id() >= first {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_CAP_ALGS {
                            alg_properties[count] = TpmsAlgProperty {
                                alg,
                                alg_properties: props,
                            };
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }
                TpmsCapabilityData::Algorithms(
                    TpmlAlgProperty::from_slice(&alg_properties[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::ECCCurves => {
                let curves = IMPLEMENTED_CURVES;
                let mut ecc_curves = [TpmEccCurve::NistP256; tpm2::TPM2_MAX_ECC_CURVES];
                let mut count = 0;
                // TPM 2.0 Part 3, TPM2_GetCapability, capability table: "TPM_CAP_ECC_CURVES
                // | TPM_ECC_CURVE(1) | TPML_ECC_CURVE" with note "[1] The TPM_ALG_ID or
                // TPM_ECC_CURVE is cast to a UINT32". The spec is silent on a `property` with
                // upper bits set; like the TCG reference (`(TPM_ECC_CURVE)in->property`), only
                // its low 16 bits count.
                let first = cmd.property as u16;
                for &curve in curves.iter() {
                    if (curve as u16) >= first {
                        if count < cmd.property_count as usize && count < tpm2::TPM2_MAX_ECC_CURVES
                        {
                            ecc_curves[count] = curve;
                            count += 1;
                        } else {
                            more_data = true;
                        }
                    }
                }
                TpmsCapabilityData::EccCurves(
                    TpmlEccCurve::from_slice(&ecc_curves[..count]).ok_or(TpmRc::FAILURE)?,
                )
            }
            TpmCap::AuthPolicies => {
                if (cmd.property >> 24) != 0x40 {
                    return Err(TpmRc::VALUE.with(property_pos));
                }
                let mut tagged_policies = tpm2::TpmlTaggedPolicy::default();
                let handles = [
                    tpm2::Handle::RH_OWNER.0,
                    tpm2::Handle::RH_LOCKOUT.0,
                    tpm2::Handle::RH_ENDORSEMENT.0,
                    tpm2::Handle::RH_PLATFORM.0,
                ];
                // The implemented ACTs, with their ACT-specific policies.
                let acts = crate::act::IMPLEMENTED_ACTS
                    .iter()
                    .map(|&act| crate::act::act_handle(act).0);
                // The firmware-limited and SVN-limited hierarchies have the policy of their base
                // hierarchy (C `EntityGetAuthPolicy` → `HierarchyNormalizeHandle`); those of
                // `TPM_RH_NULL` have none and are skipped (`TPM_ALG_ERROR`).
                let limited: &[u32] = if self.context.supports_limited_hierarchies() {
                    &LIMITED_HIERARCHY_HANDLES
                } else {
                    &[]
                };
                for h in handles
                    .into_iter()
                    .chain(acts)
                    .chain(limited.iter().copied())
                {
                    if h >= cmd.property {
                        if tagged_policies.count() < cmd.property_count as usize
                            && tagged_policies.count() < tpm2::TPM2_MAX_TAGGED_POLICIES
                        {
                            let (policy_digest, policy_alg) = match crate::hierarchy::normalize(h) {
                                0x40000001 => (
                                    &self.context.state.nv.persistent.owner_policy,
                                    self.context.state.nv.persistent.owner_alg,
                                ),
                                0x4000000A => (
                                    &self.context.state.nv.persistent.lockout_policy,
                                    self.context.state.nv.persistent.lockout_alg,
                                ),
                                0x4000000B => (
                                    &self.context.state.nv.persistent.endorsement_policy,
                                    self.context.state.nv.persistent.endorsement_alg,
                                ),
                                0x4000000C => (
                                    &self.context.state.nv.clear.platform_policy,
                                    self.context.state.nv.clear.platform_alg,
                                ),
                                _ => match crate::act::act_index(h) {
                                    Some(index) => {
                                        let policy = &self.context.state.act.policies[index];
                                        (&policy.auth_policy, policy.hash_alg)
                                    }
                                    None => continue,
                                },
                            };
                            let policy_hash = policy_alg
                                .or_else(|| {
                                    crate::engine::infer_alg_from_digest_size(
                                        policy_digest.get_size() as usize,
                                    )
                                })
                                .map(|alg| crate::engine::digest_to_tpmt_ha(alg, policy_digest));
                            let _ = tagged_policies.add(&tpm2::TpmsTaggedPolicy {
                                handle: tpm2::Handle(h),
                                policy_hash,
                            });
                        } else {
                            more_data = true;
                        }
                    }
                }
                TpmsCapabilityData::AuthPolicies(tagged_policies)
            }
            TpmCap::ACT => {
                // Part 3, TPM2_GetCapability: "TPM_CAP_ACT | TPM_HANDLE | TPML_ACT_DATA", "Returns
                // a list of TPMS_ACT_DATA, each of which contains the handle for the ACT, the
                // remaining time before it expires, and the ACT attributes". The specification
                // is silent on a property that is not an ACT handle; as the TCG reference
                // (`TPM2_GetCapability()`), it is `TPM_RC_VALUE + RC_P2`. The list holds the
                // implemented ACTs from `property` on, at most `propertyCount` (and
                // `MAX_ACT_DATA`) of them; `moreData` is YES if an implemented ACT is left out
                // (`ActGetCapabilityData()`).
                if !(tpm2::Handle::RH_ACT_0.0..=tpm2::Handle::RH_ACT_F.0).contains(&cmd.property) {
                    return Err(TpmRc::VALUE.with(property_pos));
                }
                let max = (cmd.property_count as usize).min(tpm2::TPM2_MAX_ACT_DATA);
                let mut act_data = tpm2::TpmlActData::default();
                for (index, &act) in crate::act::IMPLEMENTED_ACTS.iter().enumerate() {
                    if crate::act::act_handle(act).0 < cmd.property {
                        continue;
                    }
                    if act_data.count() < max {
                        let _ = act_data.add(&self.context.state.act.act_data(index));
                    } else {
                        more_data = true;
                        break;
                    }
                }
                TpmsCapabilityData::ActData(act_data)
            }
            #[cfg(feature = "sec-channel")]
            TpmCap::PubKeys => {
                // Part 3, TPM2_GetCapability: "TPM_CAP_PUB_KEYS - Returns a list of
                // TPM2B_PUBLIC. Currently, the only supported public keys are TPM SPDM
                // authentication public keys." Part 2, TPM_PUB_KEY: "TPM_RC_VALUE is returned
                // for not supported property values", i.e. a `property` that is not the
                // `TPM_PUB_KEY_TPM_SPDM_xx` of one of the platform's keys. The list holds the
                // keys from `property` on, "no more than the number of requested values
                // (propertyCount)", and `moreData` is YES if a key is left out.
                let first = u8::try_from(cmd.property)
                    .ok()
                    .filter(|&index| self.context.tpm_spdm_public_key(index).is_some())
                    .ok_or(TpmRc::VALUE.with(property_pos))?;
                let max = (cmd.property_count as usize).min(tpm2::TPM2_MAX_PUB_KEYS);
                let mut keys = tpm2::TpmlPubKey::default();
                for index in first..=u8::MAX {
                    let Some(public) = self.context.tpm_spdm_public_key(index) else {
                        break;
                    };
                    if keys.count() < max {
                        keys.add(&tpm2::Tpm2b(public))?;
                    } else {
                        more_data = true;
                        break;
                    }
                }
                TpmsCapabilityData::PubKeys(keys)
            }
            #[cfg(feature = "sec-channel")]
            TpmCap::SpdmSessionInfo => {
                // Part 3, TPM2_GetCapability: "TPM_CAP_SPDM_SESSION_INFO - Returns a (single
                // entry) list of TPMS_SPDM_SESSION_INFO, which contains the Name of the
                // Requester and TPM key associated with the current SPDM session". Part 2,
                // TPML_SPDM_SESSION_INFO: "If TPM2_GetCapability() is not sent within an SPDM
                // session, an empty list will be returned." The property is reserved
                // (`TPM_RC_VALUE` unless 0, as in the TCG reference); the list holds "no more
                // than the number of requested values (propertyCount)".
                if cmd.property != 0 {
                    return Err(TpmRc::VALUE.with(property_pos));
                }
                let mut list = tpm2::TpmlSpdmSessionInfo::default();
                if let Some((req_key_name, tpm_key_name)) = &spdm_session_names {
                    if cmd.property_count == 0 {
                        more_data = true;
                    } else {
                        list.add(&tpm2::TpmsSpdmSessionInfo {
                            req_key_name: req_key_name.as_tpm2b(),
                            tpm_key_name: tpm_key_name.as_tpm2b(),
                        })?;
                    }
                }
                TpmsCapabilityData::SpdmSessionInfo(list)
            }
            TpmCap::PCRProperties => {
                // Bitmaps derived from the PCR attributes of the C reference platform
                // (`s_initAttributes` in `PlatformPcr.c`, evaluated by `PCRGetProperty`).
                let pcr_props = [
                    (tpm2::TpmPtPcr::SAVE, [0xff, 0xff, 0x00]),
                    (tpm2::TpmPtPcr::EXTEND_L0, [0xff, 0xff, 0x81]),
                    (tpm2::TpmPtPcr::RESET_L0, [0x00, 0x00, 0x81]),
                    (tpm2::TpmPtPcr::EXTEND_L1, [0xff, 0xff, 0x91]),
                    (tpm2::TpmPtPcr::RESET_L1, [0x00, 0x00, 0x81]),
                    (tpm2::TpmPtPcr::EXTEND_L2, [0xff, 0xff, 0xff]),
                    (tpm2::TpmPtPcr::RESET_L2, [0x00, 0x00, 0xf1]),
                    (tpm2::TpmPtPcr::EXTEND_L3, [0xff, 0xff, 0x9f]),
                    (tpm2::TpmPtPcr::RESET_L3, [0x00, 0x00, 0x81]),
                    (tpm2::TpmPtPcr::EXTEND_L4, [0xff, 0xff, 0x87]),
                    (tpm2::TpmPtPcr::RESET_L4, [0x00, 0x00, 0x7e]),
                    (tpm2::TpmPtPcr::NO_INCREMENT, [0x00, 0x00, 0x70]),
                    (tpm2::TpmPtPcr::DRTM_RESET, [0x00, 0x00, 0x7e]),
                    (tpm2::TpmPtPcr::POLICY, [0x00, 0x00, 0x70]),
                    (tpm2::TpmPtPcr::AUTH, [0x00, 0x00, 0x70]),
                ];
                /// `TPM_PT_PCR_LAST`: the last PCR property defined by this implementation.
                const TPM_PT_PCR_LAST: u32 = 0x14;
                let max = (cmd.property_count as usize).min(tpm2::TPM2_MAX_PCR_PROPERTIES);
                let mut tagged_props =
                    [tpm2::TpmsTaggedPcrSelect::default(); tpm2::TPM2_MAX_PCR_PROPERTIES];
                let mut count = 0;
                // `PCRCapGetProperties`: walk every property value from `property` up to
                // `TPM_PT_PCR_LAST`; values without a defined property are skipped, and
                // `moreData` is set as soon as the list is full while values remain.
                let mut tag_value = cmd.property;
                while tag_value <= TPM_PT_PCR_LAST {
                    if count >= max {
                        more_data = true;
                        break;
                    }
                    if let Some(&(tag, select_bytes)) =
                        pcr_props.iter().find(|(t, _)| t.tag() == tag_value)
                    {
                        let mut sel = [0u8; tpm2::TPM2_PCR_SELECT_MAX as usize];
                        sel[..3].copy_from_slice(&select_bytes);
                        tagged_props[count] = tpm2::TpmsTaggedPcrSelect {
                            tag,
                            size_of_select: 3,
                            pcr_select: sel,
                        };
                        count += 1;
                    }
                    tag_value += 1;
                }
                TpmsCapabilityData::PcrProperties(
                    tpm2::TpmlTaggedPcrProperty::from_slice(&tagged_props[..count])
                        .ok_or(TpmRc::FAILURE)?,
                )
            }
            // `PhysicalPresenceCapGetCCList`: the commands that require Physical Presence
            // (`gp.ppList`) from the first implemented command at or after `property` (see
            // `command_list_start`); `moreData` is YES if more follow a full list.
            TpmCap::PPCommands => {
                let max = (cmd.property_count as usize).min(tpm2::TPM2_MAX_CAP_CC);
                let mut list = tpm2::TpmlCc::default();
                let first = crate::engine::command_list_start(cmd.property);
                let pp_list = self.context.state.nv.persistent.pp_list;
                for cc in self.context.implemented_commands().in_order() {
                    if !first.is_some_and(|first| cc.code() >= first) || !pp_list.is_required(cc) {
                        continue;
                    }
                    if list.count() < max {
                        list.add(&cc)?;
                    } else {
                        more_data = true;
                        break;
                    }
                }
                TpmsCapabilityData::PPCommands(list)
            }
            // `CommandAuditCapGetCCList`: the audited commands from the first implemented
            // command at or after `property` (see `command_list_start`), library commands then
            // vendor commands; `moreData` is YES if more audited commands follow a full list.
            TpmCap::AuditCommands => {
                let max = (cmd.property_count as usize).min(tpm2::TPM2_MAX_CAP_CC);
                let mut list = tpm2::TpmlCc::default();
                let first = crate::engine::command_list_start(cmd.property);
                let commands = self.context.implemented_commands();
                for cc in self
                    .context
                    .state
                    .nv
                    .persistent
                    .audit_commands
                    .iter(&commands)
                {
                    if !first.is_some_and(|first| cc.code() >= first) {
                        continue;
                    }
                    if list.count() < max {
                        list.add(&cc)?;
                    } else {
                        more_data = true;
                        break;
                    }
                }
                TpmsCapabilityData::AuditCommands(list)
            }
            _ => {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        };

        f(self, capability_data, more_data)
    }

    /// Handles the [TpmCc::TestParms] (`0x18A`) command.
    ///
    /// # Description
    /// This command is used to determine if a TPM supports a particular configuration
    /// of algorithm, key size, mode, and scheme without actually creating or loading a key.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 30.3 (TPM2_TestParms).
    ///
    /// # Relationships
    /// - Call this command to test parameters before trying to create objects with [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreatePrimary](create_primary.rs).
    pub fn test_parms(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        // The parameters are unmarshaled field by field, in wire order, by the profile-aware
        // `TPMT_PUBLIC_PARMS` unmarshaler, whose first failing field gives the response code.
        // TPM 2.0 Part 3, TPM2_TestParms, General Description: "This command is used to check
        // to see if specific combinations of algorithm parameters are supported." and "The TPM
        // will unmarshal the provided `TPMT_PUBLIC_PARMS`. If the parameters unmarshal
        // correctly, then the TPM will return `TPM_RC_SUCCESS`, indicating that the parameters
        // are valid for the TPM. The TPM will return the appropriate unmarshaling error if a
        // parameter is not valid."
        let cmd = request.try_unmarshal_command::<TestParms>([])?;
        // Leftover parameter bytes: `TPM_RC_SIZE` (`CommandDispatcher`).
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        match cmd.parameters {
            tpm2::TpmtPublicParms::Rsa(parms) => {
                // Checked in `TPMS_RSA_PARMS` unmarshaling order: symmetric, scheme, keyBits.
                validate_symmetric(parms.symmetric)?;
                if let Some(scheme) = parms.scheme {
                    match scheme {
                        tpm2::TpmtRsaScheme::Rsapss(hash)
                        | tpm2::TpmtRsaScheme::Rsassa(hash)
                        | tpm2::TpmtRsaScheme::Oaep(hash) => {
                            validate_hash_alg(Some(hash))?;
                        }
                        tpm2::TpmtRsaScheme::Rsaes => {}
                    }
                }
                // Only the key sizes of this TPM's profile (`TPMI_RSA_KEY_BITS`: RSA-1024 and
                // RSA-2048, plus RSA-3072/4096 with the `rsa3072`/`rsa4096` features); the
                // go-tpm parity tests (`TestTestParms/rsa3072|rsa4096 - unsupported`) require
                // `TPM_RC_VALUE` for the others.
                if tpm2::TpmiRsaKeyBits::try_from(u16::from(parms.key_bits)).is_err() {
                    return Err(TpmRc::VALUE.with(Position::parameter(1)));
                }
                // `exponent` is a plain UINT32 that always unmarshals; TPM2_TestParms reports
                // only unmarshaling errors (Part 3, TPM2_TestParms), so any exponent is accepted
                // here (an unusable one is rejected when a key is created or loaded).
            }
            tpm2::TpmtPublicParms::Ecc(parms) => {
                // Checked in `TPMS_ECC_PARMS` unmarshaling order: symmetric, scheme, curveID, kdf.
                validate_symmetric(parms.symmetric)?;
                if let Some(scheme) = parms.scheme {
                    match scheme {
                        tpm2::TpmtEccScheme::Ecdsa(hash) | tpm2::TpmtEccScheme::Ecdh(hash) => {
                            validate_hash_alg(Some(hash))?;
                        }
                        tpm2::TpmtEccScheme::Ecdaa(scheme) => {
                            validate_hash_alg(Some(scheme.hash_alg))?;
                        }
                        #[cfg(feature = "sm2")]
                        tpm2::TpmtEccScheme::Sm2(hash) => {
                            validate_hash_alg(Some(hash))?;
                        }
                        #[cfg(feature = "ecschnorr")]
                        tpm2::TpmtEccScheme::Ecschnorr(hash) => {
                            validate_hash_alg(Some(hash))?;
                        }
                        #[cfg(feature = "ecmqv")]
                        tpm2::TpmtEccScheme::Ecmqv(hash) => {
                            validate_hash_alg(Some(hash))?;
                        }
                        // `TPMI_ALG_ECC_SCHEME` only includes implemented schemes; the other
                        // schemes (e.g. EdDSA) are not implemented by this TPM (not in
                        // TPM_CAP_ALGS).
                        #[allow(unreachable_patterns)]
                        _ => {
                            return Err(TpmRc::SCHEME.with(Position::parameter(1)));
                        }
                    }
                }
                if crate::ecc_curves::curve_params(parms.curve_id).is_none() {
                    return Err(TpmRc::CURVE.with(Position::parameter(1)));
                }
                if let Some(kdf) = parms.kdf {
                    match kdf {
                        // `TPMI_ALG_KDF` includes every implemented KDF/MGF, MGF1 included; that
                        // an ECC key needs a NULL KDF is checked at object creation, not here.
                        tpm2::TpmtKdfScheme::Kdf1Sp800_56a(hash_alg)
                        | tpm2::TpmtKdfScheme::Kdf2(hash_alg)
                        | tpm2::TpmtKdfScheme::Kdf1Sp800_108(hash_alg)
                        | tpm2::TpmtKdfScheme::Mgf1(hash_alg) => {
                            validate_hash_alg(Some(hash_alg))?;
                        }
                        tpm2::TpmtKdfScheme::Hkdf(_) => {
                            return Err(TpmRc::KDF.with(Position::parameter(1)));
                        }
                    }
                }
            }
            tpm2::TpmtPublicParms::KeyedHash(parms) => {
                if let Some(scheme) = parms {
                    match scheme {
                        tpm2::TpmtKeyedHashScheme::Hmac(hash_alg) => {
                            validate_hash_alg(Some(hash_alg))?;
                        }
                        tpm2::TpmtKeyedHashScheme::ExclusiveOr(scheme) => {
                            validate_hash_alg(Some(scheme.hash_alg))?;
                            // `TPMS_SCHEME_XOR.kdf` is `+TPMI_ALG_KDF`: TPM_ALG_NULL is allowed.
                            if scheme.kdf == Some(tpm2::TpmiAlgKdf::Hkdf) {
                                return Err(TpmRc::KDF.with(Position::parameter(1)));
                            }
                        }
                    }
                }
            }
            tpm2::TpmtPublicParms::Sym(parms) => {
                validate_symmetric(Some(parms))?;
            }
            // The `TPMT_PUBLIC_PARMS` unmarshaler accepts these types only with their features
            // (`mlkem`, `mldsa`, `hash_mldsa`); their parameter sets and `allowExternalMu`
            // (`TPMI_YES_NO`) are checked when unmarshaled.
            tpm2::TpmtPublicParms::Mlkem(parms) => {
                validate_symmetric(parms.symmetric)?;
            }
            tpm2::TpmtPublicParms::Mldsa(_) => {}
            tpm2::TpmtPublicParms::HashMldsa(parms) => {
                validate_hash_alg(Some(parms.hash_alg))?;
            }
        }

        let response = request.into_response();
        self.write_response_message(response, &(), &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::ECCParameters] (`0x178`) command.
    ///
    /// # Description
    /// This command returns the parameters of an ECC curve identified by its TCG-assigned `curveID`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 15.4 (TPM2_ECC_Parameters).
    pub fn ecc_parameters(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<ECCParameters>([])?;

        // An unimplemented curve fails while unmarshaling `TPMI_ECC_CURVE` (`TPM_RC_CURVE + RC_P1`),
        // i.e. before the dispatcher checks for trailing parameter bytes (`TPM_RC_SIZE`).
        let curve_id = cmd.curve_id;
        let curve = crate::ecc_curves::curve_params(curve_id)
            .ok_or_else(|| TpmRc::CURVE.with(Position::parameter(1)))?;
        fn parameter(value: &'static [u8]) -> Result<Tpm2bEccParameter<'static>, TpmRc> {
            Tpm2bEccParameter::from_bytes(value).map_err(|_| TpmRc::FAILURE)
        }
        #[allow(unused_mut)]
        let mut parameters = tpm2::TpmsAlgorithmDetailEcc {
            curve_id,
            key_size: curve.key_bits,
            kdf: recommended_kdf(curve_id),
            sign: None,
            curve_p: parameter(curve.p)?,
            curve_a: parameter(curve.a)?,
            curve_b: parameter(curve.b)?,
            g_x: parameter(curve.gx)?,
            g_y: parameter(curve.gy)?,
            n: parameter(curve.n)?,
            h: parameter(curve.h)?,
        };
        // The `kdf` of `TPMS_ALGORITHM_DETAIL_ECC` is an informative recommendation that may be
        // `TPM_ALG_NULL` (TPM 2.0 Part 2; deprecated in version 185, whose reference reports
        // `TPM_ALG_NULL` for every curve).
        #[cfg(feature = "ecc-parameters-null-kdf")]
        {
            parameters.kdf = None;
        }
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let rsp = responses::ECCParameters { parameters };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}

/// The KDF that `TPM2_ECC_Parameters` recommends for `curve` (`TPMS_ALGORITHM_DETAIL_ECC.kdf`, the
/// `eccCurves` table of the reference's `CryptEccData.c`): KDF1_SP800_56A with SHA-256 for NIST
/// P-192 to P-256, SHA-384 for P-384 and SHA-512 for P-521 (none without SHA-512), none for the
/// BN curves, and KDF1_SP800_56A with SM3 for SM2 P-256 if this TPM
/// implements SM3 (a `TPMI_ALG_HASH` can only be an implemented hash; otherwise none).
fn recommended_kdf(curve: tpm2::TpmEccCurve) -> Option<tpm2::TpmtKdfScheme> {
    use tpm2::TpmEccCurve as C;
    let hash = match curve {
        #[cfg(feature = "nist_p192")]
        C::NistP192 => tpm2::TpmiAlgHash::Sha256,
        C::NistP224 | C::NistP256 => tpm2::TpmiAlgHash::Sha256,
        C::NistP384 => tpm2::TpmiAlgHash::Sha384,
        C::NistP521 => sha512()?,
        #[cfg(feature = "sm2_p256")]
        C::SM2P256 => tpm2::TpmiAlgHash::try_from(Alg::SM3_256).ok()?,
        _ => return None,
    };
    Some(tpm2::TpmtKdfScheme::Kdf1Sp800_56a(hash))
}

fn validate_hash_alg(hash_alg: Option<tpm2::TpmiAlgHash>) -> Result<(), TpmRc> {
    if let Some(alg) = hash_alg
        && !is_implemented_algorithm(Alg::from(alg))
    {
        return Err(TpmRc::HASH.with(Position::parameter(1)));
    }
    Ok(())
}

/// Validates a symmetric definition of `TPM2_TestParms` the way `TPMT_SYM_DEF_OBJECT_Unmarshal`
/// does. Every check of that unmarshaling is already made by the `tpm2` wire type, whose
/// features are this TPM's algorithms: `TPMI_ALG_SYM_OBJECT` admits only the implemented block
/// ciphers (`TPM_RC_SYMMETRIC`), `TPMI_AES_KEY_BITS`/`TPMI_CAMELLIA_KEY_BITS` only their
/// implemented key sizes (`TPM_RC_VALUE`) and `TPMI_ALG_SYM_MODE+` only the implemented modes
/// (CTR, OFB, CBC, CFB, ECB and, with the `cmac` feature, CMAC) and `TPM_ALG_NULL`
/// (`TPM_RC_MODE`). So every unmarshaled definition is accepted: the CFB requirement for
/// restricted decryption keys and the CMAC restriction to SYMCIPHER signing keys are enforced at
/// object creation, not here.
fn validate_symmetric(_symmetric: Option<tpm2::TpmtSymDefObject>) -> Result<(), TpmRc> {
    Ok(())
}
