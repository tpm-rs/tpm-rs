//! Maximum byte capacities for TPM 2.0 buffer structures ([`Tpm2bSized`]) and lists ([`Tpml`]).
//!
//! Buffer limits fall into two categories:
//! - **Vendor-defined constants**: Five implementation-specific sizes
//!   ([`MAX_2B_BUFFER_SIZE`], [`MAX_NV_BUFFER_SIZE`], [`MAX_CAP_BUFFER`],
//!   [`MAX_CONTEXT_SIZE`], and [`PRIVATE_VENDOR_SPECIFIC_BYTES`]) configured with
//!   sensible defaults matching standard reference implementations.
//! - **Spec- and algorithm-derived limits**: All remaining buffer capacities are
//!   either fixed directly by the specification (e.g., [`Timeout`], [`Event`]) or
//!   derived automatically from the maximum sizes of enabled cryptographic
//!   algorithms (e.g., [`Digest`], [`PublicKeyRsa`], [`EccParameter`]).

use crate::*;

/// Implementation-defined maximum bytes in a [`Tpm2bMaxBuffer`].
///
/// Implementations expose this via the [`TpmPt::InputBuffer`] capability,
/// which must be at least `1024`, but implementations may use a larger value.
///
/// Defaults to the minimum of `1024` bytes.
#[doc(alias = "MAX_DIGEST_BUFFER")]
#[doc(alias = "TPM2_MAX_DIGEST_BUFFER")]
pub const MAX_2B_BUFFER_SIZE: usize = 1024;
/// Implementation-defined maximum bytes that can be used with NV data commands.
///
/// Implementations expose this via the [`TpmPt::NVBufferMax`] capability.
/// Note that this is not the maximum size of an NV Index, but rather the
/// maximum buffer size that can be used with commands like `TPM2_NV_Read`.
///
/// Defaults to `1024` bytes, matching the reference implementation's
/// `MAX_NV_BUFFER_SIZE`, and doubling the PC Client Platform minimum.
#[doc(alias = "TPM2_MAX_NV_BUFFER_SIZE")]
pub const MAX_NV_BUFFER_SIZE: usize = 1024;
/// Implementation-defined maximum marshaled size of [`TpmsCapabilityData`].
///
/// Implementations expose this via the [`TpmPt::MaxCapBuffer`] capability.
/// This controls the maximum length of the relevant `Tpml*` types used to
/// report capabilities like [`TpmlTaggedPolicy`].
///
/// Defaults to `1024` bytes, which is the canonical size used in specification
/// examples and universally adopted across reference implementations.
#[doc(alias = "TPM2_MAX_CAP_BUFFER")]
pub const MAX_CAP_BUFFER: usize = 1024;
/// Implementation-defined maximum context size.
///
/// Implementations expose this via the maximum of the
/// [`TpmPt::MaxObjectContext`] and [`TpmPt::MaxSessionContext`] capabilities.
/// This is less than [`Tpm2bContextData::MAX_SIZE`] as a [`Tpm2bContextData`]
/// must also store integrity information and buffer lengths.
///
/// By default, sized to fit an internal `OBJECT` containing a vendor-sized
/// private area, a public area, and both cached object names.
#[doc(alias = "TPM2_MAX_CONTEXT_SIZE")]
pub const MAX_CONTEXT_SIZE: usize = Private::CAP + TpmtPublic::MAX_SIZE + Tpm2bName::MAX_SIZE * 2;
/// Implementation-defined maximum bytes for the vendor-specific private key
/// format inside an encrypted [`Tpm2bPrivate`].
///
/// A TPM may cache an expanded private key representation (such as the five
/// CRT components of an RSA key, or an expanded PQC key) inside `_PRIVATE`
/// rather than recomputing it on every load. This format never appears on the
/// wire in plaintext; plaintext [`Tpm2bSensitive`] buffers always carry the
/// compact single-prime or seed form.
///
/// By default, sized to fit the 5-prime CRT representation.
pub const PRIVATE_VENDOR_SPECIFIC_BYTES: usize = TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES * 5;

const _: () = assert!(MAX_2B_BUFFER_SIZE >= 1024);
const _: () = assert!(TpmsCapabilityData::MAX_SIZE == MAX_CAP_BUFFER);
const _: () = assert!(2 + PRIVATE_VENDOR_SPECIFIC_BYTES >= TpmuSensitiveComposite::MAX_SIZE);

/// Specifies the maximum capacity (`CAP`) in bytes for a [`Tpm2bSized`] buffer.
pub trait Tag {
    const CAP: usize;
}

/// Spec-mandated 8-byte maximum size for ticket timeout buffers.
pub struct Timeout;
impl Tag for Timeout {
    const CAP: usize = 8;
}
/// Implementation-defined maximum size for KDF label and context strings.
///
/// The specification says: "For interoperability and backwards compatibility,
/// `LABEL_MAX_BUFFER` is the minimum of the largest digest on the device and
/// the largest ECC parameter (`MAX_ECC_KEY_BYTES`) but no more than 32 bytes."
///
/// As any implementation must have a digest of at least 32 bytes, this can be
/// unconditionally set to `32`.
#[doc(alias = "LABEL_MAX_BUFFER")]
#[doc(alias = "TPM2_LABEL_MAX_BUFFER")]
pub struct Label;
impl Tag for Label {
    const CAP: usize = 32;
}
/// Implementation-defined maximum size for sealed data blobs.
///
/// The specification says: "For interoperability, `MAX_SYM_DATA` should be
/// 128.", so this can be unconditionally set to `128`.
#[doc(alias = "MAX_SYM_DATA")]
#[doc(alias = "TPM2_MAX_SYM_DATA")]
pub struct SensitiveData;
impl Tag for SensitiveData {
    const CAP: usize = 128;
}
/// Spec-mandated 1024-byte maximum size for PCR event buffers.
pub struct Event;
impl Tag for Event {
    const CAP: usize = 1024;
}
/// Implementation-defined tag for [`MAX_2B_BUFFER_SIZE`].
pub struct MaxBuffer;
impl Tag for MaxBuffer {
    const CAP: usize = MAX_2B_BUFFER_SIZE;
}
/// Implementation-defined tag for [`MAX_NV_BUFFER_SIZE`].
pub struct MaxNvBuffer;
impl Tag for MaxNvBuffer {
    const CAP: usize = MAX_NV_BUFFER_SIZE;
}
/// Sized to the largest supported hash digest ([`TpmiAlgHash::MAX_DIGEST_BYTES`]).
pub struct Digest;
impl Tag for Digest {
    const CAP: usize = TpmiAlgHash::MAX_DIGEST_BYTES;
}
/// Sized to the largest tagged digest structure ([`TpmtHa::MAX_SIZE`]).
pub struct Data;
impl Tag for Data {
    const CAP: usize = TpmtHa::MAX_SIZE;
}
/// Sized to the largest entity Name ([`TpmtHa::MAX_SIZE`]).
pub struct Name;
impl Tag for Name {
    const CAP: usize = TpmtHa::MAX_SIZE;
}
/// Sized to the symmetric block size ([`AlgSym::BLOCK_SIZE`]).
pub struct Iv;
impl Tag for Iv {
    const CAP: usize = AlgSym::BLOCK_SIZE;
}
/// Sized to the largest symmetric key size ([`AlgSym::MAX_KEY_BYTES`]).
pub struct SymKey;
impl Tag for SymKey {
    const CAP: usize = AlgSym::MAX_KEY_BYTES;
}
/// Sized to the maximum supported RSA key modulus ([`TpmiRsaKeyBits::MAX_PUB_KEY_BYTES`]).
pub struct PublicKeyRsa;
impl Tag for PublicKeyRsa {
    const CAP: usize = TpmiRsaKeyBits::MAX_PUB_KEY_BYTES;
}
/// Sized to the maximum supported RSA prime factor ([`TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES`]).
pub struct PrivateKeyRsa;
impl Tag for PrivateKeyRsa {
    const CAP: usize = TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES;
}
/// Sized to the maximum supported ECC coordinate length ([`TpmEccCurve::MAX_ECC_KEY_BYTES`]).
pub struct EccParameter;
impl Tag for EccParameter {
    const CAP: usize = TpmEccCurve::MAX_ECC_KEY_BYTES;
}
/// Sized to the largest supported asymmetric encrypted secret ([`TpmtPublicParms::MAX_ENCRYPTED_SECRET_BYTES`]).
pub struct EncryptedSecret;
impl Tag for EncryptedSecret {
    const CAP: usize = TpmtPublicParms::MAX_ENCRYPTED_SECRET_BYTES;
}
/// Sized to hold an encrypted sensitive area.
///
/// This structure (called `_PRIVATE` in the spec) consists of:
/// - `integrityOuter`: An outer [`Tpm2bDigest`] HMAC for integrity
/// - `integrityInner`: An inner [`Tpm2bDigest`] HMAC or IV
/// - `sensitive`: An encrypted [`Tpm2bSensitive`] whose union member may be
///   sized up to [`PRIVATE_VENDOR_SPECIFIC_BYTES`]
#[doc(alias = "_PRIVATE")]
pub struct Private;
impl Tag for Private {
    const CAP: usize = Tpm2bDigest::MAX_SIZE * 2 + Tpm2bSensitive::MAX_SIZE
        - TpmuSensitiveComposite::MAX_SIZE
        + (2 + PRIVATE_VENDOR_SPECIFIC_BYTES);
}
/// Sized to hold an encrypted credential object.
///
/// This structure (called `TPMS_ID_OBJECT` in the spec) consists of:
/// - `integrityHMAC`: A [`Tpm2bDigest`] HMAC
/// - `encIdentity`: A [`Tpm2bDigest`] credential protector
#[doc(alias = "TPMS_ID_OBJECT")]
pub struct IdObject;
impl Tag for IdObject {
    const CAP: usize = Tpm2bDigest::MAX_SIZE * 2;
}
/// Sized to hold an implementation-defined integrity-protected context.
///
/// The specifics of this structure (called `TPMS_CONTEXT_DATA` in the spec) are
/// implementation-specific, but it's sized large enough to hold:
/// - A [`Tpm2bDigest`] integrity value
/// - A [`Tpm2bSized`] sensitive area with length [`MAX_CONTEXT_SIZE`] (called
///   `TPM2B_CONTEXT_SENSITIVE` in the spec)
#[doc(alias = "TPMS_CONTEXT_DATA")]
#[doc(alias = "TPM2B_CONTEXT_SENSITIVE")]
pub struct Context;
impl Tag for Context {
    const CAP: usize = Tpm2bDigest::MAX_SIZE + 2 + MAX_CONTEXT_SIZE;
}
