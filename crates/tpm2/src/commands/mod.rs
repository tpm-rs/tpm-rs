//! TPM 2.0 Commands and Request/Response Protocol Layout
//!
//! This module defines the request and response structures, handle lists,
//! and [`Command`] / [`Message`] trait implementations for TPM 2.0 commands.
//!
//! The commands are divided into submodules corresponding to their sections in
//! **Part 3: Commands** of the TPM 2.0 Specification:
//!
//! - `startup` (e.g., [`Startup`], [`Shutdown`])
//! - `testing` (e.g., [`SelfTest`])
//! - `session` (e.g., [`StartAuthSession`])
//! - `object` (e.g., [`Create`], [`Load`])
//! - `duplication` (e.g., [`Duplicate`], [`Import`])
//! - `asymmetric` (e.g., [`RSAEncrypt`], [`RSADecrypt`])
//! - `symmetric` (e.g., [`EncryptDecrypt`])
//! - `random` (e.g., [`GetRandom`])
//! - `hash_hmac_event` (e.g., [`HashSequenceStart`])
//! - `attestation` (e.g., [`Certify`])
//! - `ephemeral` (e.g., [`Commit`])
//! - `signature` (e.g., [`VerifySignature`])
//! - `command_audit` (e.g., [`SetCommandCodeAuditStatus`])
//! - `pcr` (e.g., [`PCRRead`], [`PCRExtend`])
//! - `enhanced_auth` (e.g., [`PolicyPCR`], [`PolicySigned`])
//! - `hierarchy` (e.g., [`CreatePrimary`])
//! - `dictionary_attack` (e.g., [`DictionaryAttackLockReset`])
//! - `miscellaneous` (e.g., [`PPCommands`])
//! - `field_upgrade` (e.g., [`FieldUpgradeStart`])
//! - `context` (e.g., [`ContextSave`], [`ContextLoad`])
//! - `clock_timer` (e.g., [`ReadClock`])
//! - `capability` (e.g., [`GetCapability`])
//! - `nv_storage` (e.g., [`NVDefineSpace`], [`NVRead`])
//! - `attached_components` (e.g., [`ACGetCapability`])
//! - `vendor` (Vendor-specific command placeholders, e.g., [`VendorTcgTest`])
//!
//! The response type of each command is available in the [`responses`] module
//! under the command's name (e.g., [`responses::GetRandom`] for [`GetRandom`]).
//!
//! ## Differences from the TPM 2.0 Specification
//!
//! While most command and response types map directly to the tables in
//! **Part 3: Commands** of the TPM 2.0 Specification, several intentional
//! design differences exist:
//!
//! ### [`Handle`] types
//!
//! Currently, we do not use different types for any of the handles, so types
//! like `TPMI_DH_OBJECT`, `TPMI_DH_PCR`, or `TPMI_RH_NV_INDEX` are all just
//! represented by a [`Handle`]. In the future, when more fine-grained handle
//! types are added, [`UnmarshalMessage::unmarshal_with_handles`] will perform
//! additional validation to ensure handles are in the correct range.
//!
//! Until then, a TPM implementation has to validate the handle area itself:
//! the `tpm2-impl` engine checks every handle against its `TPMI_*` interface
//! type (in handle order, reporting the failing handle's position in the
//! response code) before it unmarshals the parameter area.
//!
//! ### Deprecated commands omitted upstream
//!
//! Upstream `tpm-rs` intentionally omits the following commands, which are
//! deprecated in v184. They are defined here because the `tpm2-impl` TPM
//! implementation needs them, and are annotated with Rust's `#[deprecated]`
//! attribute. The reasons upstream gives for omitting them still apply:
//! - [`CreateLoaded`]: deprecated in v184
//!   - Avoids issues with "Derived Objects" and "Derivation Parents".
//!   - Users can just use [`Create`]/[`CreatePrimary`] and [`Load`].
//! - [`CertifyX509`]: deprecated in v184
//!   - Very difficult to implement correctly.
//! - "Attached Components": deprecated in v184
//!   - [`ACGetCapability`]
//!   - [`ACSend`]
//!   - [`PolicyACSendSelect`]
//!
//! Any other deprecated commands are defined, but are annotated with
//! Rust's `#[deprecated]` attribute.
//!
//! ### [`SetCapability`]
//!
//! [`SetCapability`] was added in v1.83. Upstream `tpm-rs` omits it, as
//! `TPMU_SET_CAPABILITIES` is not defined anywhere in the specification. Here
//! the `setCapabilityData` parameter is kept as an opaque
//! `TPM2B_SET_CAPABILITY_DATA` buffer
//! ([`Tpm2bSetCapabilityData`](crate::Tpm2bSetCapabilityData)).
//!
//! ### Empty Responses
//!
//! Commands whose responses contain neither handles nor parameters (e.g.
//! [`Startup`]) use `type Response<'a> = ()` rather than empty unit structs.
//!
//! ### [`LoadExternal`]
//!
//! The [`in_public` command parameter](LoadExternal::in_public) has type
//! `TPM2B_PUBLIC+` in the specification. We map it to
//! [`Tpm2bPublic`](crate::Tpm2bPublic), but unmarshal it with
//! [`Tpm2bPublic::unmarshal_nullable`](crate::Tpm2bPublic::unmarshal_nullable),
//! so its `nameAlg` may be `TPM_ALG_NULL`. The `outPublic` response parameter
//! of [`ReadPublic`] is unmarshalled the same way.
//!
//! The [`in_private` command parameter](LoadExternal::in_private) allows for
//! an empty buffer to be provided (for a "public-only load"). We represent this
//! using [`Option<Tpm2bSensitive<'a>>`](crate::Tpm2bSensitive).
//!
//! ### Shared `HMAC` / `MAC` Command Codes
//!
//! In the specification:
//! - [`TpmCc::HMAC`] and [`TpmCc::MAC`] are the same (`0x00000155`).
//! - [`TpmCc::HMACStart`] and [`TpmCc::MACStart`] are the same (`0x0000015B`).
//!
//! We choose to just define [`HMAC`] and [`HMACStart`] using
//! [`Option<TpmiAlgHash>`](crate::TpmiAlgHash) (`TPMI_ALG_HASH+`) rather than
//! the `MAC` command using `TPMI_ALG_MAC_SCHEME+`.
//!
//! ### Commands needing additional types
//!
//! Upstream `tpm-rs` plans to add the following commands once the necessary
//! prerequisite types and `impl`s have been added. They are defined here,
//! using these types:
//!
//! - `TPMT_RSA_DECRYPT+` ([`Option<TpmtRsaDecrypt>`](crate::TpmtRsaDecrypt))
//!   - [`RSAEncrypt`]
//!   - [`RSADecrypt`]
//! - `TPMI_ECC_KEY_EXCHANGE` ([`TpmiEccKeyExchange`](crate::TpmiEccKeyExchange))
//!   - [`ZGen2Phase`]
//! - [`Marshal`]/[`Unmarshal`](crate::Unmarshal) `impl`s for [`Option<TpmtHa<'a>>`](crate::TpmtHa)
//!   - [`FieldUpgradeData`]
//! - NV Expanded Attributes with `TPM2B_NV_PUBLIC_2` / `TPMT_NV_PUBLIC_2`
//!   ([`Tpm2bNvPublic2`](crate::Tpm2bNvPublic2))
//!   - [`NVDefineSpace2`]
//!   - [`NVReadPublic2`]
//! - KEM commands with `TPM2B_SHARED_SECRET` and `TPM2B_KEM_CIPHERTEXT`
//!   ([`Tpm2bSharedSecret`](crate::Tpm2bSharedSecret),
//!   [`Tpm2bKemCiphertext`](crate::Tpm2bKemCiphertext))
//!   - [`Encapsulate`]
//!   - [`Decapsulate`]
//! - Signing commands with `TPM2B_SIGNATURE_HINT` and `TPM2B_SIGNATURE_CTX`
//!   ([`Tpm2bSignatureHint`](crate::Tpm2bSignatureHint),
//!   [`Tpm2bSignatureCtx`](crate::Tpm2bSignatureCtx))
//!   - [`SignDigest`]
//!   - [`VerifyDigestSignature`]
//!   - [`SignSequenceStart`]
//!   - [`VerifySequenceStart`]
//!
//! This module comment will be updated as we add new commands.
//!
//! ## [`Message`] / [`UnmarshalMessage`] implementations
//!
//! Currently, these traits are implemented manually (and repetitively) for all
//! the commands and responses. However these implementations are very simple
//! and just call [`Marshal`] / `Unmarshal` on each parameter, and do no
//! additional command validation, with the following exceptions:
//!
//! - [`PolicyOR::p_hash_list`] is checked to ensure it has at least 2 digests.
//!   A smaller count fails with `TPM_RC_SIZE` as soon as the count is read.
//! - Parameters whose `TPMI_*` interface type is narrower than their Rust type
//!   are checked against that interface type, failing with the same response
//!   code as the type's own `Unmarshal` implementation:
//!   - [`FlushContext::flush_handle`] (`TPMI_DH_CONTEXT`)
//!   - [`EvictControl::persistent_handle`] (`TPMI_DH_PERSISTENT`)
//!   - [`HierarchyControl::enable`] (`TPMI_RH_ENABLES`)
//!   - [`PCRSetAuthPolicy::pcr_num`] (`TPMI_DH_PCR`)
//!   - [`LoadExternal::hierarchy`], [`Hash::hierarchy`] and
//!     [`SequenceComplete::hierarchy`] (`TPMI_RH_HIERARCHY+`)
//! - [`LoadExternal::in_public`] (and the `outPublic` parameter of the
//!   [`ReadPublic`] response) is unmarshalled as `TPM2B_PUBLIC+`, see above.
//!
//! When the `n`-th parameter of a command (1-based, counting only the
//! parameter area) fails to unmarshal,
//! [`UnmarshalMessage::unmarshal_with_handles`] attaches that position to the
//! [`UnmarshalError`] ([`UnmarshalError::in_parameter`]), so that
//! [`UnmarshalError::to_rc`] yields the same Format-One response code (with
//! parameter position) that a TPM returns for that command. Responses are
//! unmarshalled without attaching parameter positions.
//!
#![allow(deprecated)] // So we can define now-deprecated Commands / impls.
use crate::{Handle, Marshal, TpmCc, errors::UnmarshalError};

/// Common trait for a TPM 2.0 command [`Message`].
pub trait Command: Message {
    /// The [command code](TpmCc) for this command.
    const CMD_CODE: TpmCc;
    /// The corresponding response [`Message`] for this command.
    type Response<'a>: UnmarshalMessage<'a>;
}

/// Trait implemented for every [`Command`] and [`Command::Response`].
///
/// Note that the [`Marshal`] supertrait marshals only the parameter area of the
/// message; the handle area is accessed via [`Message::handles`].
pub trait Message: Marshal {
    /// Fixed-size array of [`Handle`]s in this message's handle area (`[Handle; N]`).
    type Handles: AsRef<[Handle]> + AsMut<[Handle]> + Default + Copy;
    /// Returns the handles in this message's handle area.
    fn handles(&self) -> Self::Handles;
}

/// Trait for unmarshaling a [`Message`] from its handle area and parameter bytes.
pub trait UnmarshalMessage<'a>: Message {
    /// Unmarshals the message's parameters from `src` and combines them with `handles`.
    fn unmarshal_with_handles(
        handles: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError>;
}

impl Message for () {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl UnmarshalMessage<'_> for () {
    fn unmarshal_with_handles([]: Self::Handles, _: &mut &'_ [u8]) -> Result<Self, UnmarshalError> {
        Ok(())
    }
}

mod asymmetric;
mod attached_components;
mod attestation;
mod capability;
mod clock_timer;
mod command_audit;
mod context;
mod dictionary_attack;
mod duplication;
mod enhanced_auth;
mod ephemeral;
mod field_upgrade;
mod hash_hmac_event;
mod hierarchy;
mod miscellaneous;
mod nv_storage;
mod object;
mod pcr;
mod random;
mod session;
mod signature;
mod startup;
mod symmetric;
mod testing;
mod vendor;

pub use {
    asymmetric::{
        Decapsulate, ECCDecrypt, ECCEncrypt, ECCParameters, ECDHKeyGen, ECDHZGen, Encapsulate,
        RSADecrypt, RSAEncrypt, ZGen2Phase,
    },
    attached_components::{ACGetCapability, ACSend, PolicyACSendSelect},
    attestation::{
        Certify, CertifyCreation, CertifyX509, GetCommandAuditDigest, GetSessionAuditDigest,
        GetTime, Quote,
    },
    capability::{GetCapability, SetCapability, TestParms},
    clock_timer::{ACTSetTimeout, ClockRateAdjust, ClockSet, ReadClock},
    command_audit::SetCommandCodeAuditStatus,
    context::{ContextLoad, ContextSave, EvictControl, FlushContext},
    dictionary_attack::{DictionaryAttackLockReset, DictionaryAttackParameters},
    duplication::{Duplicate, Import, Rewrap},
    enhanced_auth::{
        PolicyAuthValue, PolicyAuthorize, PolicyAuthorizeNV, PolicyCapability, PolicyCommandCode,
        PolicyCounterTimer, PolicyCpHash, PolicyDuplicationSelect, PolicyGetDigest, PolicyLocality,
        PolicyNV, PolicyNameHash, PolicyNvWritten, PolicyOR, PolicyPCR, PolicyParameters,
        PolicyPassword, PolicyPhysicalPresence, PolicySecret, PolicySigned, PolicyTemplate,
        PolicyTicket, PolicyTransportSPDM,
    },
    ephemeral::{Commit, ECEphemeral},
    field_upgrade::{FieldUpgradeData, FieldUpgradeStart, FirmwareRead},
    hash_hmac_event::{
        EventSequenceComplete, HMACStart, HashSequenceStart, SequenceComplete, SequenceUpdate,
        SignSequenceStart, VerifySequenceStart,
    },
    hierarchy::{
        ChangeEPS, ChangePPS, Clear, ClearControl, CreatePrimary, HierarchyChangeAuth,
        HierarchyControl, ReadOnlyControl, SetPrimaryPolicy,
    },
    miscellaneous::{PPCommands, SetAlgorithmSet},
    nv_storage::{
        NVCertify, NVChangeAuth, NVDefineSpace, NVDefineSpace2, NVExtend, NVGlobalWriteLock,
        NVIncrement, NVRead, NVReadLock, NVReadPublic, NVReadPublic2, NVSetBits, NVUndefineSpace,
        NVUndefineSpaceSpecial, NVWrite, NVWriteLock,
    },
    object::{
        ActivateCredential, Create, CreateLoaded, Load, LoadExternal, MakeCredential,
        ObjectChangeAuth, ReadPublic, Unseal,
    },
    pcr::{
        HashData, HashEnd, HashStart, PCRAllocate, PCREvent, PCRExtend, PCRRead, PCRReset,
        PCRSetAuthPolicy, PCRSetAuthValue,
    },
    random::{GetRandom, StirRandom},
    session::{PolicyRestart, StartAuthSession},
    signature::{
        Sign, SignDigest, SignSequenceComplete, VerifyDigestSignature, VerifySequenceComplete,
        VerifySignature,
    },
    startup::{Init, Shutdown, Startup},
    symmetric::{EncryptDecrypt, EncryptDecrypt2, HMAC, Hash},
    testing::{GetTestResult, IncrementalSelfTest, SelfTest},
    vendor::VendorTcgTest,
};

/// Response [`Message`] types corresponding to commands in [`crate::commands`].
pub mod responses {
    pub use super::asymmetric::DecapsulateRsp as Decapsulate;
    pub use super::asymmetric::ECCDecryptRsp as ECCDecrypt;
    pub use super::asymmetric::ECCEncryptRsp as ECCEncrypt;
    pub use super::asymmetric::ECCParametersRsp as ECCParameters;
    pub use super::asymmetric::ECDHKeyGenRsp as ECDHKeyGen;
    pub use super::asymmetric::ECDHZGenRsp as ECDHZGen;
    pub use super::asymmetric::EncapsulateRsp as Encapsulate;
    pub use super::asymmetric::RSADecryptRsp as RSADecrypt;
    pub use super::asymmetric::RSAEncryptRsp as RSAEncrypt;
    pub use super::asymmetric::ZGen2PhaseRsp as ZGen2Phase;
    pub use super::attached_components::ACGetCapabilityRsp as ACGetCapability;
    pub use super::attached_components::ACSendRsp as ACSend;
    pub use super::attestation::CertifyCreationRsp as CertifyCreation;
    pub use super::attestation::CertifyRsp as Certify;
    pub use super::attestation::CertifyX509Rsp as CertifyX509;
    pub use super::attestation::GetCommandAuditDigestRsp as GetCommandAuditDigest;
    pub use super::attestation::GetSessionAuditDigestRsp as GetSessionAuditDigest;
    pub use super::attestation::GetTimeRsp as GetTime;
    pub use super::attestation::QuoteRsp as Quote;
    pub use super::capability::GetCapabilityRsp as GetCapability;
    pub use super::clock_timer::ReadClockRsp as ReadClock;
    pub use super::context::ContextLoadRsp as ContextLoad;
    pub use super::context::ContextSaveRsp as ContextSave;
    pub use super::duplication::DuplicateRsp as Duplicate;
    pub use super::duplication::ImportRsp as Import;
    pub use super::duplication::RewrapRsp as Rewrap;
    pub use super::enhanced_auth::PolicyGetDigestRsp as PolicyGetDigest;
    pub use super::enhanced_auth::PolicySecretRsp as PolicySecret;
    pub use super::enhanced_auth::PolicySignedRsp as PolicySigned;
    pub use super::ephemeral::CommitRsp as Commit;
    pub use super::ephemeral::ECEphemeralRsp as ECEphemeral;
    pub use super::field_upgrade::FieldUpgradeDataRsp as FieldUpgradeData;
    pub use super::field_upgrade::FirmwareReadRsp as FirmwareRead;
    pub use super::hash_hmac_event::EventSequenceCompleteRsp as EventSequenceComplete;
    pub use super::hash_hmac_event::HMACStartRsp as HMACStart;
    pub use super::hash_hmac_event::HashSequenceStartRsp as HashSequenceStart;
    pub use super::hash_hmac_event::SequenceCompleteRsp as SequenceComplete;
    pub use super::hash_hmac_event::SignSequenceStartRsp as SignSequenceStart;
    pub use super::hash_hmac_event::VerifySequenceStartRsp as VerifySequenceStart;
    pub use super::hierarchy::CreatePrimaryRsp as CreatePrimary;
    pub use super::nv_storage::NVCertifyRsp as NVCertify;
    pub use super::nv_storage::NVReadPublic2Rsp as NVReadPublic2;
    pub use super::nv_storage::NVReadPublicRsp as NVReadPublic;
    pub use super::nv_storage::NVReadRsp as NVRead;
    pub use super::object::ActivateCredentialRsp as ActivateCredential;
    pub use super::object::CreateLoadedRsp as CreateLoaded;
    pub use super::object::CreateRsp as Create;
    pub use super::object::LoadExternalRsp as LoadExternal;
    pub use super::object::LoadRsp as Load;
    pub use super::object::MakeCredentialRsp as MakeCredential;
    pub use super::object::ObjectChangeAuthRsp as ObjectChangeAuth;
    pub use super::object::ReadPublicRsp as ReadPublic;
    pub use super::object::UnsealRsp as Unseal;
    pub use super::pcr::PCRAllocateRsp as PCRAllocate;
    pub use super::pcr::PCREventRsp as PCREvent;
    pub use super::pcr::PCRReadRsp as PCRRead;
    pub use super::random::GetRandomRsp as GetRandom;
    pub use super::session::StartAuthSessionRsp as StartAuthSession;
    pub use super::signature::SignDigestRsp as SignDigest;
    pub use super::signature::SignRsp as Sign;
    pub use super::signature::SignSequenceCompleteRsp as SignSequenceComplete;
    pub use super::signature::VerifyDigestSignatureRsp as VerifyDigestSignature;
    pub use super::signature::VerifySequenceCompleteRsp as VerifySequenceComplete;
    pub use super::signature::VerifySignatureRsp as VerifySignature;
    pub use super::symmetric::EncryptDecrypt2Rsp as EncryptDecrypt2;
    pub use super::symmetric::EncryptDecryptRsp as EncryptDecrypt;
    pub use super::symmetric::HMACRsp as HMAC;
    pub use super::symmetric::HashRsp as Hash;
    pub use super::testing::GetTestResultRsp as GetTestResult;
    pub use super::testing::IncrementalSelfTestRsp as IncrementalSelfTest;
    pub use super::vendor::VendorTcgTestRsp as VendorTcgTest;
}
