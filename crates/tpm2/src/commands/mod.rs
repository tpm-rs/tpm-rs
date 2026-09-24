//! TPM 2.0 Commands and Request/Response Protocol Layout
//!
//! This module defines the request and response structures, handle lists,
//! and [`Command`] / [`Message`] trait implementations for TPM 2.0 commands.
//!
//! ## Differences from the TPM 2.0 Specification
//!
//! While most command and response types map directly to the tables in
//! **Part 3: Commands** of the TPM 2.0 Specification, several intentional
//! design differences exist:
//!
//! ### Intentionally omitted commands
//!
//! While we intend to have comprehensive definitions for most commands, we
//! intentionally omit definitions for:
//! - [`CreateLoaded`](TpmCc::CreateLoaded): deprecated in v184
//!   - Avoids issues with "Derived Objects" and "Derivation Parents".
//!   - Users can just use [`Create`]/[`CreatePrimary`] and [`Load`].
//! - [`CertifyX509`](TpmCc::CertifyX509): deprecated in v184
//!   - Very difficult to implement correctly.
//! - "Attached Components": deprecated in v184
//!   - [`ACGetCapability`](TpmCc::ACGetCapability)
//!   - [`ACSend`](TpmCc::ACSend)
//!   - [`PolicyACSendSelect`](TpmCc::PolicyACSendSelect)
//! - [`SetCapability`](TpmCc::SetCapability): added in v1.83
//!   - Currently impossible to define as `TPMU_SET_CAPABILITIES` is not defined
//!     anywhere in the specification.
//!
//! Any other deprecated commands are defined, but are annotated with
//! Rust's `#[deprecated]` attribute.
//!
//! ### Empty Responses
//!
//! Commands whose responses contain neither handles nor parameters (e.g.
//! [`Startup`]) use `type Response<'a> = ()` rather than empty unit structs.
//!
//! ### [`LoadExternal`]
//!
//! The [`in_public` command parameter](LoadExternal::in_public) has type
//! `TPM2B_PUBLIC+` in the specification, but we treat this like `TPM2B_PUBLIC`,
//! mapping it to [`Tpm2bPublic`](crate::Tpm2bPublic).
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
//! ### Commands to be added in the future
//!
//! We plan on adding the following commands once the necessary prerequisite
//! types and `impl`s have been added:
//!
//! - Needs `TPMT_RSA_DECRYPT+`
//!   - [`RSAEncrypt`](TpmCc::RSAEncrypt)
//!   - [`RSADecrypt`](TpmCc::RSADecrypt)
//! - Needs `TPMI_ECC_KEY_EXCHANGE`
//!   - [`ZGen2Phase`](TpmCc::ZGen2Phase)
//! - Needs [`Marshal`]/[`Unmarshal`](crate::Unmarshal) `impl`s for [`Option<TpmtHa<'a>>`](crate::TpmtHa)
//!   - [`FieldUpgradeData`](TpmCc::FieldUpgradeData)
//! - NV Expanded Attributes needing `TPM2B_NV_PUBLIC_2` / `TPMT_NV_PUBLIC_2`
//!   - [`NVDefineSpace2`](TpmCc::NVDefineSpace2)
//!   - [`NVReadPublic2`](TpmCc::NVReadPublic2)
//! - KEM commands needing `TPM2B_SHARED_SECRET` and `TPM2B_KEM_CIPHERTEXT`
//!   - [`Encapsulate`](TpmCc::Encapsulate)
//!   - [`Decapsulate`](TpmCc::Decapsulate)
//! - Signing commands needing `TPM2B_SIGNATURE_HINT` and `TPM2B_SIGNATURE_CTX`
//!   - [`SignDigest`](TpmCc::SignDigest)
//!   - [`VerifyDigestSignature`](TpmCc::VerifyDigestSignature)
//!   - [`SignSequenceStart`](TpmCc::SignSequenceStart)
//!   - [`VerifySequenceStart`](TpmCc::VerifySequenceStart)
//!
//! This module comment will be updated as we add new commands.
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

pub use {
    asymmetric::{ECCDecrypt, ECCEncrypt, ECCParameters, ECDHKeyGen, ECDHZGen},
    attestation::{
        Certify, CertifyCreation, GetCommandAuditDigest, GetSessionAuditDigest, GetTime, Quote,
    },
    capability::{GetCapability, TestParms},
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
    field_upgrade::{FieldUpgradeStart, FirmwareRead},
    hash_hmac_event::{
        EventSequenceComplete, HMACStart, HashSequenceStart, SequenceComplete, SequenceUpdate,
    },
    hierarchy::{
        ChangeEPS, ChangePPS, Clear, ClearControl, CreatePrimary, HierarchyChangeAuth,
        HierarchyControl, ReadOnlyControl, SetPrimaryPolicy,
    },
    miscellaneous::{PPCommands, SetAlgorithmSet},
    nv_storage::{
        NVCertify, NVChangeAuth, NVDefineSpace, NVExtend, NVGlobalWriteLock, NVIncrement, NVRead,
        NVReadLock, NVReadPublic, NVSetBits, NVUndefineSpace, NVUndefineSpaceSpecial, NVWrite,
        NVWriteLock,
    },
    object::{
        ActivateCredential, Create, Load, LoadExternal, MakeCredential, ObjectChangeAuth,
        ReadPublic, Unseal,
    },
    pcr::{PCRAllocate, PCREvent, PCRExtend, PCRRead, PCRReset, PCRSetAuthPolicy, PCRSetAuthValue},
    random::{GetRandom, StirRandom},
    session::{PolicyRestart, StartAuthSession},
    signature::{Sign, SignSequenceComplete, VerifySequenceComplete, VerifySignature},
    startup::{Shutdown, Startup},
    symmetric::{EncryptDecrypt, EncryptDecrypt2, HMAC, Hash},
    testing::{GetTestResult, IncrementalSelfTest, SelfTest},
};

/// Response [`Message`] types corresponding to commands in [`crate::commands`].
pub mod responses {
    pub use super::asymmetric::ECCDecryptRsp as ECCDecrypt;
    pub use super::asymmetric::ECCEncryptRsp as ECCEncrypt;
    pub use super::asymmetric::ECCParametersRsp as ECCParameters;
    pub use super::asymmetric::ECDHKeyGenRsp as ECDHKeyGen;
    pub use super::asymmetric::ECDHZGenRsp as ECDHZGen;
    pub use super::attestation::CertifyCreationRsp as CertifyCreation;
    pub use super::attestation::CertifyRsp as Certify;
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
    pub use super::field_upgrade::FirmwareReadRsp as FirmwareRead;
    pub use super::hash_hmac_event::EventSequenceCompleteRsp as EventSequenceComplete;
    pub use super::hash_hmac_event::HMACStartRsp as HMACStart;
    pub use super::hash_hmac_event::HashSequenceStartRsp as HashSequenceStart;
    pub use super::hash_hmac_event::SequenceCompleteRsp as SequenceComplete;
    pub use super::hierarchy::CreatePrimaryRsp as CreatePrimary;
    pub use super::nv_storage::NVCertifyRsp as NVCertify;
    pub use super::nv_storage::NVReadPublicRsp as NVReadPublic;
    pub use super::nv_storage::NVReadRsp as NVRead;
    pub use super::object::ActivateCredentialRsp as ActivateCredential;
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
    pub use super::signature::SignRsp as Sign;
    pub use super::signature::SignSequenceCompleteRsp as SignSequenceComplete;
    pub use super::signature::VerifySequenceCompleteRsp as VerifySequenceComplete;
    pub use super::signature::VerifySignatureRsp as VerifySignature;
    pub use super::symmetric::EncryptDecrypt2Rsp as EncryptDecrypt2;
    pub use super::symmetric::EncryptDecryptRsp as EncryptDecrypt;
    pub use super::symmetric::HMACRsp as HMAC;
    pub use super::symmetric::HashRsp as Hash;
    pub use super::testing::GetTestResultRsp as GetTestResult;
    pub use super::testing::IncrementalSelfTestRsp as IncrementalSelfTest;
}
