//! TPM 2.0 Commands and Request/Response Protocol Layout
//!
//! This module defines the request parameters, response parameters, handle lists,
//! and [`Command`] trait implementations for the commands defined in "Part 3: Commands"
//! of the TPM 2.0 Specification.
//!
//! The commands are divided into submodules corresponding to their sections in
//! the specification:
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
//! - `vendor` (Vendor-specific command placeholders)

pub use crate::Command;

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
        Decapsulate, DecapsulateHandles, DecapsulateRsp, ECCDecrypt, ECCDecryptHandles,
        ECCDecryptRsp, ECCEncrypt, ECCEncryptHandles, ECCEncryptRsp, ECCParameters,
        ECCParametersRsp, ECDHKeyGen, ECDHKeyGenHandles, ECDHKeyGenRsp, ECDHZGen, ECDHZGenHandles,
        ECDHZGenRsp, Encapsulate, EncapsulateHandles, EncapsulateRsp, RSADecrypt,
        RSADecryptHandles, RSADecryptRsp, RSAEncrypt, RSAEncryptHandles, RSAEncryptRsp, ZGen2Phase,
        ZGen2PhaseHandles, ZGen2PhaseRsp,
    },
    attached_components::{
        ACGetCapability, ACGetCapabilityHandles, ACGetCapabilityRsp, ACSend, ACSendHandles,
        ACSendRsp, PolicyACSendSelect, PolicyACSendSelectHandles,
    },
    attestation::{
        Certify, CertifyCreation, CertifyCreationHandles, CertifyCreationRsp, CertifyHandles,
        CertifyRsp, CertifyX509, CertifyX509Handles, CertifyX509Rsp, GetCommandAuditDigest,
        GetCommandAuditDigestHandles, GetCommandAuditDigestRsp, GetSessionAuditDigest,
        GetSessionAuditDigestHandles, GetSessionAuditDigestRsp, GetTime, GetTimeHandles,
        GetTimeRsp, Quote, QuoteHandles, QuoteRsp,
    },
    capability::{GetCapability, GetCapabilityRsp, SetCapability, SetCapabilityHandles, TestParms},
    clock_timer::{
        ACTSetTimeout, ACTSetTimeoutHandles, ClockRateAdjust, ClockRateAdjustHandles, ClockSet,
        ClockSetHandles, ReadClock, ReadClockRsp,
    },
    command_audit::{SetCommandCodeAuditStatus, SetCommandCodeAuditStatusHandles},
    context::{
        ContextLoad, ContextLoadRespHandles, ContextSave, ContextSaveHandles, ContextSaveRsp,
        EvictControl, EvictControlHandles, FlushContext,
    },
    dictionary_attack::{
        DictionaryAttackLockReset, DictionaryAttackLockResetHandles, DictionaryAttackParameters,
        DictionaryAttackParametersHandles,
    },
    duplication::{
        Duplicate, DuplicateHandles, DuplicateRsp, Import, ImportHandles, ImportRsp, Rewrap,
        RewrapHandles, RewrapRsp,
    },
    enhanced_auth::{
        PolicyAuthValue, PolicyAuthValueHandles, PolicyAuthorize, PolicyAuthorizeHandles,
        PolicyAuthorizeNV, PolicyAuthorizeNVHandles, PolicyCapability, PolicyCapabilityHandles,
        PolicyCommandCode, PolicyCommandCodeHandles, PolicyCounterTimer, PolicyCounterTimerHandles,
        PolicyCpHash, PolicyCpHashHandles, PolicyDuplicationSelect, PolicyDuplicationSelectHandles,
        PolicyGetDigest, PolicyGetDigestHandles, PolicyGetDigestRsp, PolicyLocality,
        PolicyLocalityHandles, PolicyNV, PolicyNVHandles, PolicyNameHash, PolicyNameHashHandles,
        PolicyNvWritten, PolicyNvWrittenHandles, PolicyOR, PolicyORHandles, PolicyPCR,
        PolicyPCRHandles, PolicyParameters, PolicyParametersHandles, PolicyPassword,
        PolicyPasswordHandles, PolicyPhysicalPresence, PolicyPhysicalPresenceHandles, PolicySecret,
        PolicySecretHandles, PolicySecretRsp, PolicySigned, PolicySignedHandles, PolicySignedRsp,
        PolicyTemplate, PolicyTemplateHandles, PolicyTicket, PolicyTicketHandles,
        PolicyTransportSPDM, PolicyTransportSPDMHandles,
    },
    ephemeral::{Commit, CommitHandles, CommitRsp, ECEphemeral, ECEphemeralRsp},
    field_upgrade::{
        FieldUpgradeData, FieldUpgradeDataRsp, FieldUpgradeStart, FieldUpgradeStartHandles,
        FirmwareRead, FirmwareReadRsp,
    },
    hash_hmac_event::{
        EventSequenceComplete, EventSequenceCompleteHandles, EventSequenceCompleteRsp,
        HashSequenceStart, HashSequenceStartHandles, HashSequenceStartRespHandles, HmacStart,
        HmacStartHandles, HmacStartRespHandles, MACStart, MACStartHandles, MACStartRespHandles,
        SequenceComplete, SequenceCompleteHandles, SequenceCompleteRsp, SequenceUpdate,
        SequenceUpdateHandles, SignSequenceStart, SignSequenceStartHandles,
        SignSequenceStartRespHandles, VerifySequenceStart, VerifySequenceStartHandles,
        VerifySequenceStartRespHandles,
    },
    hierarchy::{
        ChangeEPS, ChangeEPSHandles, ChangePPS, ChangePPSHandles, Clear, ClearControl,
        ClearControlHandles, ClearHandles, CreatePrimary, CreatePrimaryHandles,
        CreatePrimaryRespHandles, CreatePrimaryRsp, HierarchyChangeAuth,
        HierarchyChangeAuthHandles, HierarchyControl, HierarchyControlHandles, ReadOnlyControl,
        ReadOnlyControlHandles, SetPrimaryPolicy, SetPrimaryPolicyHandles,
    },
    miscellaneous::{PPCommands, PPCommandsHandles, SetAlgorithmSet, SetAlgorithmSetHandles},
    nv_storage::{
        NVCertify, NVCertifyHandles, NVCertifyRsp, NVChangeAuth, NVChangeAuthHandles,
        NVDefineSpace, NVDefineSpace2, NVDefineSpace2Handles, NVDefineSpaceHandles, NVExtend,
        NVExtendHandles, NVGlobalWriteLock, NVGlobalWriteLockHandles, NVIncrement,
        NVIncrementHandles, NVRead, NVReadHandles, NVReadLock, NVReadLockHandles, NVReadPublic,
        NVReadPublic2, NVReadPublic2Handles, NVReadPublic2Rsp, NVReadPublicHandles,
        NVReadPublicRsp, NVReadRsp, NVSetBits, NVSetBitsHandles, NVUndefineSpace,
        NVUndefineSpaceHandles, NVUndefineSpaceSpecial, NVUndefineSpaceSpecialHandles, NVWrite,
        NVWriteHandles, NVWriteLock, NVWriteLockHandles,
    },
    object::{
        ActivateCredential, ActivateCredentialHandles, ActivateCredentialRsp, Create,
        CreateHandles, CreateLoaded, CreateLoadedHandles, CreateLoadedRespHandles, CreateLoadedRsp,
        CreateRsp, Load, LoadExternal, LoadExternalRespHandles, LoadExternalRsp, LoadHandles,
        LoadRespHandles, LoadRsp, MakeCredential, MakeCredentialHandles, MakeCredentialRsp,
        ObjectChangeAuth, ObjectChangeAuthHandles, ObjectChangeAuthRsp, ReadPublic,
        ReadPublicHandles, ReadPublicRsp, Unseal, UnsealHandles, UnsealRsp,
    },
    pcr::{
        HashData, HashEnd, HashStart, PCRAllocate, PCRAllocateHandles, PCRAllocateRsp, PCREvent,
        PCREventHandles, PCREventRsp, PCRExtend, PCRExtendHandles, PCRRead, PCRReadRsp, PCRReset,
        PCRResetHandles, PCRSetAuthPolicy, PCRSetAuthPolicyHandles, PCRSetAuthValue,
        PCRSetAuthValueHandles,
    },
    random::{GetRandom, GetRandomRsp, StirRandom},
    session::{
        PolicyRestart, PolicyRestartHandles, StartAuthSession, StartAuthSessionHandles,
        StartAuthSessionRespHandles, StartAuthSessionRsp,
    },
    signature::{
        Sign, SignDigest, SignDigestHandles, SignDigestRsp, SignHandles, SignRsp,
        SignSequenceComplete, SignSequenceCompleteHandles, SignSequenceCompleteRsp,
        VerifyDigestSignature, VerifyDigestSignatureHandles, VerifyDigestSignatureRsp,
        VerifySequenceComplete, VerifySequenceCompleteHandles, VerifySequenceCompleteRsp,
        VerifySignature, VerifySignatureHandles, VerifySignatureRsp,
    },
    startup::{Init, Shutdown, Startup},
    symmetric::{
        EncryptDecrypt, EncryptDecrypt2, EncryptDecrypt2Handles, EncryptDecrypt2Rsp,
        EncryptDecryptHandles, EncryptDecryptRsp, Hash, HashRsp, Hmac, HmacHandles, HmacRsp, MAC,
        MACHandles, MACRsp,
    },
    testing::{
        GetTestResult, GetTestResultRsp, IncrementalSelfTest, IncrementalSelfTestRsp, SelfTest,
    },
    vendor::{VendorTcgTest, VendorTcgTestRsp},
};

pub mod responses {
    pub use super::{
        asymmetric::{
            DecapsulateRsp as Decapsulate, ECCDecryptRsp as ECCDecrypt,
            ECCEncryptRsp as ECCEncrypt, ECCParametersRsp as ECCParameters,
            ECDHKeyGenRsp as ECDHKeyGen, ECDHZGenRsp as ECDHZGen, EncapsulateRsp as Encapsulate,
            RSADecryptRsp as RSADecrypt, RSAEncryptRsp as RSAEncrypt, ZGen2PhaseRsp as ZGen2Phase,
        },
        attached_components::{ACGetCapabilityRsp as ACGetCapability, ACSendRsp as ACSend},
        attestation::{
            CertifyCreationRsp as CertifyCreation, CertifyRsp as Certify,
            CertifyX509Rsp as CertifyX509, GetCommandAuditDigestRsp as GetCommandAuditDigest,
            GetSessionAuditDigestRsp as GetSessionAuditDigest, GetTimeRsp as GetTime,
            QuoteRsp as Quote,
        },
        capability::GetCapabilityRsp as GetCapability,
        clock_timer::ReadClockRsp as ReadClock,
        context::ContextSaveRsp as ContextSave,
        duplication::{DuplicateRsp as Duplicate, ImportRsp as Import, RewrapRsp as Rewrap},
        enhanced_auth::{
            PolicyGetDigestRsp as PolicyGetDigest, PolicySecretRsp as PolicySecret,
            PolicySignedRsp as PolicySigned,
        },
        ephemeral::{CommitRsp as Commit, ECEphemeralRsp as ECEphemeral},
        field_upgrade::{FieldUpgradeDataRsp as FieldUpgradeData, FirmwareReadRsp as FirmwareRead},
        hash_hmac_event::{
            EventSequenceCompleteRsp as EventSequenceComplete,
            SequenceCompleteRsp as SequenceComplete,
        },
        hierarchy::CreatePrimaryRsp as CreatePrimary,
        nv_storage::{
            NVCertifyRsp as NVCertify, NVReadPublic2Rsp as NVReadPublic2,
            NVReadPublicRsp as NVReadPublic, NVReadRsp as NVRead,
        },
        object::{
            ActivateCredentialRsp as ActivateCredential, CreateLoadedRsp as CreateLoaded,
            CreateRsp as Create, LoadExternalRsp as LoadExternal, LoadRsp as Load,
            MakeCredentialRsp as MakeCredential, ObjectChangeAuthRsp as ObjectChangeAuth,
            ReadPublicRsp as ReadPublic, UnsealRsp as Unseal,
        },
        pcr::{PCRAllocateRsp as PCRAllocate, PCREventRsp as PCREvent, PCRReadRsp as PCRRead},
        random::GetRandomRsp as GetRandom,
        session::StartAuthSessionRsp as StartAuthSession,
        signature::{
            SignDigestRsp as SignDigest, SignRsp as Sign,
            SignSequenceCompleteRsp as SignSequenceComplete,
            VerifyDigestSignatureRsp as VerifyDigestSignature,
            VerifySequenceCompleteRsp as VerifySequenceComplete,
            VerifySignatureRsp as VerifySignature,
        },
        symmetric::{
            EncryptDecrypt2Rsp as EncryptDecrypt2, EncryptDecryptRsp as EncryptDecrypt,
            HashRsp as Hash, HmacRsp as Hmac, MACRsp as MAC,
        },
        testing::{
            GetTestResultRsp as GetTestResult, IncrementalSelfTestRsp as IncrementalSelfTest,
        },
        vendor::VendorTcgTestRsp as VendorTcgTest,
    };
}
