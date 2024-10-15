use crate::constants::{TpmCap, TpmCc, TpmPt, TpmSu};
use crate::Marshalable;
use crate::{TpmiYesNo, TpmlDigest, TpmlPcrSelection, TpmsCapabilityData};

/// Trait for a TPM command transaction.
pub trait TpmCommand: Marshalable {
    /// The command code.
    const CMD_CODE: TpmCc;
    /// The command handles type.
    type Handles: Marshalable + Default;
    /// The response parameters type.
    type RespT: Marshalable;
    /// The reponse handles type.
    type RespHandles: Marshalable;
}

/// [TPM2.0 1.83: 9.2] _TPM_Init
pub struct InitCmd {}

/// [TPM2.0 1.83: 9.3] TPM2_Startup (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct StartupCmd {
    pub startup_type: TpmSu,
}
impl TpmCommand for StartupCmd {
    const CMD_CODE: TpmCc = TpmCc::Startup;
    type Handles = ();
    type RespT = ();
    type RespHandles = ();
}

/// [TPM2.0 1.83: 9.4] TPM2_Shutdown (Command)
pub struct ShutdownCmd {}

/// [TPM2.0 1.83: 10.2] TPM2_SelfTest (Command)
pub struct SelfTestCmd {}

/// [TPM2.0 1.83: 10.3] TPM2_IncrementalSelfTest (Command)
pub struct IncrementalSelfTestCmd {}

/// [TPM2.0 1.83: 10.4] TPM2_GetTestResult (Command)
pub struct GetTestResultCmd {}

/// [TPM2.0 1.83: 11.1] TPM2_StartAuthSession (Command)
pub struct StartAuthSessionCmd {}

/// [TPM2.0 1.83: 11.2] TPM2_PolicyRestart (Command)
pub struct PolicyRestartCmd {}

/// [TPM2.0 1.83: 12.1] TPM2_Create (Command)
pub struct CreateCmd {}

/// [TPM2.0 1.83: 12.2] TPM2_Load (Command)
pub struct LoadCmd {}

/// [TPM2.0 1.83: 12.3] TPM2_LoadExternal (Command)
pub struct LoadExternalCmd {}

/// [TPM2.0 1.83: 12.4] TPM2_ReadPublic (Command)
pub struct ReadPublicCmd {}

/// [TPM2.0 1.83: 12.5] TPM2_ActivateCredential (Command)
pub struct ActivateCredentialCmd {}

/// [TPM2.0 1.83: 12.6] TPM2_MakeCredential (Command)
pub struct MakeCredentialCmd {}

/// [TPM2.0 1.83: 12.7] TPM2_Unseal (Command)
pub struct UnsealCmd {}

/// [TPM2.0 1.83: 12.8] TPM2_ObjectChangeAuth (Command)
pub struct ObjectChangeAuthCmd {}

/// [TPM2.0 1.83: 12.9] TPM2_CreateLoaded (Command)
pub struct CreateLoadedCmd {}

/// [TPM2.0 1.83: 13.1] TPM2_Duplicate (Command)
pub struct DuplicateCmd {}

/// [TPM2.0 1.83: 13.2] TPM2_Rewrap (Command)
pub struct RewrapCmd {}

/// [TPM2.0 1.83: 13.3] TPM2_Import (Command)
pub struct ImportCmd {}

/// [TPM2.0 1.83: 14.2] TPM2_RSA_Encrypt (Command)
pub struct RsaEncryptCmd {}

/// [TPM2.0 1.83: 14.3] TPM2_RSA_Decrypt (Command)
pub struct RsaDecryptCmd {}

/// [TPM2.0 1.83: 14.4] TPM2_ECDH_KeyGen (Command)
pub struct EcdhKeyGenCmd {}

/// [TPM2.0 1.83: 14.5] TPM2_ECDH_ZGen (Command)
pub struct EcdhZGenCmd {}

/// [TPM2.0 1.83: 14.6] TPM2_ECC_Parameters (Command)
pub struct EccParametersCmd {}

/// [TPM2.0 1.83: 14.7] TPM2_ZGen_2Phase (Command)
pub struct ZGen2PhaseCmd {}

/// [TPM2.0 1.83: 14.8] TPM2_ECC_Encrypt (Command)
pub struct EccEncryptCmd {}

/// [TPM2.0 1.83: 14.9] TPM2_ECC_Decrypt (Command)
pub struct EccDecryptCmd {}

/// [TPM2.0 1.83: 15.2] TPM2_EncryptDecrypt (Command)
pub struct EncryptDecryptCmd {}

/// [TPM2.0 1.83: 15.3] TPM2_EncryptDecrypt2 (Command)
pub struct EncryptDecrypt2Cmd {}

/// [TPM2.0 1.83: 15.4] TPM2_Hash (Command)
pub struct HashCmd {}

/// [TPM2.0 1.83: 15.5] TPM2_HMAC (Command)
pub struct HmacCmd {}

/// [TPM2.0 1.83: 15.6] TPM2_MAC (Command)
pub struct MacCmd {}

/// [TPM2.0 1.83: 16.1] TPM2_GetRandom (Command)
pub struct GetRandomCmd {}

/// [TPM2.0 1.83: 16.2] TPM2_StirRandom (Command)
pub struct StirRandomCmd {}

/// [TPM2.0 1.83: 17.2] TPM2_HMAC_Start (Command)
pub struct HmacStartCmd {}

/// [TPM2.0 1.83: 17.3] TPM2_MAC_Start (Command)
pub struct MacStartCmd {}

/// [TPM2.0 1.83: 17.4] TPM2_HashSequenceStart (Command)
pub struct HashSequenceStartCmd {}

/// [TPM2.0 1.83: 17.5] TPM2_SequenceUpdate (Command)
pub struct SequenceUpdateCmd {}

/// [TPM2.0 1.83: 17.6] TPM2_SequenceComplete (Command)
pub struct SequenceCompleteCmd {}

/// [TPM2.0 1.83: 17.7] TPM2_EventSequenceComplete (Command)
pub struct EventSequenceCompleteCmd {}

/// [TPM2.0 1.83: 18.2] TPM2_Certify (Command)
pub struct CertifyCmd {}

/// [TPM2.0 1.83: 18.3] TPM2_CertifyCreation (Command)
pub struct CertifyCreationCmd {}

/// [TPM2.0 1.83: 18.4] TPM2_Quote (Command)
pub struct QuoteCmd {}

/// [TPM2.0 1.83: 18.5] TPM2_GetSessionAuditDigest (Command)
pub struct GetSessionAuditDigestCmd {}

/// [TPM2.0 1.83: 18.6] TPM2_GetCommandAuditDigest (Command)
pub struct GetCommandAuditDigestCmd {}

/// [TPM2.0 1.83: 18.7] TPM2_GetTime (Command)
pub struct GetTimeCmd {}

/// [TPM2.0 1.83: 18.8] TPM2_CertifyX509 (Command)
pub struct CertifyX509Cmd {}

/// [TPM2.0 1.83: 19.2] TPM2_Commit (Command)
pub struct CommitCmd {}

/// [TPM2.0 1.83: 19.3] TPM2_EC_Ephemeral (Command)
pub struct EcEphemeralCmd {}

/// [TPM2.0 1.83: 20.1] TPM2_VerifySignature (Command)
pub struct VerifySignatureCmd {}

/// [TPM2.0 1.83: 20.2] TPM2_Sign (Command)
pub struct SignCmd {}

/// [TPM2.0 1.83: 21.2] TPM2_SetCommandCodeAuditStatus (Command)
pub struct SetCommandCodeAuditStatusCmd {}

/// [TPM2.0 1.83: 22.2] TPM2_PCR_Extend (Command)
pub struct PcrExtendCmd {}

/// [TPM2.0 1.83: 22.3] TPM2_PCR_Event (Command)
pub struct PcrEventCmd {}

/// [TPM2.0 1.83: 22.4] TPM2_PCR_Read (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct PcrReadCmd {
    pcr_selection_in: TpmlPcrSelection,
}
impl TpmCommand for PcrReadCmd {
    const CMD_CODE: TpmCc = TpmCc::PCRRead;
    type Handles = ();
    type RespT = PcrReadResp;
    type RespHandles = ();
}
/// [TPM2.0 1.83: 22.4] TPM2_PCR_Read (Response)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct PcrReadResp {
    pcr_update_counter: u32,
    pcr_selection_out: TpmlPcrSelection,
    pcr_values: TpmlDigest,
}

/// [TPM2.0 1.83: 22.5] TPM2_PCR_Allocate (Command)
pub struct PcrAllocateCmd {}

/// [TPM2.0 1.83: 22.6] TPM2_PCR_SetAuthPolicy (Command)
pub struct PcrSetAuthPolicyCmd {}

/// [TPM2.0 1.83: 22.7] TPM2_PCR_SetAuthValue (Command)
pub struct PcrSetAuthValueCmd {}

/// [TPM2.0 1.83: 22.8] TPM2_PCR_Reset (Command)
pub struct PcrResetCmd {}

/// [TPM2.0 1.83: 22.9] _TPM_Hash_Start
pub struct HashStartCmd {}

/// [TPM2.0 1.83: 22.10] _TPM_Hash_Data
pub struct HashStartData {}

/// [TPM2.0 1.83: 22.11] _TPM_Hash_End
pub struct HashStartEnd {}

/// [TPM2.0 1.83: 23.3] TPM2_PolicySigned (Command)
pub struct PolicySignedCmd {}

/// [TPM2.0 1.83: 23.4] TPM2_PolicySecret (Command)
pub struct PolicySecretCmd {}

/// [TPM2.0 1.83: 23.5] TPM2_PolicyTicket (Command)
pub struct PolicyTicketCmd {}

/// [TPM2.0 1.83: 23.6] TPM2_PolicyOR (Command)
pub struct PolicyOrCmd {}

/// [TPM2.0 1.83: 23.7] TPM2_PolicyPCR (Command)
pub struct PolicyPcrCmd {}

/// [TPM2.0 1.83: 23.8] TPM2_PolicyLocality (Command)
pub struct PolicyLocalityCmd {}

/// [TPM2.0 1.83: 23.9] TPM2_PolicyNV (Command)
pub struct PolicyNvCmd {}

/// [TPM2.0 1.83: 23.10] TPM2_PolicyCounterTimer (Command)
pub struct PolicyCounterTimerCmd {}

/// [TPM2.0 1.83: 23.11] TPM2_PolicyCommandCode (Command)
pub struct PolicyCommandCodeCmd {}

/// [TPM2.0 1.83: 23.12] TPM2_PolicyPhysicalPresence (Command)
pub struct PolicyPhysicalPresenceCmd {}

/// [TPM2.0 1.83: 23.13] TPM2_PolicyCpHash (Command)
pub struct PolicyCpHashCmd {}

/// [TPM2.0 1.83: 23.14] TPM2_PolicyNameHash (Command)
pub struct PolicyNameHashCmd {}

/// [TPM2.0 1.83: 23.15] TPM2_PolicyDuplicationSelect (Command)
pub struct PolicyDuplicationSelectCmd {}

/// [TPM2.0 1.83: 23.16] TPM2_PolicyAuthorize (Command)
pub struct PolicyAuthorizeCmd {}

/// [TPM2.0 1.83: 23.17] TPM2_PolicyAuthValue (Command)
pub struct PolicyAuthValueCmd {}

/// [TPM2.0 1.83: 23.18] TPM2_PolicyPassword (Command)
pub struct PolicyPasswordCmd {}

/// [TPM2.0 1.83: 23.19] TPM2_PolicyGetDigest (Command)
pub struct PolicyGetDigestCmd {}

/// [TPM2.0 1.83: 23.20] TPM2_PolicyNvWritten (Command)
pub struct PolicyNvWrittenCmd {}

/// [TPM2.0 1.83: 23.21] TPM2_PolicyTemplate (Command)
pub struct PolicyTemplateCmd {}

/// [TPM2.0 1.83: 23.22] TPM2_PolicyAuthorizeNV (Command)
pub struct PolicyAuthorizeNvCmd {}

/// [TPM2.0 1.83: 23.23] TPM2_PolicyCapability (Command)
pub struct PolicyCapabilityCmd {}

/// [TPM2.0 1.83: 23.24] TPM2_PolicyParameters (Command)
pub struct PolicyParametersCmd {}

/// [TPM2.0 1.83: 24.1] TPM2_CreatePrimary (Command)
pub struct CreatePrimaryCmd {}

/// [TPM2.0 1.83: 24.2] TPM2_HierarchyControl (Command)
pub struct HierarchyControlCmd {}

/// [TPM2.0 1.83: 24.3] TPM2_SetPrimaryPolicy (Command)
pub struct SetPrimaryPolicyCmd {}

/// [TPM2.0 1.83: 24.4] TPM2_ChangePPS (Command)
pub struct ChangePpsCmd {}

/// [TPM2.0 1.83: 24.5] TPM2_ChangeEPS (Command)
pub struct ChangeEpsCmd {}

/// [TPM2.0 1.83: 24.6] TPM2_Clear (Command)
pub struct ClearCmd {}

/// [TPM2.0 1.83: 24.7] TPM2_ClearControl (Command)
pub struct ClearControlCmd {}

/// [TPM2.0 1.83: 24.8] TPM2_HierarchyChangeAuth (Command)
pub struct HierarchyChangeAuthCmd {}

/// [TPM2.0 1.83: 25.2] TPM2_DictionaryAttackLockReset (Command)
pub struct DictionaryAttackLockResetCmd {}

/// [TPM2.0 1.83: 25.3] TPM2_DictionaryAttackParameters (Command)
pub struct DictionaryAttackParametersCmd {}

/// [TPM2.0 1.83: 26.2] TPM2_PP_Commands (Command)
pub struct PpCommandsCmd {}

/// [TPM2.0 1.83: 26.3] TPM2_SetAlgorithmSet (Command)
pub struct SetAlgorithmSetCmd {}

/// [TPM2.0 1.83: 27.2] TPM2_FieldUpgradeStart (Command)
pub struct FieldUpgradeStartCmd {}

/// [TPM2.0 1.83: 27.3] TPM2_FieldUpgradeData (Command)
pub struct FieldUpgradeDataCmd {}

/// [TPM2.0 1.83: 27.4] TPM2_FirmwareRead (Command)
pub struct FirmwareReadCmd {}

/// [TPM2.0 1.83: 28.2] TPM2_ContextSave (Command)
pub struct ContextSaveCmd {}

/// [TPM2.0 1.83: 28.3] TPM2_ContextLoad (Command)
pub struct ContextLoadCmd {}

/// [TPM2.0 1.83: 28.4] TPM2_FlushContext (Command)
pub struct FlushContextCmd {}

/// [TPM2.0 1.83: 28.5] TPM2_EvictControl (Command)
pub struct EvictControlCmd {}

/// [TPM2.0 1.83: 29.1] TPM2_ReadClock (Command)
pub struct ReadClockCmd {}

/// [TPM2.0 1.83: 29.2] TPM2_ClockSet (Command)
pub struct ClockSetCmd {}

/// [TPM2.0 1.83: 29.3] TPM2_ClockRateAdjust (Command)
pub struct ClockRateAdjustCmd {}

/// [TPM2.0 1.83: 30.2] TPM2_GetCapability (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct GetCapabilityCmd {
    pub capability: TpmCap,
    pub property: TpmPt,
    pub property_count: u32,
}
impl TpmCommand for GetCapabilityCmd {
    const CMD_CODE: TpmCc = TpmCc::GetCapability;
    type Handles = ();
    type RespT = GetCapabilityResp;
    type RespHandles = ();
}

/// [TPM2.0 1.83: 30.2] TPM2_GetCapability (Response)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct GetCapabilityResp {
    pub more_data: TpmiYesNo,
    pub capability_data: TpmsCapabilityData,
}

/// [TPM2.0 1.83: 30.3] TPM2_TestParms (Command)
pub struct TestParmsCmd {}

/// [TPM2.0 1.83: 30.4] TPM2_SetCapability (Command)
pub struct SetCapabilityCmd {}

/// [TPM2.0 1.83: 31.3] TPM2_NV_DefineSpace (Command)
pub struct NvDefineSpaceCmd {}

/// [TPM2.0 1.83: 31.4] TPM2_NV_UndefineSpace (Command)
pub struct NvUndefineSpaceCmd {}

/// [TPM2.0 1.83: 31.5] TPM2_NV_UndefineSpaceSpecial (Command)
pub struct NvUndefineSpaceSpecialCmd {}

/// [TPM2.0 1.83: 31.6] TPM2_NV_ReadPublic (Command)
pub struct NvReadPublicCmd {}

/// [TPM2.0 1.83: 31.7] TPM2_NV_Write (Command)
pub struct NvWriteCmd {}

/// [TPM2.0 1.83: 31.8] TPM2_NV_Increment (Command)
pub struct NvIncrementCmd {}

/// [TPM2.0 1.83: 31.9] TPM2_NV_Extend (Command)
pub struct NvExtendCmd {}

/// [TPM2.0 1.83: 31.10] TPM2_NV_SetBits (Command)
pub struct NvSetBitsCmd {}

/// [TPM2.0 1.83: 31.11] TPM2_NV_WriteLock (Command)
pub struct NvWriteLockCmd {}

/// [TPM2.0 1.83: 31.12] TPM2_NV_GlobalWriteLock (Command)
pub struct NvGlobalWriteLockCmd {}

/// [TPM2.0 1.83: 31.13] TPM2_NV_Read (Command)
pub struct NvReadCmd {}

/// [TPM2.0 1.83: 31.14] TPM2_NV_ReadLock (Command)
pub struct NvReadLockCmd {}

/// [TPM2.0 1.83: 31.15] TPM2_NV_ChangeAuth (Command)
pub struct NvChangeAuthCmd {}

/// [TPM2.0 1.83: 31.16] TPM2_NV_Certify (Command)
pub struct NvCertifyCmd {}

/// [TPM2.0 1.83: 31.17] TPM2_NV_DefineSpace2 (Command)
pub struct NvDefineSpace2Cmd {}

/// [TPM2.0 1.83: 31.18] TPM2_NV_ReadPublic2 (Command)
pub struct NvReadPublic2Cmd {}

/// [TPM2.0 1.83: 32.2] TPM2_AC_GetCapability (Command)
pub struct AcGetCapabilityCmd {}

/// [TPM2.0 1.83: 32.3] TPM2_AC_Send (Command)
pub struct AcSendCmd {}

/// [TPM2.0 1.83: 32.4] TPM2_Policy_AC_SendSelect (Command)
pub struct PolicyAcSendSelectCmd {}

/// [TPM2.0 1.83: 33.2] TPM2_ACT_SetTimeout (Command)
pub struct ActSetTimeoutCmd {}

/// [TPM2.0 1.83: 34.2] TPM2_Vendor_TCG_Test (Command)
pub struct VendorTcgTestCmd {}
