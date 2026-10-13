//! TPM 2.0 Enhanced Authorization (EA) Commands
//!
//! This module implements the "Enhanced Authorization (EA) Commands" commands defined in
//! **Section 23** of the TPM 2.0 Specification.
//!
//! These commands evaluate policy sessions against specific criteria (such as PCR states,
//! signature checks, timeouts, or physical presence) to authorize access to objects.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// [TPM2.0 1.83] 23.3 TPM2_PolicySigned (Command)
#[doc(alias = "TPM2_PolicySigned")]
#[doc(alias = "PolicySigned_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicySigned<'a> {
    /// Handle for a key that will validate the signature.
    pub auth_object: Handle,
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// The policy nonce for the session.
    pub nonce_tpm: Tpm2bNonce<'a>,
    /// Digest of the command parameters to which this authorization is limited.
    pub cp_hash_a: Tpm2bDigest<'a>,
    /// A reference to a policy relating to the authorization.
    pub policy_ref: Tpm2bNonce<'a>,
    /// Time when authorization will expire, measured in seconds.
    pub expiration: i32,
    /// Signed authorization (not optional).
    pub auth: TpmtSignature<'a>,
}
/// [TPM2.0 1.83] 23.3 TPM2_PolicySigned (Response)
#[doc(alias = "PolicySigned_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicySignedRsp<'a> {
    /// Implementation-dependent timeout value.
    pub timeout: Tpm2bTimeout<'a>,
    /// Produced if the command succeeds and expiration was non-zero.
    pub policy_ticket: TpmtTkAuth<'a>,
}

impl Command for PolicySigned<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicySigned;
    type Response<'a> = PolicySignedRsp<'a>;
}
impl Message for PolicySigned<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth_object, self.policy_session]
    }
}
impl Marshal for PolicySigned<'_> {
    const MAX_SIZE: usize = Tpm2bNonce::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + Tpm2bNonce::MAX_SIZE
        + i32::MAX_SIZE
        + TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; PolicySigned::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.nonce_tpm, dst, 0);
        let count = marshal_helper(&self.cp_hash_a, dst, count);
        let count = marshal_helper(&self.policy_ref, dst, count);
        let count = marshal_helper(&self.expiration, dst, count);
        marshal_helper(&self.auth, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicySigned<'a> {
    fn unmarshal_with_handles(
        [auth_object, policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_object,
            policy_session,
            nonce_tpm: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            cp_hash_a: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            policy_ref: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            expiration: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
            auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(5))?,
        })
    }
}

impl Message for PolicySignedRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for PolicySignedRsp<'_> {
    const MAX_SIZE: usize = Tpm2bTimeout::MAX_SIZE + TpmtTkAuth::MAX_SIZE;
    type MaxBuffer = [u8; PolicySignedRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.timeout, dst, 0);
        marshal_helper(&self.policy_ticket, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicySignedRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            timeout: Unmarshal::unmarshal(src)?,
            policy_ticket: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 23.4 TPM2_PolicySecret (Command)
#[doc(alias = "TPM2_PolicySecret")]
#[doc(alias = "PolicySecret_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicySecret<'a> {
    /// Handle of the authorization object (e.g. key or lockout).
    pub auth_handle: Handle,
    /// Handle of the policy session being updated.
    pub policy_session: Handle,
    /// Nonce from the TPM session.
    pub nonce_tpm: Tpm2bNonce<'a>,
    /// Digest of command parameters (optional).
    pub cp_hash_a: Tpm2bDigest<'a>,
    /// Reference policy data (optional).
    pub policy_ref: Tpm2bNonce<'a>,
    /// Expiration time for this policy assertion.
    pub expiration: i32,
}
/// [TPM2.0 1.83] 23.4 TPM2_PolicySecret (Response)
#[doc(alias = "PolicySecret_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicySecretRsp<'a> {
    /// Implementation-dependent timeout value.
    pub timeout: Tpm2bTimeout<'a>,
    /// A ticket that can be used to prove that the authorization was checked.
    pub policy_ticket: TpmtTkAuth<'a>,
}

impl Command for PolicySecret<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicySecret;
    type Response<'a> = PolicySecretRsp<'a>;
}
impl Message for PolicySecret<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.policy_session]
    }
}
impl Marshal for PolicySecret<'_> {
    const MAX_SIZE: usize =
        Tpm2bNonce::MAX_SIZE + Tpm2bDigest::MAX_SIZE + Tpm2bNonce::MAX_SIZE + i32::MAX_SIZE;
    type MaxBuffer = [u8; PolicySecret::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.nonce_tpm, dst, 0);
        let count = marshal_helper(&self.cp_hash_a, dst, count);
        let count = marshal_helper(&self.policy_ref, dst, count);
        marshal_helper(&self.expiration, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicySecret<'a> {
    fn unmarshal_with_handles(
        [auth_handle, policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            policy_session,
            nonce_tpm: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            cp_hash_a: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            policy_ref: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            expiration: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

impl Message for PolicySecretRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for PolicySecretRsp<'_> {
    const MAX_SIZE: usize = Tpm2bTimeout::MAX_SIZE + TpmtTkAuth::MAX_SIZE;
    type MaxBuffer = [u8; PolicySecretRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.timeout, dst, 0);
        marshal_helper(&self.policy_ticket, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicySecretRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            timeout: Unmarshal::unmarshal(src)?,
            policy_ticket: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 23.5 TPM2_PolicyTicket (Command)
///
/// This command allows authorization to be checked using a previously generated ticket
#[doc(alias = "TPM2_PolicyTicket")]
#[doc(alias = "PolicyTicket_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyTicket<'a> {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// Time when authorization will expire.
    pub timeout: Tpm2bTimeout<'a>,
    /// Digest of the command parameters to which this authorization is limited.
    pub cp_hash_a: Tpm2bDigest<'a>,
    /// Reference to a qualifier for the policy.
    pub policy_ref: Tpm2bNonce<'a>,
    /// Name of the object that provided the authorization.
    pub auth_name: Tpm2bName<'a>,
    /// An authorization ticket returned by the TPM in response to `TPM2_PolicySigned` or `TPM2_PolicySecret`.
    pub ticket: TpmtTkAuth<'a>,
}

impl Command for PolicyTicket<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyTicket;
    type Response<'a> = ();
}
impl Message for PolicyTicket<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyTicket<'_> {
    const MAX_SIZE: usize = Tpm2bTimeout::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + Tpm2bNonce::MAX_SIZE
        + Tpm2bName::MAX_SIZE
        + TpmtTkAuth::MAX_SIZE;
    type MaxBuffer = [u8; PolicyTicket::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.timeout, dst, 0);
        let count = marshal_helper(&self.cp_hash_a, dst, count);
        let count = marshal_helper(&self.policy_ref, dst, count);
        let count = marshal_helper(&self.auth_name, dst, count);
        marshal_helper(&self.ticket, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyTicket<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            timeout: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            cp_hash_a: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            policy_ref: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            auth_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
            ticket: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(5))?,
        })
    }
}

/// [TPM2.0 1.83] 23.6 TPM2_PolicyOR (Command)
#[doc(alias = "TPM2_PolicyOR")]
#[doc(alias = "PolicyOR_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyOR<'a> {
    pub policy_session: Handle,
    /// The list of hashes to check for a match.
    ///
    /// [`UnmarshalMessage::unmarshal_with_handles`] requires at least 2
    /// digests: a smaller count fails with `TPM_RC_SIZE` (parameter 1) as soon
    /// as the count is read, before any digest is unmarshalled.
    pub p_hash_list: TpmlDigest<'a>,
}

impl Command for PolicyOR<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyOR;
    type Response<'a> = ();
}
impl Message for PolicyOR<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyOR<'_> {
    const MAX_SIZE: usize = TpmlDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyOR::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.p_hash_list.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyOR<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            p_hash_list: TpmlDigest::unmarshal_with_min_count(src, 2)
                .map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 23.7 TPM2_PolicyPCR (Command)
#[doc(alias = "TPM2_PolicyPCR")]
#[doc(alias = "PolicyPCR_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyPCR<'a> {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// Expected digest value of the selected PCR.
    pub pcr_digest: Tpm2bDigest<'a>,
    /// The PCR to include in the check digest.
    pub pcrs: TpmlPcrSelection,
}

impl Command for PolicyPCR<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyPCR;
    type Response<'a> = ();
}
impl Message for PolicyPCR<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyPCR<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + TpmlPcrSelection::MAX_SIZE;
    type MaxBuffer = [u8; PolicyPCR::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.pcr_digest, dst, 0);
        marshal_helper(&self.pcrs, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyPCR<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            pcr_digest: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            pcrs: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 23.8 TPM2_PolicyLocality (Command)
#[doc(alias = "TPM2_PolicyLocality")]
#[doc(alias = "PolicyLocality_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyLocality {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// The allowed localities for the policy.
    pub locality: TpmaLocality,
}

impl Command for PolicyLocality {
    const CMD_CODE: TpmCc = TpmCc::PolicyLocality;
    type Response<'a> = ();
}
impl Message for PolicyLocality {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyLocality {
    const MAX_SIZE: usize = TpmaLocality::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.locality.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyLocality {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            locality: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 23.9 TPM2_PolicyNV (Command)
#[doc(alias = "TPM2_PolicyNV")]
#[doc(alias = "PolicyNV_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyNV<'a> {
    /// Handle indicating the source of the authorization value for the NV Index.
    pub auth_handle: Handle,
    /// The NV Index of the area to read.
    pub nv_index: Handle,
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// The second operand.
    pub operand_b: Tpm2bOperand<'a>,
    /// The octet offset in the NV Index for the start of operand A.
    pub offset: u16,
    /// The comparison to make.
    pub operation: TpmEo,
}

impl Command for PolicyNV<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyNV;
    type Response<'a> = ();
}
impl Message for PolicyNV<'_> {
    type Handles = [Handle; 3];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.nv_index, self.policy_session]
    }
}
impl Marshal for PolicyNV<'_> {
    const MAX_SIZE: usize = Tpm2bOperand::MAX_SIZE + u16::MAX_SIZE + TpmEo::MAX_SIZE;
    type MaxBuffer = [u8; PolicyNV::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.operand_b, dst, 0);
        let count = marshal_helper(&self.offset, dst, count);
        marshal_helper(&self.operation, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyNV<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index, policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index,
            policy_session,
            operand_b: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            offset: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            operation: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

/// [TPM2.0 1.83] 23.10 TPM2_PolicyCounterTimer (Command)
#[doc(alias = "TPM2_PolicyCounterTimer")]
#[doc(alias = "PolicyCounterTimer_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyCounterTimer<'a> {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// The second operand.
    pub operand_b: Tpm2bOperand<'a>,
    /// The octet offset in the TPMS_TIME_INFO structure for the start of operand A.
    pub offset: u16,
    /// The comparison to make.
    pub operation: TpmEo,
}

impl Command for PolicyCounterTimer<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyCounterTimer;
    type Response<'a> = ();
}
impl Message for PolicyCounterTimer<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyCounterTimer<'_> {
    const MAX_SIZE: usize = Tpm2bOperand::MAX_SIZE + u16::MAX_SIZE + TpmEo::MAX_SIZE;
    type MaxBuffer = [u8; PolicyCounterTimer::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.operand_b, dst, 0);
        let count = marshal_helper(&self.offset, dst, count);
        marshal_helper(&self.operation, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyCounterTimer<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            operand_b: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            offset: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            operation: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

/// [TPM2.0 1.83] 23.11 TPM2_PolicyCommandCode (Command)
#[doc(alias = "TPM2_PolicyCommandCode")]
#[doc(alias = "PolicyCommandCode_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyCommandCode {
    pub policy_session: Handle,
    pub code: TpmCc,
}

impl Command for PolicyCommandCode {
    const CMD_CODE: TpmCc = TpmCc::PolicyCommandCode;
    type Response<'a> = ();
}
impl Message for PolicyCommandCode {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyCommandCode {
    const MAX_SIZE: usize = TpmCc::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.code.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyCommandCode {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            code: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 23.12 TPM2_PolicyPhysicalPresence (Command)
#[doc(alias = "TPM2_PolicyPhysicalPresence")]
#[doc(alias = "PolicyPhysicalPresence_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyPhysicalPresence {
    pub policy_session: Handle,
}

impl Command for PolicyPhysicalPresence {
    const CMD_CODE: TpmCc = TpmCc::PolicyPhysicalPresence;
    type Response<'a> = ();
}
impl Message for PolicyPhysicalPresence {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyPhysicalPresence {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyPhysicalPresence {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { policy_session })
    }
}

/// [TPM2.0 1.83] 23.13 TPM2_PolicyCpHash (Command)
#[doc(alias = "TPM2_PolicyCpHash")]
#[doc(alias = "PolicyCpHash_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyCpHash<'a> {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// The cpHash added to the policy.
    pub cp_hash_a: Tpm2bDigest<'a>,
}

impl Command for PolicyCpHash<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyCpHash;
    type Response<'a> = ();
}
impl Message for PolicyCpHash<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyCpHash<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyCpHash::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.cp_hash_a.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyCpHash<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            cp_hash_a: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 23.14 TPM2_PolicyNameHash (Command)
#[doc(alias = "TPM2_PolicyNameHash")]
#[doc(alias = "PolicyNameHash_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyNameHash<'a> {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// The digest of the Names associated with the handles to be used in the authorized command.
    pub name_hash: Tpm2bDigest<'a>,
}

impl Command for PolicyNameHash<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyNameHash;
    type Response<'a> = ();
}
impl Message for PolicyNameHash<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyNameHash<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyNameHash::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.name_hash.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyNameHash<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            name_hash: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 23.15 TPM2_PolicyDuplicationSelect (Command)
#[doc(alias = "TPM2_PolicyDuplicationSelect")]
#[doc(alias = "PolicyDuplicationSelect_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyDuplicationSelect<'a> {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// The Name of the object to be duplicated.
    pub object_name: Tpm2bName<'a>,
    /// The Name of the new parent.
    pub new_parent_name: Tpm2bName<'a>,
    /// YES if objectName is to be included in the policy.
    pub include_object: bool,
}

impl Command for PolicyDuplicationSelect<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyDuplicationSelect;
    type Response<'a> = ();
}
impl Message for PolicyDuplicationSelect<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyDuplicationSelect<'_> {
    const MAX_SIZE: usize = Tpm2bName::MAX_SIZE + Tpm2bName::MAX_SIZE + bool::MAX_SIZE;
    type MaxBuffer = [u8; PolicyDuplicationSelect::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.object_name, dst, 0);
        let count = marshal_helper(&self.new_parent_name, dst, count);
        marshal_helper(&self.include_object, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyDuplicationSelect<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            object_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            new_parent_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            include_object: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

/// [TPM2.0 1.83] 23.16 TPM2_PolicyAuthorize (Command)
#[doc(alias = "TPM2_PolicyAuthorize")]
#[doc(alias = "PolicyAuthorize_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyAuthorize<'a> {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// Digest of the policy being approved.
    pub approved_policy: Tpm2bDigest<'a>,
    /// A policy qualifier.
    pub policy_ref: Tpm2bNonce<'a>,
    /// Name of a key that can sign a policy addition.
    pub key_sign: Tpm2bName<'a>,
    /// Ticket validating that approvedPolicy and policyRef were signed by keySign.
    pub check_ticket: TpmtTkVerified<'a>,
}

impl Command for PolicyAuthorize<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyAuthorize;
    type Response<'a> = ();
}
impl Message for PolicyAuthorize<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyAuthorize<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE
        + Tpm2bNonce::MAX_SIZE
        + Tpm2bName::MAX_SIZE
        + TpmtTkVerified::MAX_SIZE;
    type MaxBuffer = [u8; PolicyAuthorize::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.approved_policy, dst, 0);
        let count = marshal_helper(&self.policy_ref, dst, count);
        let count = marshal_helper(&self.key_sign, dst, count);
        marshal_helper(&self.check_ticket, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyAuthorize<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            approved_policy: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            policy_ref: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            key_sign: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            check_ticket: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

/// [TPM2.0 1.83] 23.17 TPM2_PolicyAuthValue (Command)
#[doc(alias = "TPM2_PolicyAuthValue")]
#[doc(alias = "PolicyAuthValue_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyAuthValue {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}

impl Command for PolicyAuthValue {
    const CMD_CODE: TpmCc = TpmCc::PolicyAuthValue;
    type Response<'a> = ();
}
impl Message for PolicyAuthValue {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyAuthValue {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyAuthValue {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { policy_session })
    }
}

/// [TPM2.0 1.83] 23.18 TPM2_PolicyPassword (Command)
#[doc(alias = "TPM2_PolicyPassword")]
#[doc(alias = "PolicyPassword_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyPassword {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}

impl Command for PolicyPassword {
    const CMD_CODE: TpmCc = TpmCc::PolicyPassword;
    type Response<'a> = ();
}
impl Message for PolicyPassword {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyPassword {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyPassword {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { policy_session })
    }
}

/// [TPM2.0 1.83] 23.19 TPM2_PolicyGetDigest (Command)
#[doc(alias = "TPM2_PolicyGetDigest")]
#[doc(alias = "PolicyGetDigest_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyGetDigest {
    pub policy_session: Handle,
}
/// [TPM2.0 1.83] 23.19 TPM2_PolicyGetDigest (Response)
#[doc(alias = "PolicyGetDigest_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyGetDigestRsp<'a> {
    pub policy_digest: Tpm2bDigest<'a>,
}

impl Command for PolicyGetDigest {
    const CMD_CODE: TpmCc = TpmCc::PolicyGetDigest;
    type Response<'a> = PolicyGetDigestRsp<'a>;
}
impl Message for PolicyGetDigest {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyGetDigest {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyGetDigest {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { policy_session })
    }
}

impl Message for PolicyGetDigestRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for PolicyGetDigestRsp<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyGetDigestRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_digest.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyGetDigestRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_digest: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 23.20 TPM2_PolicyNvWritten (Command)
#[doc(alias = "TPM2_PolicyNvWritten")]
#[doc(alias = "PolicyNvWritten_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyNvWritten {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
    /// YES if NV Index is required to have been written.
    pub written_set: bool,
}

impl Command for PolicyNvWritten {
    const CMD_CODE: TpmCc = TpmCc::PolicyNvWritten;
    type Response<'a> = ();
}
impl Message for PolicyNvWritten {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyNvWritten {
    const MAX_SIZE: usize = bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.written_set.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyNvWritten {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            written_set: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 23.21 TPM2_PolicyTemplate (Command)
#[doc(alias = "TPM2_PolicyTemplate")]
#[doc(alias = "PolicyTemplate_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyTemplate<'a> {
    pub policy_session: Handle,
    pub template_hash: Tpm2bDigest<'a>,
}

impl Command for PolicyTemplate<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyTemplate;
    type Response<'a> = ();
}
impl Message for PolicyTemplate<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyTemplate<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyTemplate::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.template_hash.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyTemplate<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            template_hash: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 23.22 TPM2_PolicyAuthorizeNV (Command)
#[doc(alias = "TPM2_PolicyAuthorizeNV")]
#[doc(alias = "PolicyAuthorizeNV_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyAuthorizeNV {
    pub auth_handle: Handle,
    pub nv_index: Handle,
    pub policy_session: Handle,
}

impl Command for PolicyAuthorizeNV {
    const CMD_CODE: TpmCc = TpmCc::PolicyAuthorizeNV;
    type Response<'a> = ();
}
impl Message for PolicyAuthorizeNV {
    type Handles = [Handle; 3];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle, self.nv_index, self.policy_session]
    }
}
impl Marshal for PolicyAuthorizeNV {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyAuthorizeNV {
    fn unmarshal_with_handles(
        [auth_handle, nv_index, policy_session]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index,
            policy_session,
        })
    }
}

/// [TPM2.0 1.83] 23.23 TPM2_PolicyCapability (Command)
#[doc(alias = "TPM2_PolicyCapability")]
#[doc(alias = "PolicyCapability_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyCapability<'a> {
    pub policy_session: Handle,
    pub operand_b: Tpm2bOperand<'a>,
    pub offset: u16,
    pub operation: TpmEo,
    pub capability: TpmCap,
    pub property: u32,
}

impl Command for PolicyCapability<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyCapability;
    type Response<'a> = ();
}
impl Message for PolicyCapability<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyCapability<'_> {
    const MAX_SIZE: usize =
        Tpm2bOperand::MAX_SIZE + u16::MAX_SIZE + TpmEo::MAX_SIZE + TpmCap::MAX_SIZE + u32::MAX_SIZE;
    type MaxBuffer = [u8; PolicyCapability::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.operand_b, dst, 0);
        let count = marshal_helper(&self.offset, dst, count);
        let count = marshal_helper(&self.operation, dst, count);
        let count = marshal_helper(&self.capability, dst, count);
        marshal_helper(&self.property, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyCapability<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            operand_b: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            offset: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            operation: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            capability: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
            property: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(5))?,
        })
    }
}

/// [TPM2.0 1.83] 23.24 TPM2_PolicyParameters (Command)
#[doc(alias = "TPM2_PolicyParameters")]
#[doc(alias = "PolicyParameters_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyParameters<'a> {
    pub policy_session: Handle,
    pub p_hash: Tpm2bDigest<'a>,
}

impl Command for PolicyParameters<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyParameters;
    type Response<'a> = ();
}
impl Message for PolicyParameters<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyParameters<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyParameters::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.p_hash.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyParameters<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            p_hash: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 23.25 TPM2_PolicyTransportSPDM (Command)
#[doc(alias = "TPM2_PolicyTransportSPDM")]
#[doc(alias = "PolicyTransportSPDM_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyTransportSPDM<'a> {
    pub policy_session: Handle,
    pub req_key_name: Tpm2bName<'a>,
    pub tpm_key_name: Tpm2bName<'a>,
}

impl Command for PolicyTransportSPDM<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyTransportSPDM;
    type Response<'a> = ();
}
impl Message for PolicyTransportSPDM<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}
impl Marshal for PolicyTransportSPDM<'_> {
    const MAX_SIZE: usize = Tpm2bName::MAX_SIZE + Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; PolicyTransportSPDM::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.req_key_name, dst, 0);
        marshal_helper(&self.tpm_key_name, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyTransportSPDM<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            req_key_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            tpm_key_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}
