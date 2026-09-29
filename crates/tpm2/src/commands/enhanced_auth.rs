//! TPM 2.0 Enhanced Authorization (Policy) Commands
//!
//! This module implements the "Enhanced Authorization" commands defined in
//! **Section 23** of the TPM 2.0 Specification.
//!
//! These commands evaluate policy sessions against specific criteria (such as PCR states,
//! signature checks, timeouts, or physical presence) to authorize access to objects.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

///
/// Handles for TPM2_PolicySigned command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicySignedHandles {
    /// Handle for a key that will validate the signature.
    pub auth_object: Handle,
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicySignedHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_object, dst, 0);
        marshal_helper(&self.policy_session, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicySignedHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_object: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.3 TPM2_PolicySigned (Command)
#[doc(alias = "TPM2_PolicySigned")]
#[doc(alias = "PolicySigned_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct PolicySigned<'a> {
    /// The policy nonce for the session.
    pub nonce_tpm: crate::Tpm2bNonce<'a>,
    /// Digest of the command parameters to which this authorization is limited.
    pub cp_hash_a: crate::Tpm2bDigest<'a>,
    /// A reference to a policy relating to the authorization.
    pub policy_ref: crate::Tpm2bNonce<'a>,
    /// Time when authorization will expire, measured in seconds.
    pub expiration: i32,
    /// Signed authorization (not optional).
    pub auth: crate::TpmtSignature<'a>,
}

impl<'a> Marshal for PolicySigned<'a> {
    const MAX_SIZE: usize = <crate::Tpm2bNonce>::MAX_SIZE
        + <crate::Tpm2bDigest>::MAX_SIZE
        + <crate::Tpm2bNonce>::MAX_SIZE
        + i32::MAX_SIZE
        + <crate::TpmtSignature>::MAX_SIZE;
    type MaxBuffer = [u8; PolicySigned::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.nonce_tpm, dst, 0);
        let count = marshal_helper(&self.cp_hash_a, dst, count);
        let count = marshal_helper(&self.policy_ref, dst, count);
        let count = marshal_helper(&self.expiration, dst, count);
        marshal_helper(&self.auth, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicySigned<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nonce_tpm: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            cp_hash_a: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            policy_ref: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            expiration: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
            auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(5))?,
        })
    }
}

/// [TPM2.0 1.83] 23.3 TPM2_PolicySigned (Response)
#[doc(alias = "PolicySigned_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct PolicySignedRsp<'a> {
    /// Implementation-dependent timeout value.
    pub timeout: crate::Tpm2bTimeout<'a>,
    /// Produced if the command succeeds and expiration was non-zero.
    pub policy_ticket: crate::TpmtTkAuth<'a>,
}
impl Marshal for PolicySignedRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bTimeout>::MAX_SIZE + <crate::TpmtTkAuth>::MAX_SIZE;
    type MaxBuffer = [u8; PolicySignedRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.timeout, dst, 0);
        marshal_helper(&self.policy_ticket, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicySignedRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            timeout: Unmarshal::unmarshal(src)?,
            policy_ticket: Unmarshal::unmarshal(src)?,
        })
    }
}

impl<'a> Command for PolicySigned<'a> {
    const CMD_CODE: TpmCc = TpmCc::PolicySigned;
    type Handles = PolicySignedHandles;
    type Response<'b> = PolicySignedRsp<'b>;
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicySecret command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicySecretHandles {
    /// Handle of the authorization object (e.g. key or lockout).
    pub auth_handle: Handle,
    /// Handle of the policy session being updated.
    pub policy_session: Handle,
}
impl Marshal for PolicySecretHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        marshal_helper(&self.policy_session, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicySecretHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiDhEntity::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.4 TPM2_PolicySecret (Command)
#[doc(alias = "TPM2_PolicySecret")]
#[doc(alias = "PolicySecret_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicySecret<'a> {
    /// Nonce from the TPM session.
    pub nonce_tpm: crate::Tpm2bNonce<'a>,
    /// Digest of command parameters (optional).
    pub cp_hash_a: crate::Tpm2bDigest<'a>,
    /// Reference policy data (optional).
    pub policy_ref: crate::Tpm2bNonce<'a>,
    /// Expiration time for this policy assertion.
    pub expiration: i32,
}
impl Marshal for PolicySecret<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bNonce>::MAX_SIZE
        + <crate::Tpm2bDigest>::MAX_SIZE
        + <crate::Tpm2bNonce>::MAX_SIZE
        + i32::MAX_SIZE;
    type MaxBuffer = [u8; PolicySecret::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.nonce_tpm, dst, 0);
        let count = marshal_helper(&self.cp_hash_a, dst, count);
        let count = marshal_helper(&self.policy_ref, dst, count);
        marshal_helper(&self.expiration, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicySecret<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nonce_tpm: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            cp_hash_a: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            policy_ref: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            expiration: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

/// [TPM2.0 1.83] 23.4 TPM2_PolicySecret (Response)
#[doc(alias = "PolicySecret_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct PolicySecretRsp<'a> {
    /// Implementation-dependent timeout value.
    pub timeout: crate::Tpm2bTimeout<'a>,
    /// A ticket that can be used to prove that the authorization was checked.
    pub policy_ticket: crate::TpmtTkAuth<'a>,
}
impl Marshal for PolicySecretRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bTimeout>::MAX_SIZE + <crate::TpmtTkAuth>::MAX_SIZE;
    type MaxBuffer = [u8; PolicySecretRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.timeout, dst, 0);
        marshal_helper(&self.policy_ticket, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicySecretRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            timeout: Unmarshal::unmarshal(src)?,
            policy_ticket: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for PolicySecret<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicySecret;
    type Handles = PolicySecretHandles;
    type Response<'a> = PolicySecretRsp<'a>;
    type RespHandles = ();
}

/// Handles for TPM2_PolicyTicket command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyTicketHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyTicketHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyTicketHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.5 TPM2_PolicyTicket (Command)
#[doc(alias = "TPM2_PolicyTicket")]
#[doc(alias = "PolicyTicket_In")]
///
/// This command allows authorization to be checked using a previously generated ticket
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct PolicyTicket<'a> {
    /// Time when authorization will expire.
    pub timeout: crate::Tpm2bTimeout<'a>,
    /// Digest of the command parameters to which this authorization is limited.
    pub cp_hash_a: crate::Tpm2bDigest<'a>,
    /// Reference to a qualifier for the policy.
    pub policy_ref: crate::Tpm2bNonce<'a>,
    /// Name of the object that provided the authorization.
    pub auth_name: crate::Tpm2bName<'a>,
    /// An authorization ticket returned by the TPM in response to `TPM2_PolicySigned` or `TPM2_PolicySecret`.
    pub ticket: crate::TpmtTkAuth<'a>,
}
impl Marshal for PolicyTicket<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bTimeout>::MAX_SIZE
        + <crate::Tpm2bDigest>::MAX_SIZE
        + <crate::Tpm2bNonce>::MAX_SIZE
        + <crate::Tpm2bName>::MAX_SIZE
        + <crate::TpmtTkAuth>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyTicket::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.timeout, dst, 0);
        let count = marshal_helper(&self.cp_hash_a, dst, count);
        let count = marshal_helper(&self.policy_ref, dst, count);
        let count = marshal_helper(&self.auth_name, dst, count);
        marshal_helper(&self.ticket, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyTicket<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            timeout: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            cp_hash_a: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            policy_ref: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            auth_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
            ticket: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(5))?,
        })
    }
}

impl Command for PolicyTicket<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyTicket;
    type Handles = PolicyTicketHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyORHandles {
    pub policy_session: Handle,
}
impl Marshal for PolicyORHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyORHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.6 TPM2_PolicyOR (Command)
#[doc(alias = "TPM2_PolicyOR")]
#[doc(alias = "PolicyOR_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyOR<'a> {
    pub p_hash_list: crate::TpmlDigest<'a>,
}
impl Marshal for PolicyOR<'_> {
    const MAX_SIZE: usize = <crate::TpmlDigest>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyOR::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.p_hash_list.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyOR<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            p_hash_list: crate::TpmlDigest::unmarshal_with_min_count(src, 2)
                .map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for PolicyOR<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyOR;
    type Handles = PolicyORHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicyPCR command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyPCRHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyPCRHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyPCRHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.7 TPM2_PolicyPCR (Command)
#[doc(alias = "TPM2_PolicyPCR")]
#[doc(alias = "PolicyPCR_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyPCR<'a> {
    /// Expected digest value of the selected PCR.
    pub pcr_digest: crate::Tpm2bDigest<'a>,
    /// The PCR to include in the check digest.
    pub pcrs: crate::TpmlPcrSelection,
}
impl Marshal for PolicyPCR<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bDigest>::MAX_SIZE + <crate::TpmlPcrSelection>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyPCR::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.pcr_digest, dst, 0);
        marshal_helper(&self.pcrs, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyPCR<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pcr_digest: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            pcrs: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Command for PolicyPCR<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyPCR;
    type Handles = PolicyPCRHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicyLocality command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyLocalityHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyLocalityHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyLocalityHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.8 TPM2_PolicyLocality (Command)
#[doc(alias = "TPM2_PolicyLocality")]
#[doc(alias = "PolicyLocality_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyLocality {
    /// The allowed localities for the policy.
    pub locality: crate::TpmaLocality,
}
impl Marshal for PolicyLocality {
    const MAX_SIZE: usize = <crate::TpmaLocality>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.locality.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyLocality {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            locality: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for PolicyLocality {
    const CMD_CODE: TpmCc = TpmCc::PolicyLocality;
    type Handles = PolicyLocalityHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicyNV command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyNVHandles {
    /// Handle indicating the source of the authorization value for the NV Index.
    pub auth_handle: Handle,
    /// The NV Index of the area to read.
    pub nv_index: Handle,
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyNVHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        let count = marshal_helper(&self.nv_index, dst, count);
        marshal_helper(&self.policy_session, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyNVHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(3))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.9 TPM2_PolicyNV (Command)
#[doc(alias = "TPM2_PolicyNV")]
#[doc(alias = "PolicyNV_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyNV<'a> {
    /// The second operand.
    pub operand_b: crate::Tpm2bOperand<'a>,
    /// The octet offset in the NV Index for the start of operand A.
    pub offset: u16,
    /// The comparison to make.
    pub operation: crate::TpmEo,
}
impl Marshal for PolicyNV<'_> {
    const MAX_SIZE: usize =
        <crate::Tpm2bOperand>::MAX_SIZE + u16::MAX_SIZE + <crate::TpmEo>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyNV::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.operand_b, dst, 0);
        let count = marshal_helper(&self.offset, dst, count);
        marshal_helper(&self.operation, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyNV<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            operand_b: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            offset: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            operation: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

impl Command for PolicyNV<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyNV;
    type Handles = PolicyNVHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

/// Handles for TPM2_PolicyCounterTimer command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyCounterTimerHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyCounterTimerHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyCounterTimerHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.10 TPM2_PolicyCounterTimer (Command)
#[doc(alias = "TPM2_PolicyCounterTimer")]
#[doc(alias = "PolicyCounterTimer_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyCounterTimer<'a> {
    /// The second operand.
    pub operand_b: crate::Tpm2bOperand<'a>,
    /// The octet offset in the TPMS_TIME_INFO structure for the start of operand A.
    pub offset: u16,
    /// The comparison to make.
    pub operation: crate::TpmEo,
}
impl Marshal for PolicyCounterTimer<'_> {
    const MAX_SIZE: usize =
        <crate::Tpm2bOperand>::MAX_SIZE + u16::MAX_SIZE + <crate::TpmEo>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyCounterTimer::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.operand_b, dst, 0);
        let count = marshal_helper(&self.offset, dst, count);
        marshal_helper(&self.operation, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyCounterTimer<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            operand_b: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            offset: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            operation: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

impl Command for PolicyCounterTimer<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyCounterTimer;
    type Handles = PolicyCounterTimerHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyCommandCodeHandles {
    pub policy_session: Handle,
}
impl Marshal for PolicyCommandCodeHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyCommandCodeHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.11 TPM2_PolicyCommandCode (Command)
#[doc(alias = "TPM2_PolicyCommandCode")]
#[doc(alias = "PolicyCommandCode_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyCommandCode {
    pub code: TpmCc,
}
impl Marshal for PolicyCommandCode {
    const MAX_SIZE: usize = TpmCc::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.code.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyCommandCode {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            code: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for PolicyCommandCode {
    const CMD_CODE: TpmCc = TpmCc::PolicyCommandCode;
    type Handles = PolicyCommandCodeHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyPhysicalPresenceHandles {
    pub policy_session: Handle,
}

impl Marshal for PolicyPhysicalPresenceHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyPhysicalPresenceHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.12 TPM2_PolicyPhysicalPresence (Command)
#[doc(alias = "TPM2_PolicyPhysicalPresence")]
#[doc(alias = "PolicyPhysicalPresence_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyPhysicalPresence {}

impl Marshal for PolicyPhysicalPresence {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for PolicyPhysicalPresence {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for PolicyPhysicalPresence {
    const CMD_CODE: TpmCc = TpmCc::PolicyPhysicalPresence;
    type Handles = PolicyPhysicalPresenceHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicyCpHash command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyCpHashHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyCpHashHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyCpHashHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.13 TPM2_PolicyCpHash (Command)
#[doc(alias = "TPM2_PolicyCpHash")]
#[doc(alias = "PolicyCpHash_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyCpHash<'a> {
    /// The cpHash added to the policy.
    pub cp_hash_a: crate::Tpm2bDigest<'a>,
}
impl Marshal for PolicyCpHash<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bDigest>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyCpHash::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.cp_hash_a.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyCpHash<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            cp_hash_a: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for PolicyCpHash<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyCpHash;
    type Handles = PolicyCpHashHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicyNameHash command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyNameHashHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyNameHashHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyNameHashHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.14 TPM2_PolicyNameHash (Command)
#[doc(alias = "TPM2_PolicyNameHash")]
#[doc(alias = "PolicyNameHash_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyNameHash<'a> {
    /// The digest of the Names associated with the handles to be used in the authorized command.
    pub name_hash: crate::Tpm2bDigest<'a>,
}
impl Marshal for PolicyNameHash<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bDigest>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyNameHash::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.name_hash.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyNameHash<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            name_hash: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for PolicyNameHash<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyNameHash;
    type Handles = PolicyNameHashHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicyDuplicationSelect command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyDuplicationSelectHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyDuplicationSelectHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyDuplicationSelectHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.15 TPM2_PolicyDuplicationSelect (Command)
#[doc(alias = "TPM2_PolicyDuplicationSelect")]
#[doc(alias = "PolicyDuplicationSelect_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyDuplicationSelect<'a> {
    /// The Name of the object to be duplicated.
    pub object_name: crate::Tpm2bName<'a>,
    /// The Name of the new parent.
    pub new_parent_name: crate::Tpm2bName<'a>,
    /// YES if objectName is to be included in the policy.
    pub include_object: bool,
}
impl Marshal for PolicyDuplicationSelect<'_> {
    const MAX_SIZE: usize =
        <crate::Tpm2bName>::MAX_SIZE + <crate::Tpm2bName>::MAX_SIZE + <bool>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyDuplicationSelect::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.object_name, dst, 0);
        let count = marshal_helper(&self.new_parent_name, dst, count);
        marshal_helper(&self.include_object, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyDuplicationSelect<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            new_parent_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            include_object: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

impl Command for PolicyDuplicationSelect<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyDuplicationSelect;
    type Handles = PolicyDuplicationSelectHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicyAuthorize command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyAuthorizeHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyAuthorizeHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyAuthorizeHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.16 TPM2_PolicyAuthorize (Command)
#[doc(alias = "TPM2_PolicyAuthorize")]
#[doc(alias = "PolicyAuthorize_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyAuthorize<'a> {
    /// Digest of the policy being approved.
    pub approved_policy: crate::Tpm2bDigest<'a>,
    /// A policy qualifier.
    pub policy_ref: crate::Tpm2bNonce<'a>,
    /// Name of a key that can sign a policy addition.
    pub key_sign: crate::Tpm2bName<'a>,
    /// Ticket validating that approvedPolicy and policyRef were signed by keySign.
    pub check_ticket: crate::TpmtTkVerified<'a>,
}
impl Marshal for PolicyAuthorize<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bDigest>::MAX_SIZE
        + <crate::Tpm2bNonce>::MAX_SIZE
        + <crate::Tpm2bName>::MAX_SIZE
        + <crate::TpmtTkVerified>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyAuthorize::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.approved_policy, dst, 0);
        let count = marshal_helper(&self.policy_ref, dst, count);
        let count = marshal_helper(&self.key_sign, dst, count);
        marshal_helper(&self.check_ticket, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyAuthorize<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            approved_policy: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            policy_ref: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            key_sign: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            check_ticket: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

impl Command for PolicyAuthorize<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyAuthorize;
    type Handles = PolicyAuthorizeHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicyAuthValue command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyAuthValueHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyAuthValueHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyAuthValueHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.17 TPM2_PolicyAuthValue (Command)
#[doc(alias = "TPM2_PolicyAuthValue")]
#[doc(alias = "PolicyAuthValue_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyAuthValue {}
impl Marshal for PolicyAuthValue {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for PolicyAuthValue {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for PolicyAuthValue {
    const CMD_CODE: TpmCc = TpmCc::PolicyAuthValue;
    type Handles = PolicyAuthValueHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicyPassword command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyPasswordHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyPasswordHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyPasswordHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.18 TPM2_PolicyPassword (Command)
#[doc(alias = "TPM2_PolicyPassword")]
#[doc(alias = "PolicyPassword_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyPassword {}
impl Marshal for PolicyPassword {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for PolicyPassword {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for PolicyPassword {
    const CMD_CODE: TpmCc = TpmCc::PolicyPassword;
    type Handles = PolicyPasswordHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyGetDigestHandles {
    pub policy_session: Handle,
}
impl Marshal for PolicyGetDigestHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyGetDigestHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.19 TPM2_PolicyGetDigest (Response)
#[doc(alias = "PolicyGetDigest_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyGetDigestRsp<'a> {
    pub policy_digest: crate::Tpm2bDigest<'a>,
}
impl Marshal for PolicyGetDigestRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bDigest>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyGetDigestRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_digest.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyGetDigestRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_digest: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 23.19 TPM2_PolicyGetDigest (Command)
#[doc(alias = "TPM2_PolicyGetDigest")]
#[doc(alias = "PolicyGetDigest_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyGetDigest {}
impl Marshal for PolicyGetDigest {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for PolicyGetDigest {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for PolicyGetDigest {
    const CMD_CODE: TpmCc = TpmCc::PolicyGetDigest;
    type Handles = PolicyGetDigestHandles;
    type Response<'a> = PolicyGetDigestRsp<'a>;
    type RespHandles = ();
}

///
/// Handles for TPM2_PolicyNvWritten command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyNvWrittenHandles {
    /// Handle for the policy session being extended.
    pub policy_session: Handle,
}
impl Marshal for PolicyNvWrittenHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyNvWrittenHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.20 TPM2_PolicyNvWritten (Command)
#[doc(alias = "TPM2_PolicyNvWritten")]
#[doc(alias = "PolicyNvWritten_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyNvWritten {
    /// YES if NV Index is required to have been written.
    pub written_set: bool,
}
impl Marshal for PolicyNvWritten {
    const MAX_SIZE: usize = <bool>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.written_set.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyNvWritten {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            written_set: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for PolicyNvWritten {
    const CMD_CODE: TpmCc = TpmCc::PolicyNvWritten;
    type Handles = PolicyNvWrittenHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyTemplateHandles {
    pub policy_session: Handle,
}
impl Marshal for PolicyTemplateHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyTemplateHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.21 TPM2_PolicyTemplate (Command)
#[doc(alias = "TPM2_PolicyTemplate")]
#[doc(alias = "PolicyTemplate_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyTemplate<'a> {
    pub template_hash: crate::Tpm2bDigest<'a>,
}
impl Marshal for PolicyTemplate<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bDigest>::MAX_SIZE;
    type MaxBuffer = [u8; PolicyTemplate::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.template_hash.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyTemplate<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            template_hash: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for PolicyTemplate<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyTemplate;
    type Handles = PolicyTemplateHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyAuthorizeNVHandles {
    pub auth_handle: Handle,
    pub nv_index: Handle,
    pub policy_session: Handle,
}
impl Marshal for PolicyAuthorizeNVHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_handle, dst, 0);
        let count = marshal_helper(&self.nv_index, dst, count);
        marshal_helper(&self.policy_session, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyAuthorizeNVHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
            nv_index: TpmiRhNvIndex::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(3))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.22 TPM2_PolicyAuthorizeNV (Command)
#[doc(alias = "TPM2_PolicyAuthorizeNV")]
#[doc(alias = "PolicyAuthorizeNV_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyAuthorizeNV {}
impl Marshal for PolicyAuthorizeNV {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for PolicyAuthorizeNV {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for PolicyAuthorizeNV {
    const CMD_CODE: TpmCc = TpmCc::PolicyAuthorizeNV;
    type Handles = PolicyAuthorizeNVHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyCapabilityHandles {
    pub policy_session: Handle,
}

impl Marshal for PolicyCapabilityHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyCapabilityHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.23 TPM2_PolicyCapability (Command)
#[doc(alias = "TPM2_PolicyCapability")]
#[doc(alias = "PolicyCapability_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyCapability<'a> {
    pub operand_b: crate::Tpm2bOperand<'a>,
    pub offset: u16,
    pub operation: crate::TpmEo,
    pub capability: TpmCap,
    pub property: u32,
}

impl Marshal for PolicyCapability<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bOperand>::MAX_SIZE
        + u16::MAX_SIZE
        + <crate::TpmEo>::MAX_SIZE
        + TpmCap::MAX_SIZE
        + u32::MAX_SIZE;
    type MaxBuffer = [u8; PolicyCapability::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.operand_b, dst, 0);
        let count = marshal_helper(&self.offset, dst, count);
        let count = marshal_helper(&self.operation, dst, count);
        let count = marshal_helper(&self.capability, dst, count);
        marshal_helper(&self.property, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyCapability<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            operand_b: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            offset: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            operation: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            capability: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
            property: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(5))?,
        })
    }
}

impl Command for PolicyCapability<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyCapability;
    type Handles = PolicyCapabilityHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyParametersHandles {
    pub policy_session: Handle,
}

impl Marshal for PolicyParametersHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyParametersHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.24 TPM2_PolicyParameters (Command)
#[doc(alias = "TPM2_PolicyParameters")]
#[doc(alias = "PolicyParameters_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyParameters<'a> {
    pub p_hash: Tpm2bDigest<'a>,
}

impl Marshal for PolicyParameters<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyParameters::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.p_hash.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyParameters<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            p_hash: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for PolicyParameters<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyParameters;
    type Handles = PolicyParametersHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyTransportSPDMHandles {
    pub policy_session: Handle,
}

impl Marshal for PolicyTransportSPDMHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyTransportSPDMHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 23.25 TPM2_PolicyTransportSPDM (Command)
#[doc(alias = "TPM2_PolicyTransportSPDM")]
#[doc(alias = "PolicyTransportSPDM_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyTransportSPDM<'a> {
    pub req_key_name: Tpm2bName<'a>,
    pub tpm_key_name: Tpm2bName<'a>,
}

impl Marshal for PolicyTransportSPDM<'_> {
    const MAX_SIZE: usize = Tpm2bName::MAX_SIZE + Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; PolicyTransportSPDM::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.req_key_name, dst, 0);
        marshal_helper(&self.tpm_key_name, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyTransportSPDM<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            req_key_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            tpm_key_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Command for PolicyTransportSPDM<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyTransportSPDM;
    type Handles = PolicyTransportSPDMHandles;
    type Response<'a> = ();
    type RespHandles = ();
}
