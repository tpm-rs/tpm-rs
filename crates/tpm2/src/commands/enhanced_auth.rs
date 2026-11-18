//! TPM 2.0 Enhanced Authorization (EA) Commands
//!
//! This module implements the "Enhanced Authorization (EA) Commands" commands defined in
//! **Section 23** of the TPM 2.0 Specification.
use super::{Command, Response, UnmarshalCommand, UnmarshalResponse};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_PolicySigned (Command)
#[doc(alias = "TPM2_PolicySigned")]
#[doc(alias = "PolicySigned_In")]
#[derive(Clone, Copy)]
pub struct PolicySigned<'a> {
    pub auth_object: ObjectHandle<'a>,
    pub policy_session: Handle,
    pub nonce_tpm: Tpm2bNonce<'a>,
    pub cp_hash_a: Tpm2bDigest<'a>,
    pub policy_ref: Tpm2bNonce<'a>,
    pub expiration: i32,
    pub auth: TpmtSignature<'a>,
}
/// TPM2_PolicySigned (Response)
#[doc(alias = "PolicySigned_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicySignedRsp<'a> {
    pub timeout: Tpm2bTimeout<'a>,
    pub policy_ticket: TpmtTkAuth<'a>,
}

impl Command for PolicySigned<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicySigned;
    type Handles<'a>
        = [EntityHandle<'a>; 2]
    where
        Self: 'a;
    type Response<'a> = PolicySignedRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [
            self.auth_object.into(),
            EntityHandle::Handle(self.policy_session),
        ]
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
impl<'a> UnmarshalCommand<'a> for PolicySigned<'a> {
    fn unmarshal_with_handles(
        [auth_object, policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_object: auth_object.try_into()?,
            policy_session: policy_session.try_into()?,
            nonce_tpm: Unmarshal::unmarshal(src)?,
            cp_hash_a: Unmarshal::unmarshal(src)?,
            policy_ref: Unmarshal::unmarshal(src)?,
            expiration: Unmarshal::unmarshal(src)?,
            auth: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for PolicySignedRsp<'_> {
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
impl<'a> UnmarshalResponse<'a> for PolicySignedRsp<'a> {
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

/// TPM2_PolicySecret (Command)
#[doc(alias = "TPM2_PolicySecret")]
#[doc(alias = "PolicySecret_In")]
#[derive(Clone, Copy)]
pub struct PolicySecret<'a> {
    pub auth_handle: EntityHandle<'a>,
    pub policy_session: Handle,
    pub nonce_tpm: Tpm2bNonce<'a>,
    pub cp_hash_a: Tpm2bDigest<'a>,
    pub policy_ref: Tpm2bNonce<'a>,
    pub expiration: i32,
}
/// TPM2_PolicySecret (Response)
#[doc(alias = "PolicySecret_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicySecretRsp<'a> {
    pub timeout: Tpm2bTimeout<'a>,
    pub policy_ticket: TpmtTkAuth<'a>,
}

impl Command for PolicySecret<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicySecret;
    type Handles<'a>
        = [EntityHandle<'a>; 2]
    where
        Self: 'a;
    type Response<'a> = PolicySecretRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.auth_handle, EntityHandle::Handle(self.policy_session)]
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
impl<'a> UnmarshalCommand<'a> for PolicySecret<'a> {
    fn unmarshal_with_handles(
        [auth_handle, policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            policy_session: policy_session.try_into()?,
            nonce_tpm: Unmarshal::unmarshal(src)?,
            cp_hash_a: Unmarshal::unmarshal(src)?,
            policy_ref: Unmarshal::unmarshal(src)?,
            expiration: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for PolicySecretRsp<'_> {
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
impl<'a> UnmarshalResponse<'a> for PolicySecretRsp<'a> {
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

/// TPM2_PolicyTicket (Command)
#[doc(alias = "TPM2_PolicyTicket")]
#[doc(alias = "PolicyTicket_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyTicket<'a> {
    pub policy_session: Handle,
    pub timeout: Tpm2bTimeout<'a>,
    pub cp_hash_a: Tpm2bDigest<'a>,
    pub policy_ref: Tpm2bNonce<'a>,
    pub auth_name: Name<'a>,
    pub ticket: TpmtTkAuth<'a>,
}

impl Command for PolicyTicket<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyTicket;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyTicket<'_> {
    const MAX_SIZE: usize = Tpm2bTimeout::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + Tpm2bNonce::MAX_SIZE
        + Name::MAX_SIZE
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
impl<'a> UnmarshalCommand<'a> for PolicyTicket<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            timeout: Unmarshal::unmarshal(src)?,
            cp_hash_a: Unmarshal::unmarshal(src)?,
            policy_ref: Unmarshal::unmarshal(src)?,
            auth_name: Unmarshal::unmarshal(src)?,
            ticket: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyOR (Command)
#[doc(alias = "TPM2_PolicyOR")]
#[doc(alias = "PolicyOR_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyOR<'a> {
    pub policy_session: Handle,
    pub p_hash_list: TpmlDigest<'a>,
}

impl Command for PolicyOR<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyOR;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyOR<'_> {
    const MAX_SIZE: usize = TpmlDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyOR::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.p_hash_list.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyOR<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        let p_hash_list = TpmlDigest::unmarshal(src)?;
        if p_hash_list.as_slice().len() < 2 {
            return Err(UnmarshalError);
        }
        Ok(Self {
            policy_session: policy_session.try_into()?,
            p_hash_list,
        })
    }
}

/// TPM2_PolicyPCR (Command)
#[doc(alias = "TPM2_PolicyPCR")]
#[doc(alias = "PolicyPCR_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyPCR<'a> {
    pub policy_session: Handle,
    pub pcr_digest: Tpm2bDigest<'a>,
    pub pcrs: TpmlPcrSelection,
}

impl Command for PolicyPCR<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyPCR;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
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
impl<'a> UnmarshalCommand<'a> for PolicyPCR<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            pcr_digest: Unmarshal::unmarshal(src)?,
            pcrs: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyLocality (Command)
#[doc(alias = "TPM2_PolicyLocality")]
#[doc(alias = "PolicyLocality_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyLocality {
    pub policy_session: Handle,
    pub locality: TpmaLocality,
}

impl Command for PolicyLocality {
    const CMD_CODE: TpmCc = TpmCc::PolicyLocality;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyLocality {
    const MAX_SIZE: usize = TpmaLocality::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.locality.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyLocality {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            locality: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyNV (Command)
#[doc(alias = "TPM2_PolicyNV")]
#[doc(alias = "PolicyNV_In")]
#[derive(Clone, Copy)]
pub struct PolicyNV<'a> {
    pub auth_handle: EntityHandle<'a>,
    pub nv_index: NvHandle<'a>,
    pub policy_session: Handle,
    pub operand_b: Tpm2bOperand<'a>,
    pub offset: u16,
    pub operation: TpmEo,
}

impl Command for PolicyNV<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyNV;
    type Handles<'a>
        = [EntityHandle<'a>; 3]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [
            self.auth_handle,
            self.nv_index.into(),
            EntityHandle::Handle(self.policy_session),
        ]
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
impl<'a> UnmarshalCommand<'a> for PolicyNV<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index, policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index: nv_index.try_into()?,
            policy_session: policy_session.try_into()?,
            operand_b: Unmarshal::unmarshal(src)?,
            offset: Unmarshal::unmarshal(src)?,
            operation: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyCounterTimer (Command)
#[doc(alias = "TPM2_PolicyCounterTimer")]
#[doc(alias = "PolicyCounterTimer_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyCounterTimer<'a> {
    pub policy_session: Handle,
    pub operand_b: Tpm2bOperand<'a>,
    pub offset: u16,
    pub operation: TpmEo,
}

impl Command for PolicyCounterTimer<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyCounterTimer;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
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
impl<'a> UnmarshalCommand<'a> for PolicyCounterTimer<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            operand_b: Unmarshal::unmarshal(src)?,
            offset: Unmarshal::unmarshal(src)?,
            operation: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyCommandCode (Command)
#[doc(alias = "TPM2_PolicyCommandCode")]
#[doc(alias = "PolicyCommandCode_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyCommandCode {
    pub policy_session: Handle,
    pub code: TpmCc,
}

impl Command for PolicyCommandCode {
    const CMD_CODE: TpmCc = TpmCc::PolicyCommandCode;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyCommandCode {
    const MAX_SIZE: usize = TpmCc::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.code.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyCommandCode {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            code: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyPhysicalPresence (Command)
#[doc(alias = "TPM2_PolicyPhysicalPresence")]
#[doc(alias = "PolicyPhysicalPresence_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyPhysicalPresence {
    pub policy_session: Handle,
}

impl Command for PolicyPhysicalPresence {
    const CMD_CODE: TpmCc = TpmCc::PolicyPhysicalPresence;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyPhysicalPresence {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyPhysicalPresence {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
        })
    }
}

/// TPM2_PolicyCpHash (Command)
#[doc(alias = "TPM2_PolicyCpHash")]
#[doc(alias = "PolicyCpHash_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyCpHash<'a> {
    pub policy_session: Handle,
    pub cp_hash_a: Tpm2bDigest<'a>,
}

impl Command for PolicyCpHash<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyCpHash;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyCpHash<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyCpHash::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.cp_hash_a.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyCpHash<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            cp_hash_a: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyNameHash (Command)
#[doc(alias = "TPM2_PolicyNameHash")]
#[doc(alias = "PolicyNameHash_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyNameHash<'a> {
    pub policy_session: Handle,
    pub name_hash: Tpm2bDigest<'a>,
}

impl Command for PolicyNameHash<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyNameHash;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyNameHash<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyNameHash::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.name_hash.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyNameHash<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            name_hash: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyDuplicationSelect (Command)
#[doc(alias = "TPM2_PolicyDuplicationSelect")]
#[doc(alias = "PolicyDuplicationSelect_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyDuplicationSelect<'a> {
    pub policy_session: Handle,
    pub object_name: Name<'a>,
    pub new_parent_name: Name<'a>,
    pub include_object: bool,
}

impl Command for PolicyDuplicationSelect<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyDuplicationSelect;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyDuplicationSelect<'_> {
    const MAX_SIZE: usize = Name::MAX_SIZE + Name::MAX_SIZE + bool::MAX_SIZE;
    type MaxBuffer = [u8; PolicyDuplicationSelect::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.object_name, dst, 0);
        let count = marshal_helper(&self.new_parent_name, dst, count);
        marshal_helper(&self.include_object, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyDuplicationSelect<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            object_name: Unmarshal::unmarshal(src)?,
            new_parent_name: Unmarshal::unmarshal(src)?,
            include_object: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyAuthorize (Command)
#[doc(alias = "TPM2_PolicyAuthorize")]
#[doc(alias = "PolicyAuthorize_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyAuthorize<'a> {
    pub policy_session: Handle,
    pub approved_policy: Tpm2bDigest<'a>,
    pub policy_ref: Tpm2bNonce<'a>,
    pub key_sign: Name<'a>,
    pub check_ticket: TpmtTkVerified<'a>,
}

impl Command for PolicyAuthorize<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyAuthorize;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyAuthorize<'_> {
    const MAX_SIZE: usize =
        Tpm2bDigest::MAX_SIZE + Tpm2bNonce::MAX_SIZE + Name::MAX_SIZE + TpmtTkVerified::MAX_SIZE;
    type MaxBuffer = [u8; PolicyAuthorize::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.approved_policy, dst, 0);
        let count = marshal_helper(&self.policy_ref, dst, count);
        let count = marshal_helper(&self.key_sign, dst, count);
        marshal_helper(&self.check_ticket, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyAuthorize<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            approved_policy: Unmarshal::unmarshal(src)?,
            policy_ref: Unmarshal::unmarshal(src)?,
            key_sign: Unmarshal::unmarshal(src)?,
            check_ticket: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyAuthValue (Command)
#[doc(alias = "TPM2_PolicyAuthValue")]
#[doc(alias = "PolicyAuthValue_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyAuthValue {
    pub policy_session: Handle,
}

impl Command for PolicyAuthValue {
    const CMD_CODE: TpmCc = TpmCc::PolicyAuthValue;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyAuthValue {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyAuthValue {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
        })
    }
}

/// TPM2_PolicyPassword (Command)
#[doc(alias = "TPM2_PolicyPassword")]
#[doc(alias = "PolicyPassword_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyPassword {
    pub policy_session: Handle,
}

impl Command for PolicyPassword {
    const CMD_CODE: TpmCc = TpmCc::PolicyPassword;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyPassword {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyPassword {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
        })
    }
}

/// TPM2_PolicyGetDigest (Command)
#[doc(alias = "TPM2_PolicyGetDigest")]
#[doc(alias = "PolicyGetDigest_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyGetDigest {
    pub policy_session: Handle,
}
/// TPM2_PolicyGetDigest (Response)
#[doc(alias = "PolicyGetDigest_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyGetDigestRsp<'a> {
    pub policy_digest: Tpm2bDigest<'a>,
}

impl Command for PolicyGetDigest {
    const CMD_CODE: TpmCc = TpmCc::PolicyGetDigest;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = PolicyGetDigestRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyGetDigest {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyGetDigest {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
        })
    }
}

impl Response for PolicyGetDigestRsp<'_> {
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
impl<'a> UnmarshalResponse<'a> for PolicyGetDigestRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_digest: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyNvWritten (Command)
#[doc(alias = "TPM2_PolicyNvWritten")]
#[doc(alias = "PolicyNvWritten_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyNvWritten {
    pub policy_session: Handle,
    pub written_set: bool,
}

impl Command for PolicyNvWritten {
    const CMD_CODE: TpmCc = TpmCc::PolicyNvWritten;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyNvWritten {
    const MAX_SIZE: usize = bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.written_set.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyNvWritten {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            written_set: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyTemplate (Command)
#[doc(alias = "TPM2_PolicyTemplate")]
#[doc(alias = "PolicyTemplate_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyTemplate<'a> {
    pub policy_session: Handle,
    pub template_hash: Tpm2bDigest<'a>,
}

impl Command for PolicyTemplate<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyTemplate;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyTemplate<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyTemplate::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.template_hash.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyTemplate<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            template_hash: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyAuthorizeNV (Command)
#[doc(alias = "TPM2_PolicyAuthorizeNV")]
#[doc(alias = "PolicyAuthorizeNV_In")]
#[derive(Clone, Copy)]
pub struct PolicyAuthorizeNV<'a> {
    pub auth_handle: EntityHandle<'a>,
    pub nv_index: NvHandle<'a>,
    pub policy_session: Handle,
}

impl Command for PolicyAuthorizeNV<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyAuthorizeNV;
    type Handles<'a>
        = [EntityHandle<'a>; 3]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [
            self.auth_handle,
            self.nv_index.into(),
            EntityHandle::Handle(self.policy_session),
        ]
    }
}
impl Marshal for PolicyAuthorizeNV<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyAuthorizeNV<'a> {
    fn unmarshal_with_handles(
        [auth_handle, nv_index, policy_session]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            nv_index: nv_index.try_into()?,
            policy_session: policy_session.try_into()?,
        })
    }
}

/// TPM2_PolicyCapability (Command)
#[doc(alias = "TPM2_PolicyCapability")]
#[doc(alias = "PolicyCapability_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
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
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
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
impl<'a> UnmarshalCommand<'a> for PolicyCapability<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            operand_b: Unmarshal::unmarshal(src)?,
            offset: Unmarshal::unmarshal(src)?,
            operation: Unmarshal::unmarshal(src)?,
            capability: Unmarshal::unmarshal(src)?,
            property: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyParameters (Command)
#[doc(alias = "TPM2_PolicyParameters")]
#[doc(alias = "PolicyParameters_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyParameters<'a> {
    pub policy_session: Handle,
    pub p_hash: Tpm2bDigest<'a>,
}

impl Command for PolicyParameters<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyParameters;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyParameters<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PolicyParameters::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.p_hash.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyParameters<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            p_hash: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyTransportSPDM (Command)
#[doc(alias = "TPM2_PolicyTransportSPDM")]
#[doc(alias = "PolicyTransportSPDM_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyTransportSPDM<'a> {
    pub policy_session: Handle,
    pub req_key_name: Name<'a>,
    pub tpm_key_name: Name<'a>,
}

impl Command for PolicyTransportSPDM<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyTransportSPDM;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.policy_session)]
    }
}
impl Marshal for PolicyTransportSPDM<'_> {
    const MAX_SIZE: usize = Name::MAX_SIZE + Name::MAX_SIZE;
    type MaxBuffer = [u8; PolicyTransportSPDM::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.req_key_name, dst, 0);
        marshal_helper(&self.tpm_key_name, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyTransportSPDM<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: policy_session.try_into()?,
            req_key_name: Unmarshal::unmarshal(src)?,
            tpm_key_name: Unmarshal::unmarshal(src)?,
        })
    }
}
