//! TPM 2.0 Duplication Commands
//!
//! This module implements the "Duplication Commands" commands defined in
//! **Section 13** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_Duplicate (Command)
#[doc(alias = "TPM2_Duplicate")]
#[doc(alias = "Duplicate_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Duplicate<'a> {
    pub object_handle: Handle,
    pub new_parent_handle: Handle,
    pub encryption_key_in: Tpm2bData<'a>,
    pub symmetric_alg: Option<TpmtSymDefObject>,
}
/// TPM2_Duplicate (Response)
#[doc(alias = "Duplicate_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct DuplicateRsp<'a> {
    pub encryption_key_out: Tpm2bData<'a>,
    pub duplicate: Tpm2bPrivate<'a>,
    pub out_sym_seed: Tpm2bEncryptedSecret<'a>,
}

impl Command for Duplicate<'_> {
    const CMD_CODE: TpmCc = TpmCc::Duplicate;
    type Response<'a> = DuplicateRsp<'a>;
}
impl Message for Duplicate<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.object_handle, self.new_parent_handle]
    }
}
impl Marshal for Duplicate<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE + <Option<TpmtSymDefObject>>::MAX_SIZE;
    type MaxBuffer = [u8; Duplicate::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.encryption_key_in, dst, 0);
        marshal_helper(&self.symmetric_alg, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for Duplicate<'a> {
    fn unmarshal_with_handles(
        [object_handle, new_parent_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle,
            new_parent_handle,
            encryption_key_in: Unmarshal::unmarshal(src)?,
            symmetric_alg: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for DuplicateRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for DuplicateRsp<'_> {
    const MAX_SIZE: usize =
        Tpm2bData::MAX_SIZE + Tpm2bPrivate::MAX_SIZE + Tpm2bEncryptedSecret::MAX_SIZE;
    type MaxBuffer = [u8; DuplicateRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.encryption_key_out, dst, 0);
        let count = marshal_helper(&self.duplicate, dst, count);
        marshal_helper(&self.out_sym_seed, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for DuplicateRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            encryption_key_out: Unmarshal::unmarshal(src)?,
            duplicate: Unmarshal::unmarshal(src)?,
            out_sym_seed: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_Rewrap (Command)
#[doc(alias = "TPM2_Rewrap")]
#[doc(alias = "Rewrap_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Rewrap<'a> {
    pub old_parent: Handle,
    pub new_parent: Handle,
    pub in_duplicate: Tpm2bPrivate<'a>,
    pub name: Tpm2bName<'a>,
    pub in_sym_seed: Tpm2bEncryptedSecret<'a>,
}
/// TPM2_Rewrap (Response)
#[doc(alias = "Rewrap_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct RewrapRsp<'a> {
    pub out_duplicate: Tpm2bPrivate<'a>,
    pub out_sym_seed: Tpm2bEncryptedSecret<'a>,
}

impl Command for Rewrap<'_> {
    const CMD_CODE: TpmCc = TpmCc::Rewrap;
    type Response<'a> = RewrapRsp<'a>;
}
impl Message for Rewrap<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.old_parent, self.new_parent]
    }
}
impl Marshal for Rewrap<'_> {
    const MAX_SIZE: usize =
        Tpm2bPrivate::MAX_SIZE + Tpm2bName::MAX_SIZE + Tpm2bEncryptedSecret::MAX_SIZE;
    type MaxBuffer = [u8; Rewrap::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_duplicate, dst, 0);
        let count = marshal_helper(&self.name, dst, count);
        marshal_helper(&self.in_sym_seed, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for Rewrap<'a> {
    fn unmarshal_with_handles(
        [old_parent, new_parent]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            old_parent,
            new_parent,
            in_duplicate: Unmarshal::unmarshal(src)?,
            name: Unmarshal::unmarshal(src)?,
            in_sym_seed: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for RewrapRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for RewrapRsp<'_> {
    const MAX_SIZE: usize = Tpm2bPrivate::MAX_SIZE + Tpm2bEncryptedSecret::MAX_SIZE;
    type MaxBuffer = [u8; RewrapRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_duplicate, dst, 0);
        marshal_helper(&self.out_sym_seed, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for RewrapRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_duplicate: Unmarshal::unmarshal(src)?,
            out_sym_seed: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_Import (Command)
#[doc(alias = "TPM2_Import")]
#[doc(alias = "Import_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Import<'a> {
    pub parent_handle: Handle,
    pub encryption_key: Tpm2bData<'a>,
    pub object_public: Tpm2bPublic<'a>,
    pub duplicate: Tpm2bPrivate<'a>,
    pub in_sym_seed: Tpm2bEncryptedSecret<'a>,
    pub symmetric_alg: Option<TpmtSymDefObject>,
}
/// TPM2_Import (Response)
#[doc(alias = "Import_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ImportRsp<'a> {
    pub out_private: Tpm2bPrivate<'a>,
}

impl Command for Import<'_> {
    const CMD_CODE: TpmCc = TpmCc::Import;
    type Response<'a> = ImportRsp<'a>;
}
impl Message for Import<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.parent_handle]
    }
}
impl Marshal for Import<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE
        + Tpm2bPublic::MAX_SIZE
        + Tpm2bPrivate::MAX_SIZE
        + Tpm2bEncryptedSecret::MAX_SIZE
        + <Option<TpmtSymDefObject>>::MAX_SIZE;
    type MaxBuffer = [u8; Import::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.encryption_key, dst, 0);
        let count = marshal_helper(&self.object_public, dst, count);
        let count = marshal_helper(&self.duplicate, dst, count);
        let count = marshal_helper(&self.in_sym_seed, dst, count);
        marshal_helper(&self.symmetric_alg, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for Import<'a> {
    fn unmarshal_with_handles(
        [parent_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parent_handle,
            encryption_key: Unmarshal::unmarshal(src)?,
            object_public: Unmarshal::unmarshal(src)?,
            duplicate: Unmarshal::unmarshal(src)?,
            in_sym_seed: Unmarshal::unmarshal(src)?,
            symmetric_alg: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for ImportRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ImportRsp<'_> {
    const MAX_SIZE: usize = Tpm2bPrivate::MAX_SIZE;
    type MaxBuffer = [u8; ImportRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_private.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ImportRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_private: Unmarshal::unmarshal(src)?,
        })
    }
}
