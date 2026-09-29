//! TPM 2.0 Duplication Commands
//!
//! This module implements the "Duplication Commands" defined in
//! **Section 13** of the TPM 2.0 Specification.
//!
//! These commands allow duplicating (migrating) a private key structure from one parent
//! hierarchy to another parent, permitting secure key deployment.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct DuplicateHandles {
    pub object_handle: Handle,
    pub new_parent_handle: Handle,
}
impl Marshal for DuplicateHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.object_handle, dst, 0);
        marshal_helper(&self.new_parent_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for DuplicateHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            new_parent_handle: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 13.1 TPM2_Duplicate (Command)
#[doc(alias = "TPM2_Duplicate")]
#[doc(alias = "Duplicate_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct Duplicate<'a> {
    pub encryption_key_in: crate::Tpm2bData<'a>,
    pub symmetric_alg: Option<crate::TpmtSymDefObject>,
}
impl Marshal for Duplicate<'_> {
    const MAX_SIZE: usize =
        <crate::Tpm2bData>::MAX_SIZE + <Option<crate::TpmtSymDefObject>>::MAX_SIZE;
    type MaxBuffer = [u8; Duplicate::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.encryption_key_in, dst, 0);
        marshal_helper(&self.symmetric_alg, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Duplicate<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            encryption_key_in: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            symmetric_alg: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 13.1 TPM2_Duplicate (Response)
#[doc(alias = "Duplicate_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct DuplicateRsp<'a> {
    pub encryption_key_out: crate::Tpm2bData<'a>,
    pub duplicate: crate::Tpm2bPrivate<'a>,
    pub out_sym_seed: crate::Tpm2bEncryptedSecret<'a>,
}
impl Marshal for DuplicateRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bData>::MAX_SIZE
        + <crate::Tpm2bPrivate>::MAX_SIZE
        + <crate::Tpm2bEncryptedSecret>::MAX_SIZE;
    type MaxBuffer = [u8; DuplicateRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.encryption_key_out, dst, 0);
        let count = marshal_helper(&self.duplicate, dst, count);
        marshal_helper(&self.out_sym_seed, dst, count)
    }
}

impl<'a> Unmarshal<'a> for DuplicateRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            encryption_key_out: Unmarshal::unmarshal(src)?,
            duplicate: Unmarshal::unmarshal(src)?,
            out_sym_seed: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 13.1 TPM2_Duplicate (Command)
impl Command for Duplicate<'_> {
    const CMD_CODE: TpmCc = TpmCc::Duplicate;
    type Handles = DuplicateHandles;
    type Response<'a> = DuplicateRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct RewrapHandles {
    pub old_parent: Handle,
    pub new_parent: Handle,
}
impl Marshal for RewrapHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.old_parent, dst, 0);
        marshal_helper(&self.new_parent, dst, count)
    }
}

impl<'a> Unmarshal<'a> for RewrapHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            old_parent: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            new_parent: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 13.2 TPM2_Rewrap (Command)
#[doc(alias = "TPM2_Rewrap")]
#[doc(alias = "Rewrap_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct Rewrap<'a> {
    pub in_duplicate: crate::Tpm2bPrivate<'a>,
    pub name: crate::Tpm2bName<'a>,
    pub in_sym_seed: crate::Tpm2bEncryptedSecret<'a>,
}
impl Marshal for Rewrap<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPrivate>::MAX_SIZE
        + <crate::Tpm2bName>::MAX_SIZE
        + <crate::Tpm2bEncryptedSecret>::MAX_SIZE;
    type MaxBuffer = [u8; Rewrap::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_duplicate, dst, 0);
        let count = marshal_helper(&self.name, dst, count);
        marshal_helper(&self.in_sym_seed, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Rewrap<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            in_duplicate: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            in_sym_seed: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

/// [TPM2.0 1.83] 13.2 TPM2_Rewrap (Response)
#[doc(alias = "Rewrap_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct RewrapRsp<'a> {
    pub out_duplicate: crate::Tpm2bPrivate<'a>,
    pub out_sym_seed: crate::Tpm2bEncryptedSecret<'a>,
}
impl Marshal for RewrapRsp<'_> {
    const MAX_SIZE: usize =
        <crate::Tpm2bPrivate>::MAX_SIZE + <crate::Tpm2bEncryptedSecret>::MAX_SIZE;
    type MaxBuffer = [u8; RewrapRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_duplicate, dst, 0);
        marshal_helper(&self.out_sym_seed, dst, count)
    }
}

impl<'a> Unmarshal<'a> for RewrapRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_duplicate: Unmarshal::unmarshal(src)?,
            out_sym_seed: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for Rewrap<'_> {
    const CMD_CODE: TpmCc = TpmCc::Rewrap;
    type Handles = RewrapHandles;
    type Response<'a> = RewrapRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ImportHandles {
    pub parent_handle: Handle,
}
impl Marshal for ImportHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.parent_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ImportHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parent_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 13.3 TPM2_Import (Command)
#[doc(alias = "TPM2_Import")]
#[doc(alias = "Import_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct Import<'a> {
    pub encryption_key: crate::Tpm2bData<'a>,
    pub object_public: crate::Tpm2bPublic<'a>,
    pub duplicate: crate::Tpm2bPrivate<'a>,
    pub in_sym_seed: crate::Tpm2bEncryptedSecret<'a>,
    pub symmetric_alg: Option<crate::TpmtSymDefObject>,
}
impl Marshal for Import<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bData>::MAX_SIZE
        + <crate::Tpm2bPublic>::MAX_SIZE
        + <crate::Tpm2bPrivate>::MAX_SIZE
        + <crate::Tpm2bEncryptedSecret>::MAX_SIZE
        + <Option<crate::TpmtSymDefObject>>::MAX_SIZE;
    type MaxBuffer = [u8; Import::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.encryption_key, dst, 0);
        let count = marshal_helper(&self.object_public, dst, count);
        let count = marshal_helper(&self.duplicate, dst, count);
        let count = marshal_helper(&self.in_sym_seed, dst, count);
        marshal_helper(&self.symmetric_alg, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Import<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            encryption_key: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            object_public: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            duplicate: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            in_sym_seed: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
            symmetric_alg: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(5))?,
        })
    }
}

/// [TPM2.0 1.83] 13.3 TPM2_Import (Response)
#[doc(alias = "Import_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ImportRsp<'a> {
    pub out_private: crate::Tpm2bPrivate<'a>,
}
impl Marshal for ImportRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPrivate>::MAX_SIZE;
    type MaxBuffer = [u8; ImportRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_private.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ImportRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_private: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 13.3 TPM2_Import (Command)
impl Command for Import<'_> {
    const CMD_CODE: TpmCc = TpmCc::Import;
    type Handles = ImportHandles;
    type Response<'a> = ImportRsp<'a>;
    type RespHandles = ();
}
