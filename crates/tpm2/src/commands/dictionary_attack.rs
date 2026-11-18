//! TPM 2.0 Dictionary Attack Functions Commands
//!
//! This module implements the "Dictionary Attack Functions" commands defined in
//! **Section 25** of the TPM 2.0 Specification.
use super::{Command, UnmarshalCommand};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_DictionaryAttackLockReset (Command)
#[doc(alias = "TPM2_DictionaryAttackLockReset")]
#[doc(alias = "DictionaryAttackLockReset_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct DictionaryAttackLockReset {
    pub lock_handle: Handle,
}

impl Command for DictionaryAttackLockReset {
    const CMD_CODE: TpmCc = TpmCc::DictionaryAttackLockReset;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.lock_handle)]
    }
}
impl Marshal for DictionaryAttackLockReset {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for DictionaryAttackLockReset {
    fn unmarshal_with_handles(
        [lock_handle]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            lock_handle: lock_handle.try_into()?,
        })
    }
}

/// TPM2_DictionaryAttackParameters (Command)
#[doc(alias = "TPM2_DictionaryAttackParameters")]
#[doc(alias = "DictionaryAttackParameters_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct DictionaryAttackParameters {
    pub lock_handle: Handle,
    pub new_max_tries: u32,
    pub new_recovery_time: u32,
    pub lockout_recovery: u32,
}

impl Command for DictionaryAttackParameters {
    const CMD_CODE: TpmCc = TpmCc::DictionaryAttackParameters;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.lock_handle)]
    }
}
impl Marshal for DictionaryAttackParameters {
    const MAX_SIZE: usize = u32::MAX_SIZE + u32::MAX_SIZE + u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.new_max_tries, dst, 0);
        let count = marshal_helper(&self.new_recovery_time, dst, count);
        marshal_helper(&self.lockout_recovery, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for DictionaryAttackParameters {
    fn unmarshal_with_handles(
        [lock_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            lock_handle: lock_handle.try_into()?,
            new_max_tries: Unmarshal::unmarshal(src)?,
            new_recovery_time: Unmarshal::unmarshal(src)?,
            lockout_recovery: Unmarshal::unmarshal(src)?,
        })
    }
}
