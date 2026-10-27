//! TPM 2.0 Vendor Specific Commands
//!
//! This module implements the "Vendor Specific" commands defined in
//! **Section 34** of the TPM 2.0 Specification.
//!
//! These commands provide placeholders for vendor-defined extensions and tests.
//!
//! Each command includes its request (handles first, then parameters), its
//! response, and the [`Command`] / [`Message`] / [`UnmarshalMessage`] trait
//! implementations.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, *};

/// [TPM2.0 1.83] 34.2 TPM2_Vendor_TCG_Test (Command)
#[doc(alias = "TPM2_Vendor_TCG_Test")]
#[doc(alias = "Vendor_TCG_Test_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct VendorTcgTest<'a> {
    pub input_data: Tpm2bData<'a>,
}
/// [TPM2.0 1.83] 34.2 TPM2_Vendor_TCG_Test (Response)
#[doc(alias = "Vendor_TCG_Test_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct VendorTcgTestRsp<'a> {
    pub output_data: Tpm2bData<'a>,
}

impl Command for VendorTcgTest<'_> {
    const CMD_CODE: TpmCc = TpmCc::VendorTcgTest;
    type Response<'a> = VendorTcgTestRsp<'a>;
}
impl Message for VendorTcgTest<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for VendorTcgTest<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE;
    type MaxBuffer = [u8; VendorTcgTest::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.input_data.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for VendorTcgTest<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            input_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Message for VendorTcgTestRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for VendorTcgTestRsp<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE;
    type MaxBuffer = [u8; VendorTcgTestRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.output_data.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for VendorTcgTestRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            output_data: Unmarshal::unmarshal(src)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Nuvoton proprietary commands (`NTC2_*`)
// ---------------------------------------------------------------------------
//
// These commands are not part of the TPM 2.0 Library Specification. They are
// the configuration commands of Nuvoton TPMs as emulated by the IBM software
// TPM (`ibmswtpm2`, `ntc2.c`/`ntc2lib.c`, built with `TPM_NUVOTON`), whose wire
// format they follow exactly: none of them has handles, and the only
// parameter is the raw 18-byte [`Ntc2CfgStruct`].

/// The Nuvoton TPM configuration structure (`NTC2_CFG_STRUCT` of `ibmswtpm2`'s
/// `ntc2lib.h`): 18 one-byte fields, marshaled as 18 raw bytes in field order
/// (no size prefix).
#[doc(alias = "NTC2_CFG_STRUCT")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Ntc2CfgStruct {
    pub i2c_loc1_2: u8,
    pub i2c_loc3_4: u8,
    pub alt_cfg: u8,
    pub direction: u8,
    pub pull_up: u8,
    pub push_pull: u8,
    pub cfg_a: u8,
    pub cfg_b: u8,
    pub cfg_c: u8,
    pub cfg_d: u8,
    pub cfg_e: u8,
    pub cfg_f: u8,
    pub cfg_g: u8,
    pub cfg_h: u8,
    pub cfg_i: u8,
    pub cfg_j: u8,
    /// Must be `0xAA` (not checked by `NTC2_PreConfig`).
    pub is_valid: u8,
    /// Ignored by `NTC2_PreConfig`; `NTC2_GetConfig` returns `0xAA` once the
    /// configuration is locked (`NTC2_LockPreConfig`).
    pub is_locked: u8,
}

impl Ntc2CfgStruct {
    /// The size of the structure on the wire.
    pub const SIZE: usize = 18;

    /// Returns the wire bytes of the structure (its fields in order).
    pub const fn to_bytes(&self) -> [u8; Self::SIZE] {
        [
            self.i2c_loc1_2,
            self.i2c_loc3_4,
            self.alt_cfg,
            self.direction,
            self.pull_up,
            self.push_pull,
            self.cfg_a,
            self.cfg_b,
            self.cfg_c,
            self.cfg_d,
            self.cfg_e,
            self.cfg_f,
            self.cfg_g,
            self.cfg_h,
            self.cfg_i,
            self.cfg_j,
            self.is_valid,
            self.is_locked,
        ]
    }

    /// Builds the structure from its wire bytes (its fields in order).
    pub const fn from_bytes(b: [u8; Self::SIZE]) -> Self {
        Self {
            i2c_loc1_2: b[0],
            i2c_loc3_4: b[1],
            alt_cfg: b[2],
            direction: b[3],
            pull_up: b[4],
            push_pull: b[5],
            cfg_a: b[6],
            cfg_b: b[7],
            cfg_c: b[8],
            cfg_d: b[9],
            cfg_e: b[10],
            cfg_f: b[11],
            cfg_g: b[12],
            cfg_h: b[13],
            cfg_i: b[14],
            cfg_j: b[15],
            is_valid: b[16],
            is_locked: b[17],
        }
    }
}

impl Marshal for Ntc2CfgStruct {
    const MAX_SIZE: usize = Self::SIZE;
    type MaxBuffer = [u8; Self::SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.to_bytes().marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for Ntc2CfgStruct {
    /// Fails with `TPM_RC_INSUFFICIENT` if fewer than 18 bytes remain
    /// (`Array_Unmarshal`).
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self::from_bytes(Unmarshal::unmarshal(src)?))
    }
}

/// `NTC2_PreConfig` (`0x20000211`): sets the configuration unless it is locked.
#[doc(alias = "NTC2_PreConfig")]
#[doc(alias = "NTC2_PreConfig_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Ntc2PreConfig {
    pub pre_config: Ntc2CfgStruct,
}
impl Command for Ntc2PreConfig {
    const CMD_CODE: TpmCc = TpmCc::NTC2PreConfig;
    type Response<'a> = ();
}
impl Message for Ntc2PreConfig {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for Ntc2PreConfig {
    const MAX_SIZE: usize = Ntc2CfgStruct::MAX_SIZE;
    type MaxBuffer = [u8; Ntc2PreConfig::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.pre_config.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for Ntc2PreConfig {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pre_config: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// `NTC2_LockPreConfig` (`0x20000212`): locks the configuration.
#[doc(alias = "NTC2_LockPreConfig")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Ntc2LockPreConfig;
impl Command for Ntc2LockPreConfig {
    const CMD_CODE: TpmCc = TpmCc::NTC2LockPreConfig;
    type Response<'a> = ();
}
impl Message for Ntc2LockPreConfig {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for Ntc2LockPreConfig {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for Ntc2LockPreConfig {
    fn unmarshal_with_handles([]: Self::Handles, _: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self)
    }
}

/// `NTC2_GetConfig` (`0x20000213`): returns the configuration.
#[doc(alias = "NTC2_GetConfig")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Ntc2GetConfig;
/// `NTC2_GetConfig` (Response).
#[doc(alias = "NTC2_GetConfig_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Ntc2GetConfigRsp {
    pub pre_config: Ntc2CfgStruct,
}
impl Command for Ntc2GetConfig {
    const CMD_CODE: TpmCc = TpmCc::NTC2GetConfig;
    type Response<'a> = Ntc2GetConfigRsp;
}
impl Message for Ntc2GetConfig {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for Ntc2GetConfig {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for Ntc2GetConfig {
    fn unmarshal_with_handles([]: Self::Handles, _: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self)
    }
}
impl Message for Ntc2GetConfigRsp {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for Ntc2GetConfigRsp {
    const MAX_SIZE: usize = Ntc2CfgStruct::MAX_SIZE;
    type MaxBuffer = [u8; Ntc2GetConfigRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.pre_config.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for Ntc2GetConfigRsp {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pre_config: Unmarshal::unmarshal(src)?,
        })
    }
}
