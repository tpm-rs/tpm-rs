//! Vendor-specific commands (command codes with the `V` bit, `CC_VEND`).
//!
//! * `TPM2_Vendor_TCG_Test` (TPM 2.0 Part 3, "Vendor Specific"): "a placeholder to allow
//!   testing of the dispatch code". It has no handles, and its response returns the command's
//!   `inputData` as `outputData` (the reference's `Vendor_TCG_Test.c`). Both parameters are
//!   `TPM2B_DATA`, so the command allows parameter encryption in both directions (Part 1: "Any
//!   first parameter can be encrypted as long as the parameter has a size field").
//! * With the `ntc2-vendor-commands` profile feature: the Nuvoton configuration commands
//!   `NTC2_PreConfig`, `NTC2_LockPreConfig` and `NTC2_GetConfig`, which are not part of the
//!   TPM 2.0 specification and follow `ibmswtpm2`'s emulation (`ntc2.c`, built with
//!   `TPM_NUVOTON`) exactly: no handles, no sessions (`NO_SESSIONS`), and a configuration
//!   ([`crate::engine::GlobalState::ntc2_config`]) kept in RAM only.

#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{VendorTcgTest, responses};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::TpmRc;

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};

#[cfg(feature = "ntc2-vendor-commands")]
use tpm2::commands::{Ntc2CfgStruct, Ntc2GetConfig, Ntc2LockPreConfig, Ntc2PreConfig};

/// The value of `IsLocked` (and `IsValid`) that means "SET" in the Nuvoton configuration.
#[cfg(feature = "ntc2-vendor-commands")]
pub(crate) const NTC2_SET: u8 = 0xAA;

/// The value of `IsLocked` that means "not locked" in the Nuvoton configuration.
#[cfg(feature = "ntc2-vendor-commands")]
pub(crate) const NTC2_CLEAR: u8 = 0xFF;

/// The configuration a new TPM starts with (the initializer of `ntc2state` in `ibmswtpm2`'s
/// `ntc2.c`: "config state has some required or default values").
#[cfg(feature = "ntc2-vendor-commands")]
pub const NTC2_INITIAL_CONFIG: Ntc2CfgStruct = Ntc2CfgStruct {
    i2c_loc1_2: 0xff,
    i2c_loc3_4: 0xff,
    alt_cfg: 0x13,
    direction: 0x00,
    pull_up: 0xff,
    push_pull: 0xff,
    cfg_a: 0xff,
    cfg_b: 0xff,
    cfg_c: 0xff,
    cfg_d: 0xff,
    cfg_e: 0xff,
    cfg_f: 0xff,
    cfg_g: 0xff,
    cfg_h: 0xff,
    cfg_i: 0xff,
    cfg_j: 0xff,
    is_valid: NTC2_SET,
    is_locked: NTC2_CLEAR,
};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::VendorTcgTest] (`0x20000000`) command.
    ///
    /// # Description
    /// A placeholder vendor command that tests the dispatch of vendor-specific commands: it
    /// returns its `inputData` as `outputData`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, "Vendor Specific",
    /// TPM2_Vendor_TCG_Test.
    pub fn vendor_tcg_test(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<VendorTcgTest>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<VendorTcgTest>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let rsp = responses::VendorTcgTest {
            output_data: cmd.input_data,
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])
    }

    /// Handles the Nuvoton [TpmCc::NTC2PreConfig] (`0x20000211`) command (`NTC2_PreConfig()` of
    /// `ibmswtpm2`'s `ntc2.c`).
    ///
    /// Fails with `TPM_RC_DISABLED` once the configuration is locked (`IsLocked` is `0xAA`).
    /// Otherwise the configuration becomes `preConfig` (no field is validated, not even
    /// `IsValid`), except that `IsLocked` stays `0xFF` ("cannot be set by PreConfig").
    #[cfg(feature = "ntc2-vendor-commands")]
    pub fn ntc2_pre_config(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<Ntc2PreConfig>()?;
        let cmd = request.try_unmarshal_command::<Ntc2PreConfig>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let state = &mut self.context.state;
        if state.ntc2_config.is_locked == NTC2_SET {
            return Err(TpmRc::DISABLED);
        }
        state.ntc2_config = Ntc2CfgStruct {
            is_locked: NTC2_CLEAR,
            ..cmd.pre_config
        };
        let _response = request.into_response();
        Ok(())
    }

    /// Handles the Nuvoton [TpmCc::NTC2LockPreConfig] (`0x20000212`) command
    /// (`NTC2_LockPreConfig()` of `ibmswtpm2`'s `ntc2.c`): locks the configuration (`IsLocked`
    /// becomes `0xAA`), which always succeeds.
    #[cfg(feature = "ntc2-vendor-commands")]
    pub fn ntc2_lock_pre_config(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<Ntc2LockPreConfig>()?;
        let _cmd = request.try_unmarshal_command::<Ntc2LockPreConfig>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.context.state.ntc2_config.is_locked = NTC2_SET;
        let _response = request.into_response();
        Ok(())
    }

    /// Handles the Nuvoton [TpmCc::NTC2GetConfig] (`0x20000213`) command (`NTC2_GetConfig()` of
    /// `ibmswtpm2`'s `ntc2.c`): returns the configuration.
    #[cfg(feature = "ntc2-vendor-commands")]
    pub fn ntc2_get_config(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<Ntc2GetConfig>()?;
        let _cmd = request.try_unmarshal_command::<Ntc2GetConfig>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let rsp = responses::Ntc2GetConfig {
            pre_config: self.context.state.ntc2_config,
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{
        SUPPORTED_COMMANDS, TOTAL_COMMAND_COUNT, VENDOR_COMMANDS, command_list_start,
        get_command_attribute, implemented_commands_in_order, is_command_supported,
        is_session_allowed,
    };
    use tpm2::TpmaCc;

    #[test]
    fn vendor_commands_are_sorted_vendor_codes() {
        assert_eq!(VENDOR_COMMANDS[0], TpmCc::VendorTcgTest);
        assert!(VENDOR_COMMANDS.iter().all(|cc| cc.is_vendor()));
        assert!(
            VENDOR_COMMANDS
                .windows(2)
                .all(|w| w[0].code() < w[1].code())
        );
        assert!(SUPPORTED_COMMANDS.iter().all(|cc| !cc.is_vendor()));
        assert_eq!(
            VENDOR_COMMANDS.len(),
            if cfg!(feature = "ntc2-vendor-commands") {
                4
            } else {
                1
            }
        );
        assert!(is_command_supported(TpmCc::VendorTcgTest));
        assert!(!is_command_supported(TpmCc::new(0x2000_0100)));
        assert_eq!(
            is_command_supported(TpmCc::NTC2GetConfig),
            cfg!(feature = "ntc2-vendor-commands")
        );
    }

    #[test]
    fn implemented_commands_list_library_then_vendor() {
        let all = implemented_commands_in_order();
        assert_eq!(all.len(), TOTAL_COMMAND_COUNT);
        assert!(all.windows(2).all(|w| w[0].code() < w[1].code()));
        let (library, vendor) = all.split_at(SUPPORTED_COMMANDS.len());
        assert!(library.iter().all(|cc| SUPPORTED_COMMANDS.contains(cc)));
        assert_eq!(vendor, VENDOR_COMMANDS);
    }

    #[test]
    fn command_list_start_rejects_non_command_codes() {
        for property in [0, 0x144, 0xFFFF, 0x2000_0000, 0x2000_FFFF] {
            assert_eq!(
                command_list_start(property),
                Some(property),
                "{property:#x}"
            );
        }
        for property in [0x1_0000, 0x1000_0000, 0x2001_0000, 0x4000_0000, 0xFFFF_FFFF] {
            assert_eq!(command_list_start(property), None, "{property:#x}");
        }
    }

    #[test]
    fn vendor_command_attributes() {
        assert_eq!(get_command_attribute(TpmCc::VendorTcgTest), TpmaCc::V);
        assert!(is_session_allowed(TpmCc::VendorTcgTest));
        #[cfg(feature = "ntc2-vendor-commands")]
        for cc in [
            TpmCc::NTC2PreConfig,
            TpmCc::NTC2LockPreConfig,
            TpmCc::NTC2GetConfig,
        ] {
            assert_eq!(
                get_command_attribute(cc),
                TpmaCc::V | TpmaCc::NV | TpmaCc::command_index(cc.code() as u16)
            );
            assert!(!is_session_allowed(cc));
        }
    }

    #[cfg(feature = "ntc2-vendor-commands")]
    #[test]
    fn ntc2_initial_config_matches_ibmswtpm2() {
        assert_eq!(
            NTC2_INITIAL_CONFIG.to_bytes(),
            [
                0xff, 0xff, 0x13, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xaa, 0xff,
            ]
        );
        assert_eq!(
            crate::engine::GlobalState::default().ntc2_config,
            NTC2_INITIAL_CONFIG
        );
    }
}
