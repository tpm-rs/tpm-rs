//! The Nuvoton configuration vendor commands `NTC2_PreConfig`, `NTC2_LockPreConfig` and
//! `NTC2_GetConfig` (the `ntc2-vendor-commands` feature), which are not part of the TPM 2.0
//! specification and follow `ibmswtpm2`'s emulation (`ntc2.c`, built with `TPM_NUVOTON`)
//! exactly: no handles, no sessions (`NO_SESSIONS`), the `TPMA_CC` attribute `nv`, and a
//! configuration ([`Ntc2State`]) kept in RAM only ("This emulation does not store the
//! configuration in NV memory"): it starts at [`NTC2_INITIAL_CONFIG`] and is kept across
//! `_TPM_Init`.

use tpm2::commands::{Ntc2CfgStruct, Ntc2GetConfig, Ntc2LockPreConfig, Ntc2PreConfig};
use tpm2::errors::TpmRc;
use tpm2::{TpmCc, TpmaCc, UnmarshalMessage};
use tpm2_engine::VendorCommand;

/// The value of `IsLocked` (and `IsValid`) that means "SET" in the Nuvoton configuration.
pub const NTC2_SET: u8 = 0xAA;

/// The value of `IsLocked` that means "not locked" in the Nuvoton configuration.
pub const NTC2_CLEAR: u8 = 0xFF;

/// The configuration a new TPM starts with (the initializer of `ntc2state` in `ibmswtpm2`'s
/// `ntc2.c`: "config state has some required or default values").
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

/// The `NTC2_*` commands as platform vendor commands: `ibmswtpm2` gives them the `nv`
/// attribute (and `NO_SESSIONS`, which every platform vendor command has).
pub const NTC2_VENDOR_COMMANDS: [VendorCommand; 3] = [
    VendorCommand {
        code: TpmCc::NTC2PreConfig,
        attributes: TpmaCc::NV,
    },
    VendorCommand {
        code: TpmCc::NTC2LockPreConfig,
        attributes: TpmaCc::NV,
    },
    VendorCommand {
        code: TpmCc::NTC2GetConfig,
        attributes: TpmaCc::NV,
    },
];

/// The Nuvoton configuration of the `NTC2_*` commands (`ntc2state` of `ibmswtpm2`'s `ntc2.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ntc2State {
    /// The current configuration.
    pub config: Ntc2CfgStruct,
}

impl Default for Ntc2State {
    fn default() -> Self {
        Self {
            config: NTC2_INITIAL_CONFIG,
        }
    }
}

impl Ntc2State {
    /// Executes the `NTC2_*` command `code` with the parameter area `parameters`, writing its
    /// response parameters to `response` (see `tpm2_engine::Platform::execute_vendor_command`).
    ///
    /// * `NTC2_PreConfig` fails with `TPM_RC_DISABLED` once the configuration is locked
    ///   (`IsLocked` is `0xAA`). Otherwise the configuration becomes `preConfig` (no field is
    ///   validated, not even `IsValid`), except that `IsLocked` stays `0xFF` ("cannot be set by
    ///   PreConfig").
    /// * `NTC2_LockPreConfig` locks the configuration (`IsLocked` becomes `0xAA`), which always
    ///   succeeds.
    /// * `NTC2_GetConfig` returns the configuration.
    ///
    /// A truncated parameter fails like the engine's unmarshaling (`TPM_RC_INSUFFICIENT` of
    /// parameter 1), extra octets with `TPM_RC_SIZE`.
    pub fn execute(
        &mut self,
        code: TpmCc,
        parameters: &[u8],
        response: &mut [u8],
    ) -> Result<usize, TpmRc> {
        let mut slice = parameters;
        let written = match code {
            TpmCc::NTC2PreConfig => {
                let cmd =
                    Ntc2PreConfig::unmarshal_with_handles([], &mut slice).map_err(TpmRc::from)?;
                check_consumed(slice)?;
                if self.config.is_locked == NTC2_SET {
                    return Err(TpmRc::DISABLED);
                }
                self.config = Ntc2CfgStruct {
                    is_locked: NTC2_CLEAR,
                    ..cmd.pre_config
                };
                0
            }
            TpmCc::NTC2LockPreConfig => {
                Ntc2LockPreConfig::unmarshal_with_handles([], &mut slice).map_err(TpmRc::from)?;
                check_consumed(slice)?;
                self.config.is_locked = NTC2_SET;
                0
            }
            TpmCc::NTC2GetConfig => {
                Ntc2GetConfig::unmarshal_with_handles([], &mut slice).map_err(TpmRc::from)?;
                check_consumed(slice)?;
                let bytes = self.config.to_bytes();
                response
                    .get_mut(..bytes.len())
                    .ok_or(TpmRc::FAILURE)?
                    .copy_from_slice(&bytes);
                bytes.len()
            }
            _ => return Err(TpmRc::COMMAND_CODE),
        };
        Ok(written)
    }
}

/// `TPM_RC_SIZE` if parameter octets are left over.
fn check_consumed(rest: &[u8]) -> Result<(), TpmRc> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(TpmRc::SIZE.to_rc())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEW_CONFIG: [u8; 18] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x55, NTC2_SET,
    ];

    fn get(state: &mut Ntc2State) -> [u8; 18] {
        let mut rsp = [0u8; 64];
        assert_eq!(state.execute(TpmCc::NTC2GetConfig, &[], &mut rsp), Ok(18));
        rsp[..18].try_into().unwrap()
    }

    #[test]
    fn initial_config_matches_ibmswtpm2() {
        assert_eq!(
            NTC2_INITIAL_CONFIG.to_bytes(),
            [
                0xff, 0xff, 0x13, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xaa, 0xff,
            ]
        );
        assert_eq!(
            get(&mut Ntc2State::default()),
            NTC2_INITIAL_CONFIG.to_bytes()
        );
    }

    #[test]
    fn pre_config_keeps_is_locked_clear_until_locked() {
        let mut state = Ntc2State::default();
        let mut rsp = [0u8; 64];
        assert_eq!(
            state.execute(TpmCc::NTC2PreConfig, &NEW_CONFIG, &mut rsp),
            Ok(0)
        );
        let mut expected = NEW_CONFIG;
        expected[17] = NTC2_CLEAR;
        assert_eq!(get(&mut state), expected);

        assert_eq!(
            state.execute(TpmCc::NTC2LockPreConfig, &[], &mut rsp),
            Ok(0)
        );
        expected[17] = NTC2_SET;
        assert_eq!(get(&mut state), expected);
        assert_eq!(
            state.execute(TpmCc::NTC2PreConfig, &NEW_CONFIG, &mut rsp),
            Err(TpmRc::DISABLED)
        );
        assert_eq!(get(&mut state), expected);
    }

    #[test]
    fn malformed_parameters_are_rejected() {
        let mut state = Ntc2State::default();
        let mut rsp = [0u8; 64];
        assert!(
            state
                .execute(TpmCc::NTC2PreConfig, &NEW_CONFIG[..17], &mut rsp)
                .is_err()
        );
        let mut long = NEW_CONFIG.to_vec();
        long.push(0);
        assert_eq!(
            state.execute(TpmCc::NTC2PreConfig, &long, &mut rsp),
            Err(TpmRc::SIZE.to_rc())
        );
        assert_eq!(
            state.execute(TpmCc::NTC2GetConfig, &[0], &mut rsp),
            Err(TpmRc::SIZE.to_rc())
        );
        assert_eq!(
            state.execute(TpmCc::new(0x2000_0100), &[], &mut rsp),
            Err(TpmRc::COMMAND_CODE)
        );
        assert_eq!(get(&mut state), NTC2_INITIAL_CONFIG.to_bytes());
    }
}
