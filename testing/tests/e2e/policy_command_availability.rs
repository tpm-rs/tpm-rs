//! Availability of the commands of the `cc-policy-capability`, `cc-policy-parameters`,
//! `cc-policy-physical-presence`, `cc-pp-commands`, `cc-policy-ac-send-select` and
//! `cc-set-algorithm-set` features: with its feature, each command is in TPM_CAP_COMMANDS with
//! its TPMA_CC attributes (as in the TCG reference's command attribute table); without, it is
//! absent and `TPM_RC_COMMAND_CODE`.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::GetCapability;
use tpm2::errors::TpmRc;
use tpm2::{TpmCap, TpmCc, TpmsCapabilityData};

/// The TPMA_CC of `cc` in TPM_CAP_COMMANDS, or `None` if the TPM does not list it.
fn command_attributes(tpm: &mut Tpm, cc: TpmCc) -> Option<u32> {
    let rsp = tpm
        .execute(GetCapability {
            capability: TpmCap::Commands,
            property: cc.code(),
            property_count: 1,
        })
        .expect("TPM2_GetCapability failed");
    match rsp.capability_data {
        TpmsCapabilityData::Command(list) => list
            .as_slice()
            .first()
            .map(|attributes| attributes.0)
            .filter(|attributes| attributes & 0xFFFF == cc.code() & 0xFFFF),
        other => panic!("unexpected capability data: {other:?}"),
    }
}

/// The response code of `cc` sent without handles, sessions or parameters.
fn bare_command_rc(tpm: &mut Tpm, cc: TpmCc) -> u32 {
    send_rc(
        tpm,
        &build_raw_cmd(ST_NO_SESSIONS, cc.code(), &[], None, &[]),
    )
}

/// Checks `cc` against its feature: listed with `attributes` (TPMA_CC) when `enabled`, absent
/// and `TPM_RC_COMMAND_CODE` otherwise.
fn check_availability(cc: TpmCc, enabled: bool, attributes: u32) {
    let mut tpm = Tpm::new();
    if enabled {
        assert_eq!(command_attributes(&mut tpm, cc), Some(attributes), "{cc:?}");
        assert_ne!(
            bare_command_rc(&mut tpm, cc),
            TpmRc::COMMAND_CODE.get(),
            "{cc:?}"
        );
    } else {
        assert_eq!(command_attributes(&mut tpm, cc), None, "{cc:?}");
        assert_eq!(
            bare_command_rc(&mut tpm, cc),
            TpmRc::COMMAND_CODE.get(),
            "{cc:?}"
        );
    }
}

/// TPMA_CC bit `nv`.
const NV: u32 = 1 << 22;
/// TPMA_CC `cHandles = 1`.
const ONE_HANDLE: u32 = 1 << 25;

/// TPM2_PolicyCapability: one handle (the policy session).
#[test]
fn policy_capability_follows_its_feature() {
    check_availability(
        TpmCc::PolicyCapability,
        cfg!(feature = "cc-policy-capability"),
        0x019B | ONE_HANDLE,
    );
}

/// TPM2_PolicyParameters: one handle (the policy session).
#[test]
fn policy_parameters_follows_its_feature() {
    check_availability(
        TpmCc::PolicyParameters,
        cfg!(feature = "cc-policy-parameters"),
        0x019C | ONE_HANDLE,
    );
}

/// TPM2_PolicyPhysicalPresence: one handle (the policy session).
#[test]
fn policy_physical_presence_follows_its_feature() {
    check_availability(
        TpmCc::PolicyPhysicalPresence,
        cfg!(feature = "cc-policy-physical-presence"),
        0x0187 | ONE_HANDLE,
    );
}

/// TPM2_PP_Commands: one handle (TPM_RH_PLATFORM), updates NV.
#[test]
fn pp_commands_follows_its_feature() {
    check_availability(
        TpmCc::PPCommands,
        cfg!(feature = "cc-pp-commands"),
        0x012D | ONE_HANDLE | NV,
    );
}

/// TPM2_Policy_AC_SendSelect: one handle (the policy session).
#[test]
fn policy_ac_send_select_follows_its_feature() {
    check_availability(
        TpmCc::PolicyACSendSelect,
        cfg!(feature = "cc-policy-ac-send-select"),
        0x0196 | ONE_HANDLE,
    );
}

/// TPM2_SetAlgorithmSet: one handle (TPM_RH_PLATFORM), updates NV.
#[test]
fn set_algorithm_set_follows_its_feature() {
    check_availability(
        TpmCc::SetAlgorithmSet,
        cfg!(feature = "cc-set-algorithm-set"),
        0x013F | ONE_HANDLE | NV,
    );
}
