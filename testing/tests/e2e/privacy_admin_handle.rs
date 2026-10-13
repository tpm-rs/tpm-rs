//! privacyAdminHandle validation of TPM2_GetTime and TPM2_GetCommandAuditDigest.

use crate::_common::*;
use tpm2::commands::{GetCommandAuditDigest, GetTime};
use tpm2::{Handle, Tpm2bData, TpmiAlgHash, TpmtRsaScheme};
use tpm2_simulator::create_simulator;

/// GetCommandAuditDigest rejects TPM_RH_OWNER/TPM_RH_PLATFORM as privacy administrator (VALUE+H1).
///
/// `TPM2_GetCommandAuditDigest` rejects `TPM_RH_OWNER`/`TPM_RH_PLATFORM` as the privacy
/// administrator (the handler used to accept them; the engine already rejected them earlier).
#[test]
fn command_audit_digest_rejects_owner_and_platform() {
    let mut sim = create_simulator!();
    for admin in [Handle::RH_OWNER, Handle::RH_PLATFORM] {
        let cmd = GetCommandAuditDigest {
            privacy_handle: admin,
            sign_handle: Handle::RH_NULL,
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
        };
        assert_eq!(
            execute_with_password_sessions_status(&mut sim, &cmd, 2, &[]).err(),
            Some(RC_VALUE_H1),
            "privacyAdminHandle {admin:?}"
        );
    }
}

/// GetTime with TPM_RH_NULL/OWNER/PLATFORM as privacyAdminHandle fails with VALUE+H1.
#[test]
fn get_time_rejects_null_owner_platform() {
    let mut sim = create_simulator!();
    let scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));
    let key_handle =
        create_test_key_with_options(&mut sim, &[], scheme, false, TpmiAlgHash::Sha256);

    let get_time_cmd = GetTime {
        privacy_admin_handle: Handle::RH_NULL,
        sign_handle: key_handle,
        qualifying_data: Tpm2bData::from_bytes(b"data").unwrap(),
        in_scheme: None,
    };

    // Per TPM 2.0 Spec Part 3 Section 18.7, privacyAdminHandle has type TPMI_RH_ENDORSEMENT
    // (non-nullable). Passing TPM_RH_NULL, TPM_RH_OWNER, or TPM_RH_PLATFORM must fail
    // during handle unmarshalling with TPM_RC_VALUE + TPM_RC_H + TPM_RC_1 (0x184).
    for bad_privacy_handle in [Handle::RH_NULL, Handle::RH_OWNER, Handle::RH_PLATFORM] {
        let get_time_cmd = GetTime {
            privacy_admin_handle: bad_privacy_handle,
            ..get_time_cmd
        };

        let resp = execute_with_password_sessions_status(&mut sim, &get_time_cmd, 1, &[]);
        assert_eq!(
            resp,
            Err(0x184),
            "GetTime must reject non-endorsement privacy_admin_handle {bad_privacy_handle:?} with 0x184"
        );
    }
}

/// GetTime with TPM_RH_OWNER as privacyAdminHandle fails with VALUE+H1.
///
/// `privacyAdminHandle` is a `TPMI_RH_ENDORSEMENT`: `TPM_RH_OWNER` is rejected with
/// `TPM_RC_VALUE + RC_H1`. (The engine's handle validation already enforced this before the
/// handler fix; this test guards the end-to-end behavior.)
#[test]
fn get_time_rejects_owner() {
    let mut sim = create_simulator!();
    assert_eq!(
        get_time(&mut sim, Handle::RH_OWNER, Handle::RH_NULL, None, 2).err(),
        Some(RC_VALUE_H1)
    );
}
