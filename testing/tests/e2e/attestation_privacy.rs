//! Privacy obfuscation of the TPMS_ATTEST header (clock/firmware info) depending on the signer's
//! hierarchy and on a NULL signHandle.

use crate::_common::{
    certify, create_primary_in, get_time, reported_firmware_version, rsa_sign_template,
    time_attest_info,
};
use testing::tpm::Tpm;
use tpm2::{Handle, TpmiAlgHash, TpmtRsaScheme, TpmtSigScheme};

/// Certify by an owner signer obfuscates the header, endorsement signer does not; firmware version layout.
///
/// Certify by an owner-hierarchy signer obfuscates the header, an endorsement signer does not,
/// and the plain firmware version is `TPM_PT_FIRMWARE_VERSION_1 << 32 | _2`.
#[test]
fn certify_obfuscation_by_hierarchy() {
    let mut sim = Tpm::new();
    let plain_firmware = reported_firmware_version(&mut sim);
    let template = rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)));
    let eh_key = create_primary_in(&mut sim, Handle::RH_ENDORSEMENT, template);
    let sh_key = create_primary_in(&mut sim, Handle::RH_OWNER, template);

    let eh = certify(&mut sim, eh_key, eh_key, None)
        .expect("Certify (EH)")
        .certify_info
        .0;
    assert_eq!(eh.firmware_version, plain_firmware);
    let sh = certify(&mut sim, sh_key, sh_key, None)
        .expect("Certify (SH)")
        .certify_info
        .0;
    assert_ne!(sh.firmware_version, plain_firmware);
}

/// signHandle NULL ignores a non-NULL inScheme and returns a NULL signature.
///
/// `signHandle == TPM_RH_NULL` ignores a non-NULL `inScheme` (the NULL scheme is used).
#[test]
fn null_signer_ignores_in_scheme() {
    let mut sim = Tpm::new();
    let rsp = get_time(
        &mut sim,
        Handle::RH_ENDORSEMENT,
        Handle::RH_NULL,
        Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        2,
    )
    .expect("GetTime with TPM_RH_NULL and a non-NULL scheme failed");
    assert!(rsp.signature.is_none());
}

/// With signHandle NULL the attest header counters/firmware are obfuscated deterministically; time info stays plain.
///
/// For `signHandle == TPM_RH_NULL` the header's resetCount/restartCount/firmwareVersion are
/// obfuscated, while the attested time info keeps the plain values.
#[test]
fn null_signer_obfuscates_header() {
    let mut sim = Tpm::new();
    let plain_firmware = reported_firmware_version(&mut sim);
    let rsp = get_time(&mut sim, Handle::RH_ENDORSEMENT, Handle::RH_NULL, None, 2)
        .expect("GetTime failed");
    let attest = rsp.time_info.0;
    let info = time_attest_info(&attest);
    assert_eq!(info.firmware_version, plain_firmware);
    assert_ne!(attest.firmware_version, plain_firmware);
    assert_ne!(
        (
            attest.clock_info.reset_count,
            attest.clock_info.restart_count
        ),
        (
            info.time.clock_info.reset_count,
            info.time.clock_info.restart_count
        )
    );
    // The obfuscation is a deterministic function of shProof and the qualified signer.
    let again = get_time(&mut sim, Handle::RH_ENDORSEMENT, Handle::RH_NULL, None, 2)
        .expect("GetTime failed")
        .time_info
        .0;
    assert_eq!(again.firmware_version, attest.firmware_version);
    assert_eq!(again.clock_info.reset_count, attest.clock_info.reset_count);
}

/// Owner-hierarchy signers get obfuscated headers, endorsement signers plain firmware version.
///
/// Owner-hierarchy signers are obfuscated, Endorsement-hierarchy signers are not; the plain
/// firmware version matches `TPM_PT_FIRMWARE_VERSION_1/2`.
#[test]
fn owner_signer_obfuscated_endorsement_plain() {
    let mut sim = Tpm::new();
    let plain_firmware = reported_firmware_version(&mut sim);
    let template = rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)));
    let eh_key = create_primary_in(&mut sim, Handle::RH_ENDORSEMENT, template);
    let sh_key = create_primary_in(&mut sim, Handle::RH_OWNER, template);

    let eh = get_time(&mut sim, Handle::RH_ENDORSEMENT, eh_key, None, 2)
        .expect("GetTime (EH key) failed")
        .time_info
        .0;
    let eh_info = time_attest_info(&eh);
    assert_eq!(eh.firmware_version, plain_firmware);
    assert_eq!(
        eh.clock_info.reset_count,
        eh_info.time.clock_info.reset_count
    );
    assert_eq!(
        eh.clock_info.restart_count,
        eh_info.time.clock_info.restart_count
    );

    let sh = get_time(&mut sim, Handle::RH_ENDORSEMENT, sh_key, None, 2)
        .expect("GetTime (SH key) failed")
        .time_info
        .0;
    let sh_info = time_attest_info(&sh);
    assert_eq!(sh_info.firmware_version, plain_firmware);
    assert_ne!(sh.firmware_version, plain_firmware);
}
