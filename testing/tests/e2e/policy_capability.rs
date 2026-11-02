//! TPM2_PolicyCapability: the policy digest update (also in trial sessions, which skip the
//! assertion), the property structure of every supported capability as operand A, missing
//! properties (only `TPM_EO_NEQ` holds), and the offset, operandB and capability errors.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{ClockRateAdjust, ContextSave, PolicyCapability, SetPrimaryPolicy};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, Tpm2bOperand, TpmCap, TpmCc, TpmClockAdjust, TpmEo,
    TpmSe, TpmaSession, TpmiAlgHash, TpmsAuthCommand,
};

/// `TPM_PT_FAMILY_INDICATOR`, whose value is "2.0\0".
const PT_FAMILY_INDICATOR: u32 = 0x100;
const FAMILY_2_0: [u8; 4] = *b"2.0\0";

/// `TPM2_PolicyCapability(session, operandB, offset, operation, capability, property)`.
fn policy_capability(
    tpm: &mut Tpm,
    session: Handle,
    operand_b: &[u8],
    offset: u16,
    operation: TpmEo,
    capability: TpmCap,
    property: u32,
) -> Result<(), u32> {
    execute_with_password_sessions(
        tpm,
        &PolicyCapability {
            policy_session: session,
            operand_b: Tpm2bOperand::from_bytes(leak_bytes(operand_b)).unwrap(),
            offset,
            operation,
            capability,
            property,
        },
        0,
        &[],
    )
    .map(|_| ())
}

/// A fresh SHA-256 policy session.
fn policy_session(tpm: &mut Tpm) -> Handle {
    start_session_with_nonce(tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32])
}

/// Asserts that `property` of `capability` exists: `operand` (operand A at `offset`) is EQ, and
/// NEQ fails.
fn assert_exists(tpm: &mut Tpm, capability: TpmCap, property: u32, offset: u16, operand: &[u8]) {
    let session = policy_session(tpm);
    assert_eq!(
        policy_capability(
            tpm,
            session,
            operand,
            offset,
            TpmEo::Eq,
            capability,
            property
        ),
        Ok(()),
        "{capability:?} {property:#x} EQ"
    );
    assert_eq!(
        policy_capability(
            tpm,
            session,
            operand,
            offset,
            TpmEo::Neq,
            capability,
            property
        ),
        Err(TpmRc::POLICY.get()),
        "{capability:?} {property:#x} NEQ"
    );
    flush_context(tpm, session).unwrap();
}

/// Asserts that `property` of `capability` does not exist: every operation but NEQ fails with
/// `TPM_RC_POLICY` (whatever the offset), NEQ holds.
fn assert_missing(tpm: &mut Tpm, capability: TpmCap, property: u32) {
    let session = policy_session(tpm);
    for operation in [TpmEo::Eq, TpmEo::UnsignedGE, TpmEo::BitClear] {
        assert_eq!(
            policy_capability(tpm, session, &[], 0, operation, capability, property),
            Err(TpmRc::POLICY.get()),
            "{capability:?} {property:#x} {operation:?}"
        );
    }
    assert_eq!(
        policy_capability(tpm, session, &[0; 4], 100, TpmEo::Neq, capability, property),
        Ok(()),
        "{capability:?} {property:#x} NEQ"
    );
    flush_context(tpm, session).unwrap();
}

/// The policy digest is extended with H(digest || TPM_CC_PolicyCapability || args), args =
/// H(operandB.buffer || offset || operation || capability || property), also in a trial session.
#[test]
fn extends_policy_digest_with_argument_hash() {
    let mut tpm = Tpm::new();
    let expected = {
        let args = sha256(&[
            &FAMILY_2_0,
            &4u16.to_be_bytes(),
            &(TpmEo::Eq as u16).to_be_bytes(),
            &(TpmCap::TPMProperties as u32).to_be_bytes(),
            &PT_FAMILY_INDICATOR.to_be_bytes(),
        ]);
        sha256(&[
            &[0u8; 32],
            &TpmCc::PolicyCapability.code().to_be_bytes(),
            &args,
        ])
    };
    for session_type in [TpmSe::Trial, TpmSe::Policy] {
        let session =
            start_session_with_nonce(&mut tpm, session_type, TpmiAlgHash::Sha256, &[1; 32]);
        policy_capability(
            &mut tpm,
            session,
            &FAMILY_2_0,
            4,
            TpmEo::Eq,
            TpmCap::TPMProperties,
            PT_FAMILY_INDICATOR,
        )
        .unwrap();
        assert_eq!(policy_get_digest_checked(&mut tpm, session), expected);
    }
}

/// A trial session skips the assertion: a failing comparison or an unsupported capability
/// still extends the digest.
#[test]
fn trial_session_skips_assertion() {
    let mut tpm = Tpm::new();
    let session = start_session_with_nonce(&mut tpm, TpmSe::Trial, TpmiAlgHash::Sha256, &[1; 32]);
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            b"1.2\0",
            4,
            TpmEo::Eq,
            TpmCap::TPMProperties,
            0x100
        ),
        Ok(())
    );
    assert_eq!(
        policy_capability(&mut tpm, session, &[], 0, TpmEo::Eq, TpmCap::PCRs, 0),
        Ok(())
    );
}

/// TPM properties (`TPMS_TAGGED_PROPERTY`): the comparisons on TPM_PT_FAMILY_INDICATOR, and
/// an undefined or below-PT_FIXED property is missing.
#[test]
fn tpm_property_is_tpms_tagged_property() {
    let mut tpm = Tpm::new();
    assert_exists(
        &mut tpm,
        TpmCap::TPMProperties,
        PT_FAMILY_INDICATOR,
        4,
        &FAMILY_2_0,
    );
    assert_exists(
        &mut tpm,
        TpmCap::TPMProperties,
        PT_FAMILY_INDICATOR,
        0,
        &[0, 0, 1, 0, b'2'],
    );
    let session = policy_session(&mut tpm);
    for (operation, operand, ok) in [
        (TpmEo::UnsignedGT, b"1.9\0", true),
        (TpmEo::UnsignedLT, b"1.9\0", false),
        (TpmEo::SignedLE, b"2.0\0", true),
        (TpmEo::BitSet, b"\x30\x2E\x30\0", true),
        (TpmEo::BitClear, b"\x02\0\0\0", false),
    ] {
        let rc = policy_capability(
            &mut tpm,
            session,
            operand,
            4,
            operation,
            TpmCap::TPMProperties,
            PT_FAMILY_INDICATOR,
        );
        assert_eq!(rc.is_ok(), ok, "{operation:?}");
        if !ok {
            assert_eq!(rc, Err(TpmRc::POLICY.get()));
        }
    }
    assert_missing(&mut tpm, TpmCap::TPMProperties, 0x1FF);
    assert_missing(&mut tpm, TpmCap::TPMProperties, 0);
}

/// An offset beyond the property is `TPM_RC_VALUE` (offset), an operandB longer than the rest
/// of it `TPM_RC_SIZE` (operandB); an empty operandB at the end of the property compares EQ.
#[test]
fn offset_and_operand_size_errors() {
    let mut tpm = Tpm::new();
    let session = policy_session(&mut tpm);
    let cap = TpmCap::TPMProperties;
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            &[],
            9,
            TpmEo::Eq,
            cap,
            PT_FAMILY_INDICATOR
        ),
        Err(TpmRc::VALUE.with(Position::parameter(2)).get())
    );
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            &[0; 2],
            7,
            TpmEo::Eq,
            cap,
            PT_FAMILY_INDICATOR
        ),
        Err(TpmRc::SIZE.with(Position::parameter(1)).get())
    );
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            &[0; 9],
            0,
            TpmEo::Eq,
            cap,
            PT_FAMILY_INDICATOR
        ),
        Err(TpmRc::SIZE.with(Position::parameter(1)).get())
    );
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            &[],
            8,
            TpmEo::Eq,
            cap,
            PT_FAMILY_INDICATOR
        ),
        Ok(())
    );
}

/// Capabilities without a property structure (TPM_CAP_PCRS, TPM_CAP_VENDOR_PROPERTY, and
/// without secure channel support the SPDM capabilities) and capabilities this TPM does not
/// report are `TPM_RC_VALUE` (capability).
#[test]
fn unsupported_capabilities_are_rejected() {
    let mut tpm = Tpm::new();
    let session = policy_session(&mut tpm);
    let mut unsupported = vec![TpmCap::PCRs, TpmCap::VendorProperty];
    if cfg!(not(feature = "sec-channel")) {
        unsupported.extend([TpmCap::PubKeys, TpmCap::SpdmSessionInfo]);
    }
    for capability in unsupported {
        assert_eq!(
            policy_capability(&mut tpm, session, &[], 0, TpmEo::Neq, capability, 0),
            Err(TpmRc::VALUE.with(Position::parameter(4)).get()),
            "{capability:?}"
        );
    }
    // An undefined TPM_CAP value fails as it is unmarshaled.
    let mut params = Vec::new();
    push_2b(&mut params, &[]);
    params.extend_from_slice(&0u16.to_be_bytes());
    params.extend_from_slice(&(TpmEo::Neq as u16).to_be_bytes());
    params.extend_from_slice(&0x101u32.to_be_bytes());
    params.extend_from_slice(&0u32.to_be_bytes());
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        TpmCc::PolicyCapability.code(),
        &[session.0],
        None,
        &params,
    );
    assert_eq!(
        send_rc(&mut tpm, &cmd),
        TpmRc::VALUE.with(Position::parameter(4)).get()
    );
}

/// Algorithms (`TPMS_ALG_PROPERTY`): SHA-256 has the `hash` attribute; only the low 16 bits of
/// the property select the algorithm; an unimplemented algorithm is missing.
#[test]
fn algorithm_property_is_tpms_alg_property() {
    let mut tpm = Tpm::new();
    assert_exists(&mut tpm, TpmCap::Algs, 0x000B, 0, &[0x00, 0x0B]);
    assert_exists(&mut tpm, TpmCap::Algs, 0x0001_000B, 0, &[0x00, 0x0B]);
    let session = policy_session(&mut tpm);
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            &[0, 0, 0, 4],
            2,
            TpmEo::BitSet,
            TpmCap::Algs,
            0x000B
        ),
        Ok(())
    );
    assert_missing(&mut tpm, TpmCap::Algs, 0x0002);
}

/// Commands (`TPMA_CC`): an implemented library or vendor command exists, an unimplemented one
/// is missing.
#[test]
fn command_property_is_tpma_cc() {
    let mut tpm = Tpm::new();
    assert_exists(
        &mut tpm,
        TpmCap::Commands,
        TpmCc::GetRandom.code(),
        2,
        &[0x01, 0x7B],
    );
    assert_exists(
        &mut tpm,
        TpmCap::Commands,
        TpmCc::VendorTcgTest.code(),
        0,
        &[0x20],
    );
    assert_missing(&mut tpm, TpmCap::Commands, TpmCc::FieldUpgradeStart.code());
    assert_missing(&mut tpm, TpmCap::Commands, 0x0100_017B);
}

/// Audited commands (`TPM_CC`): TPM2_SetCommandCodeAuditStatus is audited after manufacture,
/// TPM2_GetRandom is not.
#[test]
fn audited_command_property_is_tpm_cc() {
    let mut tpm = Tpm::new();
    let cc = TpmCc::SetCommandCodeAuditStatus.code();
    assert_exists(&mut tpm, TpmCap::AuditCommands, cc, 0, &cc.to_be_bytes());
    assert_missing(&mut tpm, TpmCap::AuditCommands, TpmCc::GetRandom.code());
}

/// Commands that require Physical Presence (`TPM_CC`): TPM2_PP_Commands, not TPM2_Clear.
#[cfg(feature = "cc-pp-commands")]
#[test]
fn pp_command_property_is_tpm_cc() {
    let mut tpm = Tpm::new();
    let cc = TpmCc::PPCommands.code();
    assert_exists(&mut tpm, TpmCap::PPCommands, cc, 0, &cc.to_be_bytes());
    assert_missing(&mut tpm, TpmCap::PPCommands, TpmCc::Clear.code());
}

/// ECC curves (`TPM_ECC_CURVE`): NIST P-256 exists, an undefined curve is missing.
#[test]
fn ecc_curve_property_is_tpm_ecc_curve() {
    let mut tpm = Tpm::new();
    assert_exists(&mut tpm, TpmCap::ECCCurves, 0x0003, 0, &[0x00, 0x03]);
    assert_missing(&mut tpm, TpmCap::ECCCurves, 0x0099);
}

/// PCR properties (`TPMS_TAGGED_PCR_SELECT`): TPM_PT_PCR_SAVE exists, an undefined one is
/// missing.
#[test]
fn pcr_property_is_tpms_tagged_pcr_select() {
    let mut tpm = Tpm::new();
    assert_exists(&mut tpm, TpmCap::PCRProperties, 0, 0, &[0, 0, 0, 0, 3]);
    assert_missing(&mut tpm, TpmCap::PCRProperties, 0x0B);
    assert_missing(&mut tpm, TpmCap::PCRProperties, 0x100);
}

/// Authorization policies (`TPMS_TAGGED_POLICY`): the owner's exists (even when empty); a
/// property that is not a permanent handle is `TPM_RC_VALUE` (property).
#[test]
fn auth_policy_property_is_tpms_tagged_policy() {
    let mut tpm = Tpm::new();
    assert_exists(
        &mut tpm,
        TpmCap::AuthPolicies,
        0x4000_0001,
        0,
        &0x4000_0001u32.to_be_bytes(),
    );
    assert_missing(&mut tpm, TpmCap::AuthPolicies, 0x4000_0002);
    let session = policy_session(&mut tpm);
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            &[],
            0,
            TpmEo::Neq,
            TpmCap::AuthPolicies,
            0x8000_0000
        ),
        Err(TpmRc::VALUE.with(Position::parameter(5)).get())
    );
}

/// ACTs (`TPMS_ACT_DATA`): ACT_0 exists, an unimplemented ACT is missing, and a property outside
/// the ACT handles is `TPM_RC_VALUE` (property).
#[test]
fn act_property_is_tpms_act_data() {
    let mut tpm = Tpm::new();
    let act_0 = Handle::RH_ACT_0.0;
    assert_exists(&mut tpm, TpmCap::ACT, act_0, 0, &act_0.to_be_bytes());
    assert_missing(&mut tpm, TpmCap::ACT, act_0 + 1);
    let session = policy_session(&mut tpm);
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            &[],
            0,
            TpmEo::Neq,
            TpmCap::ACT,
            act_0 - 1
        ),
        Err(TpmRc::VALUE.with(Position::parameter(5)).get())
    );
}

/// Handles (`TPM_HANDLE`) of PCRs and permanent entities; a handle type that GetCapability does
/// not list is `TPM_RC_HANDLE` (property).
#[test]
fn pcr_and_permanent_handle_properties_are_handles() {
    let mut tpm = Tpm::new();
    assert_exists(&mut tpm, TpmCap::Handles, 23, 0, &23u32.to_be_bytes());
    assert_missing(&mut tpm, TpmCap::Handles, 24);
    assert_exists(
        &mut tpm,
        TpmCap::Handles,
        0x4000_0001,
        0,
        &0x4000_0001u32.to_be_bytes(),
    );
    assert_missing(&mut tpm, TpmCap::Handles, 0x4000_0002);
    let session = policy_session(&mut tpm);
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            &[],
            0,
            TpmEo::Neq,
            TpmCap::Handles,
            0x1100_0000
        ),
        Err(TpmRc::HANDLE.with(Position::parameter(5)).get())
    );
}

/// A transient handle exists only while an object is loaded under exactly that handle.
#[test]
fn transient_handle_exists_only_while_loaded() {
    let mut tpm = Tpm::new();
    let first = create_storage_parent(&mut tpm, Handle::RH_OWNER);
    let second = create_storage_parent(&mut tpm, Handle::RH_OWNER);
    assert_exists(
        &mut tpm,
        TpmCap::Handles,
        first.0,
        0,
        &first.0.to_be_bytes(),
    );
    flush_context(&mut tpm, first).unwrap();
    assert_missing(&mut tpm, TpmCap::Handles, first.0);
    assert_exists(
        &mut tpm,
        TpmCap::Handles,
        second.0,
        0,
        &second.0.to_be_bytes(),
    );
}

/// Session handles name a session slot: `TPM_HT_LOADED_SESSION` exists while a session of the
/// slot is loaded, `TPM_HT_SAVED_SESSION` while its context is saved.
#[test]
fn session_handles_name_loaded_or_saved_slots() {
    let mut tpm = Tpm::new();
    let policy = policy_session(&mut tpm);
    let hmac = start_session_with_nonce(&mut tpm, TpmSe::HMAC, TpmiAlgHash::Sha256, &[2; 32]);
    let slot = |h: Handle| h.0 & 0x00FF_FFFF;

    // The loaded policy session, asked as a loaded session.
    let loaded_policy = 0x0200_0000 | slot(policy);
    assert_exists(
        &mut tpm,
        TpmCap::Handles,
        loaded_policy,
        0,
        &loaded_policy.to_be_bytes(),
    );
    assert_missing(&mut tpm, TpmCap::Handles, 0x0300_0000 | slot(policy));

    tpm.execute(ContextSave { save_handle: hmac }).unwrap();
    let saved = 0x0300_0000 | slot(hmac);
    assert_exists(&mut tpm, TpmCap::Handles, saved, 0, &saved.to_be_bytes());
    assert_missing(&mut tpm, TpmCap::Handles, 0x0200_0000 | slot(hmac));
}

/// A policy session with a satisfied TPM2_PolicyCapability authorizes like its trial digest.
#[test]
fn authorizes_with_matching_policy() {
    let mut tpm = Tpm::new();
    let trial = start_session_with_nonce(&mut tpm, TpmSe::Trial, TpmiAlgHash::Sha256, &[1; 32]);
    policy_capability(
        &mut tpm,
        trial,
        &FAMILY_2_0,
        4,
        TpmEo::Eq,
        TpmCap::TPMProperties,
        0x100,
    )
    .unwrap();
    let digest = policy_get_digest_checked(&mut tpm, trial);
    execute_with_password_sessions(
        &mut tpm,
        &SetPrimaryPolicy {
            auth_handle: Handle::RH_OWNER,
            auth_policy: Tpm2bDigest::from_bytes(leak_bytes(&digest)).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        1,
        &[],
    )
    .unwrap();

    let session = policy_session(&mut tpm);
    policy_capability(
        &mut tpm,
        session,
        &FAMILY_2_0,
        4,
        TpmEo::Eq,
        TpmCap::TPMProperties,
        0x100,
    )
    .unwrap();
    let auth = TpmsAuthCommand {
        session_handle: session,
        nonce: Tpm2bNonce::from_bytes(&[0x44; 16]).unwrap(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    let cmd = ClockRateAdjust {
        auth: Handle::RH_OWNER,
        rate_adjust: TpmClockAdjust::NoChange,
    };
    assert_eq!(exec_command(&mut tpm, &cmd, &[auth]).map(|_| ()), Ok(()));
}

/// TPM SPDM public keys (`TPM2B_PUBLIC`, with secure channel support): the platform's
/// TPM_PUB_KEY_TPM_SPDM_00 (an ECC key with nameAlg SHA-384) exists, another key of the
/// TPM_PUB_KEY range is missing, and a property beyond TPM_PUB_KEY_TPM_SPDM_FF is
/// `TPM_RC_VALUE` (property).
#[cfg(feature = "sec-channel")]
#[test]
fn pub_key_property_is_tpm2b_public() {
    let mut tpm = Tpm::new();
    assert_exists(&mut tpm, TpmCap::PubKeys, 0, 2, &[0x00, 0x23, 0x00, 0x0C]);
    assert_missing(&mut tpm, TpmCap::PubKeys, 1);
    assert_missing(&mut tpm, TpmCap::PubKeys, 0xFF);
    let session = policy_session(&mut tpm);
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            &[],
            0,
            TpmEo::Neq,
            TpmCap::PubKeys,
            0x100
        ),
        Err(TpmRc::VALUE.with(Position::parameter(5)).get())
    );
}

/// SPDM session information (`TPMS_SPDM_SESSION_INFO`, with secure channel support): the
/// session protecting every command of the simulator's platform has the requester key Name
/// `TPM_ALG_SHA384 || 0x11 * 48`; the reserved property must be 0 (`TPM_RC_VALUE`, property).
#[cfg(feature = "sec-channel")]
#[test]
fn spdm_session_info_property_is_tpms_spdm_session_info() {
    let mut tpm = Tpm::new();
    // reqKeyName: size 50, TPM_ALG_SHA384, then the digest (compared separately, since an
    // operandB is at most the largest digest of the profile).
    assert_exists(
        &mut tpm,
        TpmCap::SpdmSessionInfo,
        0,
        0,
        &[0x00, 0x32, 0x00, 0x0C],
    );
    assert_exists(&mut tpm, TpmCap::SpdmSessionInfo, 0, 4, &[0x11; 48]);
    let session = policy_session(&mut tpm);
    assert_eq!(
        policy_capability(
            &mut tpm,
            session,
            &[],
            0,
            TpmEo::Neq,
            TpmCap::SpdmSessionInfo,
            1
        ),
        Err(TpmRc::VALUE.with(Position::parameter(5)).get())
    );
}
