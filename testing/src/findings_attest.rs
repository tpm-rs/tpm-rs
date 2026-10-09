//! End-to-end regression tests for the `attest` findings in command-handlers.toml.
//!
//! Owned by the `fix-attest` worker; add submodules under `findings_attest/` if this grows.
//!
//! Every test is named after the finding it covers and drives the simulator purely through its
//! command interface. Expected response codes follow the C reference implementation
//! (`Attest_spt.c`, `CryptSelectSignScheme()` and the individual attestation commands).

#![allow(unused_imports)]

use crate::test_utils::*;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tpm2::commands::{
    Certify, CertifyCreation, CertifyCreationHandles, CertifyHandles, CreatePrimary,
    CreatePrimaryHandles, EvictControl, EvictControlHandles, GetCommandAuditDigest,
    GetCommandAuditDigestHandles, GetSessionAuditDigest, GetSessionAuditDigestHandles, GetTime,
    GetTimeHandles, LoadExternal, Quote, QuoteHandles, Shutdown,
};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublicKeyRsa,
    Tpm2bSensitiveData, TpmEccCurve, TpmPt, TpmSe, TpmSu, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits,
    TpmlPcrSelection, TpmsAttest, TpmsEccParms, TpmsEccPoint, TpmsRsaParms, TpmsSchemeEcdaa,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtHa, TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme,
    TpmtSigScheme, TpmtSignature, TpmtTkCreation, TpmuAttest,
};
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

/// `TPM_RC_VALUE + RC_H1`.
const RC_VALUE_H1: u32 = 0x184;
/// `TPM_RC_KEY` without a position.
const RC_KEY: u32 = 0x09C;
/// `TPM_RC_KEY + RC_H1`.
const RC_KEY_H1: u32 = 0x19C;
/// `TPM_RC_KEY + RC_H2`.
const RC_KEY_H2: u32 = 0x29C;
/// `TPM_RC_SCHEME` without a position.
const RC_SCHEME: u32 = 0x092;
/// `TPM_RC_SCHEME + RC_P2`.
const RC_SCHEME_P2: u32 = 0x2D2;
/// `TPM_RC_SCHEME + RC_P3`.
const RC_SCHEME_P3: u32 = 0x3D2;
/// `TPM_RC_TICKET + RC_P4`.
const RC_TICKET_P4: u32 = 0x4E0;
/// `TPM_RC_TYPE + RC_H3`.
const RC_TYPE_H3: u32 = 0x38A;
/// `TPM_RC_NV_UNAVAILABLE` (a warning: `RC_WARN + 0x023`).
const RC_NV_UNAVAILABLE: u32 = 0x923;

/// The plain-text firmware version reported by `TPM_PT_FIRMWARE_VERSION_1/2`.
fn reported_firmware_version(sim: &mut Simulator<'_>) -> u64 {
    let v1 = get_tpm_property(sim, TpmPt::FIRMWARE_VERSION_1) as u64;
    let v2 = get_tpm_property(sim, TpmPt::FIRMWARE_VERSION_2) as u64;
    (v1 << 32) | v2
}

/// Creates a primary object from `public` (with optional sensitive `data`) in `hierarchy` and
/// returns the full `TPM2_CreatePrimary` response together with the new handle.
fn create_primary_full(
    sim: &mut Simulator<'_>,
    hierarchy: Handle,
    public: TpmtPublic<'static>,
    data: &'static [u8],
) -> (tpm2::commands::responses::CreatePrimary<'static>, Handle) {
    let cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        }),
        in_public: tpm2::Tpm2b(public),
        ..Default::default()
    };
    let handles = CreatePrimaryHandles {
        primary_handle: hierarchy,
    };
    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &cmd, handles, 1, &[]).expect("CreatePrimary failed");
    (rsp, rsp_handles.object_handle)
}

/// Creates a primary object and returns only its handle.
fn create_primary(
    sim: &mut Simulator<'_>,
    hierarchy: Handle,
    public: TpmtPublic<'static>,
) -> Handle {
    create_primary_full(sim, hierarchy, public, &[]).1
}

/// Template for an RSA-2048 signing key with the given default scheme.
fn rsa_sign_template(scheme: Option<TpmtRsaScheme>) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// Template for an RSA-2048 decrypt-only key (`sign` clear), i.e. not a signing object.
fn rsa_decrypt_template() -> TpmtPublic<'static> {
    let mut public = rsa_sign_template(None);
    public.object_attributes = TpmaObject::DECRYPT
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::FIXED_PARENT
        | TpmaObject::FIXED_TPM;
    public
}

/// Template for a NIST P-256 signing key with the given default scheme.
fn ecc_sign_template(scheme: Option<TpmtEccScheme>) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    }
}

/// Template for a keyed-hash (HMAC-SHA256) signing key whose key bits are supplied by the
/// caller in the sensitive data.
fn hmac_sign_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::default(),
        ),
    }
}

/// Runs `TPM2_GetTime` with password sessions; returns the decoded response or the error code.
fn get_time(
    sim: &mut Simulator<'_>,
    privacy_admin_handle: Handle,
    sign_handle: Handle,
    in_scheme: Option<TpmtSigScheme>,
    num_sessions: usize,
) -> Result<tpm2::commands::responses::GetTime<'static>, u32> {
    let cmd = GetTime {
        qualifying_data: Tpm2bData::from_bytes(b"attest-findings").unwrap(),
        in_scheme,
    };
    let handles = GetTimeHandles {
        privacy_admin_handle,
        sign_handle,
    };
    execute_with_password_sessions(sim, &cmd, handles, num_sessions, &[]).map(|(rsp, _)| rsp)
}

/// Runs `TPM2_Certify` with password sessions.
fn certify(
    sim: &mut Simulator<'_>,
    object_handle: Handle,
    sign_handle: Handle,
    in_scheme: Option<TpmtSigScheme>,
) -> Result<tpm2::commands::responses::Certify<'static>, u32> {
    let cmd = Certify {
        qualifying_data: Tpm2bData::from_bytes(b"nonce").unwrap(),
        in_scheme,
    };
    let handles = CertifyHandles {
        object_handle,
        sign_handle,
    };
    // Every handle with an authorization role needs a session, even TPM_RH_NULL (C
    // ParseSessionBuffer); TPM_RH_NULL has an empty authValue.
    let sessions = 2;
    execute_with_password_sessions(sim, &cmd, handles, sessions, &[]).map(|(rsp, _)| rsp)
}

/// Runs `TPM2_Quote` (empty PCR selection) with password sessions.
fn quote(
    sim: &mut Simulator<'_>,
    sign_handle: Handle,
    in_scheme: Option<TpmtSigScheme>,
) -> Result<tpm2::commands::responses::Quote<'static>, u32> {
    let cmd = Quote {
        qualifying_data: Tpm2bData::from_bytes(b"nonce").unwrap(),
        in_scheme,
        pcr_select: TpmlPcrSelection::default(),
    };
    let handles = QuoteHandles { sign_handle };
    // signHandle has the USER role, so a session is needed even for TPM_RH_NULL.
    let sessions = 1;
    execute_with_password_sessions(sim, &cmd, handles, sessions, &[]).map(|(rsp, _)| rsp)
}

/// Runs `TPM2_CertifyCreation` with password sessions.
fn certify_creation(
    sim: &mut Simulator<'_>,
    sign_handle: Handle,
    object_handle: Handle,
    creation_hash: Tpm2bDigest<'static>,
    creation_ticket: TpmtTkCreation<'static>,
    in_scheme: Option<TpmtSigScheme>,
) -> Result<tpm2::commands::responses::CertifyCreation<'static>, u32> {
    let cmd = CertifyCreation {
        qualifying_data: Tpm2bData::default(),
        creation_hash,
        in_scheme,
        creation_ticket,
    };
    let handles = CertifyCreationHandles {
        sign_handle,
        object_handle,
    };
    // signHandle has the USER role, so a session is needed even for TPM_RH_NULL.
    let sessions = 1;
    execute_with_password_sessions(sim, &cmd, handles, sessions, &[]).map(|(rsp, _)| rsp)
}

/// Returns the attested `TPMS_TIME_ATTEST_INFO` of a `TPM2_GetTime` response.
fn time_attest_info(attest: &TpmsAttest<'_>) -> tpm2::TpmsTimeAttestInfo {
    match attest.attested {
        TpmuAttest::Time(info) => info,
        _ => panic!("GetTime did not return TPM_ST_ATTEST_TIME"),
    }
}

// ---------------------------------------------------------------------------------------------
// tpm2-gettime-tpm2-getsessionauditdigest-and-tpm2-getcommandauditdigest
// ---------------------------------------------------------------------------------------------

/// `privacyAdminHandle` is a `TPMI_RH_ENDORSEMENT`: `TPM_RH_OWNER` is rejected with
/// `TPM_RC_VALUE + RC_H1`. (The engine's handle validation already enforced this before the
/// handler fix; this test guards the end-to-end behavior.)
#[test]
fn tpm2_gettime_tpm2_getsessionauditdigest_and_tpm2_getcommandauditdigest_get_time_owner() {
    let mut sim = create_simulator!();
    assert_eq!(
        get_time(&mut sim, Handle::RH_OWNER, Handle::RH_NULL, None, 2).err(),
        Some(RC_VALUE_H1)
    );
}

/// `TPM2_GetCommandAuditDigest` rejects `TPM_RH_OWNER`/`TPM_RH_PLATFORM` as the privacy
/// administrator (the handler used to accept them; the engine already rejected them earlier).
#[test]
fn tpm2_gettime_tpm2_getsessionauditdigest_and_tpm2_getcommandauditdigest_gcad_owner() {
    let mut sim = create_simulator!();
    for admin in [Handle::RH_OWNER, Handle::RH_PLATFORM] {
        let cmd = GetCommandAuditDigest {
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
        };
        let handles = GetCommandAuditDigestHandles {
            privacy_admin_handle: admin,
            sign_handle: Handle::RH_NULL,
        };
        assert_eq!(
            execute_with_password_sessions_status(&mut sim, &cmd, handles, 2, &[]).err(),
            Some(RC_VALUE_H1),
            "privacyAdminHandle {admin:?}"
        );
    }
}

/// `TPM2_GetTime` must accept a persistent signing key (`TPMI_DH_OBJECT`); it used to look the
/// key up only among transient objects and fail with `TPM_RC_VALUE`.
#[test]
fn tpm2_gettime_tpm2_getsessionauditdigest_and_tpm2_getcommandauditdigest_persistent_key() {
    let mut sim = create_simulator!();
    let key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
    );
    let persistent = Handle(0x8100_0A77);
    let evict = EvictControl {
        persistent_handle: persistent,
    };
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: key,
    };
    execute_with_password_sessions_status(&mut sim, &evict, evict_handles, 1, &[])
        .expect("EvictControl failed");

    let rsp = get_time(&mut sim, Handle::RH_ENDORSEMENT, persistent, None, 2)
        .expect("GetTime with a persistent signing key failed");
    assert!(matches!(rsp.signature, Some(TpmtSignature::Rsassa(_))));
}

// ---------------------------------------------------------------------------------------------
// tpm2-quote-fails-to-enforce-sign-encrypt
// ---------------------------------------------------------------------------------------------

/// With `signHandle == TPM_RH_NULL` the selected scheme is NULL, so `TPM2_Quote` has no hash
/// algorithm for the PCR digest: `TPM_RC_SCHEME + RC_Quote_inScheme` (Quote.c), not success.
#[test]
fn tpm2_quote_fails_to_enforce_sign_encrypt_null_sign_handle() {
    let mut sim = create_simulator!();
    assert_eq!(
        quote(&mut sim, Handle::RH_NULL, None).err(),
        Some(RC_SCHEME_P2)
    );
    assert_eq!(
        quote(
            &mut sim,
            Handle::RH_NULL,
            Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256))
        )
        .err(),
        Some(RC_SCHEME_P2)
    );
}

/// A non-signing key fails with `TPM_RC_KEY + RC_Quote_signHandle` (H1), a scheme mismatch with
/// `TPM_RC_SCHEME + RC_Quote_inScheme` (P2).
#[test]
fn tpm2_quote_fails_to_enforce_sign_encrypt_error_positions() {
    let mut sim = create_simulator!();
    let decrypt_key = create_primary(&mut sim, Handle::RH_OWNER, rsa_decrypt_template());
    let err = quote(&mut sim, decrypt_key, None).err();
    assert_eq!(err, Some(RC_KEY_H1));
    assert_ne!(err, Some(RC_KEY));

    let sign_key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
    );
    let err = quote(
        &mut sim,
        sign_key,
        Some(TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256)),
    )
    .err();
    assert_eq!(err, Some(RC_SCHEME_P2));
    assert_ne!(err, Some(RC_SCHEME));
}

/// Keyed-hash (HMAC) signing keys can sign quotes.
#[test]
fn tpm2_quote_fails_to_enforce_sign_encrypt_hmac_key() {
    let mut sim = create_simulator!();
    let (_, key) = create_primary_full(
        &mut sim,
        Handle::RH_OWNER,
        hmac_sign_template(),
        b"quote-hmac-key-bits",
    );
    let rsp = quote(&mut sim, key, None).expect("Quote with an HMAC key failed");
    assert!(matches!(rsp.signature, Some(TpmtSignature::Hmac(_))));
}

// ---------------------------------------------------------------------------------------------
// tpm2-certify-and-tpm2-certifycreation-omit-required
// ---------------------------------------------------------------------------------------------

/// `TPM2_Certify` with a non-signing key: `TPM_RC_KEY + RC_Certify_signHandle` (H2).
#[test]
fn tpm2_certify_and_tpm2_certifycreation_omit_required_certify_key_position() {
    let mut sim = create_simulator!();
    let object = create_primary(&mut sim, Handle::RH_OWNER, rsa_sign_template(None));
    let decrypt_key = create_primary(&mut sim, Handle::RH_OWNER, rsa_decrypt_template());
    assert_eq!(
        certify(&mut sim, object, decrypt_key, None).err(),
        Some(RC_KEY_H2)
    );
}

/// `TPM2_CertifyCreation`: non-signing key -> `TPM_RC_KEY + H1`; a bad scheme is reported
/// (`TPM_RC_SCHEME + P3`) before a bad ticket; a bad ticket -> `TPM_RC_TICKET + P4`.
#[test]
fn tpm2_certify_and_tpm2_certifycreation_omit_required_certify_creation_order_and_positions() {
    let mut sim = create_simulator!();
    let (created, object) = create_primary_full(
        &mut sim,
        Handle::RH_OWNER,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
        &[],
    );
    let decrypt_key = create_primary(&mut sim, Handle::RH_OWNER, rsa_decrypt_template());
    let bad_ticket = TpmtTkCreation::new(
        Handle::RH_OWNER,
        Tpm2bDigest::from_bytes(leak_bytes(&[0x5A; 32])).unwrap(),
    );

    // Non-signing key, valid ticket.
    assert_eq!(
        certify_creation(
            &mut sim,
            decrypt_key,
            object,
            created.creation_hash,
            created.creation_ticket,
            None,
        )
        .err(),
        Some(RC_KEY_H1)
    );

    // Mismatching scheme and a bad ticket: the scheme is checked first.
    assert_eq!(
        certify_creation(
            &mut sim,
            object,
            object,
            created.creation_hash,
            bad_ticket,
            Some(TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256)),
        )
        .err(),
        Some(RC_SCHEME_P3)
    );

    // Valid scheme, bad ticket.
    assert_eq!(
        certify_creation(
            &mut sim,
            object,
            object,
            created.creation_hash,
            bad_ticket,
            None
        )
        .err(),
        Some(RC_TICKET_P4)
    );

    // Everything valid.
    certify_creation(
        &mut sim,
        object,
        object,
        created.creation_hash,
        created.creation_ticket,
        None,
    )
    .expect("CertifyCreation with a valid ticket failed");
}

/// The ticket is recomputed over `creationTicket.hierarchy`, which need not equal the certified
/// object's current hierarchy (here: the same public area reloaded into the NULL hierarchy).
#[test]
fn tpm2_certify_and_tpm2_certifycreation_omit_required_ticket_hierarchy_not_object_hierarchy() {
    let mut sim = create_simulator!();
    let mut public = rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)));
    public.object_attributes =
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH | TpmaObject::SENSITIVE_DATA_ORIGIN;
    let (created, _) = create_primary_full(&mut sim, Handle::RH_OWNER, public, &[]);

    let load = LoadExternal {
        in_private: None,
        in_public: created.out_public,
        hierarchy: Handle::RH_NULL,
    };
    let (_, loaded) = execute_with_password_sessions(&mut sim, &load, (), 0, &[])
        .expect("LoadExternal of the public area failed");

    certify_creation(
        &mut sim,
        Handle::RH_NULL,
        loaded.object_handle,
        created.creation_hash,
        created.creation_ticket,
        None,
    )
    .expect("CertifyCreation must accept an owner-hierarchy ticket for a NULL-hierarchy object");
}

// ---------------------------------------------------------------------------------------------
// attestation-missing-privacy-obfuscation-and-keyedhash-sm2-ecschnorr-support
// ---------------------------------------------------------------------------------------------

/// For `signHandle == TPM_RH_NULL` the header's resetCount/restartCount/firmwareVersion are
/// obfuscated, while the attested time info keeps the plain values.
#[test]
fn attestation_missing_privacy_obfuscation_and_keyedhash_sm2_ecschnorr_support_null_signer() {
    let mut sim = create_simulator!();
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

/// Owner-hierarchy signers are obfuscated, Endorsement-hierarchy signers are not; the plain
/// firmware version matches `TPM_PT_FIRMWARE_VERSION_1/2`.
#[test]
fn attestation_missing_privacy_obfuscation_and_keyedhash_sm2_ecschnorr_support_hierarchies() {
    let mut sim = create_simulator!();
    let plain_firmware = reported_firmware_version(&mut sim);
    let template = rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)));
    let eh_key = create_primary(&mut sim, Handle::RH_ENDORSEMENT, template);
    let sh_key = create_primary(&mut sim, Handle::RH_OWNER, template);

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

/// `signHandle == TPM_RH_NULL` ignores a non-NULL `inScheme` (the NULL scheme is used).
#[test]
fn attestation_missing_privacy_obfuscation_and_keyedhash_sm2_ecschnorr_support_null_with_scheme() {
    let mut sim = create_simulator!();
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

/// A key whose default scheme is the split-signing ECDAA scheme requires an explicit
/// `inScheme`: `TPM_RC_SCHEME + RC_Certify_inScheme`.
#[test]
fn attestation_missing_privacy_obfuscation_and_keyedhash_sm2_ecschnorr_support_split_default() {
    let mut sim = create_simulator!();
    let object = create_primary(&mut sim, Handle::RH_OWNER, rsa_sign_template(None));
    let ecdaa_key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecc_sign_template(Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count: 0,
        }))),
    );
    assert_eq!(
        certify(&mut sim, object, ecdaa_key, None).err(),
        Some(RC_SCHEME_P2)
    );
}

/// A signed attestation clears the orderly state (`NvClearOrderly`): after an orderly
/// `TPM2_Shutdown` with NV unavailable it fails with `TPM_RC_NV_UNAVAILABLE`, whereas an
/// unsigned (`TPM_RH_NULL`) attestation still succeeds.
#[test]
fn attestation_missing_privacy_obfuscation_and_keyedhash_sm2_ecschnorr_support_nv_clear_orderly() {
    let mut sim = create_simulator!();
    let key = create_primary(
        &mut sim,
        Handle::RH_ENDORSEMENT,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
    );
    execute_with_password_sessions_status(
        &mut sim,
        &Shutdown {
            shutdown_type: TpmSu::State,
        },
        (),
        0,
        &[],
    )
    .expect("Shutdown failed");
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();

    get_time(&mut sim, Handle::RH_ENDORSEMENT, Handle::RH_NULL, None, 2)
        .expect("unsigned GetTime must not touch the orderly state");
    assert_eq!(
        get_time(&mut sim, Handle::RH_ENDORSEMENT, key, None, 2).err(),
        Some(RC_NV_UNAVAILABLE)
    );
}

// ---------------------------------------------------------------------------------------------
// get-session-command-audit-digest-and-get-time-missing-issigningobject-and-validation-order
// ---------------------------------------------------------------------------------------------

/// GetSessionAuditDigest checks the signing key before the session's audit attribute.
#[test]
fn get_session_command_audit_digest_and_get_time_missing_issigningobject_and_validation_order() {
    let mut sim = create_simulator!();
    let decrypt_key = create_primary(&mut sim, Handle::RH_ENDORSEMENT, rsa_decrypt_template());
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession failed");

    let gsad = |sim: &mut Simulator<'_>, sign_handle: Handle| {
        let cmd = GetSessionAuditDigest {
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
        };
        let handles = GetSessionAuditDigestHandles {
            privacy_admin_handle: Handle::RH_ENDORSEMENT,
            sign_handle,
            session_handle: session.session_handle,
        };
        // Every handle with an authorization role needs a session, even TPM_RH_NULL (C
        // ParseSessionBuffer); TPM_RH_NULL has an empty authValue.
        let sessions = 2;
        execute_with_password_sessions_status(sim, &cmd, handles, sessions, &[]).err()
    };

    // Not an audit session, but the key error comes first.
    assert_eq!(gsad(&mut sim, decrypt_key), Some(RC_KEY_H2));
    // With an acceptable signer the audit attribute is reported.
    assert_eq!(gsad(&mut sim, Handle::RH_NULL), Some(RC_TYPE_H3));

    // GetTime reports the same positions (H2 / P2).
    assert_eq!(
        get_time(&mut sim, Handle::RH_ENDORSEMENT, decrypt_key, None, 2).err(),
        Some(RC_KEY_H2)
    );
    let rsa_key = create_primary(
        &mut sim,
        Handle::RH_ENDORSEMENT,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
    );
    assert_eq!(
        get_time(
            &mut sim,
            Handle::RH_ENDORSEMENT,
            rsa_key,
            Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
            2
        )
        .err(),
        Some(RC_SCHEME_P2)
    );
}

// ---------------------------------------------------------------------------------------------
// attestation-resolve-scheme-keyedhash-ecdaa-and-position-bugs
// ---------------------------------------------------------------------------------------------

/// An HMAC key signs `TPM2_Certify` output as `HMAC(key, H(attest))` (`CryptHmacSign`).
#[test]
fn attestation_resolve_scheme_keyedhash_ecdaa_and_position_bugs_hmac_certify() {
    let mut sim = create_simulator!();
    let key_bits: &'static [u8] = b"0123456789abcdef0123456789abcdef";
    let (_, key) = create_primary_full(&mut sim, Handle::RH_OWNER, hmac_sign_template(), key_bits);

    let rsp = certify(&mut sim, key, key, None).expect("Certify with an HMAC key failed");
    let attest_bytes = marshal_to_vec(&rsp.certify_info.0);
    let digest = Sha256::digest(&attest_bytes);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key_bits).unwrap();
    mac.update(&digest);
    let expected = mac.finalize().into_bytes();

    match rsp.signature {
        Some(TpmtSignature::Hmac(ha)) => assert_eq!(ha.digest(), expected.as_slice()),
        other => panic!("expected an HMAC signature, got {other:?}"),
    }
}

/// Every attestation command reports the scheme error at its `inScheme` position.
#[test]
fn attestation_resolve_scheme_keyedhash_ecdaa_and_position_bugs_scheme_positions() {
    let mut sim = create_simulator!();
    let key = create_primary(
        &mut sim,
        Handle::RH_ENDORSEMENT,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
    );
    let wrong = Some(TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256));
    assert_eq!(certify(&mut sim, key, key, wrong).err(), Some(RC_SCHEME_P2));
    assert_eq!(quote(&mut sim, key, wrong).err(), Some(RC_SCHEME_P2));

    let cmd = GetCommandAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: wrong,
    };
    let handles = GetCommandAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key,
    };
    assert_eq!(
        execute_with_password_sessions_status(&mut sim, &cmd, handles, 2, &[]).err(),
        Some(RC_SCHEME_P2)
    );

    // A scheme-less key with a non-signing input scheme is equally a scheme error.
    let schemeless = create_primary(&mut sim, Handle::RH_OWNER, rsa_sign_template(None));
    assert_eq!(
        certify(
            &mut sim,
            key,
            schemeless,
            Some(TpmtSigScheme::Hmac(TpmiAlgHash::Sha256))
        )
        .err(),
        Some(RC_SCHEME_P2)
    );
}

// ---------------------------------------------------------------------------------------------
// attestation-obfuscate-kdf-nv-clear-orderly-and-hmac-signer-bugs
// ---------------------------------------------------------------------------------------------

/// Certify by an owner-hierarchy signer obfuscates the header, an endorsement signer does not,
/// and the plain firmware version is `TPM_PT_FIRMWARE_VERSION_1 << 32 | _2`.
#[test]
fn attestation_obfuscate_kdf_nv_clear_orderly_and_hmac_signer_bugs_certify() {
    let mut sim = create_simulator!();
    let plain_firmware = reported_firmware_version(&mut sim);
    let template = rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)));
    let eh_key = create_primary(&mut sim, Handle::RH_ENDORSEMENT, template);
    let sh_key = create_primary(&mut sim, Handle::RH_OWNER, template);

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

/// Quote by an HMAC key also clears the orderly state (NV unavailable after orderly shutdown).
#[test]
fn attestation_obfuscate_kdf_nv_clear_orderly_and_hmac_signer_bugs_quote_nv_clear_orderly() {
    let mut sim = create_simulator!();
    let (_, key) = create_primary_full(
        &mut sim,
        Handle::RH_OWNER,
        hmac_sign_template(),
        b"orderly-hmac-key",
    );
    execute_with_password_sessions_status(
        &mut sim,
        &Shutdown {
            shutdown_type: TpmSu::State,
        },
        (),
        0,
        &[],
    )
    .expect("Shutdown failed");
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(quote(&mut sim, key, None).err(), Some(RC_NV_UNAVAILABLE));
}

/// An ECDAA attestation consumes the `TPM2_Commit` commitment: the same `count` cannot be used
/// for a second signature (`CryptGenerateR`/`CryptEndCommit`), and a count that was never
/// committed is rejected with a bare `TPM_RC_VALUE`.
#[test]
#[cfg_attr(
    feature = "crux",
    ignore = "crux backend has no ECDAA sign (ecdaa_sign returns UnsupportedAlgorithm)"
)]
fn attestation_resolve_scheme_keyedhash_ecdaa_and_position_bugs_ecdaa_commit_consumed() {
    let mut sim = create_simulator!();
    let key = create_primary(
        &mut sim,
        Handle::RH_OWNER,
        ecc_sign_template(Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count: 0,
        }))),
    );
    let commit = tpm2::commands::Commit {
        p1: tpm2::Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: tpm2::Tpm2bEccParameter::default(),
    };
    let (commit_rsp, _) = execute_with_password_sessions(
        &mut sim,
        &commit,
        tpm2::commands::CommitHandles { sign_handle: key },
        1,
        &[],
    )
    .expect("Commit failed");
    let scheme = |count| {
        Some(TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count,
        }))
    };

    // A count that was never committed.
    assert_eq!(
        certify(
            &mut sim,
            key,
            key,
            scheme(commit_rsp.counter.wrapping_add(1))
        )
        .err(),
        Some(0x084)
    );
    let rsp = certify(&mut sim, key, key, scheme(commit_rsp.counter))
        .expect("Certify with a fresh ECDAA commitment failed");
    assert!(matches!(rsp.signature, Some(TpmtSignature::Ecdaa(_))));
    // Reusing the commitment must fail (TPM_RC_VALUE).
    assert_eq!(
        certify(&mut sim, key, key, scheme(commit_rsp.counter)).err(),
        Some(0x084)
    );
}
