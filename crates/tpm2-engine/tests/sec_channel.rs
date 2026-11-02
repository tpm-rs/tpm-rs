//! White-box tests of secure channel support (the `sec-channel` feature) on platforms other than
//! the simulator's dummy: a platform without a secure transport layer (no TPM SPDM keys, no SPDM
//! session: `TPM_RC_CHANNEL`) and one whose SPDM session was established with Responder-only
//! authentication (an Empty Buffer requester key Name).
#![cfg(feature = "sec-channel")]

mod common;

use common::{
    FakeRng, FakeStorage, FakeTimer, RealCryptoEngine, TestCryptoProvider, execute_command,
    password_auth, setup_real_crypto_tpm,
};
use tpm2::commands::{
    CreatePrimary, FlushContext, GetCapability, PolicyGetDigest, PolicyTransportSPDM,
    SetPrimaryPolicy, StartAuthSession,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::platform::{SecureChannel, SimulatedSecureChannel, SpdmSession};
use tpm2::{
    Handle, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
    Tpm2bSensitiveData, TpmCap, TpmSe, TpmaObject, TpmaSession, TpmiAlgHash, TpmlPcrSelection,
    TpmsAuthCommand, TpmsCapabilityData, TpmsSensitiveCreate, TpmtPublic,
};

/// A secure transport layer whose SPDM session was established with Responder-only
/// authentication (no requester key) and the simulator's dummy TPM key.
struct ResponderOnly;

impl SecureChannel for ResponderOnly {
    fn tpm_spdm_public_key(&self, index: u8) -> Option<TpmtPublic<'_>> {
        SimulatedSecureChannel.tpm_spdm_public_key(index)
    }

    fn spdm_session(&self) -> Option<SpdmSession<'_>> {
        Some(SpdmSession {
            req_key_name: Tpm2bName::default(),
            tpm_key: 0,
        })
    }
}

/// Starts an unsalted, unbound SHA-256 session of `session_type`.
fn start_session(tpm: &mut RealCryptoEngine<'_>, session_type: TpmSe) -> Handle {
    execute_command(
        tpm,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[7; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
        &[],
    )
    .expect("TPM2_StartAuthSession failed")
    .session_handle
}

/// TPM2_PolicyTransportSPDM(`req`, `tpm`) on `session`.
fn policy_transport_spdm(
    tpm: &mut RealCryptoEngine<'_>,
    session: Handle,
    req: &'static [u8],
    tpm_key: &'static [u8],
) {
    execute_command(
        tpm,
        &PolicyTransportSPDM {
            policy_session: session,
            req_key_name: Tpm2bName::from_bytes(req).unwrap(),
            tpm_key_name: Tpm2bName::from_bytes(tpm_key).unwrap(),
        },
        &[],
    )
    .expect("TPM2_PolicyTransportSPDM failed");
}

/// Sets the owner policy to TPM2_PolicyTransportSPDM(`req`, `tpm_key`) and authorizes
/// TPM2_CreatePrimary(TPM_RH_OWNER) with a policy session asserting the same; returns the
/// response code.
fn create_primary_with_policy(
    tpm: &mut RealCryptoEngine<'_>,
    req: &'static [u8],
    tpm_key: &'static [u8],
) -> Result<(), u32> {
    let trial = start_session(tpm, TpmSe::Trial);
    policy_transport_spdm(tpm, trial, req, tpm_key);
    let digest = execute_command(
        tpm,
        &PolicyGetDigest {
            policy_session: trial,
        },
        &[],
    )
    .expect("TPM2_PolicyGetDigest failed")
    .policy_digest
    .get_buffer()
    .to_vec();
    flush(tpm, trial);
    execute_command(
        tpm,
        &SetPrimaryPolicy {
            auth_handle: Handle::RH_OWNER,
            auth_policy: Tpm2bDigest::from_bytes(Vec::leak(digest)).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        &[password_auth(b"")],
    )
    .expect("TPM2_SetPrimaryPolicy failed");
    let session = start_session(tpm, TpmSe::Policy);
    policy_transport_spdm(tpm, session, req, tpm_key);
    let policy_auth = TpmsAuthCommand {
        session_handle: session,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let rsp = execute_command(
        tpm,
        &CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::from_bytes(b"data").unwrap(),
            }),
            in_public: Tpm2b(TpmtPublic {
                name_alg: Some(TpmiAlgHash::Sha256),
                object_attributes: TpmaObject::FIXED_TPM
                    | TpmaObject::FIXED_PARENT
                    | TpmaObject::USER_WITH_AUTH,
                auth_policy: Tpm2bDigest::default(),
                parms_and_id: tpm2::PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
            }),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        &[policy_auth],
    );
    flush(tpm, session);
    rsp.map(|rsp| flush(tpm, rsp.object_handle))
}

/// TPM2_FlushContext(`handle`).
fn flush(tpm: &mut RealCryptoEngine<'_>, handle: Handle) {
    execute_command(
        tpm,
        &FlushContext {
            flush_handle: handle,
        },
        &[],
    )
    .expect("TPM2_FlushContext failed");
}

/// The capability data of TPM2_GetCapability(`capability`, 0, 1), or the response code.
fn capability(
    tpm: &mut RealCryptoEngine<'_>,
    capability: TpmCap,
) -> Result<TpmsCapabilityData<'static>, u32> {
    execute_command(
        tpm,
        &GetCapability {
            capability,
            property: 0,
            property_count: 1,
        },
        &[],
    )
    .map(|rsp| rsp.capability_data)
}

/// Without a secure transport layer the TPM has no SPDM key, reports no SPDM session and a
/// policy with TPM2_PolicyTransportSPDM fails with TPM_RC_CHANNEL
///
/// `TPM_CAP_PUB_KEYS` has no supported property (`TPM_RC_VALUE` + P2),
/// `TPM_CAP_SPDM_SESSION_INFO` is an empty list ("If TPM2_GetCapability() is not sent within an
/// SPDM session, an empty list will be returned"), and the deferred check of
/// `checkSecureChannel` is `TPM_RC_CHANNEL` with the position of the session.
#[test]
fn no_secure_channel_is_channel_error() {
    let (mut crypto, mut storage, mut timer, mut rng) = (
        TestCryptoProvider,
        FakeStorage::default(),
        FakeTimer,
        FakeRng::new(),
    );
    // `setup_real_crypto_tpm` builds the platform without a secure transport layer.
    let mut tpm = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);
    assert!(tpm.platform.secure_channel.is_none());
    assert_eq!(
        capability(&mut tpm, TpmCap::PubKeys).map(|_| ()),
        Err(TpmRc::VALUE.with(Position::parameter(2)).get())
    );
    match capability(&mut tpm, TpmCap::SpdmSessionInfo) {
        Ok(TpmsCapabilityData::SpdmSessionInfo(list)) => {
            assert!(list.spdm_session_info().is_empty())
        }
        other => panic!("unexpected response {other:?}"),
    }
    assert_eq!(
        create_primary_with_policy(&mut tpm, &[], &[]),
        Err(TpmRc::CHANNEL.with(Position::session(1)).get())
    );
}

/// With Responder-only authentication the requester key Name is an Empty Buffer
///
/// `TPMS_SPDM_SESSION_INFO.reqKeyName`: "An Empty Buffer is allowed and indicates that the SPDM
/// session was established with Responder-only authentication". A policy that checks a requester
/// key fails with `TPM_RC_CHANNEL_KEY`, one that checks only the TPM key authorizes.
#[test]
fn responder_only_session_has_no_requester_key() {
    static CHANNEL: ResponderOnly = ResponderOnly;
    let (mut crypto, mut storage, mut timer, mut rng) = (
        TestCryptoProvider,
        FakeStorage::default(),
        FakeTimer,
        FakeRng::new(),
    );
    let mut tpm = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);
    tpm.platform.secure_channel = Some(&CHANNEL);
    let tpm_key_name = match capability(&mut tpm, TpmCap::SpdmSessionInfo) {
        Ok(TpmsCapabilityData::SpdmSessionInfo(list)) => {
            let [info] = list.spdm_session_info() else {
                panic!("expected one SPDM session");
            };
            assert_eq!(info.req_key_name.get_size(), 0);
            Vec::leak(info.tpm_key_name.get_buffer().to_vec())
        }
        other => panic!("unexpected response {other:?}"),
    };
    let mut req = vec![0x00, 0x0B];
    req.extend_from_slice(&[0x11; 32]);
    assert_eq!(
        create_primary_with_policy(&mut tpm, Vec::leak(req), &[]),
        Err(TpmRc::CHANNEL_KEY.with(Position::session(1)).get())
    );
    assert_eq!(
        create_primary_with_policy(&mut tpm, &[], tpm_key_name),
        Ok(())
    );
}
