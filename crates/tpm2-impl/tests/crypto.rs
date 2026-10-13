mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, TpmaObject, TpmiAlgHash, TpmtPublic,
};
use tpm2_impl::handler::TransientObject;

/// Converts a `TPM_ST_NO_SESSIONS` request with `num_handles` handles into a `TPM_ST_SESSIONS`
/// request carrying one empty password session. Commands whose handles have an authorization
/// role need a session in the C reference (`TPM_RC_AUTH_MISSING` otherwise, CheckAuthNoSession).
fn with_pw_session(request: &[u8], num_handles: usize) -> Vec<u8> {
    let split = 10 + 4 * num_handles;
    // authorizationSize (9) || TPM_RS_PW || empty nonce || continueSession || empty hmac
    let session: [u8; 13] = [0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 0x01, 0, 0];
    let mut out = Vec::with_capacity(request.len() + session.len());
    out.extend_from_slice(&[0x80, 0x02]);
    out.extend_from_slice(&((request.len() + session.len()) as u32).to_be_bytes());
    out.extend_from_slice(&request[6..split]);
    out.extend_from_slice(&session);
    out.extend_from_slice(&request[split..]);
    out
}

fn setup_tpm_with_fake_platform<'a>(
    crypto: &'a mut FakeCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a mut FakeRng,
) -> (
    TpmEngine<'a, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup first
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

#[test]
fn test_adv_mac_unsupported_hash() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &mut rng);
    let key_handle = 0x80000001;

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xee; 1536],
        private_len: 32,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000017"
        "00000155"
        "80000001"
        "0005 68656c6c6f" // "hello"
        "0012"            // SM3256 (unsupported by fake crypto)
    );

    let mut response = [0u8; 256];
    let _size = tpm.execute_command_separate(
        &mut global_state,
        &with_pw_session(&request, 1)[..],
        &mut response[..],
    );
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code, 0x000002C3,
        "Expected TPM_RC_HASH with parameter 2 (0x2C3), got 0x{:08X}",
        error_code
    );
}

#[test]
fn test_ecdh_zgen_scheme_error() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &mut rng);
    let key_handle = 0x80000001;

    // Key with ECDSA scheme (invalid for ECDH_ZGen)
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: Some(tpm2::TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xbb; 1536],
        private_len: 32,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000054"
        "00000154"
        "80000001"
        "0044"
        "0020"
        "3561244d853489754cf0710d875a7ba4b2aca9cc38a5d02985d4ceb83bcbd0a2"
        "0020"
        "f8f0b6850f0925254ff63a19a01125a88994fc866060354d9305a711686d7177"
    );

    let mut response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &with_pw_session(&request, 1)[..],
        &mut response[..],
    );
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code,
        0x00000192, // TPM_RC_SCHEME | Position::Handle | Position::handle(1)
        "Expected TPM_RC_SCHEME + Handle + Pos1 (0x192), got error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_ecdh_zgen_public_only_key_error() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &mut rng);
    let key_handle = 0x80000001;

    // ECC key but private_len = 0
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000054"
        "00000154"
        "80000001"
        "0044"
        "0020"
        "3561244d853489754cf0710d875a7ba4b2aca9cc38a5d02985d4ceb83bcbd0a2"
        "0020"
        "f8f0b6850f0925254ff63a19a01125a88994fc866060354d9305a711686d7177"
    );

    let mut response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &with_pw_session(&request, 1)[..],
        &mut response[..],
    );
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code,
        0x0000019C, // TPM_RC_KEY | Position::Handle | Position::handle(1)
        "Expected TPM_RC_KEY + Handle + Pos1 (0x19C) for public-only key! error_code = 0x{:08X}",
        error_code
    );
}
