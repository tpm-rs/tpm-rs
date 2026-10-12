use common::marshal_to_slice;
use tpm2::UnmarshalMessage;
#[allow(deprecated)]
use tpm2::commands::responses;
mod common;

use common::{FakeStorage, FakeTimer, TestCryptoProvider};
use hex_literal::hex;
use tpm2::crypto::Random;
use tpm2::{Handle, TpmEccCurve};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bPublicKeyRsa, TpmaObject,
    TpmiAlgHash, TpmsRsaParms, TpmtRsaScheme, TpmtSignature,
};
use tpm2_impl::handler::TransientObject;
use tpm2_impl::owned::{OwnedPrivateKeyRsa, OwnedSensitiveComposite, OwnedSensitiveData};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(b"crypto_validation_tests").unwrap();
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup first
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_request, &mut startup_response);

    (tpm, global_state)
}

#[test]
fn test_ecc_parameters_exact_curve_details() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    // Call TPM2_ECC_Parameters(TPM_ECC_BN_P256)
    let request_bnp256 = hex!("8001 0000000c 00000178 0010");
    let mut response = [0u8; 1024];
    let len = tpm.execute_command_separate(&mut global_state, &request_bnp256, &mut response);
    assert_eq!(
        u32::from_be_bytes(response[6..10].try_into().unwrap()),
        0,
        "TPM2_ECC_Parameters(BNP256) should succeed"
    );

    let mut buf = &response[10..len];
    let rsp = responses::ECCParameters::unmarshal_with_handles([], &mut buf)
        .expect("Should unmarshal responses::ECCParameters");
    assert_eq!(rsp.parameters.key_size, 256);
    assert_eq!(rsp.parameters.curve_id, TpmEccCurve::BNP256);

    // Check exact coordinate P value string per TCG Part 4 Table 8
    let expected_p = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0xf0, 0xcd, 0x46, 0xe5, 0xf2, 0x5e, 0xee, 0x71, 0xa4,
        0x9f, 0x0c, 0xdc, 0x65, 0xfb, 0x12, 0x98, 0x0a, 0x82, 0xd3, 0x29, 0x2d, 0xdb, 0xae, 0xd3,
        0x30, 0x13,
    ];
    assert_eq!(rsp.parameters.curve_p.as_slice(), &expected_p);

    // Check n, a, b, g_x, g_y, h
    let expected_n = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0xf0, 0xcd, 0x46, 0xe5, 0xf2, 0x5e, 0xee, 0x71, 0xa4,
        0x9e, 0x0c, 0xdc, 0x65, 0xfb, 0x12, 0x99, 0x92, 0x1a, 0xf6, 0x2d, 0x53, 0x6c, 0xd1, 0x0b,
        0x50, 0x0d,
    ];
    assert_eq!(rsp.parameters.n.as_slice(), &expected_n);
    assert_eq!(rsp.parameters.curve_a.as_slice(), &[0; 32]);
    let mut expected_b = [0u8; 32];
    expected_b[31] = 3;
    assert_eq!(rsp.parameters.curve_b.as_slice(), &expected_b);
    let mut expected_gx = [0u8; 32];
    expected_gx[31] = 1;
    assert_eq!(rsp.parameters.g_x.as_slice(), &expected_gx);
    let mut expected_gy = [0u8; 32];
    expected_gy[31] = 2;
    assert_eq!(rsp.parameters.g_y.as_slice(), &expected_gy);
    assert_eq!(rsp.parameters.h.as_slice(), &[0x01]);
}

#[test]
fn test_verify_signature_scheme_null_validation() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let key_handle = 0x80000001;
    let public_area = tpm2::TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: tpm2::TpmiRsaKeyBits::Rsa2048,
                exponent: 65537,
            },
            Tpm2bPublicKeyRsa::new(&[1u8; 256]).unwrap(),
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        public: public_area.into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::new(&[0u8; 128]).unwrap()),
        hierarchy: Handle::RH_OWNER.0,
        name: Tpm2bName::new(&[1u8; 34]).unwrap().into(),
        qualified_name: Tpm2bName::new(&[1u8; 34]).unwrap().into(),
        auth: Tpm2bAuth::default().into(),
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    // Prepare VerifySignature command with raw TPM_ALG_NULL signature selector
    let handles_data = 0x80000001u32.to_be_bytes();
    let digest = Tpm2bDigest::new(&[2u8; 32]).unwrap();
    let null_sig: Option<TpmtSignature> = None;

    let mut param_buf = [0u8; 512];
    let mut offset = 0;
    offset += marshal_to_slice(&digest, &mut param_buf[offset..]);
    offset += marshal_to_slice(&null_sig, &mut param_buf[offset..]);

    let cmd_size = u32::try_from(10 + 4 + offset).unwrap();
    let mut request = Vec::new();
    request.extend_from_slice(&0x8001u16.to_be_bytes()); // tag
    request.extend_from_slice(&cmd_size.to_be_bytes()); // size
    request.extend_from_slice(&0x00000177u32.to_be_bytes()); // cc VerifySignature
    request.extend_from_slice(&handles_data);
    request.extend_from_slice(&param_buf[..offset]);

    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &request, &mut response);
    let error_code = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(
        error_code,
        tpm2::errors::TpmRc::SCHEME
            .with(tpm2::errors::Position::parameter(2))
            .get(),
        "VerifySignature should reject TPM_ALG_NULL signature with TPM_RC_SCHEME + TPM_RC_P + TPM_RC_2"
    );
}

#[test]
#[allow(deprecated)]
fn test_sign_and_verify_signature_hmac() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let key_handle = 0x80000001;
    let public_area = tpm2::TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(tpm2::TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::new(&[1u8; 32]).unwrap(),
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        public: public_area.into(),
        sensitive: OwnedSensitiveComposite::KeyedHash(
            OwnedSensitiveData::new(&[0x42u8; 32]).unwrap(),
        ),
        hierarchy: Handle::RH_OWNER.0,
        name: Tpm2bName::new(&[1u8; 34]).unwrap().into(),
        qualified_name: Tpm2bName::new(&[1u8; 34]).unwrap().into(),
        auth: Tpm2bAuth::default().into(),
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    // Call Sign command (0x0000015D)
    let digest = Tpm2bDigest::new(&[2u8; 32]).unwrap();
    let in_scheme = Some(tpm2::TpmtSigScheme::Hmac(TpmiAlgHash::Sha256));
    let validation = tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default());

    let mut param_buf = [0u8; 512];
    let mut offset = 0;
    offset += marshal_to_slice(&digest, &mut param_buf[offset..]);
    offset += marshal_to_slice(&in_scheme, &mut param_buf[offset..]);
    offset += marshal_to_slice(&validation, &mut param_buf[offset..]);

    let cmd_size = u32::try_from(10 + 4 + offset).unwrap();
    let mut request = Vec::new();
    request.extend_from_slice(&0x8001u16.to_be_bytes());
    request.extend_from_slice(&cmd_size.to_be_bytes());
    request.extend_from_slice(&0x0000015Du32.to_be_bytes()); // cc Sign
    request.extend_from_slice(&0x80000001u32.to_be_bytes()); // key_handle
    request.extend_from_slice(&param_buf[..offset]);

    let mut response = [0u8; 1024];
    let len = tpm.execute_command_separate(&mut global_state, &request, &mut response);
    let error_code = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(error_code, 0, "Sign command should succeed");

    let mut unmarshal_buf = &response[10..len];
    let sign_rsp = responses::Sign::unmarshal_with_handles([], &mut unmarshal_buf)
        .expect("Should unmarshal responses::Sign");

    // Now call VerifySignature command (0x00000177)
    let mut offset = 0;
    offset += marshal_to_slice(&digest, &mut param_buf[offset..]);
    offset += marshal_to_slice(&sign_rsp.signature, &mut param_buf[offset..]);

    let cmd_size = u32::try_from(10 + 4 + offset).unwrap();
    let mut request = Vec::new();
    request.extend_from_slice(&0x8001u16.to_be_bytes());
    request.extend_from_slice(&cmd_size.to_be_bytes());
    request.extend_from_slice(&0x00000177u32.to_be_bytes()); // cc VerifySignature
    request.extend_from_slice(&0x80000001u32.to_be_bytes()); // key_handle
    request.extend_from_slice(&param_buf[..offset]);

    tpm.execute_command_separate(&mut global_state, &request, &mut response);
    let error_code = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(
        error_code, 0,
        "VerifySignature on signed HMAC should return 0 (TPM_SUCCESS)"
    );
}
