use tpm2::UnmarshalMessage;
use tpm2::commands::responses;
mod common;

use common::{FakeStorage, FakeTimer, TestCryptoProvider};
use hex_literal::hex;
use tpm2::TpmEccCurve;
use tpm2::crypto::{Ecc, EccPrivateKey, EccPublicKey, Random};
use tpm2::{PublicParmsAndId, Tpm2bAuth, Tpm2bName, TpmaObject, TpmtPublic};
use tpm2_impl::handler::TransientObject;
use tpm2_impl::owned::{OwnedEccParameter, OwnedSensitiveComposite};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(b"ecdh_tests").unwrap();
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

fn create_transient_ecc_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
) -> (TransientObject, <TestCryptoProvider as Ecc>::PrivateKey) {
    let mut rng = crypto.rng_seeded(b"ecc_key_seed").unwrap();
    let key = Ecc::generate_key(crypto, &mut rng, TpmEccCurve::NistP256).unwrap();

    let mut x_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut y_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let point = key.public_key().point(&mut x_buf, &mut y_buf).unwrap();

    let mut d_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let scalar = key.scalar(&mut d_buf).unwrap();

    let public = TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            point,
        ),
    };

    let obj = TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: Tpm2bName::default().into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Ecc(OwnedEccParameter::from(scalar)),
        qualified_name: Tpm2bName::default().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    (obj, key)
}

#[test]
fn test_ecdh_keygen_success() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let key_handle = 0x80000001;
    let (obj, priv_key) = create_transient_ecc_key(
        tpm.platform.crypto,
        key_handle,
        TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(obj);

    // Call TPM2_ECDH_KeyGen with the key handle 0x80000001
    // Tag: 0x8001, Size: 0x0000000E (14), CommandCode: 0x00000163, Handle: 0x80000001
    let request = hex!("8001 0000000e 00000163 80000001");
    let mut response = [0u8; 1024];
    let len = tpm.execute_command_separate(&mut global_state, &request, &mut response);

    assert_eq!(
        u32::from_be_bytes(response[6..10].try_into().unwrap()),
        0,
        "TPM2_ECDH_KeyGen should return TPM_RC_SUCCESS"
    );

    let mut buf = &response[10..len];
    let rsp = responses::ECDHKeyGen::unmarshal_with_handles([], &mut buf)
        .expect("Should unmarshal responses::ECDHKeyGen");

    let pub_tpms = rsp.pub_point.0;
    let peer_pub = Ecc::load_public(&crypto, TpmEccCurve::NistP256, pub_tpms)
        .expect("Ecc::load_public should not error")
        .expect("pubPoint must lie on NIST P-256 curve");

    // Check zPoint coordinates match expected ECDH scalar multiplication: Z = [d_s] Q_e
    let mut exp_x = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut exp_y = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let expected_z = Ecc::ecdh(&crypto, &priv_key, &peer_pub, &mut exp_x, &mut exp_y)
        .expect("Scalar multiplication [d_s] Q_e should succeed")
        .expect("Shared point should not be at infinity");

    let z_tpms = rsp.z_point.0;
    assert_eq!(
        z_tpms.x.as_slice(),
        expected_z.x.as_slice(),
        "zPoint.x must match expected ECDH scalar multiplication [d_s] Q_e"
    );
    assert_eq!(
        z_tpms.y.as_slice(),
        expected_z.y.as_slice(),
        "zPoint.y must match expected ECDH scalar multiplication [d_s] Q_e"
    );
}

#[test]
fn test_ecc_parameters_p256() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    // Call TPM2_ECC_Parameters(TPM_ECC_BN_P256)
    // Tag: 0x8001 (2 bytes), Size: 0x0000000C (4 bytes), CC: 0x00000178 (4 bytes), CurveID: 0x0010 (2 bytes for BNP256)
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
    assert_eq!(rsp.parameters.kdf, None);
    assert_eq!(rsp.parameters.sign, None);
    assert_eq!(rsp.parameters.curve_id, TpmEccCurve::BNP256);

    // Also verify for NIST_P256 (0x0003)
    let request_nistp256 = hex!("8001 0000000c 00000178 0003");
    let len = tpm.execute_command_separate(&mut global_state, &request_nistp256, &mut response);
    assert_eq!(
        u32::from_be_bytes(response[6..10].try_into().unwrap()),
        0,
        "TPM2_ECC_Parameters(NistP256) should succeed"
    );

    let mut buf = &response[10..len];
    let rsp = responses::ECCParameters::unmarshal_with_handles([], &mut buf)
        .expect("Should unmarshal responses::ECCParameters");
    assert_eq!(rsp.parameters.key_size, 256);
    assert_eq!(rsp.parameters.kdf, None);
    assert_eq!(rsp.parameters.sign, None);
    assert_eq!(rsp.parameters.curve_id, TpmEccCurve::NistP256);
}
