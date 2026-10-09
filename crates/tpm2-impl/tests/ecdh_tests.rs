use tpm2::commands::{Command, ECCParameters, ECDHKeyGen};

use tpm2::Unmarshal;
mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;

use common::TestCryptoProvider;
use tpm2::TpmEccCurve;
use tpm2::crypto::{Asymmetric, Ecc};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bEccParameter, Tpm2bName, TpmaObject, TpmsEccPoint, TpmtPublic,
};
use tpm2_impl::handler::TransientObject;
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
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
) -> TransientObject {
    let mut pub_buf = [0u8; 512];
    let mut priv_buf = [0u8; 1024];
    use tpm2::Alg;

    let (pub_len, priv_len) = crypto
        .generate_key(
            Alg::ECC,
            Some(tpm2::crypto::asymmetric::KeyParams::Ecc(
                TpmEccCurve::NistP256,
            )),
            &mut pub_buf,
            &mut priv_buf,
            None,
        )
        .unwrap();

    let x = Tpm2bEccParameter::from_bytes(&pub_buf[..pub_len / 2]).unwrap();
    let y = Tpm2bEccParameter::from_bytes(&pub_buf[pub_len / 2..pub_len]).unwrap();

    let public = TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint { x, y },
        ),
    };
    let mut private = [0u8; 1536];
    private[..priv_len].copy_from_slice(&priv_buf[..priv_len]);

    TransientObject {
        handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: Tpm2bName::default().into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: Tpm2bName::default().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_ecdh_keygen_success() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let obj = create_transient_ecc_key(
        tpm.platform.crypto,
        key_handle,
        TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
    );
    let priv_bytes = obj.private;
    let priv_len = obj.private_len;
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
    let rsp = <ECDHKeyGen as Command>::Response::unmarshal(&mut buf)
        .expect("Should unmarshal <ECDHKeyGen as Command>::Response");

    let pub_tpms = rsp.pub_point.0;

    let mut pub_raw = [0u8; 64];
    pub_raw[..32].copy_from_slice(pub_tpms.x.get_buffer());
    pub_raw[32..64].copy_from_slice(pub_tpms.y.get_buffer());
    assert!(
        crypto
            .validate_point(TpmEccCurve::NistP256, &pub_raw)
            .is_ok(),
        "pubPoint must lie on NIST P-256 curve"
    );

    // Check zPoint coordinates match expected ECDH scalar multiplication: Z = [d_s] Q_e
    let mut expected_z_raw = [0u8; 64];
    crypto
        .point_multiply(
            TpmEccCurve::NistP256,
            &priv_bytes[..priv_len],
            &pub_raw,
            &mut expected_z_raw,
        )
        .expect("Scalar multiplication [d_s] Q_e should succeed");

    let z_tpms = rsp.z_point.0;
    let mut z_raw = [0u8; 64];
    z_raw[..32].copy_from_slice(z_tpms.x.get_buffer());
    z_raw[32..64].copy_from_slice(z_tpms.y.get_buffer());

    assert_eq!(
        z_raw, expected_z_raw,
        "zPoint coordinates must match expected ECDH scalar multiplication [d_s] Q_e"
    );
}

#[test]
fn test_ecc_parameters_p256() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Call TPM2_ECC_Parameters(TPM_ECC_BN_P256) exactly as requested in task 3.2
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
    let rsp = <ECCParameters as Command>::Response::unmarshal(&mut buf)
        .expect("Should unmarshal <ECCParameters as Command>::Response");
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
    let rsp = <ECCParameters as Command>::Response::unmarshal(&mut buf)
        .expect("Should unmarshal <ECCParameters as Command>::Response");
    assert_eq!(rsp.parameters.key_size, 256);
    // C CryptEccData.c: NIST P-256 carries {TPM_ALG_KDF1_SP800_56A, SHA256} as its KDF.
    assert_eq!(
        rsp.parameters.kdf,
        Some(tpm2::TpmtKdfScheme::Kdf1Sp800_56a(
            tpm2::TpmiAlgHash::Sha256
        ))
    );
    assert_eq!(rsp.parameters.sign, None);
    assert_eq!(rsp.parameters.curve_id, TpmEccCurve::NistP256);
}
