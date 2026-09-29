use crate::test_utils::*;
use p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, ECDHZGen, ECDHZGenHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

// Original Go test: ecdh_test.go - TestECDH
#[test]
fn test_ecdh() {
    let mut sim = create_simulator!();

    let user_auth = Tpm2bAuth::default();
    let sensitive_create = TpmsSensitiveCreate {
        user_auth,
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdh(TpmiAlgHash::Sha256)),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let in_public = tpm2::Tpm2b(pub_area);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (create_rsp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    // Generate SW P-256 key pair
    let sw_priv = SecretKey::random(&mut rand::thread_rng());
    let sw_pub = sw_priv.public_key();
    let sw_encoded = sw_pub.to_encoded_point(false);
    let sw_x = sw_encoded.x().unwrap();
    let sw_y = sw_encoded.y().unwrap();

    let sw_point = TpmsEccPoint {
        x: Tpm2bEccParameter::from_bytes(sw_x).unwrap(),
        y: Tpm2bEccParameter::from_bytes(sw_y).unwrap(),
    };
    let mut sw_point_buf = [0u8; 1024];
    let sw_point_len = marshal_to_slice(&sw_point, &mut sw_point_buf);
    let sw_tpm2b_point = Tpm2bEccPoint::from_bytes(&sw_point_buf[..sw_point_len]).unwrap();

    // Get TPM public key
    let out_public_struct = create_rsp.out_public.0;
    let tpm_ecc_point = match &out_public_struct.parms_and_id {
        PublicParmsAndId::Ecc(_, point) => point,
        _ => panic!("Expected ECC public key"),
    };

    let tpm_x = tpm_ecc_point.x.get_buffer();
    let tpm_y = tpm_ecc_point.y.get_buffer();
    let mut tpm_sec1 = [0u8; 65];
    tpm_sec1[0] = 0x04;
    tpm_sec1[1..33].copy_from_slice(tpm_x);
    tpm_sec1[33..65].copy_from_slice(tpm_y);
    let tpm_pub_key = PublicKey::from_sec1_bytes(&tpm_sec1).unwrap();

    // Compute shared secret in software: Z_sw = d_sw * Q_tpm
    let shared_secret =
        p256::ecdh::diffie_hellman(sw_priv.to_nonzero_scalar(), tpm_pub_key.as_affine());
    let z_sw_bytes = shared_secret.raw_secret_bytes();

    // Compute shared secret in TPM: Z_tpm = d_tpm * Q_sw
    let ecdh_cmd = ECDHZGen {
        in_point: sw_tpm2b_point,
    };
    let ecdh_handles = ECDHZGenHandles {
        key_handle: rsp_handles.object_handle,
    };

    let (ecdh_rsp, _) =
        execute_with_password_sessions(&mut sim, &ecdh_cmd, ecdh_handles, 1, &[]).unwrap();

    let out_point_struct = ecdh_rsp.out_point.0;
    let out_x = out_point_struct.x.get_buffer();

    assert_eq!(z_sw_bytes.as_slice(), out_x);
}
