use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};
use tpm2::Handle;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, Sign, SignHandles};
use tpm2::*;
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

use crate::test_utils::*;

// Original Go test: sign_test.go - TestSign
#[test]
fn test_sign() {
    let mut sim = create_simulator!();

    let in_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let mut pcr_select = [0u8; tpm2::TPM2_PCR_SELECT_MAX as usize];
    pcr_select[0] |= 1 << 7;
    let tpms_pcr_selection = TpmsPcrSelection::new(TpmiAlgHash::Sha1, &pcr_select[..3]).unwrap();
    let pcr_selection = TpmlPcrSelection::from_slice(&[tpms_pcr_selection]).unwrap();

    let create_primary_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(in_public),
        outside_info: Tpm2bData::default(),
        creation_pcr: pcr_selection,
    };
    let create_primary_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (create_primary_resp, create_primary_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_cmd,
        create_primary_handles,
        0,
        &[],
    )
    .expect("CreatePrimary failed");

    let object_handle = create_primary_resp_handles.object_handle;

    // Computes the SHA256 digest of "migrationpains"
    let data_to_sign = b"migrationpains";
    let digest = Sha256::digest(data_to_sign);

    let sign_cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let sign_handles = SignHandles {
        key_handle: object_handle,
    };

    let mut resp_buffer = [0u8; 4096];
    let (sign_resp, _) = execute_sign(&mut sim, &sign_cmd, sign_handles, 1, &[], &mut resp_buffer)
        .expect("Sign failed");

    // Extract the public key details from create_primary_resp
    let out_public_struct = create_primary_resp.out_public.0;
    let (n_bytes, exponent) = match &out_public_struct.parms_and_id {
        PublicParmsAndId::Rsa(rsa_parms, rsa_pub) => {
            let exponent = if rsa_parms.exponent == 0 {
                65537u32
            } else {
                rsa_parms.exponent
            };
            (rsa_pub.get_buffer(), exponent)
        }
        _ => panic!("Expected RSA public key"),
    };

    // Verify signature using rsa crate
    let n = BigUint::from_bytes_be(n_bytes);
    let e = BigUint::from(exponent);
    let rsa_pub_key = RsaPublicKey::new(n, e).expect("Failed to build RSA public key");

    let signature_bytes = match &sign_resp.signature {
        TpmtSignature::Rsassa(rsassa) => rsassa.sig.get_buffer(),
        _ => panic!("Expected RSASSA signature"),
    };

    let scheme = Pkcs1v15Sign::new::<Sha256>();
    rsa_pub_key
        .verify(scheme, &digest, signature_bytes)
        .expect("Signature verification failed");

    // Cleanup key
    flush_context(&mut sim, object_handle).unwrap();
}
