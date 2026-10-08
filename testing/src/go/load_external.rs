#![forbid(unsafe_code)]

use crate::test_utils::flush_context;
use tpm2::commands::LoadExternal;
use tpm2::{Handle, TpmEccCurve};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData, TpmaObject,
    TpmiAlgHash, TpmsEccParms, TpmsEccPoint, TpmtPublic, TpmtSensitive, TpmuSensitiveComposite,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

// Original Go test: load_external_test.go - TestLoadExternal/ECCNoSensitive
#[test]
fn test_load_external_ecc_no_sensitive() {
    let mut sim = create_simulator!();

    // Ported from ECCNoSensitive in Go's load_external_test.go
    let x_bytes = [
        0x98, 0x55, 0xef, 0xa3, 0x51, 0x48, 0x73, 0xb8, 0x80, 0x67, 0xab, 0x12, 0x7b, 0x2d, 0x46,
        0x92, 0x86, 0x4a, 0x39, 0x5d, 0xb3, 0xd9, 0xe4, 0xcc, 0xad, 0x05, 0x92, 0x47, 0x8a, 0x24,
        0x5c, 0x16,
    ];
    let y_bytes = [
        0xe8, 0x02, 0xa2, 0x66, 0x49, 0x83, 0x9a, 0x2d, 0x7b, 0x13, 0xc8, 0x12, 0xa5, 0xdc, 0x0b,
        0x61, 0xc1, 0x10, 0xcb, 0xe6, 0x2d, 0xb7, 0x84, 0xd9, 0x6e, 0x60, 0xa8, 0x23, 0x44, 0x8c,
        0x89, 0x93,
    ];

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&x_bytes).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&y_bytes).unwrap(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

// Original Go test: load_external_test.go - TestLoadExternal/KeyedHashSensitive
#[test]
fn test_load_external_keyed_hash_sensitive() {
    let mut sim = create_simulator!();

    // Ported from KeyedHashSensitive in Go's load_external_test.go
    let seed_value = Tpm2bDigest::from_bytes(b"obfuscation is my middle name!!!").unwrap();
    let sensitive_data = Tpm2bSensitiveData::from_bytes(b"secrets").unwrap();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value,
        sensitive: TpmuSensitiveComposite::KeyedHash(sensitive_data),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let unique_bytes = [
        0xed, 0x4f, 0xe8, 0xe2, 0xbf, 0xf9, 0x76, 0x65, 0xe7, 0xbf, 0xbe, 0x27, 0xc2, 0x36, 0x5d,
        0x07, 0xa9, 0xbe, 0x91, 0xdd, 0x92, 0xd9, 0x97, 0xcd, 0x91, 0xcc, 0x70, 0x6b, 0x60, 0x74,
        0xeb, 0x08,
    ];
    let unique = Tpm2bDigest::from_bytes(&unique_bytes).unwrap();

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::default(),
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, unique),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let (_resp, resp_handles) = sim.execute_with_handles(cmd, ()).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}
