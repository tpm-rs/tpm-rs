#![forbid(unsafe_code)]
use crate::test_utils::marshal_to_slice;
use tpm2::Alg;

use crate::test_utils::*;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::FromEncodedPoint as _;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, Import, ImportHandles, Load, LoadHandles, Unseal,
    UnsealHandles,
};
use tpm2::crypto::kdf::{kdfa, kdfe};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::{LinuxRng, PlatformCryptoProvider};
use tpm2_simulator::{Simulator, create_simulator};

/// go-tpm's `ECCSRKTemplate`: NIST P-256 restricted decryption storage key
/// with AES-128-CFB, NoDA, and 32-byte zero-filled unique X/Y coordinates.
fn get_ecc_srk_template() -> TpmtPublic<'static> {
    static ZEROS: [u8; 32] = [0u8; 32];
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&ZEROS).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&ZEROS).unwrap(),
            },
        ),
    }
}

/// go-tpm's `RSASRKTemplate`: RSA-2048 restricted decryption storage key with
/// AES-128-CFB, NoDA, and a 256-byte zero-filled unique modulus.
fn get_rsa_srk_template() -> TpmtPublic<'static> {
    static ZEROS: [u8; 256] = [0u8; 256];
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&ZEROS).unwrap(),
        ),
    }
}

/// Executes `CreatePrimary` under TPM_RH_OWNER (empty password session) with
/// the given public template, an empty sensitive area, empty outside info and
/// an empty creation PCR selection, as go-tpm does for
/// `CreatePrimary{PrimaryHandle: TPMRHOwner, InPublic: New2B(template)}`.
fn create_primary_owner(
    sim: &mut Simulator<'_>,
    template: TpmtPublic<'static>,
) -> (tpm2::commands::CreatePrimaryRsp<'static>, Handle) {
    let cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(template),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &cmd, handles, 1, &[]).expect("CreatePrimary() failed");
    (rsp, rsp_handles.object_handle)
}

fn make_sealed_blob(
    name_alg: TpmiAlgHash,
    obfuscation: &[u8],
    contents: &[u8],
) -> (TpmtPublic<'static>, Vec<u8>) {
    let unique_digest = match name_alg {
        TpmiAlgHash::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(obfuscation);
            hasher.update(contents);
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(obfuscation);
            hasher.update(contents);
            hasher.finalize().to_vec()
        }
        _ => panic!("Unsupported name_alg"),
    };

    let public = TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            None,
            Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&unique_digest)).unwrap(),
        ),
    };

    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(obfuscation).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(contents).unwrap(),
        ),
    };

    let mut buf = vec![0u8; 4096];
    let len = marshal_to_slice(&sensitive, &mut buf);
    buf.truncate(len);

    (public, buf)
}

fn compute_object_name(public: &TpmtPublic) -> Tpm2bName<'static> {
    let mut pub_buf = vec![0u8; 4096];
    let pub_len = marshal_to_slice(public, &mut pub_buf);
    pub_buf.truncate(pub_len);

    let digest_bytes = match public.name_alg {
        Some(TpmiAlgHash::Sha256) => {
            let mut hasher = Sha256::new();
            hasher.update(&pub_buf);
            hasher.finalize().to_vec()
        }
        Some(TpmiAlgHash::Sha1) => {
            let mut hasher = Sha1::new();
            hasher.update(&pub_buf);
            hasher.finalize().to_vec()
        }
        _ => panic!("Unsupported name_alg for hashing public area"),
    };

    let mut name_bytes = vec![0u8; 2 + digest_bytes.len()];
    name_bytes[0..2].copy_from_slice(&Alg::from(public.name_alg.unwrap()).id().to_be_bytes());
    name_bytes[2..].copy_from_slice(&digest_bytes);
    Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap()
}

// Software helper implementation for parent keys
pub(crate) enum EncapsulationKey {
    Ecc {
        pub_x: Vec<u8>,
        pub_y: Vec<u8>,
        name_alg: TpmiAlgHash,
        sym_def: Option<TpmtSymDefObject>,
    },
    Rsa {
        pub_key: rsa::RsaPublicKey,
        hash_alg: TpmiAlgHash,
        name_alg: TpmiAlgHash,
        sym_def: Option<TpmtSymDefObject>,
    },
}

fn import_encapsulation_key(public: &TpmtPublic) -> EncapsulationKey {
    match &public.parms_and_id {
        PublicParmsAndId::Ecc(ecc_parms, ecc_point) => EncapsulationKey::Ecc {
            pub_x: ecc_point.x.get_buffer().to_vec(),
            pub_y: ecc_point.y.get_buffer().to_vec(),
            name_alg: public.name_alg.unwrap(),
            sym_def: ecc_parms.symmetric,
        },
        PublicParmsAndId::Rsa(rsa_parms, rsa_pub) => {
            let n_bytes = rsa_pub.get_buffer();
            let n = rsa::BigUint::from_bytes_be(n_bytes);
            let exponent = if rsa_parms.exponent == 0 {
                65537u32
            } else {
                rsa_parms.exponent
            };
            let e = rsa::BigUint::from(exponent);
            let pub_key = rsa::RsaPublicKey::new(n, e).expect("Failed to build RSA public key");

            // Decide OAEP scheme hash alg
            let hash_alg = match &rsa_parms.scheme {
                Some(TpmtRsaScheme::Oaep(alg)) => Some(*alg),
                _ => public.name_alg,
            };

            EncapsulationKey::Rsa {
                pub_key,
                hash_alg: hash_alg.expect("REASON"),
                name_alg: public.name_alg.unwrap(),
                sym_def: rsa_parms.symmetric,
            }
        }
        _ => panic!("Unsupported encapsulation key type"),
    }
}

// Derives a symmetric key and encrypts/HMACs sensitive data to create the duplicate blob.
fn create_duplicate(
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    key: &EncapsulationKey,
    name: &[u8],
    sensitive: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let crypto = PlatformCryptoProvider;

    // 1. Labeled Key Encapsulation (Encapsulate)
    let (secret, ciphertext) = match key {
        EncapsulationKey::Ecc { pub_x, pub_y, .. } => {
            // Generate ephemeral ECC key pair
            let eph_private = p256::SecretKey::random(rng);
            let eph_public = eph_private.public_key();
            let eph_point = eph_public.to_encoded_point(false);
            let eph_x = eph_point.x().unwrap().to_vec();
            let eph_y = eph_point.y().unwrap().to_vec();

            // Perform ECDH key exchange
            let parent_pub_point =
                p256::PublicKey::from_encoded_point(&p256::EncodedPoint::from_affine_coordinates(
                    pub_x.as_slice().into(),
                    pub_y.as_slice().into(),
                    false,
                ))
                .expect("Failed to parse parent ECC public key");
            let shared_secret = p256::ecdh::diffie_hellman(
                eph_private.to_nonzero_scalar(),
                parent_pub_point.as_affine(),
            );
            let z = shared_secret.raw_secret_bytes();

            // KDFe derivation
            let mut secret_derived = [0u8; 32];
            kdfe(
                &crypto,
                TpmiAlgHash::Sha256,
                z.as_slice(),
                b"DUPLICATE",
                &eph_x,
                pub_x,
                256,
                &mut secret_derived,
            )
            .unwrap();

            let ciphertext_point = TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&eph_x).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&eph_y).unwrap(),
            };
            let mut cipher_bytes = vec![0u8; 1024];
            let cipher_len = marshal_to_slice(&ciphertext_point, &mut cipher_bytes);
            cipher_bytes.truncate(cipher_len);

            (secret_derived.to_vec(), cipher_bytes)
        }
        EncapsulationKey::Rsa {
            pub_key, hash_alg, ..
        } => {
            let digest_size = match *hash_alg {
                TpmiAlgHash::Sha256 => 32,
                TpmiAlgHash::Sha1 => 20,
                _ => panic!("Unsupported hash alg for RSA-OAEP"),
            };
            let mut secret = vec![0u8; digest_size];
            rng.fill_bytes(&mut secret);

            // OAEP Label is "DUPLICATE\0"
            let label = "DUPLICATE\0";

            let enc_secret = match *hash_alg {
                TpmiAlgHash::Sha256 => pub_key
                    .encrypt(rng, rsa::Oaep::new_with_label::<Sha256, _>(label), &secret)
                    .expect("RSA-OAEP encryption failed"),
                TpmiAlgHash::Sha1 => pub_key
                    .encrypt(rng, rsa::Oaep::new_with_label::<Sha1, _>(label), &secret)
                    .expect("RSA-OAEP encryption failed"),
                _ => panic!("Unsupported hash alg"),
            };

            (secret, enc_secret)
        }
    };

    // 2. Symmetric parameter evaluation
    let (sym_alg, sym_key_bits, sym_mode) = match key {
        EncapsulationKey::Ecc { sym_def, .. } | EncapsulationKey::Rsa { sym_def, .. } => {
            match sym_def {
                Some(TpmtSymDefObject::Aes128(mode)) => (Alg::AES, 128, *mode),
                Some(TpmtSymDefObject::Aes256(mode)) => (Alg::AES, 256, *mode),
                _ => panic!("Unsupported symmetric algorithm"),
            }
        }
    };
    assert_eq!(sym_alg, Alg::AES);
    assert_eq!(sym_mode.unwrap(), TpmiAlgSymMode::CFB);

    // 3. Marshal sensitive structure to TPM2B_SENSITIVE (2B wrapper)
    let mut sensitive_2b = vec![0u8; 2 + sensitive.len()];
    sensitive_2b[0..2].copy_from_slice(&(sensitive.len() as u16).to_be_bytes());
    sensitive_2b[2..].copy_from_slice(sensitive);

    // 4. Derive AES CFB key using KDFa
    let mut derived_aes_key = vec![0u8; (sym_key_bits / 8) as usize];
    kdfa(
        &crypto,
        TpmiAlgHash::Sha256,
        &secret,
        b"STORAGE",
        name,
        &[],
        (sym_key_bits) as u32,
        &mut derived_aes_key,
    )
    .unwrap();

    // 5. Encrypt sensitive data using AES-CFB
    use aes::cipher::{AsyncStreamCipher, KeyIvInit};
    type Aes128Cfb8 = cfb_mode::Encryptor<aes::Aes128>;
    type Aes256Cfb8 = cfb_mode::Encryptor<aes::Aes256>;

    let mut dup_sensitive = sensitive_2b.clone();
    let iv = vec![0u8; 16];
    if sym_key_bits == 128 {
        let cipher = Aes128Cfb8::new_from_slices(&derived_aes_key, &iv).unwrap();
        cipher.encrypt(&mut dup_sensitive);
    } else if sym_key_bits == 256 {
        let cipher = Aes256Cfb8::new_from_slices(&derived_aes_key, &iv).unwrap();
        cipher.encrypt(&mut dup_sensitive);
    } else {
        panic!("Unsupported AES key size");
    }

    // 6. Compute HMAC of (dupSensitive || name)
    let mut hmac_key = vec![0u8; 32];
    kdfa(
        &crypto,
        TpmiAlgHash::Sha256,
        &secret,
        b"INTEGRITY",
        &[],
        &[],
        256,
        &mut hmac_key,
    )
    .unwrap();

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&hmac_key).unwrap();
    mac.update(&dup_sensitive);
    mac.update(name);
    let outer_hmac = mac.finalize().into_bytes().to_vec();

    // 7. Marshal virtual _PRIVATE (2B size prefix of HMAC + HMAC + dup_sensitive)
    let mut duplicate = vec![0u8; 2 + outer_hmac.len() + dup_sensitive.len()];
    duplicate[0..2].copy_from_slice(&(outer_hmac.len() as u16).to_be_bytes());
    duplicate[2..2 + outer_hmac.len()].copy_from_slice(&outer_hmac);
    duplicate[2 + outer_hmac.len()..].copy_from_slice(&dup_sensitive);

    (duplicate, ciphertext)
}

// Original Go test: import_test.go - TestCleartextImport
#[test]
fn test_cleartext_import() {
    let mut sim = create_simulator!();

    // 1. Create Owner SRK (go-tpm ECCSRKTemplate) via CreatePrimary.
    let (_, srk_handle) = create_primary_owner(&mut sim, get_ecc_srk_template());

    // 2. Generate ECC key pair using p256
    let mut rng = rand::rngs::OsRng;
    let private_key = p256::SecretKey::random(&mut rng);
    let public_key = private_key.public_key();
    let public_point = public_key.to_encoded_point(false);
    let x = public_point.x().unwrap();
    let y = public_point.y().unwrap();
    let d = private_key.to_bytes();

    // 3. Construct sensitive area (TpmtSensitive), wrapped in a TPM2B
    // (sensitive) and then in a TPM2B_PRIVATE buffer.
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(&d).unwrap()),
    };
    let mut sens_buf = vec![0u8; 1024];
    let sens_len = marshal_to_slice(&sensitive, &mut sens_buf);
    sens_buf.truncate(sens_len);

    let mut dup_buf = vec![0u8; 2 + sens_len];
    dup_buf[0..2].copy_from_slice(&(sens_len as u16).to_be_bytes());
    dup_buf[2..].copy_from_slice(&sens_buf);
    let duplicate = Tpm2bPrivate::from_bytes(&dup_buf).unwrap();

    // 4. Construct public area (TpmtPublic): SignEncrypt only.
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(x).unwrap(),
                y: Tpm2bEccParameter::from_bytes(y).unwrap(),
            },
        ),
    };
    let object_public = tpm2::Tpm2b(public);

    // 5. Execute Import (parent authorized with an empty password).
    let import_cmd = Import {
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate,
        in_sym_seed: Tpm2bEncryptedSecret::default(),
        symmetric_alg: None,
    };
    let import_handles = ImportHandles {
        parent_handle: srk_handle,
    };
    execute_with_password_sessions(&mut sim, &import_cmd, import_handles, 1, &[])
        .expect("could not import");

    // Deferred cleanup in Go: flushing the SRK must succeed.
    flush_context(&mut sim, srk_handle).expect("could not flush SRK");
}

/// Body of each `TestSWDuplicateImport` subtest: creates a primary storage key
/// from `pub_template`, duplicates a software-made sealed blob to it with
/// go-tpm's `CreateDuplicate` algorithm, imports and loads it, and checks that
/// Unseal returns the original plaintext.
fn run_sw_duplicate_import(sim: &mut Simulator<'_>, pub_template: TpmtPublic<'static>) {
    // 1. Create Primary
    let (primary, primary_handle) = create_primary_owner(sim, pub_template);

    // 2. Import parent public key as encapsulation key
    let public = primary.out_public.0;
    let key = import_encapsulation_key(&public);

    // 3. Make sealed key blob (KEYEDHASH)
    let plaintext = b"hello, unseal";
    let (sealed_pub, sealed_priv) = make_sealed_blob(TpmiAlgHash::Sha256, &[0u8; 32], plaintext);
    let sealed_name = compute_object_name(&sealed_pub);

    // 4. Create duplication blob in software
    let mut rng = rand::rngs::OsRng;
    let (duplicate, enc_secret) =
        create_duplicate(&mut rng, &key, sealed_name.get_buffer(), &sealed_priv);

    // 5. Execute Import under primary parent key
    let import_cmd = Import {
        encryption_key: Tpm2bData::default(),
        object_public: tpm2::Tpm2b(sealed_pub),
        duplicate: Tpm2bPrivate::from_bytes(&duplicate).unwrap(),
        in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_secret).unwrap(),
        symmetric_alg: None,
    };
    let import_handles = ImportHandles {
        parent_handle: primary_handle,
    };
    let (impo, _) = execute_with_password_sessions(sim, &import_cmd, import_handles, 1, &[])
        .expect("Import() failed");

    // 6. Load the imported private key
    let load_cmd = Load {
        in_private: impo.out_private,
        in_public: tpm2::Tpm2b(sealed_pub),
    };
    let load_handles = LoadHandles {
        parent_handle: primary_handle,
    };
    let (_, load_resp_handles) =
        execute_with_password_sessions(sim, &load_cmd, load_handles, 1, &[])
            .expect("Load() failed");
    let loaded_handle = load_resp_handles.object_handle;

    // 7. Unseal the plaintext contents
    let unseal_cmd = Unseal {};
    let unseal_handles = UnsealHandles {
        item_handle: loaded_handle,
    };
    let (unseal, _) = execute_with_password_sessions(sim, &unseal_cmd, unseal_handles, 1, &[])
        .expect("Unseal() failed");

    assert_eq!(
        unseal.out_data.get_buffer(),
        plaintext,
        "Unseal() = {:x?}, want {:x?}",
        unseal.out_data.get_buffer(),
        plaintext
    );

    // Deferred cleanup in Go (LIFO): loaded object, then primary.
    let _ = flush_context(sim, loaded_handle);
    let _ = flush_context(sim, primary_handle);
}

// Original Go test: import_test.go - TestSWDuplicateImport/ECDH-P256
#[test]
fn test_sw_duplicate_import_ecdh_p256() {
    let mut sim = create_simulator!();
    run_sw_duplicate_import(&mut sim, get_ecc_srk_template());
}

// Original Go test: import_test.go - TestSWDuplicateImport/RSA-2048
#[test]
fn test_sw_duplicate_import_rsa_2048() {
    let mut sim = create_simulator!();
    run_sw_duplicate_import(&mut sim, get_rsa_srk_template());
}
