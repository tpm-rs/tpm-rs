#![allow(unused_imports, dead_code)]
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
    CreateLoaded, CreateLoadedHandles, Import, ImportHandles, Load, LoadHandles, Unseal,
    UnsealHandles,
};
use tpm2::crypto::kdf::{kdfa, kdfe};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::{LinuxRng, PlatformCryptoProvider};
use tpm2_simulator::{Simulator, create_simulator};

fn get_ecc_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
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
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

fn get_rsa_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
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
            Tpm2bPublicKeyRsa::default(),
        ),
    }
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
enum EncapsulationKey {
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

#[allow(clippy::too_many_arguments)]
fn create_duplicate_challenged(
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    key: &EncapsulationKey,
    name: &[u8],
    sensitive: &[u8],
    inner_sym_def: Option<TpmtSymDefObject>,
    explicit_inner_key: Option<&[u8]>,
    tamper_outer_hmac: bool,
    tamper_ciphertext: bool,
    tamper_seed: bool,
    wrong_name: Option<&[u8]>,
    tamper_inner_hmac: bool,
) -> (Vec<u8>, Vec<u8>) {
    let crypto = PlatformCryptoProvider;

    // 1. Labeled Key Encapsulation (Encapsulate)
    let (secret, mut ciphertext) = match key {
        EncapsulationKey::Ecc { pub_x, pub_y, .. } => {
            // Ephemeral ECC key pair
            let eph_private = p256::SecretKey::random(rng);
            let eph_public = eph_private.public_key();
            let eph_point = eph_public.to_encoded_point(false);
            let eph_x = eph_point.x().unwrap().to_vec();
            let eph_y = eph_point.y().unwrap().to_vec();

            // ECDH
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

            // KDFe
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
                _ => panic!("Unsupported hash alg"),
            };
            let mut secret = vec![0u8; digest_size];
            rng.fill_bytes(&mut secret);

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

    if tamper_seed && !ciphertext.is_empty() {
        ciphertext[0] ^= 1;
    }

    // Outer symmetric param evaluation
    let (outer_sym_alg, outer_sym_key_bits, outer_sym_mode) = match key {
        EncapsulationKey::Ecc { sym_def, .. } | EncapsulationKey::Rsa { sym_def, .. } => {
            match sym_def {
                Some(TpmtSymDefObject::Aes128(mode)) => (Alg::AES, 128, *mode),
                Some(TpmtSymDefObject::Aes256(mode)) => (Alg::AES, 256, *mode),
                _ => panic!("Unsupported symmetric algorithm"),
            }
        }
    };
    assert_eq!(outer_sym_alg, Alg::AES);
    assert_eq!(outer_sym_mode.unwrap(), TpmiAlgSymMode::CFB);

    // Inner wrapper symmetric key
    let mut inner_key = [0u8; 32];
    let mut inner_key_len = 0;
    let has_inner = inner_sym_def.is_some();
    if has_inner {
        inner_key_len = match inner_sym_def {
            Some(TpmtSymDefObject::Aes128(_)) => 16,
            Some(TpmtSymDefObject::Aes256(_)) => 32,
            _ => panic!("Unsupported inner sym alg"),
        };
        if let Some(k) = explicit_inner_key {
            inner_key[..inner_key_len].copy_from_slice(k);
        } else {
            // Derive inner symmetric wrapper key from the decrypted seed
            kdfa(
                &crypto,
                TpmiAlgHash::Sha256,
                &secret,
                b"STORAGE",
                name,
                &[],
                (inner_key_len * 8) as u32,
                &mut inner_key[..inner_key_len],
            )
            .unwrap();
        }
    }

    // Marshal sensitive structure
    let mut inner_blob_plaintext = Vec::new();
    if has_inner {
        let mut sens_buf = vec![0u8; 2 + sensitive.len()];
        sens_buf[0..2].copy_from_slice(&(sensitive.len() as u16).to_be_bytes());
        sens_buf[2..].copy_from_slice(sensitive);

        // Compute inner integrity hash (plain hash per TPM 2.0 Spec Part 1 Section 23.3.1)
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(&sens_buf);
        hasher.update(name);
        let mut inner_hmac = hasher.finalize().to_vec();

        if tamper_inner_hmac {
            inner_hmac[0] ^= 1;
        }

        inner_blob_plaintext.extend_from_slice(&(inner_hmac.len() as u16).to_be_bytes());
        inner_blob_plaintext.extend_from_slice(&inner_hmac);
        inner_blob_plaintext.extend_from_slice(&sens_buf);

        // Encrypt inner blob using AES-CFB
        use aes::cipher::{AsyncStreamCipher, KeyIvInit};
        type Aes128Cfb8 = cfb_mode::Encryptor<aes::Aes128>;
        type Aes256Cfb8 = cfb_mode::Encryptor<aes::Aes256>;

        let iv = vec![0u8; 16];
        if inner_key_len == 16 {
            let cipher = Aes128Cfb8::new_from_slices(&inner_key[..inner_key_len], &iv).unwrap();
            cipher.encrypt(&mut inner_blob_plaintext);
        } else if inner_key_len == 32 {
            let cipher = Aes256Cfb8::new_from_slices(&inner_key[..inner_key_len], &iv).unwrap();
            cipher.encrypt(&mut inner_blob_plaintext);
        } else {
            panic!("Unsupported AES key size");
        }
    } else {
        inner_blob_plaintext.extend_from_slice(&(sensitive.len() as u16).to_be_bytes());
        inner_blob_plaintext.extend_from_slice(sensitive);
    }

    // Derive outer AES CFB key using KDFa
    let mut derived_outer_aes_key = vec![0u8; (outer_sym_key_bits / 8) as usize];
    kdfa(
        &crypto,
        TpmiAlgHash::Sha256,
        &secret,
        b"STORAGE",
        name,
        &[],
        (outer_sym_key_bits) as u32,
        &mut derived_outer_aes_key,
    )
    .unwrap();

    // Encrypt inner_blob_plaintext using outer AES-CFB
    use aes::cipher::{AsyncStreamCipher, KeyIvInit};
    type Aes128Cfb8 = cfb_mode::Encryptor<aes::Aes128>;
    type Aes256Cfb8 = cfb_mode::Encryptor<aes::Aes256>;

    let mut dup_sensitive = inner_blob_plaintext.clone();
    let iv = vec![0u8; 16];
    if outer_sym_key_bits == 128 {
        let cipher = Aes128Cfb8::new_from_slices(&derived_outer_aes_key, &iv).unwrap();
        cipher.encrypt(&mut dup_sensitive);
    } else if outer_sym_key_bits == 256 {
        let cipher = Aes256Cfb8::new_from_slices(&derived_outer_aes_key, &iv).unwrap();
        cipher.encrypt(&mut dup_sensitive);
    } else {
        panic!("Unsupported AES key size");
    }
    // Compute outer HMAC of (dupSensitive || name)
    let hmac_name = wrong_name.unwrap_or(name);
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
    mac.update(hmac_name);
    let mut outer_hmac = mac.finalize().into_bytes().to_vec();

    if tamper_ciphertext {
        dup_sensitive[0] ^= 1;
    }

    if tamper_outer_hmac {
        outer_hmac[0] ^= 1;
    }

    // Marshal virtual _PRIVATE (2B size prefix of HMAC + HMAC + dup_sensitive)
    let mut duplicate = vec![0u8; 2 + outer_hmac.len() + dup_sensitive.len()];
    duplicate[0..2].copy_from_slice(&(outer_hmac.len() as u16).to_be_bytes());
    duplicate[2..2 + outer_hmac.len()].copy_from_slice(&outer_hmac);
    duplicate[2 + outer_hmac.len()..].copy_from_slice(&dup_sensitive);

    (duplicate, ciphertext)
}

#[test]
fn test_import_adversarial_challenges() {
    let mut sim = create_simulator!();

    fn is_integrity_error(rc: u32) -> bool {
        (rc & 0xBF) == 0x9F
    }

    fn is_value_or_ecc_point_error(rc: u32) -> bool {
        let err = rc & 0xBF;
        err == 0x84 || err == 0xA7 || err == 0x95 || err == 0x9F
    }

    for tc in &[
        ("ECDH-P256", get_ecc_srk_template()),
        ("RSA-2048", get_rsa_srk_template()),
    ] {
        let name = tc.0;
        let pub_template = &tc.1;
        std::println!("Running adversarial import test cases: {}", name);

        // 1. Create Primary (SRK)
        let in_public = crate::test_utils::make_template(pub_template);
        let create_srk_cmd = CreateLoaded {
            in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public,
        };
        let create_srk_handles = CreateLoadedHandles {
            parent_handle: Handle(0x40000001), // TPMRH_OWNER
        };
        let (srk_resp, srk_resp_handles) =
            execute_with_password_sessions(&mut sim, &create_srk_cmd, create_srk_handles, 1, &[])
                .unwrap();
        let srk_handle = srk_resp_handles.object_handle;

        let parent_public = srk_resp.out_public.0;
        let enc_key = import_encapsulation_key(&parent_public);

        let plaintext = b"secure message";
        let (sealed_pub, sealed_priv) =
            make_sealed_blob(TpmiAlgHash::Sha256, &[0u8; 32], plaintext);
        let sealed_name = compute_object_name(&sealed_pub);

        let mut rng = rand::rngs::OsRng;

        // Challenge 1: Tampered outer HMAC
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            None,
            None,
            true, // tamper outer hmac
            false,
            false,
            None,
            false,
        );
        let import_cmd = Import {
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(
            &mut sim,
            &import_cmd,
            ImportHandles {
                parent_handle: srk_handle,
            },
            1,
            &[],
        );
        assert!(res.is_err(), "Expected tampered outer HMAC to fail");
        let err = res.unwrap_err();
        assert!(
            is_integrity_error(err),
            "Expected TPM_RC_INTEGRITY error, got: 0x{:X}",
            err
        );

        // Challenge 2: Tampered outer ciphertext
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            None,
            None,
            false,
            true, // tamper ciphertext
            false,
            None,
            false,
        );
        let import_cmd = Import {
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(
            &mut sim,
            &import_cmd,
            ImportHandles {
                parent_handle: srk_handle,
            },
            1,
            &[],
        );
        std::println!("Challenge 2 result: {:?}", res);
        assert!(res.is_err(), "Expected tampered outer ciphertext to fail");
        let err = res.unwrap_err();
        assert!(
            is_integrity_error(err),
            "Expected TPM_RC_INTEGRITY error, got: 0x{:X}",
            err
        );

        // Challenge 3: Tampered seed
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            None,
            None,
            false,
            false,
            true, // tamper seed
            None,
            false,
        );
        let import_cmd = Import {
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(
            &mut sim,
            &import_cmd,
            ImportHandles {
                parent_handle: srk_handle,
            },
            1,
            &[],
        );
        assert!(res.is_err(), "Expected tampered seed to fail");
        let err = res.unwrap_err();
        assert!(
            is_value_or_ecc_point_error(err) || err == 0x01 || err == 0x101,
            "Expected seed decryption/parsing/integrity error, got: 0x{:X}",
            err
        );

        // Challenge 4: Wrong Name in HMAC
        let wrong_name = vec![0u8; sealed_name.get_size() as usize];
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            None,
            None,
            false,
            false,
            false,
            Some(&wrong_name),
            false,
        );
        let import_cmd = Import {
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(
            &mut sim,
            &import_cmd,
            ImportHandles {
                parent_handle: srk_handle,
            },
            1,
            &[],
        );
        assert!(res.is_err(), "Expected wrong Name in HMAC to fail");
        let err = res.unwrap_err();
        assert!(
            is_integrity_error(err),
            "Expected TPM_RC_INTEGRITY error, got: 0x{:X}",
            err
        );

        // Challenge 5: Inner wrapper AES-128 CFB (derived inner key) - Success
        let inner_sym_def = Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)));
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            inner_sym_def,
            None, // derive inner key from seed
            false,
            false,
            false,
            None,
            false,
        );
        let import_cmd = Import {
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: inner_sym_def,
        };
        let import_resp = execute_with_password_sessions(
            &mut sim,
            &import_cmd,
            ImportHandles {
                parent_handle: srk_handle,
            },
            1,
            &[],
        )
        .unwrap();
        let load_cmd = Load {
            in_private: import_resp.0.out_private,
            in_public: tpm2::Tpm2b(sealed_pub),
        };
        let (_, load_resp_handles) = execute_with_password_sessions(
            &mut sim,
            &load_cmd,
            LoadHandles {
                parent_handle: srk_handle,
            },
            1,
            &[],
        )
        .unwrap();
        let loaded_handle = load_resp_handles.object_handle;
        let (unseal_resp, _) = execute_with_password_sessions(
            &mut sim,
            &Unseal {},
            UnsealHandles {
                item_handle: loaded_handle,
            },
            1,
            &[],
        )
        .unwrap();
        assert_eq!(unseal_resp.out_data.get_buffer(), plaintext);
        flush_context(&mut sim, loaded_handle).unwrap();

        // Challenge 6: Inner wrapper AES-128 CFB (explicit inner key) - Success
        let explicit_inner_key = b"0123456789abcdef"; // 16 bytes
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            inner_sym_def,
            Some(explicit_inner_key),
            false,
            false,
            false,
            None,
            false,
        );
        let import_cmd = Import {
            encryption_key: Tpm2bData::from_bytes(explicit_inner_key).unwrap(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: inner_sym_def,
        };
        let import_resp = execute_with_password_sessions(
            &mut sim,
            &import_cmd,
            ImportHandles {
                parent_handle: srk_handle,
            },
            1,
            &[],
        )
        .unwrap();
        let load_cmd = Load {
            in_private: import_resp.0.out_private,
            in_public: tpm2::Tpm2b(sealed_pub),
        };
        let (_, load_resp_handles) = execute_with_password_sessions(
            &mut sim,
            &load_cmd,
            LoadHandles {
                parent_handle: srk_handle,
            },
            1,
            &[],
        )
        .unwrap();
        let loaded_handle = load_resp_handles.object_handle;
        let (unseal_resp, _) = execute_with_password_sessions(
            &mut sim,
            &Unseal {},
            UnsealHandles {
                item_handle: loaded_handle,
            },
            1,
            &[],
        )
        .unwrap();
        assert_eq!(unseal_resp.out_data.get_buffer(), plaintext);
        flush_context(&mut sim, loaded_handle).unwrap();

        // Challenge 7: Inner wrapper AES-128 CFB with tampered inner HMAC - Failure
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            inner_sym_def,
            None,
            false,
            false,
            false,
            None,
            true, // tamper inner hmac
        );
        let import_cmd = Import {
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: inner_sym_def,
        };
        let res = execute_with_password_sessions(
            &mut sim,
            &import_cmd,
            ImportHandles {
                parent_handle: srk_handle,
            },
            1,
            &[],
        );
        assert!(res.is_err(), "Expected tampered inner HMAC to fail");
        let err = res.unwrap_err();
        assert!(
            is_integrity_error(err),
            "Expected TPM_RC_INTEGRITY error, got: 0x{:X}",
            err
        );

        // Challenge 8: Wrong Parental Key Attributes - Failure
        let sign_parent_pub = TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SIGN_ENCRYPT, // lacks RESTRICTED and DECRYPT
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: None,
                    scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                TpmsEccPoint {
                    x: Tpm2bEccParameter::default(),
                    y: Tpm2bEccParameter::default(),
                },
            ),
        };
        let in_public_sign = crate::test_utils::make_template(&sign_parent_pub);
        let create_sign_parent_cmd = CreateLoaded {
            in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: in_public_sign,
        };
        let (_, sign_parent_handles) = execute_with_password_sessions(
            &mut sim,
            &create_sign_parent_cmd,
            CreateLoadedHandles {
                parent_handle: Handle(0x40000001),
            },
            1,
            &[],
        )
        .unwrap();
        let sign_parent_handle = sign_parent_handles.object_handle;

        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            None,
            None,
            false,
            false,
            false,
            None,
            false,
        );
        let import_cmd = Import {
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(
            &mut sim,
            &import_cmd,
            ImportHandles {
                parent_handle: sign_parent_handle,
            },
            1,
            &[],
        );
        assert!(
            res.is_err(),
            "Expected Import to fail with parent lacking DECRYPT/RESTRICTED"
        );
        let err = res.unwrap_err();
        assert_eq!(
            err, 0x182,
            "Expected Attributes error for Handle 1 (0x182), got 0x{:03X}",
            err
        );

        flush_context(&mut sim, sign_parent_handle).unwrap();

        // Challenge 9: Mismatched Key Type (Type mismatch) - Failure
        let ecc_sensitive = TpmtSensitive {
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap(),
            sensitive: TpmuSensitiveComposite::Ecc(
                Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
            ),
        };
        let mut ecc_sens_buf = vec![0u8; 1024];
        let ecc_sens_len = marshal_to_slice(&ecc_sensitive, &mut ecc_sens_buf);
        ecc_sens_buf.truncate(ecc_sens_len);

        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &ecc_sens_buf, // mismatched sensitive area
            None,
            None,
            false,
            false,
            false,
            None,
            false,
        );
        let import_cmd = Import {
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(
            &mut sim,
            &import_cmd,
            ImportHandles {
                parent_handle: srk_handle,
            },
            1,
            &[],
        );
        assert!(
            res.is_err(),
            "Expected Import to fail with mismatched key type"
        );
        let err = res.unwrap_err();
        assert_eq!(
            err, 0x3CA,
            "Expected Type error for Parameter 3 (0x3CA), got 0x{:03X}",
            err
        );

        // Cleanup
        flush_context(&mut sim, srk_handle).unwrap();
    }
}
