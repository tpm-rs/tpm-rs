//! `TPM_ALG_CAMELLIA` (the `camellia128`/`camellia192`/`camellia256` profile features): the
//! algorithm in `TPM_CAP_ALGS`, Camellia key sizes in `TPM2_TestParms`, SYMCIPHER Camellia keys
//! with `TPM2_EncryptDecrypt`/`TPM2_EncryptDecrypt2` in CFB mode (against a client-side
//! Camellia-CFB), Camellia as the symmetric algorithm of RSA, ECC and SYMCIPHER storage parents
//! (Create/Load/Unseal of children, Duplicate/Import with a Camellia inner wrapper under a
//! Camellia parent), of credential protectors (`TPM2_MakeCredential`/`TPM2_ActivateCredential`)
//! and of sessions (command and response parameter encryption).
#![cfg_attr(
    not(any(
        feature = "camellia128",
        feature = "camellia192",
        feature = "camellia256"
    )),
    allow(unused_imports, dead_code)
)]
#![allow(deprecated)] // TPM2_EncryptDecrypt is deprecated upstream but still implemented.

use crate::_common::{
    CLIENT_CRYPTO, create_srk, create_unwrap, dup_import_load, execute_with_hmac_sessions,
    execute_with_password_sessions, flush_context, get_bound_unique, leak_bytes, load_with_name,
    load_with_private, no_session_command, rc_of, read_public, rsa_dup_target, rsa_public, run_raw,
    start_auth_session, storage_attrs, sym_decrypt, sym_encrypt, try_create_owner_primary,
};
use testing::tpm::Tpm;
use tpm2::commands::{
    ActivateCredential, Create, CreatePrimary, EncryptDecrypt, EncryptDecrypt2, GetCapability,
    Load, MakeCredential, TestParms, Unseal,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, AlgSym, Handle, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bDigest, Tpm2bIv, Tpm2bMaxBuffer,
    Tpm2bSensitiveData, Tpm2bSymKey, TpmCap, TpmCc, TpmEccCurve, TpmSe, TpmaAlgorithm, TpmaObject,
    TpmaSession, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmsCapabilityData,
    TpmsSensitiveCreate, TpmtPublic, TpmtPublicParms, TpmtSymDefObject, TpmuSensitiveComposite,
};

/// Whether this TPM implements Camellia with any key size.
const CAMELLIA: bool = cfg!(any(
    feature = "camellia128",
    feature = "camellia192",
    feature = "camellia256"
));

/// Camellia with `alg`'s key size in CFB mode.
const fn camellia_cfb(alg: AlgSym) -> TpmtSymDefObject {
    TpmtSymDefObject {
        alg,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
    }
}

/// The Camellia key sizes this TPM implements, each in CFB mode.
fn implemented_camellia() -> Vec<TpmtSymDefObject> {
    [
        #[cfg(feature = "camellia128")]
        camellia_cfb(AlgSym::Camellia128),
        #[cfg(feature = "camellia192")]
        camellia_cfb(AlgSym::Camellia192),
        #[cfg(feature = "camellia256")]
        camellia_cfb(AlgSym::Camellia256),
    ]
    .to_vec()
}

/// Whether this TPM implements Camellia with `bits`-bit keys.
fn camellia_key_size_implemented(bits: u16) -> bool {
    // Not a `match`: with every key size enabled, its arms would all be `true` for the sizes and
    // clippy (`match_like_matches_macro`) would ask for a `matches!` that is wrong for the other
    // feature combinations.
    (bits == 128 && cfg!(feature = "camellia128"))
        || (bits == 192 && cfg!(feature = "camellia192"))
        || (bits == 256 && cfg!(feature = "camellia256"))
}

/// `TPM_CAP_ALGS` lists `TPM_ALG_CAMELLIA` as a symmetric algorithm exactly when Camellia is
/// implemented with some key size.
#[test]
fn capability_lists_camellia_when_implemented() {
    let mut sim = Tpm::new();
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::Algs,
            property: u32::from(Alg::CAMELLIA.id()),
            property_count: 1,
        })
        .expect("TPM2_GetCapability");
    let TpmsCapabilityData::Algorithms(algs) = rsp.capability_data else {
        panic!("unexpected capability data");
    };
    let first = algs.as_ref().first().copied();
    if CAMELLIA {
        let first = first.expect("TPM_ALG_CAMELLIA in TPM_CAP_ALGS");
        assert_eq!(first.alg, Alg::CAMELLIA);
        assert_eq!(first.alg_properties, TpmaAlgorithm::SYMMETRIC);
    } else {
        assert!(first.is_none_or(|a| a.alg != Alg::CAMELLIA));
    }
}

/// `TPM2_TestParms` accepts a SYMCIPHER Camellia definition (CFB) for each implemented key size
/// and rejects the other key sizes with `TPM_RC_VALUE` (not a `TPMI_CAMELLIA_KEY_BITS` value of
/// this TPM); without Camellia, `TPM_ALG_CAMELLIA` is not a `TPMI_ALG_SYM_OBJECT`
/// (`TPM_RC_SYMMETRIC`).
#[test]
fn testparms_accepts_implemented_camellia_key_sizes() {
    let mut sim = Tpm::new();
    for bits in [128u16, 192, 256] {
        // AES-128-CFB is marshaled and its algorithm and keyBits replaced (header, type, then
        // TPMT_SYM_DEF_OBJECT).
        let cmd = TestParms {
            parameters: TpmtPublicParms::Sym(camellia_cfb(AlgSym::Aes128)),
        };
        let mut command = no_session_command(TpmCc::TestParms, &cmd);
        command[12..14].copy_from_slice(&Alg::CAMELLIA.id().to_be_bytes());
        command[14..16].copy_from_slice(&bits.to_be_bytes());
        let expected = if camellia_key_size_implemented(bits) {
            0
        } else if CAMELLIA {
            TpmRc::VALUE.with(Position::parameter(1)).get()
        } else {
            TpmRc::SYMMETRIC.with(Position::parameter(1)).get()
        };
        assert_eq!(
            rc_of(&run_raw(&mut sim, &command)),
            expected,
            "Camellia-{bits}"
        );
    }
}

/// Loads (`TPM2_LoadExternal`, NULL hierarchy) a SYMCIPHER encryption/decryption key `key` with
/// the symmetric definition `sym` and an empty authValue.
fn load_camellia_key(sim: &mut Tpm, sym: TpmtSymDefObject, key: &[u8]) -> Handle {
    let key: &'static [u8] = leak_bytes(key);
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(sym, get_bound_unique(key)),
    };
    load_with_private(
        sim,
        public,
        TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(key).unwrap()),
        &[0x02; 32],
    )
}

/// `TPM2_EncryptDecrypt(key, decrypt, CFB, iv, data)`: (outData, ivOut).
fn encrypt_decrypt(
    sim: &mut Tpm,
    key: Handle,
    decrypt: bool,
    iv: &[u8; 16],
    data: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let rsp = execute_with_password_sessions(
        sim,
        &EncryptDecrypt {
            key_handle: key,
            decrypt,
            mode: Some(TpmiAlgCipherMode::Cfb),
            iv_in: Tpm2bIv::from_bytes(leak_bytes(iv)).unwrap(),
            in_data: Tpm2bMaxBuffer::from_bytes(leak_bytes(data)).unwrap(),
        },
        1,
        &[],
    )
    .expect("TPM2_EncryptDecrypt");
    (
        rsp.out_data.get_buffer().to_vec(),
        rsp.iv_out.get_buffer().to_vec(),
    )
}

/// `TPM2_EncryptDecrypt2(key, data, decrypt, CFB, iv)`: (outData, ivOut).
fn encrypt_decrypt2(
    sim: &mut Tpm,
    key: Handle,
    decrypt: bool,
    iv: &[u8; 16],
    data: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let rsp = execute_with_password_sessions(
        sim,
        &EncryptDecrypt2 {
            key_handle: key,
            in_data: Tpm2bMaxBuffer::from_bytes(leak_bytes(data)).unwrap(),
            decrypt,
            mode: Some(TpmiAlgCipherMode::Cfb),
            iv_in: Tpm2bIv::from_bytes(leak_bytes(iv)).unwrap(),
        },
        1,
        &[],
    )
    .expect("TPM2_EncryptDecrypt2");
    (
        rsp.out_data.get_buffer().to_vec(),
        rsp.iv_out.get_buffer().to_vec(),
    )
}

/// `TPM2_EncryptDecrypt` and `TPM2_EncryptDecrypt2` with a SYMCIPHER Camellia key in CFB mode
/// produce the client-side Camellia-CFB ciphertext and the output chaining value (`ivOut`: the
/// last ciphertext block, zero-padded after a partial block), for lengths around the block size,
/// and decrypt it back.
#[test]
fn encrypt_decrypt_camellia_cfb_matches_client() {
    let mut sim = Tpm::new();
    let iv: [u8; 16] = core::array::from_fn(|i| i as u8);
    let plaintext: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(37) ^ 0x5c).collect();
    for sym in implemented_camellia() {
        let key_bytes: Vec<u8> = (0..sym.alg.key_bytes() as u8).map(|i| 0xa0 ^ i).collect();
        let key = load_camellia_key(&mut sim, sym, &key_bytes);
        for len in [1usize, 15, 16, 17, 37, 64] {
            let mut expected = plaintext[..len].to_vec();
            let mut client_iv = iv;
            sym_encrypt(
                CLIENT_CRYPTO,
                sym,
                &key_bytes,
                &mut client_iv,
                &mut expected,
            )
            .unwrap();
            // ivOut is the last ciphertext block; after a partial last block, its ciphertext
            // padded with zeros (as `CryptSymmetricEncrypt`/`CryptSymmetricDecrypt` of the TCG
            // reference implementation pad the IV for the next round).
            let last = (len - 1) / 16 * 16;
            let mut expected_iv = [0u8; 16];
            expected_iv[..len - last].copy_from_slice(&expected[last..]);
            for (name, two) in [("EncryptDecrypt", false), ("EncryptDecrypt2", true)] {
                let op = if two {
                    encrypt_decrypt2
                } else {
                    encrypt_decrypt
                };
                let (ciphertext, iv_out) = op(&mut sim, key, false, &iv, &plaintext[..len]);
                assert_eq!(
                    ciphertext, expected,
                    "{name} {sym:?} encrypt of {len} bytes"
                );
                assert_eq!(iv_out, expected_iv, "{name} {sym:?} ivOut of {len} bytes");
                let (decrypted, iv_out) = op(&mut sim, key, true, &iv, &ciphertext);
                assert_eq!(
                    decrypted,
                    &plaintext[..len],
                    "{name} {sym:?} decrypt of {len} bytes"
                );
                assert_eq!(iv_out, expected_iv, "{name} {sym:?} decrypt ivOut");
            }
            // The client decrypts what the TPM encrypted.
            let mut client_iv = iv;
            sym_decrypt(
                CLIENT_CRYPTO,
                sym,
                &key_bytes,
                &mut client_iv,
                &mut expected,
            )
            .unwrap();
            assert_eq!(expected, &plaintext[..len]);
        }
        flush_context(&mut sim, key).unwrap();
    }
}

/// The SYMCIPHER restricted decryption (storage) template with the symmetric definition `sym`.
fn symcipher_storage(sym: TpmtSymDefObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: storage_attrs(),
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(sym, Tpm2bDigest::default()),
    }
}

/// The ECC NIST P-256 storage template with the symmetric definition `sym`.
fn ecc_storage(sym: TpmtSymDefObject) -> TpmtPublic<'static> {
    crate::_common::ecc_public_with_policy(
        TpmiAlgHash::Sha256,
        storage_attrs(),
        &[],
        TpmEccCurve::NistP256,
        Some(sym),
    )
}

/// A sealed data object (KEYEDHASH, NULL scheme) template with `userWithAuth`.
fn sealed_data_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    }
}

/// Seals `data` under `parent` (`TPM2_Create`), loads it (`TPM2_Load`) and returns the unsealed
/// data (`TPM2_Unseal`).
fn seal_load_unseal(sim: &mut Tpm, parent: Handle, data: &'static [u8]) -> Vec<u8> {
    let created = execute_with_password_sessions(
        sim,
        &Create {
            parent_handle: parent,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::from_bytes(b"sealed").unwrap(),
                data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
            }),
            in_public: Tpm2b(sealed_data_template()),
            ..Default::default()
        },
        1,
        &[],
    )
    .expect("TPM2_Create");
    let loaded = execute_with_password_sessions(
        sim,
        &Load {
            parent_handle: parent,
            in_private: created.out_private,
            in_public: created.out_public,
        },
        1,
        &[],
    )
    .expect("TPM2_Load");
    let unsealed = execute_with_password_sessions(
        sim,
        &Unseal {
            item_handle: loaded.object_handle,
        },
        1,
        b"sealed",
    )
    .expect("TPM2_Unseal");
    flush_context(sim, loaded.object_handle).unwrap();
    unsealed.out_data.get_buffer().to_vec()
}

/// RSA, ECC and SYMCIPHER storage parents whose symmetric algorithm is Camellia (CFB) protect
/// their children with it: a sealed child is created, loaded and unsealed under each.
#[test]
fn storage_parents_with_camellia_protect_children() {
    let mut sim = Tpm::new();
    for sym in implemented_camellia() {
        for (kind, template) in [
            (
                "RSA",
                rsa_public(TpmiAlgHash::Sha256, storage_attrs(), &[], Some(sym)),
            ),
            ("ECC", ecc_storage(sym)),
            ("SYMCIPHER", symcipher_storage(sym)),
        ] {
            let (parent, _) = try_create_owner_primary(&mut sim, template)
                .unwrap_or_else(|rc| panic!("{kind} {sym:?} parent: {rc:#x}"));
            assert_eq!(
                seal_load_unseal(&mut sim, parent, b"camellia-protected secret"),
                b"camellia-protected secret",
                "{kind} {sym:?}"
            );
            flush_context(&mut sim, parent).unwrap();
        }
    }
}

/// Duplicate -> Import -> Load of a signing key to an RSA parent whose symmetric algorithm is
/// Camellia (CFB), without an inner wrapper and with an AES or Camellia inner wrapper.
#[test]
fn duplicate_import_with_camellia_parent_and_inner_wrapper() {
    let mut sim = Tpm::new();
    let srk = create_srk(&mut sim);
    let target = create_unwrap(
        &mut sim,
        srk,
        rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    );
    for parent_sym in implemented_camellia() {
        let (parent, _) = try_create_owner_primary(
            &mut sim,
            rsa_public(TpmiAlgHash::Sha256, storage_attrs(), &[], Some(parent_sym)),
        )
        .expect("Camellia storage parent");
        let wrappers = [None, Some(crate::_common::AES128_CFB)]
            .into_iter()
            .chain(implemented_camellia().into_iter().map(Some));
        for inner in wrappers {
            let (target_handle, target_name) =
                load_with_name(&mut sim, srk, target.out_private, target.out_public).unwrap();
            dup_import_load(
                &mut sim,
                target_handle,
                target.out_public,
                &target_name,
                TpmiAlgHash::Sha256,
                parent,
                inner,
                &format!("parent_sym={parent_sym:?}, inner={inner:?}"),
            );
        }
        flush_context(&mut sim, parent).unwrap();
    }
}

/// `TPM2_MakeCredential` and `TPM2_ActivateCredential` round-trip a credential under RSA and ECC
/// protectors (restricted decryption keys) whose symmetric algorithm is Camellia (CFB), which
/// encrypts the credential (Part 1, "Credential Protection": "CFB_ekSymAlg").
#[test]
fn credential_round_trips_under_camellia_protector() {
    let mut sim = Tpm::new();
    for sym in implemented_camellia() {
        for (kind, template) in [
            (
                "RSA",
                rsa_public(TpmiAlgHash::Sha256, storage_attrs(), &[], Some(sym)),
            ),
            ("ECC", ecc_storage(sym)),
        ] {
            let (key, name) = try_create_owner_primary(&mut sim, template)
                .unwrap_or_else(|rc| panic!("{kind} {sym:?} protector: {rc:#x}"));
            let made = execute_with_password_sessions(
                &mut sim,
                &MakeCredential {
                    handle: key,
                    credential: Tpm2bDigest::from_bytes(b"Camellia secret").unwrap(),
                    object_name: tpm2::Tpm2bName::from_bytes(leak_bytes(&name)).unwrap(),
                },
                0,
                &[],
            )
            .expect("TPM2_MakeCredential");
            let activated = execute_with_password_sessions(
                &mut sim,
                &ActivateCredential {
                    activate_handle: key,
                    key_handle: key,
                    credential_blob: made.credential_blob,
                    secret: made.secret,
                },
                2,
                &[],
            )
            .expect("TPM2_ActivateCredential");
            assert_eq!(
                activated.cert_info.get_buffer(),
                b"Camellia secret",
                "{kind} {sym:?}"
            );
            flush_context(&mut sim, key).unwrap();
        }
    }
}

/// A session started with a Camellia (CFB) symmetric algorithm encrypts command and response
/// parameters with it: `TPM2_CreatePrimary` of a sealed object with an encrypted `inSensitive`
/// (the TPM unseals the data with the encrypted authValue) and an encrypted `outPublic` (equal
/// to `TPM2_ReadPublic`), and `TPM2_Unseal` with an encrypted `outData`.
#[test]
fn session_with_camellia_encrypts_parameters() {
    let mut sim = Tpm::new();
    for sym in implemented_camellia() {
        let mut session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            Some(sym),
            TpmiAlgHash::Sha256,
        )
        .unwrap_or_else(|rc| panic!("StartAuthSession({sym:?}): {rc:#x}"));
        session.attributes =
            TpmaSession::CONTINUE_SESSION | TpmaSession::DECRYPT | TpmaSession::ENCRYPT;

        let created = execute_with_hmac_sessions(
            &mut sim,
            &CreatePrimary {
                primary_handle: Handle::RH_OWNER,
                in_sensitive: Tpm2b(TpmsSensitiveCreate {
                    user_auth: Tpm2bAuth::from_bytes(b"camellia auth").unwrap(),
                    data: Tpm2bSensitiveData::from_bytes(b"sealed under camellia").unwrap(),
                }),
                in_public: Tpm2b(sealed_data_template()),
                ..Default::default()
            },
            &[],
            core::slice::from_mut(&mut session),
            &[&[]],
        )
        .unwrap_or_else(|rc| panic!("CreatePrimary({sym:?}): {rc:#x}"));
        let object = created.object_handle;
        let public = read_public(&mut sim, object).expect("TPM2_ReadPublic");
        assert_eq!(created.out_public, public.out_public, "{sym:?} outPublic");

        let unsealed = execute_with_password_sessions(
            &mut sim,
            &Unseal {
                item_handle: object,
            },
            1,
            b"camellia auth",
        )
        .expect("TPM2_Unseal with the password");
        assert_eq!(unsealed.out_data.get_buffer(), b"sealed under camellia");

        session.attributes = TpmaSession::CONTINUE_SESSION | TpmaSession::ENCRYPT;
        let unsealed = execute_with_hmac_sessions(
            &mut sim,
            &Unseal {
                item_handle: object,
            },
            &[],
            core::slice::from_mut(&mut session),
            &[b"camellia auth"],
        )
        .unwrap_or_else(|rc| panic!("Unseal({sym:?}): {rc:#x}"));
        assert_eq!(
            unsealed.out_data.get_buffer(),
            b"sealed under camellia",
            "{sym:?} outData"
        );
        flush_context(&mut sim, object).unwrap();
        flush_context(&mut sim, session.session_handle).unwrap();
    }
}
