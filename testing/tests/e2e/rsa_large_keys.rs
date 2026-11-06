//! RSA-3072 and RSA-4096 keys (the `rsa3072`/`rsa4096` features of `tpm2-engine`; every
//! differential target enables both, as all three C references implement `RSA_3072` and
//! `RSA_4096`). TPM 2.0 Part 2, Table "Definition of (RSA) (TPM_KEY_BITS) TPMI_RSA_KEY_BITS
//! Type": "$RSA_KEY_SIZES_BITS | the number of bits in the supported key". At each size: primary
//! and ordinary keys (with the CRT form of the sensitive area under a *fixedTPM* parent),
//! RSASSA/RSAPSS signing and verification, RSA encryption and decryption, salted sessions,
//! `TPM2_TestParms`, context save/load, persistence, duplication and import, and public-only
//! `TPM2_LoadExternal`, cross-checked with the `rsa` crate.
#![cfg(any(feature = "rsa3072", feature = "rsa4096"))]
#![allow(deprecated)] // `TPM2_Sign`/`TPM2_VerifySignature` are deprecated upstream.

use crate::_common::{
    context_load, context_save, dup_import_load, dup_policy_digest_for, encapsulate_secret,
    evict_control, execute_with_password_sessions, flush_context, get_tpm_property, leak_bytes,
    load_external_public, load_with_name, marshal_to_vec, rsa_public_bits, sign, start_salted,
};
use sha2::{Digest as _, Sha256};
use testing::tpm::Tpm;
use tpm2::commands::{Create, CreatePrimary, RSADecrypt, RSAEncrypt, TestParms, VerifySignature};
use tpm2::{
    Handle, Marshal as _, PublicParmsAndId, Tpm2b, Tpm2bData, Tpm2bDigest, Tpm2bPublicKeyRsa,
    TpmPt, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsRsaParms, TpmtPublic, TpmtPublicParms,
    TpmtRsaDecrypt, TpmtSigScheme, TpmtSignature, TpmtSymDefObject,
};

/// An RSA key template of `bits` bits with `attributes`, no symmetric definition and no scheme
/// (any scheme may be chosen per command).
fn template(bits: u16, attributes: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attributes,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits::new(bits).expect("implemented RSA key size"),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// An unrestricted signing key of `bits` bits that never leaves the TPM.
fn signing_template(bits: u16) -> TpmtPublic<'static> {
    template(
        bits,
        TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
    )
}

/// An unrestricted decryption key of `bits` bits.
fn decryption_template(bits: u16) -> TpmtPublic<'static> {
    template(
        bits,
        TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
    )
}

/// `TPM2_CreatePrimary` of `public` in the owner hierarchy; returns the handle and the created
/// public area, whose modulus must have exactly the key size.
fn create_primary(tpm: &mut Tpm, public: TpmtPublic<'static>) -> (Handle, TpmtPublic<'static>) {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_public: Tpm2b(public),
        in_sensitive: Default::default(),
        outside_info: Default::default(),
        creation_pcr: Default::default(),
    };
    let rsp = execute_with_password_sessions(tpm, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("CreatePrimary failed: {rc:#x}"));
    check_modulus(&rsp.out_public.0);
    (rsp.object_handle, rsp.out_public.0)
}

/// `TPM2_Create` of `public` under `parent` and `TPM2_Load` of the result; returns the handle,
/// the created public area and the size of the private blob.
fn create_and_load(
    tpm: &mut Tpm,
    parent: Handle,
    public: TpmtPublic<'static>,
) -> (Handle, TpmtPublic<'static>, usize) {
    let cmd = Create {
        parent_handle: parent,
        in_public: Tpm2b(public),
        in_sensitive: Default::default(),
        outside_info: Default::default(),
        creation_pcr: Default::default(),
    };
    let rsp = execute_with_password_sessions(tpm, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("Create failed: {rc:#x}"));
    check_modulus(&rsp.out_public.0);
    let (handle, _) = load_with_name(tpm, parent, rsp.out_private, rsp.out_public)
        .unwrap_or_else(|rc| panic!("Load failed: {rc:#x}"));
    (
        handle,
        rsp.out_public.0,
        usize::from(rsp.out_private.get_size()),
    )
}

/// The key size and the modulus of the RSA public area `public`.
fn rsa_key(public: &TpmtPublic<'static>) -> (u16, &'static [u8]) {
    let PublicParmsAndId::Rsa(parms, unique) = public.parms_and_id else {
        panic!("expected an RSA key");
    };
    (parms.key_bits.as_u16(), unique.get_buffer())
}

/// The modulus of a created key has exactly `keyBits` bits.
fn check_modulus(public: &TpmtPublic<'static>) {
    let (bits, modulus) = rsa_key(public);
    assert_eq!(modulus.len(), usize::from(bits) / 8);
    assert!(modulus[0] >= 0x80, "the modulus has fewer than {bits} bits");
}

/// The client-side view of the RSA public area `public` (default exponent).
fn client_key(public: &TpmtPublic<'static>) -> rsa::RsaPublicKey {
    rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(rsa_key(public).1),
        rsa::BigUint::from(65537u32),
    )
    .unwrap()
}

/// Signs a SHA-256 digest with `key` (whose public area is `public`) with RSASSA and RSAPSS,
/// checks each signature with the `rsa` crate and with `TPM2_VerifySignature` of `verifier` (a
/// handle of the same key), and checks that a corrupted signature fails to verify.
fn sign_and_verify(tpm: &mut Tpm, key: Handle, verifier: Handle, public: &TpmtPublic<'static>) {
    let (bits, _) = rsa_key(public);
    let digest: &'static [u8] = leak_bytes(&Sha256::digest(format!("RSA-{bits} message")));
    let client = client_key(public);
    for scheme in [
        TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256),
        TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256),
    ] {
        let signature = sign(tpm, key, &[], digest, Some(scheme))
            .unwrap_or_else(|rc| panic!("Sign({scheme:?}) failed: {rc:#x}"));
        let (rsassa, sig) = match signature {
            TpmtSignature::Rsassa(s) => (true, s),
            TpmtSignature::Rsapss(s) => (false, s),
            other => panic!("unexpected signature {other:?}"),
        };
        assert_eq!(sig.hash, TpmiAlgHash::Sha256);
        assert_eq!(sig.sig.get_buffer().len(), usize::from(bits) / 8);
        if rsassa {
            client
                .verify(
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<Sha256>(),
                    digest,
                    sig.sig.get_buffer(),
                )
                .unwrap();
        } else {
            client
                .verify(rsa::pss::Pss::new::<Sha256>(), digest, sig.sig.get_buffer())
                .unwrap();
        }
        let verify = VerifySignature {
            key_handle: verifier,
            digest: Tpm2bDigest::from_bytes(digest).unwrap(),
            signature,
        };
        execute_with_password_sessions(tpm, &verify, 0, &[])
            .unwrap_or_else(|rc| panic!("VerifySignature({scheme:?}) failed: {rc:#x}"));

        let mut corrupted = sig.sig.get_buffer().to_vec();
        corrupted[1] ^= 0x01;
        let corrupted = tpm2::TpmsSignatureRsa {
            hash: TpmiAlgHash::Sha256,
            sig: Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&corrupted)).unwrap(),
        };
        let verify = VerifySignature {
            key_handle: verifier,
            digest: Tpm2bDigest::from_bytes(digest).unwrap(),
            signature: if rsassa {
                TpmtSignature::Rsassa(corrupted)
            } else {
                TpmtSignature::Rsapss(corrupted)
            },
        };
        assert_eq!(
            execute_with_password_sessions(tpm, &verify, 0, &[])
                .map(|_| ())
                .unwrap_err(),
            tpm2::errors::TpmRc::SIGNATURE
                .with(tpm2::errors::Position::parameter(2))
                .get()
        );
    }
}

/// A primary signing key of `bits` bits signs with RSASSA and RSAPSS.
fn primary_signing_key_signs(bits: u16) {
    let mut tpm = Tpm::new();
    let (key, public) = create_primary(&mut tpm, signing_template(bits));
    sign_and_verify(&mut tpm, key, key, &public);
    flush_context(&mut tpm, key).unwrap();
}

/// An ordinary signing key created under a storage parent of the same size: its private area
/// (protected by a *fixedTPM* parent) holds the CRT form of the key, five values of half the
/// modulus size (TPM 2.0 Part 2, TPM2B_PRIVATE_KEY_RSA: "`RSA_PRIVATE_SIZE` ... can be
/// (`MAX_RSA_KEY_BYTES` / 2) or ((`MAX_RSA_KEY_BYTES` \* 5) / 2)"), and the loaded key signs.
fn ordinary_key_has_crt_private_area(bits: u16) {
    let mut tpm = Tpm::new();
    let (parent, _) = create_primary(&mut tpm, rsa_public_bits(bits));
    let (key, public, private_size) = create_and_load(&mut tpm, parent, signing_template(bits));
    assert!(
        private_size > 5 * usize::from(bits) / 16,
        "a private blob of {private_size} octets cannot hold the CRT form"
    );
    sign_and_verify(&mut tpm, key, key, &public);
    flush_context(&mut tpm, key).unwrap();
    flush_context(&mut tpm, parent).unwrap();
}

/// A decryption key of `bits` bits: `TPM2_RSA_Encrypt` and `TPM2_RSA_Decrypt` round-trip with
/// OAEP and RSAES, and an OAEP ciphertext of the `rsa` crate decrypts in the TPM.
fn decryption_round_trips(bits: u16) {
    let mut tpm = Tpm::new();
    let (key, public) = create_primary(&mut tpm, decryption_template(bits));
    let message: &'static [u8] = leak_bytes(format!("a secret for RSA-{bits}").as_bytes());
    let decrypt = |tpm: &mut Tpm, ciphertext: &[u8], scheme: TpmtRsaDecrypt| {
        let cmd = RSADecrypt {
            key_handle: key,
            cipher_text: Tpm2bPublicKeyRsa::from_bytes(leak_bytes(ciphertext)).unwrap(),
            in_scheme: Some(scheme),
            label: Tpm2bData::default(),
        };
        let rsp = execute_with_password_sessions(tpm, &cmd, 1, &[])
            .unwrap_or_else(|rc| panic!("RSA_Decrypt({scheme:?}) failed: {rc:#x}"));
        rsp.message.get_buffer().to_vec()
    };
    for scheme in [
        TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha256),
        TpmtRsaDecrypt::Rsaes,
    ] {
        let cmd = RSAEncrypt {
            key_handle: key,
            message: Tpm2bPublicKeyRsa::from_bytes(message).unwrap(),
            in_scheme: Some(scheme),
            label: Tpm2bData::default(),
        };
        let rsp = execute_with_password_sessions(&mut tpm, &cmd, 0, &[])
            .unwrap_or_else(|rc| panic!("RSA_Encrypt({scheme:?}) failed: {rc:#x}"));
        let ciphertext = rsp.out_data.get_buffer().to_vec();
        assert_eq!(ciphertext.len(), usize::from(bits) / 8);
        assert_eq!(decrypt(&mut tpm, &ciphertext, scheme), message);
    }
    let ciphertext = client_key(&public)
        .encrypt(
            &mut crate::_common::client_rng(),
            rsa::Oaep::new::<Sha256>(),
            message,
        )
        .unwrap();
    assert_eq!(
        decrypt(
            &mut tpm,
            &ciphertext,
            TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha256)
        ),
        message
    );
    flush_context(&mut tpm, key).unwrap();
}

/// A session salted with a decryption key of `bits` bits: the `encryptedSalt` (an OAEP
/// ciphertext as large as the modulus, Part 1, "Secret Sharing", RSA-OAEP with the label
/// "SECRET") fits `TPM2B_ENCRYPTED_SECRET` and is decrypted.
fn salted_session_starts(bits: u16) {
    let mut tpm = Tpm::new();
    let (key, public) = create_primary(&mut tpm, decryption_template(bits));
    let (_, salt) = encapsulate_secret(&marshal_to_vec(&public), "SECRET", u64::from(bits))
        .expect("an RSA-OAEP salt");
    assert_eq!(salt.len(), usize::from(bits) / 8);
    start_salted(&mut tpm, key, Handle::RH_NULL, &salt)
        .unwrap_or_else(|rc| panic!("StartAuthSession failed: {rc:#x}"));
    flush_context(&mut tpm, key).unwrap();
}

/// `TPM2_TestParms` accepts the key size, with and without a symmetric definition.
fn test_parms_accepts(bits: u16) {
    let mut tpm = Tpm::new();
    for symmetric in [None, Some(TpmtSymDefObject::aes_cfb(128).unwrap())] {
        let cmd = TestParms {
            parameters: TpmtPublicParms::Rsa(TpmsRsaParms {
                symmetric,
                scheme: None,
                key_bits: TpmiRsaKeyBits::new(bits).expect("implemented RSA key size"),
                exponent: 0,
            }),
        };
        tpm.execute(cmd)
            .unwrap_or_else(|e| panic!("TestParms({bits}, {symmetric:?}) failed: {e:?}"));
    }
}

/// The context of a loaded key of `bits` bits fits `TPM_PT_MAX_OBJECT_CONTEXT`, and the key
/// loaded again from it signs like the original (its private key is restored).
fn context_round_trip_keeps_the_key(bits: u16) {
    let mut tpm = Tpm::new();
    let (parent, _) = create_primary(&mut tpm, rsa_public_bits(bits));
    let (key, public, _) = create_and_load(&mut tpm, parent, signing_template(bits));
    let context = context_save(&mut tpm, key);
    let mut buffer = [0u8; tpm2::TpmsContext::MAX_SIZE];
    let size = context.marshal(&mut buffer);
    assert!(
        size as u32 <= get_tpm_property(&mut tpm, TpmPt::MAX_OBJECT_CONTEXT),
        "a context of {size} octets"
    );
    flush_context(&mut tpm, key).unwrap();
    let key = context_load(&mut tpm, context).unwrap_or_else(|rc| panic!("{rc:#x}"));
    sign_and_verify(&mut tpm, key, key, &public);
    flush_context(&mut tpm, key).unwrap();
    flush_context(&mut tpm, parent).unwrap();
}

/// A persistent key of `bits` bits (`TPM2_EvictControl`) signs through its persistent handle,
/// and can be evicted again.
fn persistent_key_signs(bits: u16) {
    let mut tpm = Tpm::new();
    let (key, public) = create_primary(&mut tpm, signing_template(bits));
    let persistent = Handle(0x8100_0040);
    evict_control(&mut tpm, Handle::RH_OWNER, key, persistent)
        .unwrap_or_else(|rc| panic!("EvictControl failed: {rc:#x}"));
    flush_context(&mut tpm, key).unwrap();
    sign_and_verify(&mut tpm, persistent, persistent, &public);
    evict_control(&mut tpm, Handle::RH_OWNER, persistent, persistent)
        .unwrap_or_else(|rc| panic!("EvictControl (remove) failed: {rc:#x}"));
}

/// A duplicable key of `bits` bits is duplicated (with an inner AES-128-CFB wrapper and the
/// seed encrypted to the new parent: an OAEP ciphertext as large as its modulus) to another
/// storage parent of the same size, imported and loaded there with the same Name.
fn duplicate_and_import(bits: u16) {
    let mut tpm = Tpm::new();
    let (old_parent, _) = create_primary(&mut tpm, rsa_public_bits(bits));
    let mut new_parent_template = rsa_public_bits(bits);
    new_parent_template.object_attributes |= TpmaObject::NO_DA;
    let (new_parent, _) = create_primary(&mut tpm, new_parent_template);
    let mut duplicable = template(
        bits,
        TpmaObject::SENSITIVE_DATA_ORIGIN | TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT,
    );
    duplicable.auth_policy = dup_policy_digest_for(TpmiAlgHash::Sha256);
    let cmd = Create {
        parent_handle: old_parent,
        in_public: Tpm2b(duplicable),
        in_sensitive: Default::default(),
        outside_info: Default::default(),
        creation_pcr: Default::default(),
    };
    let rsp = execute_with_password_sessions(&mut tpm, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("Create failed: {rc:#x}"));
    let (key, name) = load_with_name(&mut tpm, old_parent, rsp.out_private, rsp.out_public)
        .unwrap_or_else(|rc| panic!("Load failed: {rc:#x}"));
    dup_import_load(
        &mut tpm,
        key,
        rsp.out_public,
        &name,
        TpmiAlgHash::Sha256,
        new_parent,
        Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
        &format!("RSA-{bits}"),
    );
    flush_context(&mut tpm, new_parent).unwrap();
    flush_context(&mut tpm, old_parent).unwrap();
}

/// The public area of a key of `bits` bits loads with `TPM2_LoadExternal` (public only), and
/// verifies the signatures of the original key.
fn public_only_key_verifies(bits: u16) {
    let mut tpm = Tpm::new();
    let (key, public) = create_primary(&mut tpm, signing_template(bits));
    let mut external = public;
    external.object_attributes = TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT;
    let verifier = load_external_public(&mut tpm, external);
    sign_and_verify(&mut tpm, key, verifier, &public);
    flush_context(&mut tpm, verifier).unwrap();
    flush_context(&mut tpm, key).unwrap();
}

/// Declares the tests of one key size, gated by its feature.
macro_rules! key_size_tests {
    ($feature:literal, $bits:literal, $module:ident) => {
        #[cfg(feature = $feature)]
        mod $module {
            /// A primary signing key signs with RSASSA and RSAPSS.
            #[test]
            fn primary_signing_key_signs() {
                super::primary_signing_key_signs($bits);
            }

            /// An ordinary key under a storage parent keeps the CRT form and signs.
            #[test]
            fn ordinary_key_has_crt_private_area() {
                super::ordinary_key_has_crt_private_area($bits);
            }

            /// RSA encryption and decryption round-trip.
            #[test]
            fn decryption_round_trips() {
                super::decryption_round_trips($bits);
            }

            /// A session salted with the key starts.
            #[test]
            fn salted_session_starts() {
                super::salted_session_starts($bits);
            }

            /// `TPM2_TestParms` accepts the key size.
            #[test]
            fn test_parms_accepts() {
                super::test_parms_accepts($bits);
            }

            /// Context save and load keep the key.
            #[test]
            fn context_round_trip_keeps_the_key() {
                super::context_round_trip_keeps_the_key($bits);
            }

            /// A persistent key signs.
            #[test]
            fn persistent_key_signs() {
                super::persistent_key_signs($bits);
            }

            /// Duplication and import to another parent keep the key.
            #[test]
            fn duplicate_and_import() {
                super::duplicate_and_import($bits);
            }

            /// A public-only external key verifies the key's signatures.
            #[test]
            fn public_only_key_verifies() {
                super::public_only_key_verifies($bits);
            }
        }
    };
}

key_size_tests!("rsa3072", 3072, rsa_3072);
key_size_tests!("rsa4096", 4096, rsa_4096);
