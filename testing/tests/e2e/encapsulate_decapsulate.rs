//! TPM2_Encapsulate and TPM2_Decapsulate (TPM 2.0 v185) with ML-KEM keys: shared secrets agree
//! between the TPM and a client-side FIPS 203 implementation in both directions for every
//! parameter set, fresh randomness per encapsulation, implicit rejection of tampered
//! ciphertexts, and the key, attribute, ciphertext-size and authorization checks.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{Decapsulate, Encapsulate};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bKemCiphertext, TpmaObject, TpmiMlkemParms, TpmtPublic};

/// Runs TPM2_Encapsulate on `key`; returns `(shared secret, ciphertext)` or the response code.
fn encapsulate(sim: &mut Tpm, key: Handle) -> Result<(Vec<u8>, Vec<u8>), u32> {
    run_command(sim, Encapsulate { key_handle: key }).map(|rsp| {
        (
            rsp.shared_secret.get_buffer().to_vec(),
            rsp.ciphertext.get_buffer().to_vec(),
        )
    })
}

/// Runs TPM2_Decapsulate of `ciphertext` on `key` with a password session carrying `auth`;
/// returns the shared secret or the response code.
fn decapsulate_with_auth(
    sim: &mut Tpm,
    key: Handle,
    ciphertext: &[u8],
    auth: &[u8],
) -> Result<Vec<u8>, u32> {
    execute_with_password_sessions(
        sim,
        &Decapsulate {
            key_handle: key,
            ciphertext: Tpm2bKemCiphertext::from_bytes(leak_bytes(ciphertext)).unwrap(),
        },
        1,
        auth,
    )
    .map(|rsp| rsp.shared_secret.get_buffer().to_vec())
}

/// Runs TPM2_Decapsulate of `ciphertext` on `key` with an empty password.
fn decapsulate(sim: &mut Tpm, key: Handle, ciphertext: &[u8]) -> Result<Vec<u8>, u32> {
    decapsulate_with_auth(sim, key, ciphertext, &[])
}

/// Creates a primary unrestricted ML-KEM decryption key; returns its handle and public area.
fn mlkem_primary(sim: &mut Tpm, parameter_set: TpmiMlkemParms) -> (Handle, TpmtPublic<'static>) {
    create_primary_returning_public(sim, mlkem_decryption_public(parameter_set), &[])
}

/// Loads a client-generated ML-KEM key pair with TPM2_LoadExternal; returns its handle and seed.
fn external_key_pair(sim: &mut Tpm, parameter_set: TpmiMlkemParms) -> (Handle, Vec<u8>) {
    let (seed, public_key) = mlkem_client_key(parameter_set);
    let public = mlkem_public_with_key(
        parameter_set,
        TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        None,
        &public_key,
    );
    let handle = load_external(sim, public, Some(mlkem_sensitive(&seed)), Handle::RH_NULL)
        .unwrap_or_else(|rc| panic!("LoadExternal failed: {rc:#x}"));
    (handle, seed)
}

/// TPM2_Encapsulate on a TPM key returns a 32-byte shared secret and a ciphertext of the
/// parameter set's size, and TPM2_Decapsulate of that ciphertext returns the same secret.
#[cfg(all(feature = "cc-encapsulate", feature = "cc-decapsulate"))]
#[test]
fn encapsulate_then_decapsulate_agree() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (key, _) = mlkem_primary(&mut sim, parameter_set);
        let (shared_secret, ciphertext) = encapsulate(&mut sim, key).unwrap();
        assert_eq!(shared_secret.len(), MLKEM_SHARED_SECRET_BYTES);
        assert_eq!(ciphertext.len(), parameter_set.ct_bytes());
        assert_eq!(
            decapsulate(&mut sim, key, &ciphertext).unwrap(),
            shared_secret,
            "{parameter_set:?}"
        );
        flush_context(&mut sim, key).unwrap();
    }
}

/// TPM2_Decapsulate recovers the shared secret of a client-side encapsulation to the TPM key's
/// encapsulation key.
#[cfg(feature = "cc-decapsulate")]
#[test]
fn decapsulate_recovers_client_encapsulation() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (key, public) = mlkem_primary(&mut sim, parameter_set);
        let (_, public_key) = mlkem_public_key(&public);
        let (shared_secret, ciphertext) = mlkem_client_encapsulate(parameter_set, &public_key);
        assert_eq!(
            decapsulate(&mut sim, key, &ciphertext).unwrap(),
            shared_secret,
            "{parameter_set:?}"
        );
        flush_context(&mut sim, key).unwrap();
    }
}

/// TPM2_Encapsulate to a public-only key loaded from a client-side key pair produces a
/// ciphertext that the client decapsulates to the same shared secret.
#[cfg(feature = "cc-encapsulate")]
#[test]
fn encapsulate_to_public_only_key_matches_client_decapsulation() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (seed, public_key) = mlkem_client_key(parameter_set);
        let public = mlkem_public_with_key(
            parameter_set,
            TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
            None,
            &public_key,
        );
        let key = load_external(&mut sim, public, None, Handle::RH_OWNER).unwrap();
        let (shared_secret, ciphertext) = encapsulate(&mut sim, key).unwrap();
        assert_eq!(
            mlkem_client_decapsulate(parameter_set, &seed, &ciphertext),
            shared_secret,
            "{parameter_set:?}"
        );
        flush_context(&mut sim, key).unwrap();
    }
}

/// Every TPM2_Encapsulate draws fresh randomness: two encapsulations to the same key give
/// different ciphertexts and shared secrets.
#[cfg(feature = "cc-encapsulate")]
#[test]
fn encapsulate_uses_fresh_randomness() {
    let mut sim = Tpm::new();
    let (key, _) = mlkem_primary(&mut sim, TpmiMlkemParms::Mlkem512);
    let (first_secret, first_ciphertext) = encapsulate(&mut sim, key).unwrap();
    let (second_secret, second_ciphertext) = encapsulate(&mut sim, key).unwrap();
    assert_ne!(first_ciphertext, second_ciphertext);
    assert_ne!(first_secret, second_secret);
}

/// TPM2_Encapsulate needs no authorization and does not check the key's attributes: it works
/// with a key whose authValue is set and with a restricted (storage) ML-KEM key.
#[cfg(feature = "cc-encapsulate")]
#[test]
fn encapsulate_needs_no_authorization_and_ignores_attributes() {
    let mut sim = Tpm::new();
    let protected = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        mlkem_decryption_public(TpmiMlkemParms::Mlkem768),
        b"secret",
    );
    let (_, ciphertext) = encapsulate(&mut sim, protected).unwrap();
    assert_eq!(ciphertext.len(), 1088);
    let (storage, _) = create_primary_returning_public(
        &mut sim,
        mlkem_storage_public(TpmiMlkemParms::Mlkem1024),
        &[],
    );
    let (_, ciphertext) = encapsulate(&mut sim, storage).unwrap();
    assert_eq!(ciphertext.len(), 1568);
}

/// TPM2_Encapsulate with a key that is not a KEM key (RSA, ECC, keyed hash) fails with
/// TPM_RC_KEY + H1.
#[cfg(feature = "cc-encapsulate")]
#[test]
fn encapsulate_rejects_keys_that_are_not_kem_keys() {
    let mut sim = Tpm::new();
    let (rsa, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(TpmaObject::DECRYPT | sdo_user(), None),
        &[],
    );
    let (ecc, _) = create_primary_returning_public(
        &mut sim,
        ecc_public(TpmaObject::DECRYPT | sdo_user(), None, None),
        &[],
    );
    let (keyed_hash, _) = create_primary_returning_public(
        &mut sim,
        hmac_key_template(tpm2::TpmiAlgHash::Sha256),
        &[],
    );
    for key in [rsa, ecc, keyed_hash] {
        assert_eq!(
            encapsulate(&mut sim, key),
            Err(TpmRc::KEY.with(Position::handle(1)).get())
        );
    }
}

/// TPM2_Encapsulate with an ML-DSA key fails with TPM_RC_KEY + H1.
#[cfg(all(feature = "cc-encapsulate", feature = "mldsa"))]
#[test]
fn encapsulate_rejects_mldsa_key() {
    let mut sim = Tpm::new();
    let (key, _) = create_primary_returning_public(
        &mut sim,
        mldsa_signing_public(tpm2::TpmiMldsaParms::Mldsa44),
        &[],
    );
    assert_eq!(
        encapsulate(&mut sim, key),
        Err(TpmRc::KEY.with(Position::handle(1)).get())
    );
}

/// TPM2_Encapsulate to a public-only key whose encapsulation key fails the FIPS 203 modulus
/// check (a coefficient >= q) fails with a bare TPM_RC_PARMS; TPM2_LoadExternal accepts it.
#[cfg(feature = "cc-encapsulate")]
#[test]
fn encapsulate_rejects_invalid_encapsulation_key() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (_, mut public_key) = mlkem_client_key(parameter_set);
        // The first 12-bit coefficient becomes 0xFFF (4095 >= q = 3329).
        public_key[0] = 0xFF;
        public_key[1] |= 0x0F;
        let public = mlkem_public_with_key(
            parameter_set,
            TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
            None,
            &public_key,
        );
        let key = load_external(&mut sim, public, None, Handle::RH_OWNER).unwrap();
        assert_eq!(
            encapsulate(&mut sim, key),
            Err(rc_bare(TpmRc::PARMS)),
            "{parameter_set:?}"
        );
        flush_context(&mut sim, key).unwrap();
    }
}

/// TPM2_Encapsulate with an unloaded transient handle fails with TPM_RC_REFERENCE_H0.
#[cfg(feature = "cc-encapsulate")]
#[test]
fn encapsulate_rejects_unloaded_handle() {
    let mut sim = Tpm::new();
    assert_eq!(
        encapsulate(&mut sim, Handle(0x8000_0002)),
        Err(TpmRc::REFERENCE_H0.get())
    );
}

/// TPM2_Decapsulate with a key pair loaded from client-side seeds returns the shared secret
/// of a client-side encapsulation for every parameter set.
#[cfg(feature = "cc-decapsulate")]
#[test]
fn decapsulate_with_external_key_pair() {
    let mut sim = Tpm::new();
    for parameter_set in MLKEM_PARAMETER_SETS {
        let (key, seed) = external_key_pair(&mut sim, parameter_set);
        let public_key = mlkem_client_public_key(parameter_set, &seed);
        let (shared_secret, ciphertext) = mlkem_client_encapsulate(parameter_set, &public_key);
        assert_eq!(
            decapsulate(&mut sim, key, &ciphertext).unwrap(),
            shared_secret
        );
        flush_context(&mut sim, key).unwrap();
    }
}

/// TPM2_Decapsulate of a tampered ciphertext succeeds with ML-KEM's implicit rejection: the
/// shared secret differs from the original, is the same on every attempt and matches a
/// client-side decapsulation with the same seed.
#[cfg(feature = "cc-decapsulate")]
#[test]
fn decapsulate_rejects_tampered_ciphertext_implicitly() {
    let mut sim = Tpm::new();
    let parameter_set = TpmiMlkemParms::Mlkem768;
    let (key, seed) = external_key_pair(&mut sim, parameter_set);
    let public_key = mlkem_client_public_key(parameter_set, &seed);
    let (shared_secret, mut ciphertext) = mlkem_client_encapsulate(parameter_set, &public_key);
    ciphertext[10] ^= 0x01;
    let rejected = decapsulate(&mut sim, key, &ciphertext).unwrap();
    assert_ne!(rejected, shared_secret);
    assert_eq!(decapsulate(&mut sim, key, &ciphertext).unwrap(), rejected);
    assert_eq!(
        mlkem_client_decapsulate(parameter_set, &seed, &ciphertext),
        rejected
    );
}

/// TPM2_Decapsulate with a ciphertext that does not have the size of the key's parameter set
/// fails with a bare TPM_RC_PARMS.
#[cfg(feature = "cc-decapsulate")]
#[test]
fn decapsulate_rejects_ciphertext_of_wrong_size() {
    let mut sim = Tpm::new();
    let (key, _) = mlkem_primary(&mut sim, TpmiMlkemParms::Mlkem768);
    for size in [0usize, 1, 768, 1087, 1089, 1568] {
        assert_eq!(
            decapsulate(&mut sim, key, &vec![0x5A; size]),
            Err(rc_bare(TpmRc::PARMS)),
            "ciphertext of {size} bytes"
        );
    }
}

/// TPM2_Decapsulate with a restricted ML-KEM key (a storage key) fails with
/// TPM_RC_ATTRIBUTES + H1.
#[cfg(feature = "cc-decapsulate")]
#[test]
fn decapsulate_rejects_restricted_key() {
    let mut sim = Tpm::new();
    let (key, public) = create_primary_returning_public(
        &mut sim,
        mlkem_storage_public(TpmiMlkemParms::Mlkem512),
        &[],
    );
    let (_, public_key) = mlkem_public_key(&public);
    let (_, ciphertext) = mlkem_client_encapsulate(TpmiMlkemParms::Mlkem512, &public_key);
    assert_eq!(
        decapsulate(&mut sim, key, &ciphertext),
        Err(TpmRc::ATTRIBUTES.with(Position::handle(1)).get())
    );
}

/// TPM2_Decapsulate with an RSA decryption key fails with TPM_RC_KEY + H1.
#[cfg(feature = "cc-decapsulate")]
#[test]
fn decapsulate_rejects_key_that_is_not_kem_key() {
    let mut sim = Tpm::new();
    let (rsa, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(TpmaObject::DECRYPT | sdo_user(), None),
        &[],
    );
    assert_eq!(
        decapsulate(&mut sim, rsa, &[0; 768]),
        Err(TpmRc::KEY.with(Position::handle(1)).get())
    );
}

/// TPM2_Decapsulate requires the USER authorization of the key: a wrong password fails with
/// TPM_RC_BAD_AUTH + S1 (the key is noDA), the right one succeeds.
#[cfg(all(feature = "cc-encapsulate", feature = "cc-decapsulate"))]
#[test]
fn decapsulate_requires_user_authorization() {
    let mut sim = Tpm::new();
    let mut template = mlkem_decryption_public(TpmiMlkemParms::Mlkem512);
    template.object_attributes |= TpmaObject::NO_DA;
    let key = create_primary_with_auth_in(&mut sim, Handle::RH_OWNER, template, b"secret");
    let (shared_secret, ciphertext) = encapsulate(&mut sim, key).unwrap();
    assert_eq!(
        decapsulate_with_auth(&mut sim, key, &ciphertext, b"wrong"),
        Err(TpmRc::BAD_AUTH.with(Position::session(1)).get())
    );
    assert_eq!(
        decapsulate_with_auth(&mut sim, key, &ciphertext, b"secret").unwrap(),
        shared_secret
    );
}

/// TPM2_Decapsulate with a public-only ML-KEM key fails with TPM_RC_AUTH_UNAVAILABLE: the key
/// has no sensitive area, so no authValue to authorize the USER role with.
#[cfg(feature = "cc-decapsulate")]
#[test]
fn decapsulate_rejects_public_only_key() {
    let mut sim = Tpm::new();
    let (_, public_key) = mlkem_client_key(TpmiMlkemParms::Mlkem512);
    let public = mlkem_public_with_key(
        TpmiMlkemParms::Mlkem512,
        TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        None,
        &public_key,
    );
    let key = load_external(&mut sim, public, None, Handle::RH_OWNER).unwrap();
    let (_, ciphertext) = mlkem_client_encapsulate(TpmiMlkemParms::Mlkem512, &public_key);
    assert_eq!(
        decapsulate(&mut sim, key, &ciphertext),
        Err(TpmRc::AUTH_UNAVAILABLE.get())
    );
}
