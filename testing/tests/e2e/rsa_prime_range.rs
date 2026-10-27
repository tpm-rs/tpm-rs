//! The range of RSA primes: TPM 2.0 Part 1, "RSA", "Introduction": "The TPM will also validate
//! that the provided and computed prime factors are in an acceptable range. To be acceptable,
//! the square of the prime is required to have the same number of significant bits as the
//! public modulus." A key whose provided prime `P` or computed prime `Q = N / P` is out of that
//! range is a binding error wherever a sensitive area is loaded or validated.

use crate::_common::{
    create_and_load, ecc_storage_template_with, hx, import, leak_bytes, load, load_external,
    marshal_to_vec, owner_srk,
};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bPrivate,
    Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsRsaParms,
    TpmtPublic, TpmtRsaScheme, TpmtSensitive, TpmuSensitiveComposite,
};

/// An RSA-1024 key whose primes both have 512 bits, but the square of `P` has only 1023:
/// `(N, P, Q)`.
fn short_square_key() -> (&'static [u8], &'static [u8], &'static [u8]) {
    (
        leak_bytes(&hx(concat!(
            "85ccdf2ad9771c603812a391733b0d1cd87fb014be4f319a7c33772e5393fb9b",
            "9a9dffde1a99b401d65bca29750c10db238724a4ad70e726ea39aac99ccc9c5d",
            "4fadc0663b23cbb5cfe9118d337154bf9ddd99476efd84bdbfa76fc1ba24e8e8",
            "6b6203a516859af7f6b2d9aa7db92056818cf136c6026a8a5f57ac078af936d5"
        ))),
        leak_bytes(&hx(concat!(
            "8cd2c4ddf6312c583c79771d5db2b61211fb90d6fe609721bb563ddd2b1d0734",
            "a7b725871940760f9a5445b4a00d889a9ec3c538cf673f12885e1007377468ef"
        ))),
        leak_bytes(&hx(concat!(
            "f33ba31a84759c002045852e8c16c6b8f3eeb4f038fe98052819fb4044ae7abb",
            "299dd590f117a39a2bfe7b3ee31d4f0080c54f5aa62220ba755d5fd89869f47b"
        ))),
    )
}

/// An RSA-1024 key whose provided prime `P` is in range, but `Q = N / P` has 513 bits: `(N, P)`.
fn long_cofactor_key_1024() -> (&'static [u8], &'static [u8]) {
    (
        leak_bytes(&hx(concat!(
            "c2e18a1ebf9bdb7542a04db391071db525ae32db63144bf30744b4b83de713b6",
            "a53850948059a21f890c812f8b514b0180562f6bf8d0cd46b032cccb7a644850",
            "3ee6f65b0811c022e8a76138ed21aaad7b4a5b962bb22ccd83b526fe5e52b385",
            "e2d535d825362903fec57efa7f03d46181a2e411b1e00c52e3474f961e551a03"
        ))),
        leak_bytes(&hx(concat!(
            "b999c7ce312533703190a6a0ac8a83f81934fd0185f4c4be95382c8d40155e51",
            "f6e044b75b7727a1bee26e837171d3a03b5a5e43ef63d6dee4775adf11fe0d33"
        ))),
    )
}

/// An RSA-2048 key whose provided prime `P` is in range, but `Q = N / P` has 1025 bits: `(N, P)`.
fn long_cofactor_key_2048() -> (&'static [u8], &'static [u8]) {
    (
        leak_bytes(&hx(concat!(
            "c2eb5cfdc0f1af0df8a4ff3b7418dec057bd05dc69fe19c893acb448ec62d8b4",
            "78c93e8916531fbdbf962324d868cd72003755f2fef952acbf046b12849af958",
            "c19cb8f13d746ebbbaf6c28435a727b8c598168c47ddc7f45823510420f11b47",
            "29dc0cc8f9402ebad4ed543312f158c469a9c03ce6ca77d67046e06594a0404b",
            "06ea7d21f495a9d09f4dceb9d1f2da1e22508002965f818ef28d886cde185be3",
            "d9e907c629843bf5e3f39c466b35bdcfa7c0435a0b35ca9a686687a4f85507f6",
            "3a539ec709501372bb985fb76c63225e05737fc1b06abe12da1581dcb8ce1044",
            "f600cb7bc804a656523398865d5f4713dd08ba821a4aa12e727a0a2b258e0e05"
        ))),
        leak_bytes(&hx(concat!(
            "b99b56d0fe84358be22db7132cdf318acc644df2aed81cefceaa1c596e1b3fcf",
            "3a3d4cfc8beba5e6bf4c7e735b6f335a2607eeec0d8db59ba19744d674135106",
            "cdf89e2c85803ad5ebdf1042a8475a81ec87af4615702fd84ec8dbba0f6beb72",
            "3ba45dad276832cb5a4bcf83237ebaf3e4f5cbf6f5edfbdb9183c099aa9adcdb"
        ))),
    )
}

/// The public area of a duplicable RSASSA signing key with modulus `n`.
fn public(n: &'static [u8]) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(8 * n.len() as u16),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(n).unwrap(),
        ),
    }
}

/// The sensitive area with the prime `p`.
fn sensitive(p: &'static [u8]) -> TpmtSensitive<'static> {
    TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(p).unwrap()),
    }
}

/// A plaintext (unwrapped) duplicate with the prime `p`.
fn plain_duplicate(p: &'static [u8]) -> Tpm2bPrivate<'static> {
    let marshaled = marshal_to_vec(&sensitive(p));
    let mut blob = (marshaled.len() as u16).to_be_bytes().to_vec();
    blob.extend(marshaled);
    Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap()
}

/// `TPM2_LoadExternal` rejects a provided prime whose square is one bit short, and the other
/// prime of the same key (then the computed prime is out of range), with `TPM_RC_BINDING`.
#[test]
fn load_external_rejects_prime_with_short_square() {
    let mut sim = Tpm::new();
    let (n, p, q) = short_square_key();
    for prime in [p, q] {
        assert_eq!(
            load_external(&mut sim, public(n), Some(sensitive(prime)), Handle::RH_NULL),
            Err(TpmRc::BINDING.to_rc().get())
        );
    }
}

/// `TPM2_LoadExternal` rejects a key whose computed prime has one bit more than half the
/// modulus with `TPM_RC_BINDING` (RSA-1024 and RSA-2048).
#[test]
fn load_external_rejects_long_cofactor() {
    let mut sim = Tpm::new();
    for (n, p) in [long_cofactor_key_1024(), long_cofactor_key_2048()] {
        assert_eq!(
            load_external(&mut sim, public(n), Some(sensitive(p)), Handle::RH_NULL),
            Err(TpmRc::BINDING.to_rc().get()),
            "RSA-{}",
            8 * n.len()
        );
    }
}

/// `TPM2_Import` under a fixedTPM parent validates the key (as if loaded) and rejects out-of-range
/// primes with `TPM_RC_BINDING`; under a parent that is not fixedTPM, the duplicate is imported
/// unvalidated and `TPM2_Load` rejects it.
#[test]
fn import_rejects_out_of_range_primes() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let other = create_and_load(
        &mut sim,
        srk,
        ecc_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    )
    .0;
    let (n_short, p_short, _) = short_square_key();
    let keys = [
        (n_short, p_short),
        long_cofactor_key_1024(),
        long_cofactor_key_2048(),
    ];
    for (n, p) in keys {
        let label = format!("RSA-{}", 8 * n.len());
        assert_eq!(
            import(
                &mut sim,
                srk,
                Tpm2b(public(n)),
                plain_duplicate(p),
                Tpm2bEncryptedSecret::default(),
            ),
            Err(TpmRc::BINDING.to_rc().get()),
            "{label} under a fixedTPM parent"
        );
        let private = import(
            &mut sim,
            other,
            Tpm2b(public(n)),
            plain_duplicate(p),
            Tpm2bEncryptedSecret::default(),
        )
        .expect("Import under a parent that is not fixedTPM");
        assert_eq!(
            load(&mut sim, other, private, Tpm2b(public(n))),
            Err(TpmRc::BINDING.to_rc().get()),
            "{label} loaded under a parent that is not fixedTPM"
        );
    }
}
