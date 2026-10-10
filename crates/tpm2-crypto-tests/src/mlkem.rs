//! Tests for [`Mlkem`].

use tpm2::{
    Tpm2b, Tpm2bKemCiphertext, Tpm2bPublicKeyMlkem, TpmiMlkemParms,
    crypto::{Mlkem, MlkemPrivateKey, MlkemPublicKey},
};

use crate::{
    Caps, Check, expect_support,
    util::{MLKEM, assert_bytes, flip, seeded_rng},
    vectors::mlkem as kat,
};

/// Returns the encoded encapsulation key of `key`.
pub(crate) fn encoded<K: MlkemPublicKey>(key: &K) -> Vec<u8> {
    let mut out = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
    key.encoded(&mut out)
        .check("MlkemPublicKey::encoded")
        .as_slice()
        .to_vec()
}

/// Returns the 64-byte `(d || z)` seed of `key`.
pub(crate) fn seed<K: MlkemPrivateKey>(key: &K) -> [u8; 64] {
    let mut out = [0u8; 64];
    let s = key.seed(&mut out).check("MlkemPrivateKey::seed");
    *s.0
}

/// Derives a key pair from `seed`, or returns `None` if `parms` is
/// (correctly) unsupported.
pub(crate) fn derive<C: Mlkem>(
    c: &C,
    caps: &Caps,
    parms: TpmiMlkemParms,
    seed: &[u8; 64],
) -> Option<C::PrivateKey> {
    let result = Mlkem::derive_key(c, parms, Tpm2b(seed));
    expect_support(caps.mlkem.contains(&parms), format!("{parms:?}"), result)
}

/// Loads an encoded encapsulation key, returning `None` if it is rejected.
pub(crate) fn load_public<C: Mlkem>(
    c: &C,
    parms: TpmiMlkemParms,
    bytes: &[u8],
) -> Option<C::PublicKey> {
    let ek = Tpm2bPublicKeyMlkem::new(bytes).expect("ML-KEM public key too long");
    Mlkem::load_public(c, parms, ek).check("Mlkem::load_public")
}

/// Encapsulates to `key`, returning `(ciphertext, shared_secret)`.
pub(crate) fn encapsulate<C: Mlkem>(
    c: &C,
    rng: &mut C::Rng,
    key: &C::PublicKey,
) -> (Vec<u8>, Vec<u8>) {
    let mut ct_buf = [0u8; TpmiMlkemParms::MAX_CT_BYTES];
    let mut ss_buf = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
    let (ct, ss) =
        Mlkem::encapsulate(c, rng, key, &mut ct_buf, &mut ss_buf).check("Mlkem::encapsulate");
    (ct.as_slice().to_vec(), ss.as_slice().to_vec())
}

/// Decapsulates `ciphertext`, returning `None` if it has the wrong length.
pub(crate) fn decapsulate<C: Mlkem>(
    c: &C,
    key: &C::PrivateKey,
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let ct = Tpm2bKemCiphertext::new(ciphertext).expect("ML-KEM ciphertext too long");
    let mut ss_buf = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
    Mlkem::decapsulate(c, key, ct, &mut ss_buf)
        .check("Mlkem::decapsulate")
        .map(|ss| ss.as_slice().to_vec())
}

/// NIST ACVP `ML-KEM-keyGen-FIPS203` known answers for ML-KEM-512, ML-KEM-768,
/// and ML-KEM-1024.
pub fn mlkem_keygen_kat<C: Mlkem>(c: &C, caps: &Caps) {
    for (parms, seed_bytes, expected_ek) in kat::KEYGEN {
        let Some(private) = derive(c, caps, parms, &seed_bytes) else {
            continue;
        };
        let public = private.public_key();
        assert_eq!(public.parameter_set(), parms);
        assert_bytes(&seed(&private), &seed_bytes, format!("{parms:?} seed"));
        assert_bytes(
            &encoded(public),
            expected_ek,
            format!("{parms:?} encapsulation key"),
        );
    }
}

/// Key generation, public key reload, and encapsulation/decapsulation
/// round-trip for every parameter set, including implicit rejection on a
/// corrupted ciphertext.
pub fn mlkem_roundtrip<C: Mlkem>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "mlkem_roundtrip");
    for &parms in MLKEM {
        let result = Mlkem::generate_key(c, &mut rng, parms);
        let Some(key) = expect_support(caps.mlkem.contains(&parms), format!("{parms:?}"), result)
        else {
            continue;
        };
        assert_eq!(key.public_key().parameter_set(), parms);
        let ek = encoded(key.public_key());
        assert_eq!(
            ek.len(),
            parms.pub_key_bytes(),
            "{parms:?}: public key length"
        );

        let reloaded = load_public(c, parms, &ek).expect("generated encapsulation key rejected");
        assert_eq!(reloaded.parameter_set(), parms);
        assert_bytes(
            &encoded(&reloaded),
            &ek,
            format!("{parms:?} reloaded public key"),
        );

        let (ct1, ss1) = encapsulate(c, &mut rng, &reloaded);
        assert_eq!(ct1.len(), parms.ct_bytes(), "{parms:?}: ciphertext length");
        assert_eq!(
            ss1.len(),
            TpmiMlkemParms::SHARED_SECRET_BYTES,
            "{parms:?}: shared secret length"
        );

        // Encapsulation is randomized.
        let (ct2, ss2) = encapsulate(c, &mut rng, &reloaded);
        assert_ne!(
            ct1, ct2,
            "{parms:?}: encapsulation produced identical ciphertexts"
        );
        assert_ne!(
            ss1, ss2,
            "{parms:?}: encapsulation produced identical shared secrets"
        );

        let dec1 = decapsulate(c, &key, &ct1).expect("valid ciphertext rejected");
        assert_bytes(&dec1, &ss1, format!("{parms:?} decapsulation 1"));
        let dec2 = decapsulate(c, &key, &ct2).expect("valid ciphertext rejected");
        assert_bytes(&dec2, &ss2, format!("{parms:?} decapsulation 2"));

        // Corrupted ciphertext of the right length is implicitly rejected with
        // a pseudorandom secret different from the encapsulated one.
        let corrupted = flip(&ct1, 0);
        let rejected = decapsulate(c, &key, &corrupted).expect("implicit rejection returned None");
        assert_eq!(rejected.len(), TpmiMlkemParms::SHARED_SECRET_BYTES);
        assert_ne!(
            rejected, ss1,
            "{parms:?}: corrupted ciphertext yielded the same secret"
        );
    }
}

/// Ciphertexts of the wrong length are rejected with `Ok(None)`.
pub fn mlkem_decapsulate_rejects<C: Mlkem>(c: &C, caps: &Caps) {
    for (parms, seed_bytes, _) in kat::KEYGEN {
        let Some(key) = derive(c, caps, parms, &seed_bytes) else {
            continue;
        };
        let len = parms.ct_bytes();
        assert!(
            decapsulate(c, &key, &[]).is_none(),
            "{parms:?}: empty ciphertext accepted"
        );
        assert!(
            decapsulate(c, &key, &vec![0u8; len - 1]).is_none(),
            "{parms:?}: short ciphertext accepted"
        );
        if len < Tpm2bKemCiphertext::CAP {
            assert!(
                decapsulate(c, &key, &vec![0u8; len + 1]).is_none(),
                "{parms:?}: long ciphertext accepted"
            );
        }
    }
}

/// Malformed encapsulation keys (wrong length or failing the FIPS 203 Section
/// 7.2 modulus check) are rejected with `Ok(None)`.
pub fn mlkem_load_public_rejects<C: Mlkem>(c: &C, caps: &Caps) {
    for (parms, _, ek) in kat::KEYGEN {
        let probe = Tpm2bPublicKeyMlkem::new(ek).expect("valid key");
        let result = Mlkem::load_public(c, parms, probe);
        let Some(loaded) =
            expect_support(caps.mlkem.contains(&parms), format!("{parms:?}"), result)
        else {
            continue;
        };
        assert!(loaded.is_some(), "{parms:?}: valid KAT key rejected");

        // Wrong lengths.
        assert!(
            load_public(c, parms, &[]).is_none(),
            "{parms:?}: empty key accepted"
        );
        assert!(
            load_public(c, parms, &ek[..ek.len() - 1]).is_none(),
            "{parms:?}: short key accepted"
        );
        if ek.len() < Tpm2bPublicKeyMlkem::CAP {
            let long = [ek, &[0x00]].concat();
            assert!(
                load_public(c, parms, &long).is_none(),
                "{parms:?}: long key accepted"
            );
        }

        // Modulus check failure: the first 12-bit coefficient is 0xFFF = 4095 >= q (3329).
        let mut unreduced = ek.to_vec();
        unreduced[0] = 0xFF;
        unreduced[1] = 0xFF;
        unreduced[2] = 0xFF;
        assert!(
            load_public(c, parms, &unreduced).is_none(),
            "{parms:?}: key with coefficient >= q accepted"
        );
    }
}

/// [`Mlkem::load_private`] accepts the matching `(d || z)` seed and rejects a
/// seed whose `d` derives a different encapsulation key with `Ok(None)`.
pub fn mlkem_load_private<C: Mlkem>(c: &C, caps: &Caps) {
    for (parms, seed_bytes, ek) in kat::KEYGEN {
        if !caps.mlkem.contains(&parms) {
            continue;
        }
        let public = load_public(c, parms, ek).expect("valid KAT key rejected");
        let private = Mlkem::load_private(c, public, Tpm2b(&seed_bytes))
            .check("Mlkem::load_private")
            .expect("matching seed rejected");
        assert_bytes(
            &seed(&private),
            &seed_bytes,
            format!("{parms:?} loaded seed"),
        );
        assert_bytes(
            &encoded(private.public_key()),
            ek,
            format!("{parms:?} loaded public key"),
        );

        // Flipping a bit in `d` (the first 32 bytes) derives a different public key.
        let mut bad_seed = seed_bytes;
        bad_seed[0] ^= 0x01;
        let public = load_public(c, parms, ek).expect("valid KAT key rejected");
        let rejected =
            Mlkem::load_private(c, public, Tpm2b(&bad_seed)).check("Mlkem::load_private");
        assert!(rejected.is_none(), "{parms:?}: mismatched seed accepted");
    }
}
