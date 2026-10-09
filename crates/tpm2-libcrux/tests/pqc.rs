//! ML-KEM and ML-DSA tests. The known-answer hashes were computed with
//! OpenSSL 3.6 from the same seeds.

use hex_literal::hex;
use tpm2::crypto::{
    CryptoError, Mldsa, MldsaMessage, MldsaPrivateKey, MldsaPublicKey, Mlkem, MlkemPrivateKey,
    MlkemPublicKey, Random, hash,
};
use tpm2::{
    Tpm2b, Tpm2bKemCiphertext, Tpm2bPublicKeyMldsa, Tpm2bPublicKeyMlkem, Tpm2bSignatureCtx,
    Tpm2bSignatureMldsa, TpmiAlgHash, TpmiMldsaParms, TpmiMlkemParms,
};
use tpm2_libcrux::Libcrux;

const C: Libcrux = Libcrux::new();

const MESSAGE: &[u8] = b"tpm2-libcrux";

const MLKEM: [TpmiMlkemParms; 3] = [
    TpmiMlkemParms::Mlkem512,
    TpmiMlkemParms::Mlkem768,
    TpmiMlkemParms::Mlkem1024,
];

const MLDSA: [TpmiMldsaParms; 3] = [
    TpmiMldsaParms::Mldsa44,
    TpmiMldsaParms::Mldsa65,
    TpmiMldsaParms::Mldsa87,
];

/// Returns the seed `0, 1, 2, ...`.
fn counting<const N: usize>() -> [u8; N] {
    core::array::from_fn(|i| u8::try_from(i).unwrap())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 64];
    let digest = hash(&C, TpmiAlgHash::Sha256, data, &mut out).unwrap();
    digest.digest().try_into().unwrap()
}

#[test]
fn mlkem_known_answers() {
    // SHA-256 of the encapsulation keys OpenSSL derives from the seed
    // `(d || z) = 0, 1, ..., 63`.
    let expected = [
        hex!("3ae268dccc5456ac0d0f9b39257dc48fe081383b97c400512d712b739762daee"),
        hex!("0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"),
        hex!("c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530"),
    ];
    let seed = counting::<64>();
    for (set, expected) in MLKEM.into_iter().zip(expected) {
        let private = Mlkem::derive_key(&C, set, Tpm2b(&seed)).unwrap();
        let mut out = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        let public = private.public_key().encoded(&mut out).unwrap();
        assert_eq!(public.as_slice().len(), set.pub_key_bytes(), "{set:?}");
        assert_eq!(sha256(public.as_slice()), expected, "{set:?}");
        let mut out = [0u8; 64];
        assert_eq!(*private.seed(&mut out).unwrap().0, seed);
    }
}

#[test]
fn mlkem_round_trip() {
    let mut rng = C.rng_seeded(b"mlkem").unwrap();
    for set in MLKEM {
        let private = Mlkem::generate_key(&C, &mut rng, set).unwrap();
        assert_eq!(private.public_key().parameter_set(), set);

        // Reload the key pair from its encoding and seed. Only `d` determines
        // the encapsulation key.
        let mut out = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        let encoded = private.public_key().encoded(&mut out).unwrap();
        let load = || Mlkem::load_public(&C, set, encoded).unwrap().unwrap();
        let mut seed = [0u8; 64];
        let seed = *private.seed(&mut seed).unwrap().0;
        let reloaded = Mlkem::load_private(&C, load(), Tpm2b(&seed));
        let reloaded = reloaded.unwrap().unwrap();
        let mut wrong = seed;
        wrong[0] ^= 1;
        let wrong = Mlkem::load_private(&C, load(), Tpm2b(&wrong));
        assert!(wrong.unwrap().is_none(), "{set:?}");

        let mut ct = [0u8; TpmiMlkemParms::MAX_CT_BYTES];
        let mut ss = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
        let (ciphertext, secret) =
            Mlkem::encapsulate(&C, &mut rng, &load(), &mut ct, &mut ss).unwrap();
        assert_eq!(ciphertext.as_slice().len(), set.ct_bytes(), "{set:?}");
        for key in [&private, &reloaded] {
            let mut out = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
            let decapsulated = Mlkem::decapsulate(&C, key, ciphertext, &mut out);
            assert_eq!(decapsulated, Ok(Some(secret)), "{set:?}");
        }

        // A modified ciphertext gives a different (implicit rejection) secret,
        // and one of the wrong length is rejected.
        let mut tampered = ciphertext.as_slice().to_vec();
        tampered[0] ^= 1;
        let mut out = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
        let ciphertext = Tpm2bKemCiphertext::new(&tampered).unwrap();
        let rejected = Mlkem::decapsulate(&C, &private, ciphertext, &mut out).unwrap();
        assert!(
            rejected.is_some_and(|rejected| rejected != secret),
            "{set:?}"
        );
        let ciphertext = Tpm2bKemCiphertext::new(&tampered[1..]).unwrap();
        let rejected = Mlkem::decapsulate(&C, &private, ciphertext, &mut out);
        assert_eq!(rejected, Ok(None), "{set:?}");

        // Encapsulation keys of the wrong length, or with coefficients that
        // aren't reduced modulo q.
        let ff = vec![0xff; set.pub_key_bytes()];
        for key in [&encoded.as_slice()[1..], &ff[..]] {
            let key = Tpm2bPublicKeyMlkem::new(key).unwrap();
            assert!(
                Mlkem::load_public(&C, set, key).unwrap().is_none(),
                "{set:?}"
            );
        }
    }
}

#[test]
fn mldsa_known_answers() {
    // SHA-256 of the public keys OpenSSL derives from the seed
    // `ξ = 0, 1, ..., 31`.
    let expected = [
        hex!("9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46"),
        hex!("d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9"),
        hex!("91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd"),
    ];
    let seed = counting::<32>();
    for (set, expected) in MLDSA.into_iter().zip(expected) {
        let private = Mldsa::derive_key(&C, set, Tpm2b(&seed)).unwrap();
        let mut out = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let public = private.public_key().encoded(&mut out).unwrap();
        assert_eq!(public.as_slice().len(), set.pub_key_bytes(), "{set:?}");
        assert_eq!(sha256(public.as_slice()), expected, "{set:?}");
        let mut out = [0u8; 32];
        assert_eq!(*private.seed(&mut out).unwrap().0, seed);
    }
}

#[test]
fn mldsa_sign_verify() {
    let mut rng = C.rng_seeded(b"mldsa").unwrap();
    let context = Tpm2bSignatureCtx::new(b"context").unwrap();
    let other = Tpm2bSignatureCtx::new(b"other").unwrap();
    let (mut d1, mut d2) = ([0u8; 64], [0u8; 64]);
    let sha256 = hash(&C, TpmiAlgHash::Sha256, MESSAGE, &mut d1).unwrap();
    let sha512 = hash(&C, TpmiAlgHash::Sha512, MESSAGE, &mut d2).unwrap();
    // A signature over one of the first three messages only verifies with
    // that message.
    let messages = [
        MldsaMessage::Pure {
            context,
            message: MESSAGE,
        },
        MldsaMessage::Pure {
            context: Tpm2bSignatureCtx::default(),
            message: MESSAGE,
        },
        MldsaMessage::PreHash {
            context,
            digest: sha256,
        },
        MldsaMessage::Pure {
            context: other,
            message: MESSAGE,
        },
        MldsaMessage::Pure {
            context,
            message: b"other",
        },
        MldsaMessage::PreHash {
            context: other,
            digest: sha256,
        },
        MldsaMessage::PreHash {
            context,
            digest: sha512,
        },
    ];
    for set in MLDSA {
        let private = Mldsa::generate_key(&C, &mut rng, set).unwrap();
        assert_eq!(private.public_key().parameter_set(), set);
        let mut out = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let encoded = private.public_key().encoded(&mut out).unwrap();
        let public = Mldsa::load_public(&C, set, encoded).unwrap().unwrap();

        for (i, &message) in messages[..3].iter().enumerate() {
            let mut out = [0u8; TpmiMldsaParms::MAX_SIG_BYTES];
            let signature = Mldsa::sign(&C, &mut rng, &private, message, &mut out);
            let signature = signature.unwrap().unwrap();
            assert_eq!(signature.as_slice().len(), set.sig_bytes(), "{set:?}");
            for (j, &message) in messages.iter().enumerate() {
                let valid = Mldsa::verify(&C, &public, message, signature);
                assert_eq!(valid, Ok(i == j), "{set:?} {i} {j}");
            }
            let truncated = Tpm2bSignatureMldsa::new(&signature.as_slice()[1..]).unwrap();
            let valid = Mldsa::verify(&C, &public, message, truncated);
            assert_eq!(valid, Ok(false), "{set:?}");
        }
    }
}

#[test]
fn mldsa_keys() {
    let mut rng = C.rng_seeded(b"mldsa").unwrap();
    for set in MLDSA {
        let private = Mldsa::generate_key(&C, &mut rng, set).unwrap();
        let mut out = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let encoded = private.public_key().encoded(&mut out).unwrap();
        let load = || Mldsa::load_public(&C, set, encoded).unwrap().unwrap();

        // Reload the private key from its seed.
        let mut seed = [0u8; 32];
        let seed = *private.seed(&mut seed).unwrap().0;
        let reloaded = Mldsa::load_private(&C, load(), Tpm2b(&seed));
        assert!(reloaded.unwrap().is_some(), "{set:?}");
        let mut wrong = seed;
        wrong[0] ^= 1;
        let wrong = Mldsa::load_private(&C, load(), Tpm2b(&wrong));
        assert!(wrong.unwrap().is_none(), "{set:?}");

        // A public key of the wrong length.
        let short = Tpm2bPublicKeyMldsa::new(&encoded.as_slice()[1..]).unwrap();
        assert!(
            Mldsa::load_public(&C, set, short).unwrap().is_none(),
            "{set:?}"
        );

        // libcrux can't sign or verify an external `µ`, or compute it
        // incrementally.
        let mu = [0u8; TpmiMldsaParms::MU_BYTES];
        let message = MldsaMessage::ExternalMu(&mu);
        let mut out = [0u8; TpmiMldsaParms::MAX_SIG_BYTES];
        let signature = Mldsa::sign(&C, &mut rng, &private, message, &mut out);
        assert_eq!(signature, Err(CryptoError::Unsupported));
        let signature = Tpm2bSignatureMldsa::new(&out[..set.sig_bytes()]).unwrap();
        let valid = Mldsa::verify(&C, &load(), message, signature);
        assert_eq!(valid, Err(CryptoError::Unsupported));
        let mu = Mldsa::mu_start(&C, &load(), Tpm2bSignatureCtx::default());
        assert!(matches!(mu, Err(CryptoError::Unsupported)));
    }
}
