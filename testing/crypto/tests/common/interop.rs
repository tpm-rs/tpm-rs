//! Interoperability tests between two crypto backends `A` and `B`, defined by
//! the including test target.
//!
//! Each test checks both directions (`A` to `B` and `B` to `A`). A case for an
//! algorithm, key size, curve, parameter set, or scheme which either backend
//! doesn't implement is skipped if the operation selecting it returns
//! `Err(CryptoError::Unsupported)` (see [`supported`]). Any other error, or a
//! wrong result, fails the test.

use super::{A, B};
use testing_crypto::supported;
use tpm2::{
    TpmEccCurve, TpmiAlgHash, TpmiMldsaParms, TpmiMlkemParms, TpmiRsaKeyBits, TpmtEccScheme,
    TpmtSigScheme, TpmtSignature,
    crypto::{
        Crypto, EccPrivateKey, EccPublicKey, MAX_ECC_COORD_BYTES, MAX_SIGNATURE_BYTES,
        MldsaPrivateKey, MldsaPublicKey, MlkemPrivateKey, MlkemPublicKey, RsaEncryptScheme,
        RsaPrivateKey, RsaPublicKey,
    },
};

const WEIERSTRASS_CURVES: [TpmEccCurve; 11] = [
    TpmEccCurve::NistP192,
    TpmEccCurve::NistP224,
    TpmEccCurve::NistP256,
    TpmEccCurve::NistP384,
    TpmEccCurve::NistP521,
    TpmEccCurve::BNP256,
    TpmEccCurve::BNP638,
    TpmEccCurve::SM2P256,
    TpmEccCurve::BpP256R1,
    TpmEccCurve::BpP384R1,
    TpmEccCurve::BpP512R1,
];
const MLKEM_PARMS: [TpmiMlkemParms; 3] = [
    TpmiMlkemParms::Mlkem512,
    TpmiMlkemParms::Mlkem768,
    TpmiMlkemParms::Mlkem1024,
];
const MLDSA_PARMS: [TpmiMldsaParms; 3] = [
    TpmiMldsaParms::Mldsa44,
    TpmiMldsaParms::Mldsa65,
    TpmiMldsaParms::Mldsa87,
];

/// Loads the public part of `key` (from backend `X`) into backend `Y`, or
/// returns `None` if `Y` doesn't support the key's curve or scheme.
fn ecc_public<X: Crypto, Y: Crypto>(
    key: &EccPrivateKey<X>,
    scheme: Option<TpmtEccScheme>,
) -> Option<EccPublicKey<Y>> {
    let (mut x, mut y) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
    let point = key.point(&mut x, &mut y).unwrap();
    let public = supported(EccPublicKey::load(key.curve(), scheme, point))?;
    Some(public.expect("valid public key"))
}

/// Generates an RSA-2048 key in `X`, and loads its public key into `Y`.
fn rsa_keys<X: Crypto, Y: Crypto>(seed: &[u8]) -> Option<(RsaPrivateKey<X>, RsaPublicKey<Y>)> {
    let mut rng = X::from_seed(seed).unwrap();
    let key = supported(RsaPrivateKey::<X>::generate(
        &mut rng,
        TpmiRsaKeyBits::Rsa2048,
        0,
    ))?;
    let mut n = [0; 256];
    let n = key.modulus(&mut n).unwrap();
    let public = supported(RsaPublicKey::<Y>::load(key.bits(), key.exponent(), n))?;
    Some((key, public.expect("valid modulus")))
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/// RSASSA and RSAPSS signatures from `S` verify in `V`.
fn rsa_signatures<S: Crypto, V: Crypto>() {
    let Some((key, public)) = rsa_keys::<S, V>(b"rsa_signatures") else {
        return;
    };
    let mut rng = S::from_entropy().unwrap();
    let digest = [0x55; 32];
    for scheme in [
        TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256),
        TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256),
    ] {
        let mut buf = [0; MAX_SIGNATURE_BYTES];
        let sig = key.sign(&mut rng, scheme, &digest, &mut buf).unwrap();
        let verify = |digest: &[u8]| public.verify(digest, sig);
        assert!(verify(&digest).unwrap(), "{scheme:?}");
        assert!(!verify(&[0x56; 32]).unwrap(), "{scheme:?}");
    }
}

#[test]
fn rsa_signatures_interoperate() {
    rsa_signatures::<A, B>();
    rsa_signatures::<B, A>();
}

/// RSAES and OAEP ciphertexts from `E` decrypt in `D`.
fn rsa_encryption<E: Crypto, D: Crypto>() {
    let Some((key, public)) = rsa_keys::<D, E>(b"rsa_encryption") else {
        return;
    };
    let mut rng_e = E::from_entropy().unwrap();
    let mut rng_d = D::from_seed(b"rsa_encryption D").unwrap();
    let msg = b"secret payload";
    for scheme in [
        RsaEncryptScheme::Rsaes,
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha1,
            label: None,
        },
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha256,
            label: Some(c"INTEROP"),
        },
    ] {
        let mut ct = [0; 256];
        let ct = public.encrypt(&mut rng_e, scheme, msg, &mut ct).unwrap();
        let mut pt = [0; 256];
        let pt = key.decrypt(&mut rng_d, scheme, ct.unwrap().as_slice(), &mut pt);
        assert_eq!(pt.unwrap().unwrap().as_slice(), msg, "{scheme:?}");
    }
}

#[test]
fn rsa_encryption_interoperates() {
    rsa_encryption::<A, B>();
    rsa_encryption::<B, A>();
}

/// A private key generated in `G` loads (from its modulus and prime `p`) into
/// `L`, which can then sign for and decrypt from `G`.
fn rsa_private_key_import<G: Crypto, L: Crypto>() {
    let Some((key, public)) = rsa_keys::<G, L>(b"rsa_private_key_import") else {
        return;
    };
    let (mut n, mut p) = ([0; 256], [0; 128]);
    let n = key.modulus(&mut n).unwrap();
    let g_public = RsaPublicKey::<G>::load(key.bits(), key.exponent(), n)
        .unwrap()
        .unwrap();
    let imported = RsaPrivateKey::<L>::load(public, key.prime_p(&mut p).unwrap())
        .unwrap()
        .expect("valid prime");
    let mut rng_g = G::from_entropy().unwrap();
    let mut rng_l = L::from_entropy().unwrap();

    let digest = [0x55; 32];
    let scheme = TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256);
    let mut buf = [0; MAX_SIGNATURE_BYTES];
    let sig = imported.sign(&mut rng_l, scheme, &digest, &mut buf);
    assert!(g_public.verify(&digest, sig.unwrap()).unwrap());

    let scheme = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label: Some(c"INTEROP"),
    };
    let msg = b"secret payload";
    let mut ct = [0; 256];
    let ct = g_public.encrypt(&mut rng_g, scheme, msg, &mut ct).unwrap();
    let mut pt = [0; 256];
    let pt = imported.decrypt(&mut rng_l, scheme, ct.unwrap().as_slice(), &mut pt);
    assert_eq!(pt.unwrap().unwrap().as_slice(), msg);
}

#[test]
fn rsa_private_key_import_interoperates() {
    rsa_private_key_import::<A, B>();
    rsa_private_key_import::<B, A>();
}

// ---------------------------------------------------------------------------
// ECC
// ---------------------------------------------------------------------------

/// Signatures with `scheme` (`ECDSA` or `SM2`) from `S` verify in `V`, on
/// every Weierstrass curve.
fn ecc_signatures<S: Crypto, V: Crypto>(scheme: TpmtSigScheme) {
    let mut rng = S::from_entropy().unwrap();
    let digest = [0x44; 32];
    for curve in WEIERSTRASS_CURVES {
        let Some(key) = supported(EccPrivateKey::<S>::generate(&mut rng, curve, None)) else {
            continue;
        };
        let Some(public) = ecc_public::<S, V>(&key, None) else {
            continue;
        };
        let mut buf = [0; MAX_SIGNATURE_BYTES];
        let Some(sig) = supported(key.sign(&mut rng, scheme, &digest, &mut buf)) else {
            continue;
        };
        let Some(valid) = supported(public.verify(&digest, sig)) else {
            continue;
        };
        assert!(valid, "{curve:?} {scheme:?}");
        let valid = public.verify(&[0x45; 32], sig);
        assert!(!valid.unwrap(), "{curve:?} {scheme:?}");
    }
}

#[test]
fn ecdsa_signatures_interoperate() {
    let scheme = TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256);
    ecc_signatures::<A, B>(scheme);
    ecc_signatures::<B, A>(scheme);
}

#[test]
fn sm2_signatures_interoperate() {
    let scheme = TpmtSigScheme::Sm2(TpmiAlgHash::Sm3_256);
    ecc_signatures::<A, B>(scheme);
    ecc_signatures::<B, A>(scheme);
}

/// ECDH between keys from `X` and `Y` agrees, on every Weierstrass and
/// Montgomery (X25519, X448) curve.
fn ecdh<X: Crypto, Y: Crypto>() {
    let mut rng_x = X::from_seed(b"ecdh X").unwrap();
    let mut rng_y = Y::from_seed(b"ecdh Y").unwrap();
    let curves = WEIERSTRASS_CURVES
        .into_iter()
        .chain([TpmEccCurve::Curve25519, TpmEccCurve::Curve448]);
    for curve in curves {
        let Some(x) = supported(EccPrivateKey::<X>::generate(&mut rng_x, curve, None)) else {
            continue;
        };
        let Some(y) = supported(EccPrivateKey::<Y>::generate(&mut rng_y, curve, None)) else {
            continue;
        };
        let x_public = ecc_public::<X, Y>(&x, None).unwrap();
        let y_public = ecc_public::<Y, X>(&y, None).unwrap();
        let (mut xx, mut xy) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
        let (mut yx, mut yy) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
        let zx = x.ecdh(&y_public, &mut xx, &mut xy).unwrap();
        let zy = y.ecdh(&x_public, &mut yx, &mut yy).unwrap();
        assert_eq!(zx.unwrap(), zy.unwrap(), "{curve:?}");
    }
}

#[test]
fn ecdh_interoperates() {
    ecdh::<A, B>();
    ecdh::<B, A>();
}

/// EdDSA and HashEdDSA signatures from `S` verify in `V`, on Ed25519 and Ed448.
fn eddsa_signatures<S: Crypto, V: Crypto>() {
    let mut rng = S::from_seed(b"eddsa_signatures").unwrap();
    let scheme = Some(TpmtEccScheme::Eddsa);
    for curve in [TpmEccCurve::Curve25519, TpmEccCurve::Curve448] {
        let Some(key) = supported(EccPrivateKey::<S>::generate(&mut rng, curve, scheme)) else {
            continue;
        };
        let Some(public) = ecc_public::<S, V>(&key, scheme) else {
            continue;
        };

        // Pure EdDSA, with the message split differently.
        let mut buf = [0; MAX_SIGNATURE_BYTES];
        let msg: [&[u8]; 2] = [b"hello ", b"eddsa"];
        let sig = key.sign_message(&msg, &mut buf).unwrap();
        assert!(
            public.verify_message(&[b"hello eddsa"], sig).unwrap(),
            "{curve:?}"
        );
        assert!(
            !public.verify_message(&[b"wrong"], sig).unwrap(),
            "{curve:?}"
        );

        // HashEdDSA.
        let prehash = [0x5a; 64];
        let mut buf = [0; MAX_SIGNATURE_BYTES];
        let scheme = TpmtSigScheme::HashEddsa;
        let Some(sig) = supported(key.sign(&mut rng, scheme, &prehash, &mut buf)) else {
            continue;
        };
        let Some(valid) = supported(public.verify(&prehash, sig)) else {
            continue;
        };
        assert!(valid, "{curve:?}");
        assert!(!public.verify(&[0x5b; 64], sig).unwrap(), "{curve:?}");

        // A HashEdDSA signature isn't a pure EdDSA signature of the prehash.
        let TpmtSignature::HashEddsa(sig) = sig else {
            panic!("{sig:?}");
        };
        let sig = TpmtSignature::Eddsa(sig);
        assert!(
            !public.verify_message(&[&prehash], sig).unwrap(),
            "{curve:?}"
        );
    }
}

#[test]
fn eddsa_signatures_interoperate() {
    eddsa_signatures::<A, B>();
    eddsa_signatures::<B, A>();
}

// ---------------------------------------------------------------------------
// ML-KEM and ML-DSA
// ---------------------------------------------------------------------------

/// `E` encapsulates to an ML-KEM key from `D`, and `D` decapsulates the same
/// shared secret.
fn mlkem<E: Crypto, D: Crypto>() {
    let mut rng_e = E::from_entropy().unwrap();
    let mut rng_d = D::from_seed(b"mlkem D").unwrap();
    for parms in MLKEM_PARMS {
        let Some(key) = supported(MlkemPrivateKey::<D>::generate(&mut rng_d, parms)) else {
            continue;
        };
        let mut pk = [0; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        let pk = key.public(&mut pk).unwrap();
        let Some(public) = supported(MlkemPublicKey::<E>::load(parms, pk)) else {
            continue;
        };
        let public = public.expect("valid public key");
        let (mut ct, mut ss) = ([0; TpmiMlkemParms::MAX_CT_BYTES], [0; 32]);
        let (ct, ss) = public.encapsulate(&mut rng_e, &mut ct, &mut ss).unwrap();
        let mut ss2 = [0; 32];
        let ss2 = key.decapsulate(ct, &mut ss2).unwrap().unwrap();
        assert_eq!(ss2, ss, "{parms:?}");
    }
}

#[test]
fn mlkem_interoperates() {
    mlkem::<A, B>();
    mlkem::<B, A>();
}

/// External-µ ML-DSA, pure ML-DSA, and HashML-DSA signatures from `S` verify
/// in `V`.
fn mldsa_signatures<S: Crypto, V: Crypto>() {
    let mut rng = S::from_entropy().unwrap();
    for parms in MLDSA_PARMS {
        let Some(key) = supported(MldsaPrivateKey::<S>::generate(&mut rng, parms)) else {
            continue;
        };
        let mut pk = [0; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let pk = key.public(&mut pk).unwrap();
        let Some(public) = supported(MldsaPublicKey::<V>::load(parms, pk)) else {
            continue;
        };
        let public = public.expect("valid public key");
        let mut buf = [0; MAX_SIGNATURE_BYTES];

        // External µ (with an empty context).
        let mu = [0x42; 64];
        let sig = key.sign_mu(&mut rng, &mu, &mut buf).unwrap();
        assert!(public.verify(b"", &mu, sig).unwrap(), "{parms:?}");
        assert!(!public.verify(b"", &[0x43; 64], sig).unwrap(), "{parms:?}");

        // Pure ML-DSA, with the message split differently.
        for ctx in [&b""[..], b"tpm2 test context"] {
            let msg: [&[u8]; 2] = [b"hello ", b"world"];
            let sig = key.sign_message(&mut rng, ctx, &msg, &mut buf).unwrap();
            let verify = |ctx, msg: &[u8]| public.verify_message(ctx, &[msg], sig);
            assert!(verify(ctx, b"hello world").unwrap(), "{parms:?}");
            assert!(!verify(b"wrong ctx", b"hello world").unwrap(), "{parms:?}");
            assert!(!verify(ctx, b"wrong msg").unwrap(), "{parms:?}");
        }

        // HashML-DSA (SHA-256).
        let digest = [0xaa; 32];
        for ctx in [&b""[..], b"tpm2 test context"] {
            let sig = key
                .sign_prehash(&mut rng, TpmiAlgHash::Sha256, ctx, &digest, &mut buf)
                .unwrap();
            let verify = |ctx, digest: &[u8]| public.verify(ctx, digest, sig);
            assert!(verify(ctx, &digest).unwrap(), "{parms:?}");
            assert!(!verify(b"wrong ctx", &digest).unwrap(), "{parms:?}");
            assert!(!verify(ctx, &[0xab; 32]).unwrap(), "{parms:?}");

            // A HashML-DSA signature isn't a pure ML-DSA signature of
            // `OID || digest`.
            let TpmtSignature::HashMldsa(sig) = sig else {
                panic!("{sig:?}");
            };
            let sha256_oid = [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ];
            let msg = [&sha256_oid[..], &digest];
            let sig = TpmtSignature::Mldsa(sig.signature);
            let valid = public.verify_message(ctx, &msg, sig);
            assert!(!valid.unwrap(), "{parms:?}");
        }
    }
}

#[test]
fn mldsa_signatures_interoperate() {
    mldsa_signatures::<A, B>();
    mldsa_signatures::<B, A>();
}
