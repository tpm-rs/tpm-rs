//! ECC and ECDSA tests. The fixed keys and signatures were generated with
//! pyca/cryptography (OpenSSL).

use hex_literal::hex;
use tpm2::crypto::{
    CryptoError, Ecc, EccPrivateKey, EccPublicKey, Random, SignatureBuffer, SigningKey,
    VerifyingKey, hash, sign, verify,
};
use tpm2::{
    Tpm2bEccParameter, TpmEccCurve, TpmiAlgHash, TpmiRsaKeyBits, TpmsEccPoint, TpmsSchemeEcdaa,
    TpmsSignatureEcc, TpmtSigScheme, TpmtSignature,
};
use tpm2_libcrux::{EccPublic, Libcrux};

const C: Libcrux = Libcrux::new();

const MESSAGE: &[u8] = b"tpm2-libcrux";

/// The size of ECC coordinate and scalar buffers.
const MAX: usize = TpmEccCurve::MAX_ECC_KEY_BYTES;

const CURVES: [TpmEccCurve; 3] = [
    TpmEccCurve::NistP256,
    TpmEccCurve::NistP384,
    TpmEccCurve::NistP521,
];

/// A private key `d` with public point `(x, y)`, and ECDSA signatures
/// `(r, s)` of digests of [`MESSAGE`].
struct Vector {
    curve: TpmEccCurve,
    d: &'static [u8],
    x: &'static [u8],
    y: &'static [u8],
    signatures: [(TpmiAlgHash, &'static [u8], &'static [u8]); 2],
}

const VECTORS: [Vector; 3] = [
    Vector {
        curve: TpmEccCurve::NistP256,
        // The key from RFC 6979, Appendix A.2.5.
        d: &hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"),
        x: &hex!("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"),
        y: &hex!("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"),
        signatures: [
            (
                TpmiAlgHash::Sha1,
                &hex!("2182d640c8c57942489eae54ffb2f76570fe80264384e31262e4f0dc6f113773"),
                &hex!("fa84ad234d69bb70c9da75edfb59d8c9a1fe849ce852af0e4bc9f4a51b4d28f1"),
            ),
            (
                TpmiAlgHash::Sha512,
                &hex!("c945ed74547f842ede7bb3282ea77aa9500340e48b57c214329cea33e3342fb0"),
                &hex!("f058f01d6d0810a45cae7ebea219a346ce61e3769b6b1d4fc1c285fe87ff9346"),
            ),
        ],
    },
    Vector {
        curve: TpmEccCurve::NistP384,
        d: &hex!(
            "00936bf03ef6b28c00a40a4c8ccb257e361abe4387a57b62"
            "4b07b2c99cea67567cf6f196d13537b6728e766c8c4393cd"
        ),
        x: &hex!(
            "b68eaf97244feefc7b238bff88df4d332c3fada62782c49f"
            "d7dcf77628e72874c656eef40d19fed444b4df7a91f2b0a2"
        ),
        y: &hex!(
            "e409dcf650cae1bd98a203046bbcb9d056461fd7fbe318d3"
            "08e40d220677940d9e631edecfa8128c8652c3249f527c17"
        ),
        signatures: [
            (
                TpmiAlgHash::Sha256,
                &hex!(
                    "931ca46242c4d051aee3984c4a3c13fed110cc7a3c2fa608"
                    "a223638ee9c8f47e30d5fb51fefaea2929d958d3c6e09a56"
                ),
                &hex!(
                    "b6938066f441e6abb7526c8ea1db8706a18e63388a5ace4e"
                    "51cc27fdc75def30ae152215b53f4c37757911642d065b8a"
                ),
            ),
            (
                TpmiAlgHash::Sha512,
                &hex!(
                    "032810ffb39b70d1f53f22d4510f19b006ce4147cface8ef"
                    "6298fe6eb1a978340d5594c4bda26b3343342a64e759c496"
                ),
                &hex!(
                    "1c8790845a319e6edf26a358108598a5b579dcc16a901d1f"
                    "ae66f0d5df104e55481c542ba18da9d6e7eaa18370a887d3"
                ),
            ),
        ],
    },
    Vector {
        curve: TpmEccCurve::NistP521,
        d: &hex!(
            "000096d4b891f978200aa20bdf10f00207627635149507e085e44be8d4869bc630"
            "95928b07a01662f9f4d23ccdafbf17eea0d6b178257202cbac0301e6690004bd0a"
        ),
        x: &hex!(
            "003d4c493d45dde85b0e4803d2c89e8ec4dd9f1da15f4617ad6da7479e4fbc569f"
            "08523052429c6b8e154f9af1f421e90ff2016d774969d24c2e284bcaddf64d6176"
        ),
        y: &hex!(
            "0077e8b9ef4b02019d6f32aabef788cd2a98c3a903db79349aa06f523c2e07e2e9"
            "09a957e77a7c9e6c52a584725c1acf053e7e7a3090ffab20111a3cb3058abd6b1d"
        ),
        signatures: [
            (
                TpmiAlgHash::Sha256,
                &hex!(
                    "00a81e0d4f3cdea04e50ef91ed59d70b8128d544ca55d28ea4b8902b14e8a40e31"
                    "cd3b3218fb5f989ffdcacd6ed9714c90c40fb85c5e8d709b5cc7894a588399b957"
                ),
                &hex!(
                    "01780882aa78c8a3f26c050dbe2bb9e12c1e4a197a8e100d312d0f86b9a7ab4c53"
                    "2c8dbf43b0af4bb5b65b77159fe45eff47448178b41463e80467bce46148acd941"
                ),
            ),
            (
                TpmiAlgHash::Sha512,
                &hex!(
                    "01c80fb0b7f571b4b989f10334027485dd13bf6d4cf4c05b70401f7ff7be28c390"
                    "c70628564fedafcc36b898d702c943fb2173db2fd8d1f110299043a18d3c17f522"
                ),
                &hex!(
                    "016590df5008ab30e542ab03d8cade91bbc4d8834bf3c7f8d9c14c9fd5e2e7bc65"
                    "5b877e247a1e02561e2facc643710539fdc905eb9c91da9064bae1779c62597f2a"
                ),
            ),
        ],
    },
];

fn param(value: &[u8]) -> Tpm2bEccParameter<'_> {
    Tpm2bEccParameter::new(value).unwrap()
}

fn point<'a>(x: &'a [u8], y: &'a [u8]) -> TpmsEccPoint<'a> {
    TpmsEccPoint {
        x: param(x),
        y: param(y),
    }
}

fn load_public(curve: TpmEccCurve, x: &[u8], y: &[u8]) -> Option<EccPublic> {
    Ecc::load_public(&C, curve, point(x, y)).unwrap()
}

fn ecdsa<'a>(hash: TpmiAlgHash, r: &'a [u8], s: &'a [u8]) -> TpmtSignature<'a> {
    TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash,
        signature_r: param(r),
        signature_s: param(s),
    })
}

fn digest<'a>(alg: TpmiAlgHash, message: &[u8], out: &'a mut [u8; 64]) -> &'a [u8] {
    hash(&C, alg, message, out).unwrap().digest()
}

#[test]
fn ecdsa_openssl_vectors() {
    let mut rng = C.rng_seeded(b"ecdsa").unwrap();
    for v in &VECTORS {
        let public = load_public(v.curve, v.x, v.y).unwrap();
        assert_eq!(public.curve(), v.curve);
        let private = Ecc::load_private(&C, public, param(v.d)).unwrap().unwrap();
        let mut d = [0u8; MAX];
        assert_eq!(private.scalar(&mut d).unwrap().as_slice(), v.d);
        let (mut x, mut y) = ([0u8; MAX], [0u8; MAX]);
        let public = private.public_key().point(&mut x, &mut y);
        assert_eq!(public.unwrap(), point(v.x, v.y));

        for (alg, r, s) in v.signatures {
            let mut d = [0u8; 64];
            let digest = digest(alg, MESSAGE, &mut d);
            let key = || VerifyingKey::Ecc(private.public_key());
            let valid = verify(&C, key(), digest, ecdsa(alg, r, s));
            assert_eq!(valid, Ok(true), "{:?} {alg:?}", v.curve);
            let valid = verify(&C, key(), digest, ecdsa(alg, s, r));
            assert_eq!(valid, Ok(false), "{:?} {alg:?}", v.curve);

            // Our own signatures over the same digest verify too.
            let mut out: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
            let key = SigningKey::Ecc(&private);
            let scheme = TpmtSigScheme::Ecdsa(alg);
            let sig = sign(&C, &mut rng, key, scheme, digest, &mut out).unwrap();
            let key = VerifyingKey::Ecc(private.public_key());
            assert_eq!(
                verify(&C, key, digest, sig),
                Ok(true),
                "{:?} {alg:?}",
                v.curve
            );
        }
    }
}

#[test]
fn ecdsa_round_trip() {
    let mut rng = C.rng_seeded(b"ecdsa").unwrap();
    for curve in CURVES {
        let private = Ecc::generate_key(&C, &mut rng, curve).unwrap();
        let other = Ecc::generate_key(&C, &mut rng, curve).unwrap();
        for alg in [
            TpmiAlgHash::Sha1,
            TpmiAlgHash::Sha256,
            TpmiAlgHash::Sha384,
            TpmiAlgHash::Sha512,
        ] {
            let mut d = [0u8; 64];
            let digest = digest(alg, MESSAGE, &mut d);
            let mut out: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
            let key = SigningKey::Ecc(&private);
            let scheme = TpmtSigScheme::Ecdsa(alg);
            let sig = sign(&C, &mut rng, key, scheme, digest, &mut out).unwrap();
            let TpmtSignature::Ecdsa(ecc) = sig else {
                panic!("{sig:?}")
            };
            assert_eq!(ecc.hash, alg);
            assert_eq!(ecc.signature_r.as_slice().len(), curve.key_bytes());
            assert_eq!(ecc.signature_s.as_slice().len(), curve.key_bytes());

            let key = VerifyingKey::Ecc(private.public_key());
            assert_eq!(verify(&C, key, digest, sig), Ok(true), "{curve:?} {alg:?}");
            let key = VerifyingKey::Ecc(other.public_key());
            assert_eq!(verify(&C, key, digest, sig), Ok(false), "{curve:?} {alg:?}");
        }
    }
}

#[test]
fn ecdsa_signature_encoding() {
    let v = &VECTORS[0];
    let public = load_public(v.curve, v.x, v.y).unwrap();
    let (alg, r, s) = v.signatures[0];
    let mut d = [0u8; 64];
    let digest = digest(alg, MESSAGE, &mut d);
    let order = hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

    // Leading zeros are ignored.
    let mut padded = [0u8; 40];
    padded[8..].copy_from_slice(r);
    let valid = verify(
        &C,
        VerifyingKey::Ecc(&public),
        digest,
        ecdsa(alg, &padded, s),
    );
    assert_eq!(valid, Ok(true));

    // `r` and `s` must be in `[1, n - 1]`.
    let mut long = padded;
    long[7] = 1;
    for (r, s) in [
        (&[0u8; 0][..], s),
        (&[0u8][..], s),
        (r, &order[..]),
        (&long[..], s),
    ] {
        let valid = verify(&C, VerifyingKey::Ecc(&public), digest, ecdsa(alg, r, s));
        assert_eq!(valid, Ok(false));
    }
}

#[test]
fn ecdh_agreement() {
    let mut rng = C.rng_seeded(b"ecdh").unwrap();
    for curve in CURVES {
        let len = curve.key_bytes();
        let a = Ecc::generate_key(&C, &mut rng, curve).unwrap();
        let b = Ecc::generate_key(&C, &mut rng, curve).unwrap();

        // Reload `b` from its public point and scalar.
        let (mut x, mut y) = ([0u8; MAX], [0u8; MAX]);
        let mut d = [0u8; MAX];
        let point = b.public_key().point(&mut x, &mut y).unwrap();
        assert_eq!(point.x.as_slice().len(), len);
        assert_eq!(point.y.as_slice().len(), len);
        let public = Ecc::load_public(&C, curve, point).unwrap().unwrap();
        let b = Ecc::load_private(&C, public, b.scalar(&mut d).unwrap())
            .unwrap()
            .unwrap();

        let (mut x1, mut y1) = ([0u8; MAX], [0u8; MAX]);
        let (mut x2, mut y2) = ([0u8; MAX], [0u8; MAX]);
        let z1 = C.ecdh(&a, b.public_key(), &mut x1, &mut y1).unwrap();
        let z2 = C.ecdh(&b, a.public_key(), &mut x2, &mut y2).unwrap();
        assert_eq!(z1, z2, "{curve:?}");
        assert_eq!(z1.unwrap().x.as_slice().len(), len);
    }
}

#[test]
fn ecc_invalid_keys() {
    for (i, v) in VECTORS.iter().enumerate() {
        let len = v.curve.key_bytes();
        // A point that isn't on the curve.
        let mut y = v.y.to_vec();
        y[len - 1] ^= 1;
        // Coordinates that aren't less than `p`.
        let ff = vec![0xff; len];
        // Coordinates that are too long.
        let mut long = vec![1];
        long.extend_from_slice(v.x);
        for (x, y) in [(v.x, &y[..]), (&ff[..], v.y), (&long[..], v.y)] {
            assert!(load_public(v.curve, x, y).is_none(), "{:?}", v.curve);
        }

        // Scalars that are out of range or don't match the public key.
        let other = VECTORS[(i + 1) % VECTORS.len()].d;
        for d in [&[0u8][..], &[1u8], &ff[..], other] {
            let public = load_public(v.curve, v.x, v.y).unwrap();
            let private = Ecc::load_private(&C, public, param(d));
            assert!(matches!(private, Ok(None)), "{:?}", v.curve);
        }
    }
}

#[test]
fn ecc_unsupported() {
    let mut rng = C.rng_seeded(b"ecc").unwrap();
    for curve in [
        TpmEccCurve::NistP192,
        TpmEccCurve::BNP256,
        TpmEccCurve::SM2P256,
        TpmEccCurve::Curve25519,
    ] {
        let private = Ecc::generate_key(&C, &mut rng, curve);
        assert!(
            matches!(private, Err(CryptoError::Unsupported)),
            "{curve:?}"
        );
        let public = Ecc::load_public(&C, curve, point(&[1; 32], &[1; 32]));
        assert!(matches!(public, Err(CryptoError::Unsupported)), "{curve:?}");
    }

    // ECDH between keys on different curves.
    let a = Ecc::generate_key(&C, &mut rng, TpmEccCurve::NistP256).unwrap();
    let b = Ecc::generate_key(&C, &mut rng, TpmEccCurve::NistP384).unwrap();
    let (mut x, mut y) = ([0u8; MAX], [0u8; MAX]);
    let z = C.ecdh(&a, b.public_key(), &mut x, &mut y);
    assert_eq!(z, Err(CryptoError::Unsupported));

    // Signature schemes other than ECDSA.
    let mut d = [0u8; 64];
    let digest = digest(TpmiAlgHash::Sha256, MESSAGE, &mut d);
    let ecdaa = TpmsSchemeEcdaa {
        hash_alg: TpmiAlgHash::Sha256,
        count: 0,
    };
    for scheme in [
        TpmtSigScheme::Ecdaa(ecdaa),
        TpmtSigScheme::Sm2(TpmiAlgHash::Sha256),
        TpmtSigScheme::Ecschnorr(TpmiAlgHash::Sha256),
    ] {
        let mut out: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let sig = sign(&C, &mut rng, SigningKey::Ecc(&a), scheme, digest, &mut out);
        assert_eq!(sig, Err(CryptoError::Unsupported), "{scheme:?}");
    }
    let sig = TpmtSignature::Sm2(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: param(&[1]),
        signature_s: param(&[1]),
    });
    let valid = verify(&C, VerifyingKey::Ecc(a.public_key()), digest, sig);
    assert_eq!(valid, Err(CryptoError::Unsupported));
}
