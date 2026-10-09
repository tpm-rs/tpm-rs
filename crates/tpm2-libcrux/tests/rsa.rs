//! RSA tests. The fixed key, signatures and ciphertext were generated with
//! pyca/cryptography (OpenSSL).

use hex_literal::hex;
use tpm2::crypto::{
    CryptoError, Random, Rsa, RsaEncryptScheme, RsaPrivateKey, RsaPublicKey, SignatureBuffer,
    SigningKey, VerifyingKey, hash, sign, verify,
};
use tpm2::{
    Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmiAlgHash, TpmiRsaKeyBits, TpmsSignatureRsa,
    TpmtSigScheme, TpmtSignature,
};
use tpm2_libcrux::{Libcrux, RsaPrivate, RsaPublic};

const C: Libcrux = Libcrux::new();

const MESSAGE: &[u8] = b"tpm2-libcrux";

/// The modulus of an RSA-1024 key with `e = 65537`.
const N: [u8; 128] = hex!(
    "f865cea666ddabbed9ebe26f75312e11a9d9662dca2bec439dfa3b419b0311ea"
    "21a5e63ed2669e6cd0b06aeedcfec1d02bfdef405bf4b40f616678383d7c739d"
    "c2a6cf2b9964ff7fbe7c453a07842f2f924cf4afc2ad4c3287bdee2eb0aa26f9"
    "6d4c47c06d58cc301401bfff9014210c61118362c53e326e926cb3ac5e19a3f9"
);
/// The first prime factor of [`N`].
const P: [u8; 64] = hex!(
    "ff1fd080fb97268899ce34e33a50aa657840c9270e66d2c9a766a9aae72f762d"
    "c2a713d1a5d7cf02c2721d71dffa308ae3332d01af276264304917e5712689bb"
);
/// RSASSA-PKCS1-v1_5 signature of `SHA-256(MESSAGE)`.
const RSASSA_SHA256: [u8; 128] = hex!(
    "c1214e1a18f1f1fe358c1a502fc228dce63be82b5af6a58d4726ea4537d615b3"
    "2c6fb26d0e259651e48a181ac99e5da58412fe1154be73ce4c8dedd5c5f0f20e"
    "394a6fef12a123f7a0c7435d4aa44de042014b181e2fbf1fb3ad06ba246c88c9"
    "04814a110ba7f36512cb55484d20ecc00a8303e555c93f9561e885c6e309de8c"
);
/// RSASSA-PSS signature of `SHA-512(MESSAGE)` with a 62-byte salt, the
/// longest the key allows.
const RSAPSS_SHA512: [u8; 128] = hex!(
    "83faece9a8e00fcada13874fb97ce065531fdf4cd740f3868213ba2ef7a99c11"
    "2515be4f42b830f0d80c54fdb3a8fdbaabdc7e8c5cc61796a66b3a471f1c50b3"
    "b8909c9cfc64d4588cf2c95f1dc5426f2ae44f1c69ae8b055f0d2b684f175756"
    "0f7071fa7d299ffa792534f7cd13af6adb0a686b6ab73a955b78d5e06cf0301b"
);
/// RSAES-OAEP encryption of `MESSAGE` with SHA-256 and the label
/// `"DUPLICATE\0"`.
const OAEP_SHA256: [u8; 128] = hex!(
    "a2af4d5faeb9be5a3a05bf1574664524ac60d8b615d0314ad7431e83f6d1fc5a"
    "85e37591e4d94f80ee2632f398623aa6765f24eda86f8c973fa1406d24c71469"
    "0083a37aff56b22f588d8d5066aae2c1ec2cb6fffe42f0d8e1e058ebe70c140f"
    "1b088ffcaaa72cc6d69175d607c0bd1c36e5dc2d4009baddece404a24ac61196"
);

fn load_public() -> RsaPublic {
    let modulus = Tpm2bPublicKeyRsa::new(&N).unwrap();
    Rsa::load_public(&C, TpmiRsaKeyBits::Rsa1024, 0, modulus)
        .unwrap()
        .unwrap()
}

fn load_private() -> RsaPrivate {
    let prime = Tpm2bPrivateKeyRsa::new(&P).unwrap();
    Rsa::load_private(&C, load_public(), prime)
        .unwrap()
        .unwrap()
}

fn digest<'a>(alg: TpmiAlgHash, message: &[u8], out: &'a mut [u8; 64]) -> &'a [u8] {
    hash(&C, alg, message, out).unwrap().digest()
}

fn signature(scheme: TpmtSigScheme, sig: &[u8]) -> TpmtSignature<'_> {
    let sig = Tpm2bPublicKeyRsa::new(sig).unwrap();
    match scheme {
        TpmtSigScheme::Rsassa(hash) => TpmtSignature::Rsassa(TpmsSignatureRsa { hash, sig }),
        TpmtSigScheme::Rsapss(hash) => TpmtSignature::Rsapss(TpmsSignatureRsa { hash, sig }),
        _ => unreachable!(),
    }
}

#[test]
fn rsa_openssl_vectors() {
    let private = load_private();
    let public = private.public_key();
    assert_eq!(public.bits(), TpmiRsaKeyBits::Rsa1024);
    assert_eq!(public.exponent(), 65537);

    for (scheme, sig) in [
        (TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256), &RSASSA_SHA256),
        (TpmtSigScheme::Rsapss(TpmiAlgHash::Sha512), &RSAPSS_SHA512),
    ] {
        let (TpmtSigScheme::Rsassa(alg) | TpmtSigScheme::Rsapss(alg)) = scheme else {
            unreachable!()
        };
        let mut d = [0u8; 64];
        let digest = digest(alg, MESSAGE, &mut d);
        let key = VerifyingKey::Rsa(public);
        assert_eq!(verify(&C, key, digest, signature(scheme, sig)), Ok(true));

        let mut tampered = *sig;
        tampered[64] ^= 1;
        let key = VerifyingKey::Rsa(public);
        assert_eq!(
            verify(&C, key, digest, signature(scheme, &tampered)),
            Ok(false)
        );
    }

    let scheme = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label: b"DUPLICATE\0",
    };
    let mut out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let plaintext = C.decrypt(&private, scheme, &OAEP_SHA256, &mut out);
    assert_eq!(plaintext.unwrap().unwrap().as_slice(), MESSAGE);
}

#[test]
fn rsa_generate_and_sign() {
    let mut rng = C.rng_seeded(b"rsa").unwrap();
    let private = Rsa::generate_key(&C, &mut rng, TpmiRsaKeyBits::Rsa1024, 0).unwrap();
    assert_eq!(private.public_key().exponent(), 65537);

    // Reload the key from its modulus and first prime.
    let mut n = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let mut p = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let n = private.public_key().modulus(&mut n).unwrap();
    let p = private.prime_p(&mut p).unwrap();
    assert_eq!((n.as_slice().len(), p.as_slice().len()), (128, 64));
    let loaded = Rsa::load_public(&C, TpmiRsaKeyBits::Rsa1024, 65537, n)
        .unwrap()
        .unwrap();
    let loaded = Rsa::load_private(&C, loaded, p).unwrap().unwrap();

    for scheme in [
        TpmtSigScheme::Rsassa(TpmiAlgHash::Sha1),
        TpmtSigScheme::Rsassa(TpmiAlgHash::Sha384),
        TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256),
        TpmtSigScheme::Rsapss(TpmiAlgHash::Sha512),
    ] {
        let (TpmtSigScheme::Rsassa(alg) | TpmtSigScheme::Rsapss(alg)) = scheme else {
            unreachable!()
        };
        let mut d = [0u8; 64];
        let digest = digest(alg, MESSAGE, &mut d);
        let mut out: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let key = SigningKey::Rsa(&private);
        let sig = sign(&C, &mut rng, key, scheme, digest, &mut out).unwrap();
        let key = VerifyingKey::Rsa(loaded.public_key());
        assert_eq!(verify(&C, key, digest, sig), Ok(true), "{scheme:?}");

        let mut other = [0u8; 64];
        let other = self::digest(alg, b"other", &mut other);
        let key = VerifyingKey::Rsa(loaded.public_key());
        assert_eq!(verify(&C, key, other, sig), Ok(false), "{scheme:?}");
    }

    let mut out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let scheme = TpmtSigScheme::Rsassa(TpmiAlgHash::Sha3_256);
    let key = SigningKey::Rsa(&private);
    assert_eq!(
        sign(&C, &mut rng, key, scheme, &[0; 32], &mut out),
        Err(CryptoError::Unsupported)
    );
}

#[test]
fn rsa_signature_range() {
    let public = load_public();
    let mut d = [0u8; 64];
    let digest = digest(TpmiAlgHash::Sha256, MESSAGE, &mut d);
    let scheme = TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256);
    // Signatures must be exactly as long as the modulus and less than it.
    for sig in [&RSASSA_SHA256[1..], &N] {
        let key = VerifyingKey::Rsa(&public);
        assert_eq!(verify(&C, key, digest, signature(scheme, sig)), Ok(false));
    }
}

#[test]
fn rsa_encrypt_decrypt() {
    let private = load_private();
    let public = private.public_key();
    let mut rng = C.rng_seeded(b"rsa").unwrap();
    let mut ct = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let mut pt = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];

    for scheme in [
        RsaEncryptScheme::Rsaes,
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha1,
            label: b"",
        },
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha384,
            label: b"DUPLICATE\0",
        },
    ] {
        let ciphertext = C.encrypt(&mut rng, public, scheme, MESSAGE, &mut ct);
        let mut ciphertext: [u8; 128] = ciphertext.unwrap().unwrap().as_slice().try_into().unwrap();
        let plaintext = C.decrypt(&private, scheme, &ciphertext, &mut pt);
        assert_eq!(
            plaintext.unwrap().unwrap().as_slice(),
            MESSAGE,
            "{scheme:?}"
        );

        ciphertext[64] ^= 1;
        let plaintext = C.decrypt(&private, scheme, &ciphertext, &mut pt);
        assert_eq!(plaintext, Ok(None), "{scheme:?}");
        let plaintext = C.decrypt(&private, scheme, &ciphertext[1..], &mut pt);
        assert_eq!(plaintext, Ok(None), "{scheme:?}");
    }

    // Raw RSA decryption returns the whole modulus-sized block.
    let mut block = [0u8; 128];
    block[128 - MESSAGE.len()..].copy_from_slice(MESSAGE);
    let ciphertext = C.encrypt(&mut rng, public, RsaEncryptScheme::Raw, MESSAGE, &mut ct);
    let ciphertext = ciphertext.unwrap().unwrap().as_slice();
    let plaintext = C.decrypt(&private, RsaEncryptScheme::Raw, ciphertext, &mut pt);
    assert_eq!(plaintext.unwrap().unwrap().as_slice(), block);

    // Inputs that are too long or not less than the modulus.
    let too_long = [1u8; 128 - 10];
    let cases = [
        (RsaEncryptScheme::Raw, &N[..]),
        (RsaEncryptScheme::Rsaes, &too_long[..]),
        (
            RsaEncryptScheme::Oaep {
                hash: TpmiAlgHash::Sha512,
                label: b"",
            },
            MESSAGE,
        ),
    ];
    for (scheme, plaintext) in cases {
        let ciphertext = C.encrypt(&mut rng, public, scheme, plaintext, &mut ct);
        assert_eq!(ciphertext, Ok(None), "{scheme:?}");
    }
    let plaintext = C.decrypt(&private, RsaEncryptScheme::Raw, &N, &mut pt);
    assert_eq!(plaintext, Ok(None));

    // The `rsa` crate only supports UTF-8 labels.
    let scheme = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label: &[0xff],
    };
    let ciphertext = C.encrypt(&mut rng, public, scheme, MESSAGE, &mut ct);
    assert_eq!(ciphertext, Err(CryptoError::Unsupported));
}

#[test]
fn rsa_invalid_keys() {
    let bits = TpmiRsaKeyBits::Rsa1024;
    let modulus = Tpm2bPublicKeyRsa::new(&N).unwrap();
    let mut even = N;
    even[127] &= !1;
    let mut short = N;
    short[0] = 0;
    for (bits, exponent, modulus) in [
        (TpmiRsaKeyBits::Rsa2048, 0, modulus),
        (bits, 1, modulus),
        (bits, 65536, modulus),
        (bits, 0, Tpm2bPublicKeyRsa::new(&even).unwrap()),
        (bits, 0, Tpm2bPublicKeyRsa::new(&short).unwrap()),
        (bits, 0, Tpm2bPublicKeyRsa::new(&N[1..]).unwrap()),
    ] {
        let public = Rsa::load_public(&C, bits, exponent, modulus);
        assert!(matches!(public, Ok(None)), "{bits:?} {exponent}");
    }

    let mut wrong = P;
    wrong[63] ^= 2;
    for prime in [&wrong[..], &[1u8], &N] {
        let prime = Tpm2bPrivateKeyRsa::new(prime).unwrap();
        let private = Rsa::load_private(&C, load_public(), prime);
        assert!(matches!(private, Ok(None)));
    }

    let mut rng = C.rng_seeded(b"rsa").unwrap();
    let private = Rsa::generate_key(&C, &mut rng, bits, 4);
    assert!(matches!(private, Err(CryptoError::Unsupported)));
}
