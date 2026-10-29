use tpm2::crypto::Rng;
use tpm2::crypto::backend::{AsymmetricKey, EdwardsCurve, MldsaKey, MlkemKey, MontgomeryCurve};
use tpm2_openssl::ecc::{Ed25519, X25519};
use tpm2_openssl::mldsa::Mldsa44;
use tpm2_openssl::mlkem::Mlkem512;

struct DummyRng;
impl Rng for DummyRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), tpm2::crypto::CryptoError> {
        out.fill(42);
        Ok(())
    }

    fn stir_bytes(&mut self, _: &[u8]) -> Result<(), tpm2::crypto::CryptoError> {
        Ok(())
    }
}

#[test]
fn test_mlkem512_keygen() {
    let mut rng = DummyRng;
    let priv_key = Mlkem512::generate(&mut rng, ()).unwrap();
    let pub_key = Mlkem512::as_public(&priv_key);
    let mut out_pub = [0u8; 800];
    Mlkem512::store_public(pub_key, &mut out_pub).unwrap();

    let mut ct = [0u8; 768];
    let mut ss = [0u8; 32];
    Mlkem512::encapsulate(&mut rng, pub_key, &mut ct, &mut ss).unwrap();

    let mut ss2 = [0u8; 32];
    Mlkem512::decapsulate(&priv_key, &ct, &mut ss2).unwrap();
    assert_eq!(ss, ss2);
}

#[test]
fn test_mldsa44_keygen() {
    let mut rng = DummyRng;
    let priv_key = Mldsa44::generate(&mut rng, ()).unwrap();
    let pub_key = Mldsa44::as_public(&priv_key);
    let mut out_pub = [0u8; 1312];
    Mldsa44::store_public(pub_key, &mut out_pub).unwrap();

    let msg = b"hello";
    let mut sig = [0u8; 2420];
    Mldsa44::sign_message(&mut rng, &priv_key, &[], &[msg], &mut sig).expect("ML-DSA sign failed");

    assert!(Mldsa44::verify_message(pub_key, &[], &[msg], &sig).unwrap());
}

#[test]
fn test_ed25519() {
    let mut rng = DummyRng;
    let priv_key = Ed25519::generate(&mut rng, ()).unwrap();
    let pub_key = Ed25519::as_public(&priv_key);
    let mut pub_bytes = [0u8; 32];
    Ed25519::store_public(pub_key, &mut pub_bytes).unwrap();

    let msg = b"hello";
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    Ed25519::sign_message(&priv_key, &[msg], &mut sig_r, &mut sig_s).expect("Ed25519 sign failed");

    assert!(Ed25519::verify_message(pub_key, &[msg], &sig_r, &sig_s).unwrap());
}

#[test]
fn test_x25519() {
    let mut rng = DummyRng;
    let priv_key = X25519::generate(&mut rng, ()).unwrap();
    let pub_key = X25519::as_public(&priv_key);
    let mut pub_bytes = [0u8; 32];
    X25519::store_public(pub_key, &mut pub_bytes).unwrap();

    let mut rng2 = DummyRng;
    let priv_key2 = X25519::generate(&mut rng2, ()).unwrap();
    let pub_key2 = X25519::as_public(&priv_key2);

    let mut ss1 = [0u8; 32];
    let mut ss2 = [0u8; 32];
    X25519::ecdh(&priv_key, pub_key2, &mut ss1).unwrap();
    X25519::ecdh(&priv_key2, pub_key, &mut ss2).unwrap();
    assert_eq!(ss1, ss2);
}
