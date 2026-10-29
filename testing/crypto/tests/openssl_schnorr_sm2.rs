use tpm2::crypto::Random;
use tpm2::crypto::backend::{AsymmetricKey, Ecc, EccCurve, EccSigScheme};
use tpm2_openssl::OpensslBackend;

use tpm2::TpmiAlgHash;

#[test]
fn test_ecschnorr() {
    let mut rng = OpensslBackend::from_seed(b"test_seed").unwrap();
    let priv_key = <OpensslBackend as Ecc>::NistP256::generate(&mut rng, ()).unwrap();
    let pub_key = <OpensslBackend as Ecc>::NistP256::as_public(&priv_key);

    let digest_data = b"hello world";
    let mut hash = vec![0u8; tpm2::TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash::<OpensslBackend>(
        TpmiAlgHash::Sha256,
        &[digest_data.as_slice()],
        &mut hash,
    )
    .unwrap();

    let mut out_r = [0u8; 32];
    let mut out_s = [0u8; 32];

    <OpensslBackend as Ecc>::NistP256::sign::<OpensslBackend>(
        &mut rng,
        &priv_key,
        EccSigScheme::Ecschnorr,
        digest,
        &mut out_r,
        &mut out_s,
    )
    .unwrap();

    let valid = <OpensslBackend as Ecc>::NistP256::verify::<OpensslBackend>(
        pub_key,
        EccSigScheme::Ecschnorr,
        digest,
        &out_r,
        &out_s,
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn test_sm2() {
    let mut rng = OpensslBackend::from_seed(b"test_seed_sm2").unwrap();
    let priv_key = <OpensslBackend as Ecc>::SM2P256::generate(&mut rng, ()).unwrap();
    let pub_key = <OpensslBackend as Ecc>::SM2P256::as_public(&priv_key);

    let digest_data = b"hello sm2";
    let mut hash = vec![0u8; tpm2::TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash::<OpensslBackend>(
        TpmiAlgHash::Sm3_256,
        &[digest_data.as_slice()],
        &mut hash,
    )
    .unwrap();

    let mut out_r = [0u8; 32];
    let mut out_s = [0u8; 32];

    <OpensslBackend as Ecc>::SM2P256::sign::<OpensslBackend>(
        &mut rng,
        &priv_key,
        EccSigScheme::Sm2,
        digest,
        &mut out_r,
        &mut out_s,
    )
    .unwrap();

    let valid = <OpensslBackend as Ecc>::SM2P256::verify::<OpensslBackend>(
        pub_key,
        EccSigScheme::Sm2,
        digest,
        &out_r,
        &out_s,
    )
    .unwrap();
    assert!(valid);
}
