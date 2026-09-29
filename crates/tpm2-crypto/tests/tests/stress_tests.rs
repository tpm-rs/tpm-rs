use tpm2::crypto::CryptoError;
use tpm2::crypto::{Finalize as _, Hash as _, Update as _};
use tpm2_crypto_tests::TestProvider;

#[test]
fn test_unsupported_algorithm_id() {
    let provider = TestProvider;

    // sm3_256 should fail
    let res = tpm2::crypto::Hash::sm3_256(&provider);
    assert!(matches!(res, Err(CryptoError::UnsupportedAlgorithm)));

    // hmac sm3_256 should fail
    let res_hmac = tpm2::crypto::Hmac::sm3_256(&provider, &[0u8; 16]);
    assert!(matches!(res_hmac, Err(CryptoError::UnsupportedAlgorithm)));

    // direct hash should fail
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let res_hash_direct =
        tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sm3_256, &[1, 2, 3], &mut out);
    assert!(matches!(
        res_hash_direct,
        Err(CryptoError::UnsupportedAlgorithm)
    ));

    // direct hmac should fail
    let res_hmac_direct = tpm2::crypto::hmac(
        &provider,
        tpm2::TpmiAlgHash::Sm3_256,
        &[0u8; 16],
        &[1, 2, 3],
        &mut out,
    );
    assert!(matches!(
        res_hmac_direct,
        Err(CryptoError::UnsupportedAlgorithm)
    ));
}

#[test]
fn test_empty_and_massive_inputs() {
    let provider = TestProvider;

    // Empty key and data for HMAC
    let key_empty = [];
    let data_empty = [];
    let mut out_empty = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let hmac_empty = tpm2::crypto::hmac(
        &provider,
        tpm2::TpmiAlgHash::Sha256,
        &key_empty,
        &data_empty,
        &mut out_empty,
    )
    .unwrap();

    // Verify against standard implementation
    use hmac::{Hmac, Mac};
    use sha2::Digest as _;
    use sha2::Sha256 as StdSha256;
    let mut mac = Hmac::<StdSha256>::new_from_slice(&key_empty).unwrap();
    mac.update(&data_empty);
    let expected = mac.finalize().into_bytes();
    assert_eq!(hmac_empty.digest(), &expected[..]);

    // Massive data: 10MB of data (using streaming updates)
    let chunk = vec![0xAAu8; 1024 * 1024]; // 1MB chunk
    let mut state = provider.sha256().unwrap();
    let mut std_hasher = StdSha256::new();

    for _ in 0..10 {
        state.update(&chunk).unwrap();
        std_hasher.update(&chunk);
    }
    let mut digest = [0u8; 32];
    state.finalize(&mut digest).unwrap();
    let std_digest = std_hasher.finalize();
    assert_eq!(&digest[..], &std_digest[..]);
}

#[test]
fn test_fine_grained_incremental_updates() {
    let provider = TestProvider;

    // Update 1 byte at a time to stress buffer boundary transitions
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut state = provider.sha256().unwrap();
    for byte in data {
        state.update(&[*byte]).unwrap();
    }
    let mut digest = [0u8; 32];
    state.finalize(&mut digest).unwrap();

    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected =
        tpm2::crypto::hash(&provider, tpm2::TpmiAlgHash::Sha256, data, &mut out).unwrap();
    assert_eq!(&digest[..], expected.digest());
}
