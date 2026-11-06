use tpm2::TpmiAlgHash;
use tpm2::crypto::backend::{Hash, HashState, Hmac, HmacState};
use tpm2::crypto::{CryptoError, HashContext};
use tpm2_crypto_tests::TestProvider;

#[test]
fn test_unsupported_algorithm_id() {
    // SM3-256 is outside the TPM's profile (no `TpmiAlgHash::Sm3_256` exists to dispatch on),
    // and no provider implements it: its backend states are `!`, whose `init` fails.

    // sm3_256 should fail
    let res = <<TestProvider as Hash>::Sm3_256 as HashState<32>>::init();
    assert!(matches!(res, Err(CryptoError::Unsupported)));

    // hmac sm3_256 should fail
    let res_hmac = <<TestProvider as Hmac>::Sm3_256 as HmacState<32>>::init(&[0u8; 16]);
    assert!(matches!(res_hmac, Err(CryptoError::Unsupported)));
}

#[test]
fn test_empty_and_massive_inputs() {
    // Empty key and data for HMAC
    let key_empty: [u8; 0] = [];
    let data_empty: [u8; 0] = [];
    let mut out_empty = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let hmac_empty = tpm2::crypto::hmac::<TestProvider>(
        TpmiAlgHash::Sha256,
        &key_empty,
        &[&data_empty],
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

    // No input parts at all is the same empty message.
    let mut out_none = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let hmac_none =
        tpm2::crypto::hmac::<TestProvider>(TpmiAlgHash::Sha256, &key_empty, &[], &mut out_none)
            .unwrap();
    assert_eq!(hmac_none.digest(), &expected[..]);

    // Massive data: 10MB of data (using streaming updates)
    let chunk = vec![0xAAu8; 1024 * 1024]; // 1MB chunk
    let mut state = HashContext::<TestProvider>::new(TpmiAlgHash::Sha256).unwrap();
    let mut std_hasher = StdSha256::new();

    for _ in 0..10 {
        state.update(&chunk).unwrap();
        std_hasher.update(&chunk);
    }
    let mut digest = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = state.finalize(&mut digest).unwrap();
    let std_digest = std_hasher.finalize();
    assert_eq!(digest.digest(), &std_digest[..]);
}

#[test]
fn test_fine_grained_incremental_updates() {
    // Update 1 byte at a time to stress buffer boundary transitions
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut state = HashContext::<TestProvider>::new(TpmiAlgHash::Sha256).unwrap();
    for byte in data {
        state.update(&[*byte]).unwrap();
    }
    let mut digest = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = state.finalize(&mut digest).unwrap();

    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected =
        tpm2::crypto::hash::<TestProvider>(TpmiAlgHash::Sha256, &[data], &mut out).unwrap();
    assert_eq!(digest.digest(), expected.digest());
}
