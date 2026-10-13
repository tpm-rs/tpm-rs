//! AES-CFB encrypt/decrypt round trips through the crypto provider, as used
//! for session parameter encryption.

use tpm2::crypto::{ModeIv, SymmetricKey};
use tpm2_crypto_tests::TestProvider;

/// Client-side sanity check that the AES-CFB helper used for parameter encryption round-trips
#[test]
fn client_cfb_round_trip() {
    // Client-side sanity check of the CFB primitive used by the session
    // parameter-encryption helpers; no TPM interaction is needed.
    let crypto = &TestProvider;

    let key = [0u8; 16];
    let original_iv = [0u8; 16];

    for size in 0..64 {
        let mut data = vec![0xABu8; size];
        let mut iv_enc = original_iv;
        tpm2::crypto::encrypt(
            crypto,
            SymmetricKey::Aes128(&key),
            ModeIv::Cfb(&mut iv_enc),
            &mut data,
        )
        .unwrap();

        let mut iv_dec = original_iv;
        tpm2::crypto::decrypt(
            crypto,
            SymmetricKey::Aes128(&key),
            ModeIv::Cfb(&mut iv_dec),
            &mut data,
        )
        .unwrap();

        assert_eq!(data, vec![0xABu8; size], "CFB failed for size {}", size);
    }
}
