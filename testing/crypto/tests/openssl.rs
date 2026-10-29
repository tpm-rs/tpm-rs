use testing_crypto::*;
use tpm2_openssl::OpensslBackend;
use tpm2_rustcrypto::RustCrypto;

#[test]
fn test_hash_one_shot() {
    hash_one_shot::<OpensslBackend>();
}
#[test]
fn test_hash_one_shot_parts() {
    hash_one_shot_parts::<OpensslBackend>();
}
#[test]
fn test_hash_streaming() {
    hash_streaming::<OpensslBackend>();
}
#[test]
fn test_hash_wrong_output_size() {
    hash_wrong_output_size::<OpensslBackend>();
}
#[test]
fn test_hash_longer_output_buffer() {
    hash_longer_output_buffer::<OpensslBackend>();
}

#[test]
fn test_hmac_one_shot() {
    hmac_one_shot::<OpensslBackend>();
}
#[test]
fn test_hmac_streaming() {
    hmac_streaming::<OpensslBackend>();
}
#[test]
fn test_kdfa_single_block_matches_hmac() {
    kdfa_single_block_matches_hmac::<OpensslBackend>();
}
#[test]
fn test_kdfa_xor_matches_kdfa() {
    kdfa_xor_matches_kdfa::<OpensslBackend>();
}
#[test]
fn test_kdfe_single_block_matches_hash() {
    kdfe_single_block_matches_hash::<OpensslBackend>();
}
#[test]
fn test_specialized_one_shot_override() {
    specialized_one_shot_override::<OpensslBackend>();
}
#[test]
fn test_implements_crypto() {
    implements_crypto::<OpensslBackend>();
}
#[test]
fn test_random() {
    random_tests::<OpensslBackend>();
}
#[test]
fn test_fips197_ecb() {
    fips197_ecb::<OpensslBackend>();
}
#[test]
fn test_sp800_38a_modes() {
    sp800_38a_modes::<OpensslBackend>();
}
#[test]
fn test_chaining_matches_single_call() {
    chaining_matches_single_call::<OpensslBackend>();
}
#[test]
fn test_matches_reference_implementation() {
    matches_reference_implementation::<OpensslBackend>();
}
#[test]
fn test_cipher_input_validation() {
    cipher_input_validation::<OpensslBackend>();
}
#[test]
fn test_symmetric_key() {
    symmetric_key::<OpensslBackend>();
}
#[test]
fn test_unsupported() {
    unsupported::<OpensslBackend>();
}

#[test]
fn test_cmac_vectors() {
    cmac_vectors::<OpensslBackend>();
}

#[test]
fn test_rsa_vectors() {
    use tpm2::crypto::Random;
    let mut rng = OpensslBackend::from_seed(b"test").unwrap();
    rsa_vectors::<OpensslBackend>(&mut rng);
}

#[test]
fn test_interop() {
    use tpm2::crypto::Random;
    let mut rng = OpensslBackend::from_seed(b"test").unwrap();
    interop_rsa_encrypt_decrypt::<OpensslBackend, RustCrypto>(&mut rng);
    interop_rsa_encrypt_decrypt::<RustCrypto, OpensslBackend>(&mut rng);
    interop_ecdsa_sign_verify::<OpensslBackend, RustCrypto>(&mut rng);
    interop_rsa_sign_verify::<OpensslBackend, RustCrypto>(&mut rng);
    interop_rsa_sign_verify::<RustCrypto, OpensslBackend>(&mut rng);
    interop_ecdsa_sign_verify::<RustCrypto, OpensslBackend>(&mut rng);
    interop_ecdh::<OpensslBackend, RustCrypto>(&mut rng);
    interop_ecdh::<RustCrypto, OpensslBackend>(&mut rng);
}

#[test]
fn test_ecc_vectors() {
    use tpm2::crypto::Random;
    let mut rng = OpensslBackend::from_seed(b"test").unwrap();
    ecc_vectors::<OpensslBackend>(&mut rng);
}

#[test]
fn test_hash_vectors() {
    hash_vectors::<OpensslBackend>();
}
#[test]
fn test_hmac_vectors() {
    hmac_vectors::<OpensslBackend>();
}
#[test]
fn test_kdf_vectors() {
    kdf_vectors::<OpensslBackend>();
}
#[test]
fn test_cipher_vectors() {
    cipher_vectors::<OpensslBackend>();
}

#[test]
fn test_asym_vectors() {
    use tpm2::crypto::Random;
    let mut rng = OpensslBackend::from_seed(b"test").unwrap();
    asym_vectors::<OpensslBackend>(&mut rng);
}

#[test]
fn test_asym_interop() {
    use tpm2::crypto::Random;
    let mut rng = OpensslBackend::from_seed(b"test").unwrap();
    interop_ed25519::<OpensslBackend, RustCrypto>(&mut rng);
    interop_ed25519::<RustCrypto, OpensslBackend>(&mut rng);
    interop_ed448::<OpensslBackend, RustCrypto>(&mut rng);
    interop_ed448::<RustCrypto, OpensslBackend>(&mut rng);
    interop_x25519::<OpensslBackend, RustCrypto>(&mut rng);
    interop_x25519::<RustCrypto, OpensslBackend>(&mut rng);
    interop_mlkem::<OpensslBackend, RustCrypto>(&mut rng);
    interop_mlkem::<RustCrypto, OpensslBackend>(&mut rng);
    interop_mldsa::<OpensslBackend, RustCrypto>(&mut rng);
    interop_mldsa::<RustCrypto, OpensslBackend>(&mut rng);
}
