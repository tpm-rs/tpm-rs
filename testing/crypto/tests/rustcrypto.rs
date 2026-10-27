use testing_crypto::*;
use tpm2_rustcrypto::RustCrypto;

#[test]
fn test_hash_one_shot() {
    hash_one_shot::<RustCrypto>();
}
#[test]
fn test_hash_one_shot_parts() {
    hash_one_shot_parts::<RustCrypto>();
}
#[test]
fn test_hash_streaming() {
    hash_streaming::<RustCrypto>();
}
#[test]
fn test_hash_wrong_output_size() {
    hash_wrong_output_size::<RustCrypto>();
}
#[test]
fn test_hash_longer_output_buffer() {
    hash_longer_output_buffer::<RustCrypto>();
}

#[test]
fn test_hmac_one_shot() {
    hmac_one_shot::<RustCrypto>();
}
#[test]
fn test_hmac_streaming() {
    hmac_streaming::<RustCrypto>();
}
#[test]
fn test_kdfa_single_block_matches_hmac() {
    kdfa_single_block_matches_hmac::<RustCrypto>();
}
#[test]
fn test_kdfa_xor_matches_kdfa() {
    kdfa_xor_matches_kdfa::<RustCrypto>();
}
#[test]
fn test_kdfe_single_block_matches_hash() {
    kdfe_single_block_matches_hash::<RustCrypto>();
}
#[test]
fn test_specialized_one_shot_override() {
    specialized_one_shot_override::<RustCrypto>();
}
#[test]
fn test_implements_crypto() {
    implements_crypto::<RustCrypto>();
}
#[test]
fn test_random() {
    random_tests::<RustCrypto>();
}
#[test]
fn test_fips197_ecb() {
    fips197_ecb::<RustCrypto>();
}
#[test]
fn test_sp800_38a_modes() {
    sp800_38a_modes::<RustCrypto>();
}
#[test]
fn test_chaining_matches_single_call() {
    chaining_matches_single_call::<RustCrypto>();
}
#[test]
fn test_matches_reference_implementation() {
    matches_reference_implementation::<RustCrypto>();
}
#[test]
fn test_cipher_input_validation() {
    cipher_input_validation::<RustCrypto>();
}
#[test]
fn test_symmetric_key() {
    symmetric_key::<RustCrypto>();
}
#[test]
fn test_unsupported() {
    unsupported::<RustCrypto>();
}

#[test]
fn test_cmac_vectors() {
    cmac_vectors::<RustCrypto>();
}

#[test]
fn test_rsa_vectors() {
    let mut rng = <RustCrypto as tpm2::crypto::Random>::from_seed(b"seed").unwrap();
    rsa_vectors::<RustCrypto>(&mut rng);
}

#[test]
fn test_interop() {
    let mut rng = <RustCrypto as tpm2::crypto::Random>::from_seed(b"seed").unwrap();
    interop_rsa_encrypt_decrypt::<RustCrypto, RustCrypto>(&mut rng);
    interop_rsa_sign_verify::<RustCrypto, RustCrypto>(&mut rng);
    interop_ecdsa_sign_verify::<RustCrypto, RustCrypto>(&mut rng);
    interop_ecdh::<RustCrypto, RustCrypto>(&mut rng);
    interop_x25519::<RustCrypto, RustCrypto>(&mut rng);
    interop_ed25519::<RustCrypto, RustCrypto>(&mut rng);
    interop_ed448::<RustCrypto, RustCrypto>(&mut rng);
    interop_mlkem::<RustCrypto, RustCrypto>(&mut rng);
    interop_mldsa::<RustCrypto, RustCrypto>(&mut rng);
}

#[test]
fn test_ecc_vectors() {
    let mut rng = <RustCrypto as tpm2::crypto::Random>::from_seed(b"seed").unwrap();
    ecc_vectors::<RustCrypto>(&mut rng);
}

#[test]
fn test_asym_vectors() {
    let mut rng = <RustCrypto as tpm2::crypto::Random>::from_seed(b"seed").unwrap();
    asym_vectors::<RustCrypto>(&mut rng);
}

#[test]
fn test_hash_vectors() {
    hash_vectors::<RustCrypto>();
}

#[test]
fn test_hmac_vectors() {
    hmac_vectors::<RustCrypto>();
}

#[test]
fn test_kdf_vectors() {
    kdf_vectors::<RustCrypto>();
}

#[test]
fn test_cipher_vectors() {
    cipher_vectors::<RustCrypto>();
}
