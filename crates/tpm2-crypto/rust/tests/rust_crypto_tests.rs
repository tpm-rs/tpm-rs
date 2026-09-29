use hex_literal::hex;
use tpm2::crypto::Rng;
use tpm2::crypto::{Finalize, Hash, Hmac, Update};
use tpm2_crypto_rust::RustCryptoProvider;

#[test]
fn test_rust_crypto_provider_get_random() {
    let provider = RustCryptoProvider;
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    provider.get_random(&mut buf1).expect("get_random failed");
    provider.get_random(&mut buf2).expect("get_random failed");
    assert_ne!(buf1, buf2, "get_random produced identical buffers");
}

#[test]
fn test_rust_crypto_provider_hash_sha256() {
    let provider = RustCryptoProvider;
    let data = b"hello world";
    let mut ctx = Hash::sha256(&provider).expect("sha256 failed");
    ctx.update(data).expect("update failed");
    let mut digest = [0u8; 32];
    ctx.finalize(&mut digest).expect("finalize failed");
    let expected = hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    assert_eq!(digest, expected);
}

#[test]
fn test_rust_crypto_provider_hmac_sha256() {
    let provider = RustCryptoProvider;
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut ctx = Hmac::sha256(&provider, key).expect("hmac sha256 failed");
    ctx.update(data).expect("update failed");
    let mut digest = [0u8; 32];
    ctx.finalize(&mut digest).expect("finalize failed");
    let expected = hex!("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    assert_eq!(digest, expected);
}

#[test]
fn test_rust_crypto_provider_concurrency() {
    use std::thread;
    let provider = std::sync::Arc::new(RustCryptoProvider);

    let mut handles = vec![];
    for i in 0..10 {
        let p = provider.clone();
        handles.push(thread::spawn(move || {
            let data = format!("hello world {}", i);
            let mut ctx = Hash::sha256(&*p).expect("sha256 failed");
            ctx.update(data.as_bytes()).expect("update failed");
            let mut digest = [0u8; 32];
            ctx.finalize(&mut digest).expect("finalize failed");
            assert_eq!(digest.len(), 32);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
