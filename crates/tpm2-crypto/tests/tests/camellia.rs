//! Camellia-128/192/256 through the crypto backend under test: CFB encryption
//! and decryption (`<TestProvider as Symmetric>::Camellia*`; the other modes
//! are covered by `block_cipher_modes.rs`) and CMAC
//! (`<TestProvider as Cmac>::Camellia*`).
//!
//! The backend traits are called directly rather than through
//! `SymmetricKey`/`CmacContext`, whose Camellia variants only exist with the
//! `tpm2` Camellia features, which these tests must not enable (Cargo features
//! unify across the workspace and would widen the TPM).
//!
//! The block vectors are those of RFC 3713, Appendix A. The CFB and CMAC
//! vectors were computed with OpenSSL (`openssl enc -camellia-<n>-cfb` and
//! `openssl mac -cipher CAMELLIA-<n>-CBC -macopt hexkey:<key> CMAC`) for the
//! RFC 3713 keys, the IV `000102..0f` and prefixes of the NIST SP 800-38A
//! example plaintext.

use hex_literal::hex;
use tpm2::TpmiAlgCipherMode;
use tpm2::crypto::backend::{Cmac, CmacState, Symmetric, SymmetricState};
use tpm2::crypto::{CipherInput, Direction};
use tpm2_crypto_tests::TestProvider;

/// RFC 3713, Appendix A: Camellia-128 key (also the plaintext of every key size).
const KEY_128: [u8; 16] = hex!("0123456789abcdeffedcba9876543210");
/// RFC 3713, Appendix A: Camellia-192 key.
const KEY_192: [u8; 24] = hex!("0123456789abcdeffedcba98765432100011223344556677");
/// RFC 3713, Appendix A: Camellia-256 key.
const KEY_256: [u8; 32] = hex!("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
/// RFC 3713, Appendix A: the plaintext block of the three examples.
const RFC_PLAINTEXT: [u8; 16] = hex!("0123456789abcdeffedcba9876543210");

/// IV of the CFB vectors.
const IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
/// Plaintext of the CFB and CMAC vectors (NIST SP 800-38A, Appendix F).
const PLAINTEXT: [u8; 64] = hex!(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
);

/// One Camellia key size: its backend cipher `S`, key, RFC 3713 ciphertext
/// block and CFB ciphertext of [`PLAINTEXT`] under [`IV`].
struct CfbCase<S, const N: usize> {
    name: &'static str,
    key: [u8; N],
    rfc_ciphertext: [u8; 16],
    cfb_ciphertext: [u8; 64],
    cipher: core::marker::PhantomData<S>,
}

const CFB_128: CfbCase<<TestProvider as Symmetric>::Camellia128, 16> = CfbCase {
    name: "Camellia-128",
    key: KEY_128,
    rfc_ciphertext: hex!("67673138549669730857065648eabe43"),
    cfb_ciphertext: hex!(
        "3b5dd6f915870064fd3296068eddc95b"
        "73997f398188c10610da0e24cf47380b"
        "a9f79f3753f2cdd548dc4a8cd595757f"
        "e115a0fc165a3c999abfbd223a4a5b78"
    ),
    cipher: core::marker::PhantomData,
};

const CFB_192: CfbCase<<TestProvider as Symmetric>::Camellia192, 24> = CfbCase {
    name: "Camellia-192",
    key: KEY_192,
    rfc_ciphertext: hex!("b4993401b3e996f84ee5cee7d79b09b9"),
    cfb_ciphertext: hex!(
        "895af9df74daf66f538ed8cda3670300"
        "f286e259c8ba46fb27ad3db644347a67"
        "2d677c1e0b8df28a8f4008238c031363"
        "5d73a6a179c3f1e7277654c383035a50"
    ),
    cipher: core::marker::PhantomData,
};

const CFB_256: CfbCase<<TestProvider as Symmetric>::Camellia256, 32> = CfbCase {
    name: "Camellia-256",
    key: KEY_256,
    rfc_ciphertext: hex!("9acc237dff16d76c20ef7c919e3a7509"),
    cfb_ciphertext: hex!(
        "cabc1be5af6a98e74af5be7d4bf6861a"
        "61b00c403a4a200e80c5248508921266"
        "c78e087010a81a540498d05c85b5c927"
        "58f1ef158f7ca49a43f1c8e8ae3cb065"
    ),
    cipher: core::marker::PhantomData,
};

impl<S: SymmetricState<N>, const N: usize> CfbCase<S, N> {
    /// Runs the case's cipher in CFB mode on `data` with `iv`, through
    /// `SymmetricState::crypt` (the TPM's chaining value: a partial final
    /// ciphertext block is zero padded).
    fn cfb(&self, iv: &mut [u8; 16], dir: Direction, data: &mut [u8]) {
        let input = CipherInput::new(TpmiAlgCipherMode::Cfb, iv, data).unwrap();
        S::crypt_once(&self.key, dir, input)
            .unwrap_or_else(|e| panic!("{} CFB failed: {e:?}", self.name));
    }

    /// Runs the backend's raw `SymmetricState::cfb` mode method on `data`
    /// with `iv`.
    fn raw_cfb(&self, iv: &mut [u8; 16], dir: Direction, data: &mut [u8]) {
        S::init(&self.key)
            .and_then(|s| s.cfb(dir, iv, data))
            .unwrap_or_else(|e| panic!("{} raw CFB failed: {e:?}", self.name));
    }

    /// The first CFB keystream block is `E_K(IV)`, so encrypting a zero block
    /// with the RFC 3713 plaintext as IV yields the RFC 3713 ciphertext.
    fn check_rfc_block(&self) {
        let mut iv = RFC_PLAINTEXT;
        let mut data = [0u8; 16];
        self.cfb(&mut iv, Direction::Encrypt, &mut data);
        assert_eq!(data, self.rfc_ciphertext, "{} RFC 3713 block", self.name);
        assert_eq!(iv, self.rfc_ciphertext, "{} ivOut", self.name);
        // The RFC 3713 block in ECB mode.
        let mut blocks = [RFC_PLAINTEXT];
        S::init(&self.key)
            .and_then(|s| s.ecb(Direction::Encrypt, &mut blocks))
            .unwrap();
        assert_eq!(blocks[0], self.rfc_ciphertext, "{} RFC 3713 ECB", self.name);
        S::init(&self.key)
            .and_then(|s| s.ecb(Direction::Decrypt, &mut blocks))
            .unwrap();
        assert_eq!(
            blocks[0], RFC_PLAINTEXT,
            "{} RFC 3713 ECB decrypt",
            self.name
        );
    }

    /// Whole-block encryption and decryption of [`PLAINTEXT`]; `ivOut` is the
    /// last ciphertext block.
    fn check_multi_block(&self) {
        let mut iv = IV;
        let mut data = PLAINTEXT;
        self.cfb(&mut iv, Direction::Encrypt, &mut data);
        assert_eq!(data, self.cfb_ciphertext, "{} CFB encrypt", self.name);
        assert_eq!(iv, self.cfb_ciphertext[48..], "{} encrypt ivOut", self.name);

        let mut iv = IV;
        self.cfb(&mut iv, Direction::Decrypt, &mut data);
        assert_eq!(data, PLAINTEXT, "{} CFB decrypt", self.name);
        assert_eq!(iv, self.cfb_ciphertext[48..], "{} decrypt ivOut", self.name);
    }

    /// A trailing partial block: the ciphertext is a prefix of the full one and
    /// `ivOut` is the partial ciphertext block zero padded (the TCG
    /// reference's chaining value, produced by `SymmetricState::crypt`). The
    /// backend's raw `cfb` method must produce the same output and the partial
    /// ciphertext in `ivOut[..n]` (the rest of its `ivOut` is unspecified).
    /// Covers every length from 0 to 64 bytes.
    fn check_partial_blocks(&self) {
        for len in 0..=PLAINTEXT.len() {
            for dir in [Direction::Encrypt, Direction::Decrypt] {
                let (input, output) = match dir {
                    Direction::Encrypt => (&PLAINTEXT, &self.cfb_ciphertext),
                    Direction::Decrypt => (&self.cfb_ciphertext, &PLAINTEXT),
                };
                let mut iv = IV;
                let mut data = input[..len].to_vec();
                self.cfb(&mut iv, dir, &mut data);
                assert_eq!(data, output[..len], "{} {dir:?} of {len} bytes", self.name);

                let full = len / 16 * 16;
                let rest = len - full;
                let mut expected_iv = if full == 0 {
                    IV
                } else {
                    self.cfb_ciphertext[full - 16..full].try_into().unwrap()
                };
                if rest != 0 {
                    expected_iv = [0; 16];
                    expected_iv[..rest].copy_from_slice(&self.cfb_ciphertext[full..len]);
                }
                assert_eq!(
                    iv, expected_iv,
                    "{} {dir:?} ivOut of {len} bytes",
                    self.name
                );

                let mut raw_iv = IV;
                let mut raw_data = input[..len].to_vec();
                self.raw_cfb(&mut raw_iv, dir, &mut raw_data);
                assert_eq!(raw_data, output[..len], "{} raw {dir:?} {len}", self.name);
                let checked = if rest == 0 { 16 } else { rest };
                assert_eq!(
                    raw_iv[..checked],
                    expected_iv[..checked],
                    "{} raw {dir:?} ivOut of {len} bytes",
                    self.name
                );
            }
        }
    }

    /// Chaining whole-block calls through the IV is the same as one call.
    fn check_iv_chaining(&self) {
        let mut iv = IV;
        let mut data = PLAINTEXT;
        let (a, rest) = data.split_at_mut(16);
        let (b, c) = rest.split_at_mut(32);
        self.cfb(&mut iv, Direction::Encrypt, a);
        self.cfb(&mut iv, Direction::Encrypt, b);
        self.cfb(&mut iv, Direction::Encrypt, c);
        assert_eq!(data, self.cfb_ciphertext, "{} chained encrypt", self.name);

        let mut iv = IV;
        for chunk in data.chunks_mut(16) {
            self.cfb(&mut iv, Direction::Decrypt, chunk);
        }
        assert_eq!(data, PLAINTEXT, "{} chained decrypt", self.name);
    }

    fn check_all(&self) {
        self.check_rfc_block();
        self.check_multi_block();
        self.check_partial_blocks();
        self.check_iv_chaining();
    }
}

/// Camellia-128 in CFB mode matches RFC 3713 and OpenSSL.
#[test]
fn camellia128_cfb() {
    CFB_128.check_all();
}

/// Camellia-192 in CFB mode matches RFC 3713 and OpenSSL.
#[test]
fn camellia192_cfb() {
    CFB_192.check_all();
}

/// Camellia-256 in CFB mode matches RFC 3713 and OpenSSL.
#[test]
fn camellia256_cfb() {
    CFB_256.check_all();
}

/// A Camellia-CMAC vector: (message length, Camellia-128 MAC, Camellia-192 MAC,
/// Camellia-256 MAC), the message being the first `len` bytes of [`PLAINTEXT`].
type CmacVector = (usize, [u8; 16], [u8; 16], [u8; 16]);

/// Camellia-CMAC of the first `len` bytes of [`PLAINTEXT`], per key size.
const CMAC_VECTORS: [CmacVector; 9] = [
    (
        0,
        hex!("857ebdbf5da9e55e8138ca9cca9102da"),
        hex!("184003312f82031a42870e1cd8a785aa"),
        hex!("b2ad1aaf88e03765465532cdc1988cf2"),
    ),
    (
        1,
        hex!("6bec29e9047c12e3f29bbb79e867d23b"),
        hex!("f15570cb1e65af4344c8e4658aa2a56d"),
        hex!("8ec834de7bb23d62a78b3cc582a1a8bd"),
    ),
    (
        15,
        hex!("133acf3edc3246d40adfe528c2fbb05a"),
        hex!("05fca06e065e354c71e15729db2448f8"),
        hex!("4a73a3d9c64369e85bd094d7f10a8889"),
    ),
    (
        16,
        hex!("dac259b031262650346baa4c2dede130"),
        hex!("a96ee30762e01062ec7bdc731c2746cb"),
        hex!("9802f833c89f70db687be9036b0b14f6"),
    ),
    (
        17,
        hex!("fb50c1ab34fa652e6746238525c560a2"),
        hex!("89b40da0675d416afb88e21a4170c387"),
        hex!("206a3de8fbc21f1d7bf8f4394b159736"),
    ),
    (
        20,
        hex!("08d1aa223278f9f013d7ba991c24fb05"),
        hex!("103b7d3b6d5752c78ee9480376d712d5"),
        hex!("3b56df81e0335f393c7677bb5d30a15f"),
    ),
    (
        32,
        hex!("344fc5d3918d926005bc500679376d8e"),
        hex!("b68ab74e9609aa035dfc0fc78fd3eb6a"),
        hex!("bab44284c5f143aee3c12b6db794e41e"),
    ),
    (
        40,
        hex!("4110fed4f1384abf732b610633694781"),
        hex!("fb47bfc101de50b31498b2afcb63ce66"),
        hex!("691f8de428e0bd1b1a8d06050dafc7ff"),
    ),
    (
        64,
        hex!("8cc09cb87266c4a390c71e2acb880908"),
        hex!("a0a14b73cf944861684785823f91db34"),
        hex!("f4354bb8462d9c7e232d5aa9dfb5dc26"),
    ),
];

/// Checks the backend's CMAC state `M` with `key` against `expected(vector)`
/// for every vector: one-shot (`CmacState::cmac`, also with the message split
/// into slices) and streamed in pieces (split at every position).
fn check_cmac<M: CmacState<N>, const N: usize>(
    name: &str,
    key: &[u8; N],
    expected: impl Fn(&CmacVector) -> [u8; 16],
) {
    for vector in &CMAC_VECTORS {
        let len = vector.0;
        let message = &PLAINTEXT[..len];

        let mut ctx = M::init(key).unwrap();
        ctx.update(message).unwrap();
        let mut mac = [0u8; 16];
        ctx.finalize(&mut mac).unwrap();
        assert_eq!(mac, expected(vector), "{name} CMAC of {len} bytes");

        let mut mac = [0u8; 16];
        M::cmac(key, &[message], &mut mac).unwrap();
        assert_eq!(mac, expected(vector), "{name} one-shot CMAC of {len} bytes");

        for split in 0..=len {
            let mut ctx = M::init(key).unwrap();
            ctx.update(&message[..split]).unwrap();
            ctx.update(&[]).unwrap();
            ctx.update(&message[split..]).unwrap();
            let mut mac = [0u8; 16];
            ctx.finalize(&mut mac).unwrap();
            assert_eq!(
                mac,
                expected(vector),
                "{name} CMAC of {len} bytes split at {split}"
            );

            let mut mac = [0u8; 16];
            M::cmac(key, &[&message[..split], &[], &message[split..]], &mut mac).unwrap();
            assert_eq!(
                mac,
                expected(vector),
                "{name} one-shot CMAC of {len} bytes split at {split}"
            );
        }
    }
}

/// Camellia-128-CMAC matches OpenSSL, including the empty message and lengths
/// that are not a multiple of the block size.
#[test]
fn camellia128_cmac() {
    check_cmac::<<TestProvider as Cmac>::Camellia128, 16>("Camellia-128", &KEY_128, |v| v.1);
}

/// Camellia-192-CMAC matches OpenSSL, including the empty message and lengths
/// that are not a multiple of the block size.
#[test]
fn camellia192_cmac() {
    check_cmac::<<TestProvider as Cmac>::Camellia192, 24>("Camellia-192", &KEY_192, |v| v.2);
}

/// Camellia-256-CMAC matches OpenSSL, including the empty message and lengths
/// that are not a multiple of the block size.
#[test]
fn camellia256_cmac() {
    check_cmac::<<TestProvider as Cmac>::Camellia256, 32>("Camellia-256", &KEY_256, |v| v.3);
}
