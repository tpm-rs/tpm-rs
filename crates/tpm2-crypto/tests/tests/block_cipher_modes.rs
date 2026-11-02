//! AES-128/192/256 and Camellia-128/192/256 in the CTR, OFB, CBC and ECB block cipher modes
//! through the crypto provider (`Symmetric::aes*`/`Symmetric::camellia*`): the ciphertexts, the
//! output chaining values (`ivOut`) of the TCG reference implementation (CTR: the next counter,
//! also after a trailing partial block; OFB: the last keystream block; CBC: the last ciphertext
//! block), chaining across calls, the CTR counter wrap and the block-multiple precondition of
//! CBC and ECB. (CFB is covered by `cfb_round_trip.rs`, `camellia.rs` and the backend tests.)
//!
//! The trait methods are called directly rather than through `SymmetricKey`, whose Camellia
//! variants only exist with the `tpm2` Camellia features, which these tests must not enable.
//!
//! The AES vectors are those of NIST SP 800-38A, Appendix F (F.1 ECB, F.2 CBC, F.4 OFB, F.5 CTR);
//! the Camellia vectors were computed with OpenSSL (`openssl enc -camellia-<n>-<mode> -nopad`)
//! for the RFC 3713 keys and the same IVs, counter and plaintext.

use hex_literal::hex;
use tpm2::crypto::{CryptoError, Direction, ModeIv, Symmetric};
use tpm2_crypto_tests::TestProvider;

/// NIST SP 800-38A, Appendix F: the plaintext of every example.
const PLAINTEXT: [u8; 64] = hex!(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
);
/// NIST SP 800-38A, Appendix F: the IV of the CBC and OFB examples.
const IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
/// NIST SP 800-38A, Appendix F.5: the initial counter block of the CTR examples.
const COUNTER: [u8; 16] = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

/// A one-shot `Symmetric` operation with a fixed cipher and key.
type Op = Box<dyn Fn(ModeIv<'_>, Direction, &mut [u8]) -> Result<(), CryptoError>>;

/// A block cipher with a key, and its ciphertexts of [`PLAINTEXT`] in each mode.
struct Case {
    name: &'static str,
    op: Op,
    ecb: [u8; 64],
    cbc: [u8; 64],
    ofb: [u8; 64],
    ctr: [u8; 64],
}

/// The block cipher modes with an IV.
#[derive(Clone, Copy, Debug)]
enum IvMode {
    Ctr,
    Ofb,
    Cbc,
}

impl IvMode {
    fn mode_iv(self, iv: &mut [u8; 16]) -> ModeIv<'_> {
        match self {
            Self::Ctr => ModeIv::Ctr(iv),
            Self::Ofb => ModeIv::Ofb(iv),
            Self::Cbc => ModeIv::Cbc(iv),
        }
    }

    fn initial_iv(self) -> [u8; 16] {
        match self {
            Self::Ctr => COUNTER,
            Self::Ofb | Self::Cbc => IV,
        }
    }
}

/// `counter + n` as a 128-bit big-endian integer (wrapping).
fn add_to_counter(counter: [u8; 16], n: u128) -> [u8; 16] {
    u128::from_be_bytes(counter).wrapping_add(n).to_be_bytes()
}

impl Case {
    fn ciphertext(&self, mode: IvMode) -> &[u8; 64] {
        match mode {
            IvMode::Ctr => &self.ctr,
            IvMode::Ofb => &self.ofb,
            IvMode::Cbc => &self.cbc,
        }
    }

    /// The `ivOut` after processing the first `len` bytes of [`PLAINTEXT`] (or of the
    /// ciphertext) in `mode`.
    fn expected_iv(&self, mode: IvMode, len: usize) -> [u8; 16] {
        let blocks = len.div_ceil(16);
        if blocks == 0 {
            return mode.initial_iv();
        }
        let ct = self.ciphertext(mode);
        let last = &ct[16 * (blocks - 1)..16 * blocks];
        match mode {
            IvMode::Ctr => add_to_counter(COUNTER, blocks as u128),
            // The keystream block is the XOR of a full ciphertext and plaintext block.
            IvMode::Ofb => core::array::from_fn(|i| last[i] ^ PLAINTEXT[16 * (blocks - 1) + i]),
            IvMode::Cbc => last.try_into().unwrap(),
        }
    }

    /// One call in `mode` over `data` starting from `iv`; returns the output and `ivOut`.
    fn run(&self, mode: IvMode, dir: Direction, iv: [u8; 16], data: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut iv = iv;
        let mut data = data.to_vec();
        (self.op)(mode.mode_iv(&mut iv), dir, &mut data)
            .unwrap_or_else(|e| panic!("{} {mode:?} {dir:?}: {e:?}", self.name));
        (data, iv)
    }

    /// Whole-message encryption and decryption match the vectors, with the expected `ivOut`.
    fn check_vectors(&self) {
        for mode in [IvMode::Ctr, IvMode::Ofb, IvMode::Cbc] {
            let ct = self.ciphertext(mode);
            let (out, iv) = self.run(mode, Direction::Encrypt, mode.initial_iv(), &PLAINTEXT);
            assert_eq!(out, ct, "{} {mode:?} encrypt", self.name);
            assert_eq!(
                iv,
                self.expected_iv(mode, 64),
                "{} {mode:?} ivOut",
                self.name
            );
            let (out, iv) = self.run(mode, Direction::Decrypt, mode.initial_iv(), ct);
            assert_eq!(out, PLAINTEXT, "{} {mode:?} decrypt", self.name);
            assert_eq!(
                iv,
                self.expected_iv(mode, 64),
                "{} {mode:?} ivOut",
                self.name
            );
        }
        for (dir, input, output) in [
            (Direction::Encrypt, &PLAINTEXT, &self.ecb),
            (Direction::Decrypt, &self.ecb, &PLAINTEXT),
        ] {
            let mut data = *input;
            (self.op)(ModeIv::Ecb, dir, &mut data).unwrap();
            assert_eq!(&data, output, "{} ECB {dir:?}", self.name);
        }
    }

    /// Calls chained through `ivOut` at block boundaries give the one-call result.
    fn check_chaining(&self) {
        for mode in [IvMode::Ctr, IvMode::Ofb, IvMode::Cbc] {
            for (dir, input, output) in [
                (Direction::Encrypt, &PLAINTEXT, self.ciphertext(mode)),
                (Direction::Decrypt, self.ciphertext(mode), &PLAINTEXT),
            ] {
                let mut iv = mode.initial_iv();
                let mut out = Vec::new();
                for range in [0..16, 16..48, 48..48, 48..64] {
                    let (part, next_iv) = self.run(mode, dir, iv, &input[range]);
                    out.extend_from_slice(&part);
                    iv = next_iv;
                }
                assert_eq!(&out[..], output, "{} {mode:?} {dir:?} chained", self.name);
            }
        }
    }

    /// CTR and OFB accept any length: a prefix of the message gives a prefix of the ciphertext,
    /// and `ivOut` after a trailing partial block is that of the whole block (CTR: the counter is
    /// advanced; OFB: the full keystream block).
    fn check_partial_blocks(&self) {
        for mode in [IvMode::Ctr, IvMode::Ofb] {
            for len in 0..=64 {
                for (dir, input, output) in [
                    (Direction::Encrypt, &PLAINTEXT, self.ciphertext(mode)),
                    (Direction::Decrypt, self.ciphertext(mode), &PLAINTEXT),
                ] {
                    let (out, iv) = self.run(mode, dir, mode.initial_iv(), &input[..len]);
                    assert_eq!(out, output[..len], "{} {mode:?} {dir:?} {len}", self.name);
                    assert_eq!(
                        iv,
                        self.expected_iv(mode, len),
                        "{} {mode:?} {dir:?} ivOut of {len} bytes",
                        self.name
                    );
                }
            }
        }
    }

    /// The CTR counter is a 128-bit big-endian integer that wraps from all ones to zero; the
    /// keystream blocks are the encrypted counters (checked with ECB).
    fn check_counter_wrap(&self) {
        let start = [0xffu8; 16];
        let (keystream, iv) = self.run(IvMode::Ctr, Direction::Encrypt, start, &[0u8; 32]);
        assert_eq!(iv, add_to_counter(start, 2), "{} CTR wrap", self.name);
        let mut counters = [0u8; 32];
        counters[..16].copy_from_slice(&start);
        counters[16..].copy_from_slice(&add_to_counter(start, 1));
        (self.op)(ModeIv::Ecb, Direction::Encrypt, &mut counters).unwrap();
        assert_eq!(keystream, counters, "{} CTR keystream", self.name);
        // A carry through several bytes.
        let start = hex!("000000000000000000000000ffffffff");
        let (_, iv) = self.run(IvMode::Ctr, Direction::Encrypt, start, &[0u8; 17]);
        assert_eq!(iv, hex!("00000000000000000000000100000001"));
    }

    /// CBC and ECB need whole blocks: other lengths fail (`CryptoError::Internal`, a
    /// precondition violation) without touching the data or the IV; empty data is accepted.
    fn check_block_multiple(&self) {
        for len in [1usize, 15, 17, 63] {
            for dir in [Direction::Encrypt, Direction::Decrypt] {
                let mut data = PLAINTEXT[..len].to_vec();
                let mut iv = IV;
                assert_eq!(
                    (self.op)(ModeIv::Cbc(&mut iv), dir, &mut data),
                    Err(CryptoError::Internal),
                    "{} CBC {dir:?} {len}",
                    self.name
                );
                assert_eq!((&data[..], iv), (&PLAINTEXT[..len], IV));
                assert_eq!(
                    (self.op)(ModeIv::Ecb, dir, &mut data),
                    Err(CryptoError::Internal),
                    "{} ECB {dir:?} {len}",
                    self.name
                );
                assert_eq!(data, PLAINTEXT[..len]);
            }
        }
        for mode in [IvMode::Ctr, IvMode::Ofb, IvMode::Cbc] {
            let (out, iv) = self.run(mode, Direction::Encrypt, mode.initial_iv(), &[]);
            assert!(out.is_empty());
            assert_eq!(iv, mode.initial_iv(), "{} {mode:?} empty", self.name);
        }
        (self.op)(ModeIv::Ecb, Direction::Encrypt, &mut []).unwrap();
    }

    fn check_all(&self) {
        self.check_vectors();
        self.check_chaining();
        self.check_partial_blocks();
        self.check_counter_wrap();
        self.check_block_multiple();
    }
}

/// AES-128 in CTR, OFB, CBC and ECB matches NIST SP 800-38A (F.5.1, F.4.1, F.2.1, F.1.1).
#[test]
fn aes128_modes() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    Case {
        name: "AES-128",
        op: Box::new(move |m, d, data| TestProvider.aes128(&key, m, d, data)),
        ecb: hex!(
            "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
            "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
        ),
        cbc: hex!(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
        ),
        ofb: hex!(
            "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
            "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"
        ),
        ctr: hex!(
            "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
        ),
    }
    .check_all();
}

/// AES-192 in CTR, OFB, CBC and ECB matches NIST SP 800-38A (F.5.3, F.4.3, F.2.3, F.1.3).
#[test]
fn aes192_modes() {
    let key = hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    Case {
        name: "AES-192",
        op: Box::new(move |m, d, data| TestProvider.aes192(&key, m, d, data)),
        ecb: hex!(
            "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef"
            "ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e"
        ),
        cbc: hex!(
            "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a"
            "571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd"
        ),
        ofb: hex!(
            "cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c1100401"
            "8d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a"
        ),
        ctr: hex!(
            "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94"
            "1e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050"
        ),
    }
    .check_all();
}

/// AES-256 in CTR, OFB, CBC and ECB matches NIST SP 800-38A (F.5.5, F.4.5, F.2.5, F.1.5).
#[test]
fn aes256_modes() {
    let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    Case {
        name: "AES-256",
        op: Box::new(move |m, d, data| TestProvider.aes256(&key, m, d, data)),
        ecb: hex!(
            "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870"
            "b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7"
        ),
        cbc: hex!(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"
        ),
        ofb: hex!(
            "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d"
            "71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484"
        ),
        ctr: hex!(
            "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
            "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"
        ),
    }
    .check_all();
}

/// Camellia-128 in CTR, OFB, CBC and ECB matches OpenSSL.
#[test]
fn camellia128_modes() {
    let key = hex!("0123456789abcdeffedcba9876543210");
    Case {
        name: "Camellia-128",
        op: Box::new(move |m, d, data| TestProvider.camellia128(&key, m, d, data)),
        ecb: hex!(
            "8933635eae66d08781d649d23d089162c864e83d681758a3dd32f5167cb4f644"
            "6d9361e6b51d3c77bd2bf6951efc486ce0102162179d4bf4486500e42f119293"
        ),
        cbc: hex!(
            "6b9f90995aacb3e9c47debaa10fde80937aded36c7f0a6b2692b9cc975554953"
            "ebdde8c4ce359b3c8acc6cdcb131b3a96e6ca1039b20e1d63bffa876e7c03e8e"
        ),
        ofb: hex!(
            "3b5dd6f915870064fd3296068eddc95b3f7839e9b494d4959c1b52a8e30a9fb0"
            "109cc8a577a1c4a8c34dc235591298699d7062263cdfc4f467688f42371b6aea"
        ),
        ctr: hex!(
            "872bb979b579f73f10845534e87b5ded0b8c3403207dfd01b7938dee920ac4fa"
            "c56adcc44206178948e22dffff7337045af6a53e70282a4b158b9fee825ac67b"
        ),
    }
    .check_all();
}

/// Camellia-192 in CTR, OFB, CBC and ECB matches OpenSSL.
#[test]
fn camellia192_modes() {
    let key = hex!("0123456789abcdeffedcba98765432100011223344556677");
    Case {
        name: "Camellia-192",
        op: Box::new(move |m, d, data| TestProvider.camellia192(&key, m, d, data)),
        ecb: hex!(
            "bf084800ce49edc2edf6c36ca60876df82e9315b26c16d1bfcc05795877891f0"
            "99b7f5301914b39e2215d41961b6f310b8a63ffa8b3db42120797f9954f38e8e"
        ),
        cbc: hex!(
            "9da5006aa8fc26de71baa6b9bd5dad7df2bb569b7a3db2a8f3ad83d218238a79"
            "65903c0795e5dd9caa5969e9703493e1e8c8ec1efe48466b782e5c255a03bf77"
        ),
        ofb: hex!(
            "895af9df74daf66f538ed8cda3670300c54b08ee0645939e29aca1e6e3a5d867"
            "a195381acb451cac19ff66aa202071d2cd5798b869b380cd3785b33c457dc77d"
        ),
        ctr: hex!(
            "b7d330026c03dc92a252d1a7cf721b0755871fdbe7dbf7a9b14ed9fc5d3bf92c"
            "fb86dcc97174c9bcf92d79b5fc170680559ad68a30cf9ccf76b65e8208ad40d4"
        ),
    }
    .check_all();
}

/// Camellia-256 in CTR, OFB, CBC and ECB matches OpenSSL.
#[test]
fn camellia256_modes() {
    let key = hex!("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
    Case {
        name: "Camellia-256",
        op: Box::new(move |m, d, data| TestProvider.camellia256(&key, m, d, data)),
        ecb: hex!(
            "0dea81432c8c6b7f8763633167fc68903602ff29a8f91f6b6e44e0d40401230b"
            "4b14a6f8ed7cb3058549e171d5792a90878773a0dcacde3ed9a9d2b472450cb0"
        ),
        cbc: hex!(
            "b3f606fe654c926dad34545ec6607928a9089e0150ce09d65de253f57a137672"
            "bf50da7f64935ec69d1fde13d5b6c309a39017b6d2af5b357648a2115cafa296"
        ),
        ofb: hex!(
            "cabc1be5af6a98e74af5be7d4bf6861ad4d40dc824582077aec94033d6963304"
            "7b519e9c781aa0c44c50755bc46db2195650bb106ad40d9875077d07464d1108"
        ),
        ctr: hex!(
            "83fd6a0f3c442b79abd61c773b7c8aa94ce9a9bc7abe02814d264e194e7433b6"
            "1547e4377fb00b50eab51bad4fe67ea5fecccce2c45b8aa69e33a47ecc0e0f67"
        ),
    }
    .check_all();
}
