// Known-answer test vectors. See the crate documentation for sources.

use hex_literal::hex;

/// 448-bit message from FIPS 180-2 / GB/T 32905 examples.
pub(crate) const MSG_448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

/// `(message, digest)` pairs for Sha1 (hashlib).
pub(crate) const SHA1: &[(&[u8], &[u8])] = &[
    (b"", &hex!("da39a3ee5e6b4b0d3255bfef95601890afd80709")),
    (b"abc", &hex!("a9993e364706816aba3e25717850c26c9cd0d89d")),
    (MSG_448, &hex!("84983e441c3bd26ebaae4aa1f95129e5e54670f1")),
];
/// Sha1 digest of one million `'a'` bytes.
pub(crate) const SHA1_MILLION_A: [u8; 20] = hex!("34aa973cd4c4daa4f61eeb2bdbad27316534016f");

/// `(message, digest)` pairs for Sha256 (hashlib).
pub(crate) const SHA256: &[(&[u8], &[u8])] = &[
    (
        b"",
        &hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ),
    (
        b"abc",
        &hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ),
    (
        MSG_448,
        &hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ),
];
/// Sha256 digest of one million `'a'` bytes.
pub(crate) const SHA256_MILLION_A: [u8; 32] =
    hex!("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

/// `(message, digest)` pairs for Sha384 (hashlib).
pub(crate) const SHA384: &[(&[u8], &[u8])] = &[
    (
        b"",
        &hex!(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
            "274edebfe76f65fbd51ad2f14898b95b"
        ),
    ),
    (
        b"abc",
        &hex!(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7"
        ),
    ),
    (
        MSG_448,
        &hex!(
            "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6"
            "b0455a8520bc4e6f5fe95b1fe3c8452b"
        ),
    ),
];
/// Sha384 digest of one million `'a'` bytes.
pub(crate) const SHA384_MILLION_A: [u8; 48] = hex!(
    "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
    "07b8b3dc38ecc4ebae97ddd87f3d8985"
);

/// `(message, digest)` pairs for Sha512 (hashlib).
pub(crate) const SHA512: &[(&[u8], &[u8])] = &[
    (
        b"",
        &hex!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ),
    ),
    (
        b"abc",
        &hex!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        ),
    ),
    (
        MSG_448,
        &hex!(
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
            "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
        ),
    ),
];
/// Sha512 digest of one million `'a'` bytes.
pub(crate) const SHA512_MILLION_A: [u8; 64] = hex!(
    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
    "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
);

/// `(message, digest)` pairs for Sm3_256 (hashlib).
pub(crate) const SM3_256: &[(&[u8], &[u8])] = &[
    (
        b"",
        &hex!("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
    ),
    (
        b"abc",
        &hex!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    ),
    (
        MSG_448,
        &hex!("639b6cc5e64d9e37a390b192df4fa1ea0720ab747ff692b9f38c4e66ad7b8c05"),
    ),
];
/// Sm3_256 digest of one million `'a'` bytes.
pub(crate) const SM3_256_MILLION_A: [u8; 32] =
    hex!("c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3");

/// `(message, digest)` pairs for Sha3_256 (hashlib).
pub(crate) const SHA3_256: &[(&[u8], &[u8])] = &[
    (
        b"",
        &hex!("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    ),
    (
        b"abc",
        &hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    ),
    (
        MSG_448,
        &hex!("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
    ),
];
/// Sha3_256 digest of one million `'a'` bytes.
pub(crate) const SHA3_256_MILLION_A: [u8; 32] =
    hex!("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1");

/// `(message, digest)` pairs for Sha3_384 (hashlib).
pub(crate) const SHA3_384: &[(&[u8], &[u8])] = &[
    (
        b"",
        &hex!(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
            "c3713831264adb47fb6bd1e058d5f004"
        ),
    ),
    (
        b"abc",
        &hex!(
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
            "98d88cea927ac7f539f1edf228376d25"
        ),
    ),
    (
        MSG_448,
        &hex!(
            "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5a"
            "a04a1f076e62fea19eef51acd0657c22"
        ),
    ),
];
/// Sha3_384 digest of one million `'a'` bytes.
pub(crate) const SHA3_384_MILLION_A: [u8; 48] = hex!(
    "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e7684"
    "7aa0774ddb90a842190d2c558b4b8340"
);

/// `(message, digest)` pairs for Sha3_512 (hashlib).
pub(crate) const SHA3_512: &[(&[u8], &[u8])] = &[
    (
        b"",
        &hex!(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        ),
    ),
    (
        b"abc",
        &hex!(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        ),
    ),
    (
        MSG_448,
        &hex!(
            "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636d"
            "ee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"
        ),
    ),
];
/// Sha3_512 digest of one million `'a'` bytes.
pub(crate) const SHA3_512_MILLION_A: [u8; 64] = hex!(
    "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859"
    "ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"
);
