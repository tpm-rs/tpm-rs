// Known-answer test vectors. See the crate documentation for sources.

use hex_literal::hex;

/// `(key, data)` pairs: RFC 4231 test cases 1, 2, 3, 4, 6, and 7, then an
/// empty key with empty data.
pub(crate) const CASES: &[(&[u8], &[u8])] = &[
    (&hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), b"Hi There"),
    (b"Jefe", b"what do ya want for nothing?"),
    (&hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), &hex!(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddddddd"
    )),
    (&hex!("0102030405060708090a0b0c0d0e0f10111213141516171819"), &hex!(
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    )),
    (&hex!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaa"
    ), b"Test Using Larger Than Block-Size Key - Hash Key First"),
    (&hex!(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaa"
    ), b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
    (b"", b""),
];

/// HMAC-Sha1 of each entry of [`CASES`] (Python `hmac`).
pub(crate) const SHA1: &[&[u8]] = &[
    &hex!("b617318655057264e28bc0b6fb378c8ef146be00"),
    &hex!("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
    &hex!("125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
    &hex!("4c9007f4026250c6bc8414f9bf50c86c2d7235da"),
    &hex!("90d0dace1c1bdc957339307803160335bde6df2b"),
    &hex!("217e44bb08b6e06a2d6c30f3cb9f537f97c63356"),
    &hex!("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"),
];

/// HMAC-Sha256 of each entry of [`CASES`] (Python `hmac`).
pub(crate) const SHA256: &[&[u8]] = &[
    &hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    &hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    &hex!("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    &hex!("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    &hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    &hex!("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    &hex!("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"),
];

/// HMAC-Sha384 of each entry of [`CASES`] (Python `hmac`).
pub(crate) const SHA384: &[&[u8]] = &[
    &hex!(
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
        "faea9ea9076ede7f4af152e8b2fa9cb6"
    ),
    &hex!(
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e"
        "8e2240ca5e69e2c78b3239ecfab21649"
    ),
    &hex!(
        "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b"
        "2a5ab39dc13814b94e3ab6e101a34f27"
    ),
    &hex!(
        "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e"
        "6801dd23c4a7d679ccf8a386c674cffb"
    ),
    &hex!(
        "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6"
        "0c2ef6ab4030fe8296248df163f44952"
    ),
    &hex!(
        "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5"
        "a678cc31e799176d3860e6110c46523e"
    ),
    &hex!(
        "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d35"
        "51289e75e8209cd4b792302840234adc"
    ),
];

/// HMAC-Sha512 of each entry of [`CASES`] (Python `hmac`).
pub(crate) const SHA512: &[&[u8]] = &[
    &hex!(
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    ),
    &hex!(
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    ),
    &hex!(
        "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
        "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
    ),
    &hex!(
        "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
        "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
    ),
    &hex!(
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
        "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
    ),
    &hex!(
        "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
        "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
    ),
    &hex!(
        "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac673"
        "0c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47"
    ),
];

/// HMAC-Sm3_256 of each entry of [`CASES`] (Python `hmac`).
pub(crate) const SM3_256: &[&[u8]] = &[
    &hex!("51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"),
    &hex!("2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882"),
    &hex!("dd9421e1c725bdf52ec1aa34edadb3c97f5951a83a2fa93f73a7902bc1dcc777"),
    &hex!("b57c79be03472aeb8cada581dea332cb2ba83d19cb1b052dd07194def75fb8cd"),
    &hex!("b4fd844e13342002f0b2e0690ea7741f1497d993a70494cea601e657bedf67a0"),
    &hex!("5acbdeb0c8c1ef3a99088fe51c0a1d5f4e1c175935f016aee74eb8056db18acb"),
    &hex!("0d23f72ba15e9c189a879aefc70996b06091de6e64d31b7a84004356dd915261"),
];

/// HMAC-Sha3_256 of each entry of [`CASES`] (Python `hmac`).
pub(crate) const SHA3_256: &[&[u8]] = &[
    &hex!("ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb"),
    &hex!("c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5"),
    &hex!("84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207"),
    &hex!("57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7"),
    &hex!("ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b"),
    &hex!("65c5b06d4c3de32a7aef8763261e49adb6e2293ec8e7c61e8de61701fc63e123"),
    &hex!("e841c164e5b4f10c9f3985587962af72fd607a951196fc92fb3a5251941784ea"),
];

/// HMAC-Sha3_384 of each entry of [`CASES`] (Python `hmac`).
pub(crate) const SHA3_384: &[&[u8]] = &[
    &hex!(
        "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a"
        "20d370b47743130e26ac7e3d532886bd"
    ),
    &hex!(
        "f1101f8cbf9766fd6764d2ed61903f21ca9b18f57cf3e1a23ca13508a93243ce"
        "48c045dc007f26a21b3f5e0e9df4c20a"
    ),
    &hex!(
        "275cd0e661bb8b151c64d288f1f782fb91a8abd56858d72babb2d476f0458373"
        "b41b6ab5bf174bec422e53fc3135ac6e"
    ),
    &hex!(
        "3a5d7a879702c086bc96d1dd8aa15d9c46446b95521311c606fdc4e308f4b984"
        "da2d0f9449b3ba8425ec7fb8c31bc136"
    ),
    &hex!(
        "0fc19513bf6bd878037016706a0e57bc528139836b9a42c3d419e498e0e1fb96"
        "16fd669138d33a1105e07c72b6953bcc"
    ),
    &hex!(
        "026fdf6b50741e373899c9f7d5406d4eb09fc6665636fc1a530029ddf5cf3ca5"
        "a900edce01f5f61e2f408cdf2fd3e7e8"
    ),
    &hex!(
        "adca89f07bbfbeaf58880c1572379ea2416568fd3b66542bd42599c57c4567e6"
        "ae086299ea216c6f3e7aef90b6191d24"
    ),
];

/// HMAC-Sha3_512 of each entry of [`CASES`] (Python `hmac`).
pub(crate) const SHA3_512: &[&[u8]] = &[
    &hex!(
        "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba"
        "47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e"
    ),
    &hex!(
        "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b"
        "287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024"
    ),
    &hex!(
        "309e99f9ec075ec6c6d475eda1180687fcf1531195802a99b5677449a8625182"
        "851cb332afb6a89c411325fbcbcd42afcb7b6e5aab7ea42c660f97fd8584bf03"
    ),
    &hex!(
        "b27eab1d6e8d87461c29f7f5739dd58e98aa35f8e823ad38c5492a2088fa0281"
        "993bbfff9a0e9c6bf121ae9ec9bb09d84a5ebac817182ea974673fb133ca0d1d"
    ),
    &hex!(
        "00f751a9e50695b090ed6911a4b65524951cdc15a73a5d58bb55215ea2cd839a"
        "c79d2b44a39bafab27e83fde9e11f6340b11d991b1b91bf2eee7fc872426c3a4"
    ),
    &hex!(
        "38a456a004bd10d32c9ab8336684112862c3db61adcca31829355eaf46fd5c73"
        "d06a1f0d13fec9a652fb3811b577b1b1d1b9789f97ae5b83c6f44dfcf1d67eba"
    ),
    &hex!(
        "cbcf45540782d4bc7387fbbf7d30b3681d6d66cc435cafd82546b0fce96b367e"
        "a79662918436fba442e81a01d0f9592dfcd30f7a7a8f1475693d30be4150ca84"
    ),
];
