// Known-answer test vectors. See the crate documentation for sources.

use hex_literal::hex;
use tpm2::TpmEccCurve;

/// ECDH vector: our scalar `d`, our point `(x, y)`, the peer point
/// `(x, y)`, and the shared point `[d]Q_peer`.
pub(crate) struct EcdhKat {
    pub curve: TpmEccCurve,
    pub d: &'static [u8],
    pub q: (&'static [u8], &'static [u8]),
    pub peer: (&'static [u8], &'static [u8]),
    pub z: (&'static [u8], &'static [u8]),
}

/// ECDSA vector: public point, digest, and signature `(r, s)`.
pub(crate) struct EcdsaKat {
    pub curve: TpmEccCurve,
    pub q: (&'static [u8], &'static [u8]),
    pub hash: tpm2::TpmiAlgHash,
    pub digest: &'static [u8],
    pub sig: (&'static [u8], &'static [u8]),
}

/// ECDH known answers, one per curve.
pub(crate) const ECDH: &[EcdhKat] = &[
    // NistP256: RFC 5903, Section 8.1.
    EcdhKat {
        curve: TpmEccCurve::NistP256,
        d: &hex!("c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433"),
        q: (
            &hex!("dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180"),
            &hex!("5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3"),
        ),
        peer: (
            &hex!("d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63"),
            &hex!("56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab"),
        ),
        z: (
            &hex!("d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de"),
            &hex!("522bde0af0d8585b8def9c183b5ae38f50235206a8674ecb5d98edb20eb153a2"),
        ),
    },
    // NistP384: computed with Python big-integer arithmetic.
    EcdhKat {
        curve: TpmEccCurve::NistP384,
        d: &hex!(
            "a8593cd74ad548731fc80189ad26211eda1f932d9bffaa9b461f037cfe4c9390"
            "7ad6152fc04c2f694aeeaf1833a654a5"
        ),
        q: (
            &hex!(
                "2712fb33cd7b79e5d5d3f0664a9026cb9c8064aa3354596b2bebfcecaebf0244"
                "08f82b772da5922b352e165b6065c1d3"
            ),
            &hex!(
                "106d3e49c1e6eb5f7c3d9748bc3cd2c1887ae772d7d8b007f4da0c8c22433362"
                "92db931fbe54e542b90ae1378867027c"
            ),
        ),
        peer: (
            &hex!(
                "33a6e01341944b6049e8e32c581dd940c0db36cdd7f4e30602998160db74cec1"
                "9dc507836cc057f7ef18195a9995e7ff"
            ),
            &hex!(
                "98be4c94deec550d2b93c8d5d9300d924c8b1102d6a763ddb4db8888a45fbbb5"
                "afeb9ebae5a2ce77fba53db65bf18d98"
            ),
        ),
        z: (
            &hex!(
                "d514f3acbedda9313c7ea019ee631cae81c29e87ededfc3c02f6d011fda63422"
                "4854b60d983de52cac2e399292f879f5"
            ),
            &hex!(
                "0c4fda45446539b40d5abad2e970a05520cfa1ec21d4cc5dc0613e5577a4e592"
                "7ff3286643209886eca949c12f05fa0b"
            ),
        ),
    },
    // NistP521: computed with Python big-integer arithmetic.
    EcdhKat {
        curve: TpmEccCurve::NistP521,
        d: &hex!(
            "0000f5395ced598dca012b27a0106afa23bad4b3398d3ed181dffc7b6c2bab57"
            "9a28bc1660b12796ef48420bfa79dad35867afe9ccf0b9cb80855ae033f07e90"
            "8400"
        ),
        q: (
            &hex!(
                "017c03fdbdd707ee1d340bf94a1a3829a6057c9c68f9177288d3eb4b1c77dade"
                "e37e53a31c1805658a9df8c33d6a0180f7e111b8918ed2bc4460cc26dff56006"
                "3acb"
            ),
            &hex!(
                "01da710d579e7e2ddc8834edc9fa39a3af8a19cb245733db701f1783b71b6cf8"
                "536391f91226c98edcd21be4a214556b0427273a0a7cb990fd01a4fd994e73a9"
                "b459"
            ),
        ),
        peer: (
            &hex!(
                "016663043b4065a71f4fc67ddbea71fc64f0a434729324f2d74df6535266725f"
                "f2ac709260cdd04f9748aa5fddbb6056128f385ca2cf7e4c602e196f3e18b1fa"
                "b621"
            ),
            &hex!(
                "0033b2dbcc97fcf7f7d62a5facca87549e6629dc56271acee76f93612e51b239"
                "f12276f31f09f63c8eaaa8722376e87f9558d5c1d7d7bd13397b3c1fcc2d52f6"
                "1c7d"
            ),
        ),
        z: (
            &hex!(
                "00f250358f85aff20a5cea7b02807a3e9d02e96b679f135505d4ee5cbfae8467"
                "49955f949b6996fc088f319a38d189ae091bb902ed656f758a693baf9ef319df"
                "6df3"
            ),
            &hex!(
                "01a71bfbaa45e52ed0ffd666bc8160ddcbb1d25e9568a686b16e3053b21e37bd"
                "0b0897afc923d0a8ba5cad74f76a55e45b43586b4cd0a006377f574299eaaa8d"
                "9187"
            ),
        ),
    },
    // SM2P256: computed with Python big-integer arithmetic.
    EcdhKat {
        curve: TpmEccCurve::SM2P256,
        d: &hex!("72a9cf18eebd94b15df561475f7786e1084f009f553180e6092e973dacf1aee2"),
        q: (
            &hex!("d24d2c9f07ee28a623e4efabdb7b230af79a0daf337677f1c3a9a6ed2fab1fdc"),
            &hex!("cb9126e3007ffc7991738e99002aa6f99c3463d5cfbfbcb0e8cc4c19bc463f8f"),
        ),
        peer: (
            &hex!("60bab0a1ed3d70c7b9fe760a13e296f7d31e4aba9f7374871e556b7926f4a7b9"),
            &hex!("4d22ee111366011984709ed7c9d0e95cf1d7fb3fefe72e77153917adc14ff0c4"),
        ),
        z: (
            &hex!("67feb1e7609eb0392ca9725082c387e23c7d01730132ad7febac9a75a4eeb8c9"),
            &hex!("9905eb60753f9cd358c0dfc7ca51ef1a2207d0f0bfdb36d8b1efd1da2d3d17a8"),
        ),
    },
];

/// ECDSA verification known answers.
pub(crate) const ECDSA: &[EcdsaKat] = &[
    // NistP256: RFC 6979, Section A.2.5.
    EcdsaKat {
        curve: TpmEccCurve::NistP256,
        q: (
            &hex!("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"),
            &hex!("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"),
        ),
        hash: tpm2::TpmiAlgHash::Sha256,
        digest: &hex!("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"),
        sig: (
            &hex!("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"),
            &hex!("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"),
        ),
    },
    // NistP384: signed with pyca/cryptography.
    EcdsaKat {
        curve: TpmEccCurve::NistP384,
        q: (
            &hex!(
                "9bf5a6ff5d1c2d27bd2a75f78845ec340685b0aadc5c8bc1346a80ed567127b6"
                "6835415028bb28b3ca67bee0a993e4ea"
            ),
            &hex!(
                "39e654ea86ef01a92a6f280a27b9425191d81a8a69ab3295b0111110e8337764"
                "725d1adcb39742e49c95eb30a5824a13"
            ),
        ),
        hash: tpm2::TpmiAlgHash::Sha384,
        digest: &hex!(
            "94a5f001e2fed3573de698c881c691a151c1ae95bf7978ca7799819808290b0e"
            "038b65773b2c161da03d0d9cef03cf5e"
        ),
        sig: (
            &hex!(
                "c334c034fbb9062df45b67bb1142df8b0a27a51dec364138e1b8cb4a60786beb"
                "f79e69b8419e997097d9450179fb954c"
            ),
            &hex!(
                "504243beca97744beed93d9c27d58c3432da6e506cd2deaea3ceb3c2c8fceeca"
                "7812922557e498523c700b0c43d6631c"
            ),
        ),
    },
    // NistP521: signed with pyca/cryptography.
    EcdsaKat {
        curve: TpmEccCurve::NistP521,
        q: (
            &hex!(
                "0075959dd4baeb5b14f9e7ba74e439fb1e2b6aa9c2d34ec97cb1dabb5a6cd3f1"
                "55d50ffd21db54ba718e44c8ebeef2cc2e029cb4f6322f0b43d9cbaf32ab3550"
                "676d"
            ),
            &hex!(
                "01b7fb9cbc2a388652159b6dc459bd1a214fa9466bc88e3765144ba398119b43"
                "743569bb55d14aedae1518806b5ea16b958aee4af00615085040634372c794e7"
                "7657"
            ),
        ),
        hash: tpm2::TpmiAlgHash::Sha512,
        digest: &hex!(
            "441da4041242ff8f512eff8123be20b17f8a338b535c20371d81509ebe2017d3"
            "c4b921072423774cde59ca5d885e9045a987b316ef9da190739615197322c00a"
        ),
        sig: (
            &hex!(
                "002ca72f5213f7fa856ca19384576f232f72b17650ca8c1b53b9b33116ee289f"
                "296b592c6cab852b2fc780ead7a0966934933f66d0c3df679226c885f7e4cd6d"
                "12b1"
            ),
            &hex!(
                "01f4349a999a5c6ca7ca8e7577336f5927b612bd878cd9d731230477952dbe9b"
                "d4f0d903051e64bb397d9e19f082ed0c6c1e0cba0adf01fe15482d6e63a8970b"
                "4232"
            ),
        ),
    },
];
