// Known-answer test vectors. See the crate documentation for sources.

use core::ffi::CStr;

use hex_literal::hex;

/// A KDFa (`key` is the HMAC key) or KDFe (`key` is the shared secret `Z`)
/// vector, computed with Python `hmac`/`hashlib` per TPM 2.0 Part 1.
pub(crate) struct KdfKat {
    pub key: &'static [u8],
    pub label: &'static CStr,
    pub context_u: &'static [u8],
    pub context_v: &'static [u8],
    pub out: &'static [u8],
}

const KEY: &[u8] = b"tpm-rs kdf test key";
const CONTEXT_U: &[u8] = &hex!("101112131415161718191a1b1c1d1e1f");
const CONTEXT_V: &[u8] = &hex!("808182838485868788898a8b8c8d8e8f9091929394959697");

/// KDFa vectors for Sha1.
pub(crate) const KDFA_SHA1: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "6d6e63c20f3f256866f2912aa1c5fe96795526e7a2218d774acba4c1d630ce57"
            "a67e9dd1b59881d1b62d1f"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("4b0b1b5bc810214088fb4efe4e722ac0"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("3e2af77ee19fa12f59c79e5d38626a336aa1b6811611f63281c94d5f198d315f"),
    },
];
/// KDFa vectors for Sha256.
pub(crate) const KDFA_SHA256: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "992681e63f44be6078d24c3caeab16827182d4c15721bbac3d8f46ddef663dd0"
            "5d644fe8817a54de8992e0293fc1f845acd5572a4c85bbb914d23fc566815a66"
            "c0f58c"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("712da452e44efd721762f48fccdb9268"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("7b498ff291f1592682621576f6ed014e166fe61810a56d039c765a59ee98c0c9"),
    },
];
/// KDFa vectors for Sha384.
pub(crate) const KDFA_SHA384: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "8db1b9bbbcab3b2dd9e2846dbca13d540eb1e05a9525f4889c065477a975a867"
            "42f57cb63fc7553c3b4f7cc82606df643df8b95811d0af507f88d9e623b17f94"
            "bc9905c679448bf0c1cc09a4cc7ef5d35c4899e9d212dff29fe4b2bf8209e720"
            "4a6766"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("d8b86b7bac6983f046ec84d28cb40200"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("4dc9b6c07a04441bf6b90f1f3eb3e3f6b58172bdb9013d76430e4ddb28067bcd"),
    },
];
/// KDFa vectors for Sha512.
pub(crate) const KDFA_SHA512: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "a957e7fd7267f45540aa6ead03665bfc02ef35dce63534abba8e60861ffeb124"
            "609bfcdf2242cb2db94e672af23f6176fc0965ce57b221bc4daf6925e3763cb4"
            "87d647306fd8120e8ffd005e016f8ae15923a2671e12c542b832994d46a47577"
            "bd392d76475b3af27849d675ec3b203625cef0eca8c51a85a347c6456e32c316"
            "74da62"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("843c9a08993c0f5fb908feedd8d438c9"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("22bc6f1b171c08c4ae2f27444af8fc8b3087a90006caea91fdcfb47c1b8733b8"),
    },
];
/// KDFa vectors for Sm3_256.
pub(crate) const KDFA_SM3_256: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "34a9093e4d3c34512e8c73155ee33109890c96ce09e81e1ca57516f3d3ea4ecd"
            "a1c4bd35cf231875930ed036db778fc7f1d3a6acd7e480c5ea5c38d21fe5ae83"
            "e600c8"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("daf6e66321fa74e459dc3621cfc9227b"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("5f670a09b2dac8e06ed665a31630e3f5b22177949b24a6698c845d089e34e717"),
    },
];
/// KDFa vectors for Sha3_256.
pub(crate) const KDFA_SHA3_256: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "b4f6b8f9f99c849aa20ab6382862390cdf983aa3392442b2312756f85daca06c"
            "e3711b82fa1d88a237c3348428527c1f7a737f6254d5b404b3a7b752fcf739be"
            "f46192"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("44b3a2f5a87f3b3998bd0c0b7a7b4cb4"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("55d316bdefbcfc4ef5dd17d2aeca46747dca94196c756ee36805ecc1b175cb38"),
    },
];
/// KDFa vectors for Sha3_384.
pub(crate) const KDFA_SHA3_384: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "e8a5c6713d8be87b490ccc32d9cfd8b302dd8106d9e2d62b6a8629f81262f3a9"
            "e5ec1b6a14fa4b8b4d00068d93d283e1e2ae288ab305026a4f94264135c4f829"
            "9100d9789defdc77527e2271cb830212d3e0d69a77e087a312b805c377870062"
            "bc1b37"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("461cc8fac38c0393aaffbfacccf2cb62"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("d2a2d05ad1a2782ba24812125decda6c64615d62a5cb3e9f1d595d7dcb01face"),
    },
];
/// KDFa vectors for Sha3_512.
pub(crate) const KDFA_SHA3_512: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "536d6a7e86c25841cfee2f297ebe913d1640c6c0a93b71d99a189236fd0d30fc"
            "d0822991b62aa6fc20d82456a930792cf9c643224d040cbffe180d03624874ec"
            "3a733140b9f53daf6085c18c3573e5233087421f0461929464eec9d78eaefc5d"
            "8066dad796fee1112ef74ce112b21a811637c0e74bd9026495299c2d8fbd5c2e"
            "d9b905"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("1a2172a6ee04a18e1f99ea0f8aeb6620"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("a0b5c81ec7faaddecda98a962fad42339afec2180002e0df3610dc40c220ed1b"),
    },
];
/// KDFe vectors for Sha1.
pub(crate) const KDFE_SHA1: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "bb7a72b68c91a9cc04290baca3d1a46983abb61ffecd9bc4af7daa3fe3f9de74"
            "28deecd046e53d805d6994"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("6db85604c80ace54f6576f30db0aede5"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("2ed3ce0129a65472a50d8ed6f9e08b4d993799fcb65358e3d4e2c1814bbeb146"),
    },
];
/// KDFe vectors for Sha256.
pub(crate) const KDFE_SHA256: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "4cc4be30a72003a2a4ca8066d0921783f6b56d43af0b66b8e96f1972f3bd4f98"
            "53fb4ce374b907b1434f7a767a8054429efb1976542e0d6ff0568592271ee302"
            "2688cd"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("2734867ff3451edff966a60f46a44e86"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("060dc63e5595dffbd161c9ec98bc06fcf67cb22e2e75ecdf0003821388aeee4d"),
    },
];
/// KDFe vectors for Sha384.
pub(crate) const KDFE_SHA384: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "db32de1de0d2d1ae1b654a814b9db13334e038c0e733f775ce047ee1e5c2851e"
            "c807be873324e5cd67651ee7edb57b4543a3c5af9ac15ea3ab493d456520c06b"
            "0b457992dce682e98de4b9746212c5ab7dfb0d69ce91c7590812803f50bc49d9"
            "7d4228"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("d72b1d69a323d1e81f3b37a145261eb2"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("703de8b238576c3c0547b2da4090f4966aafdb0e94d76fa7dfa59f02b4d12b6e"),
    },
];
/// KDFe vectors for Sha512.
pub(crate) const KDFE_SHA512: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "d9a20a8cf5fc04948b56877ee393c2dbf7e522072f6a07694e216b5b1b77f7c8"
            "3c71834e62cfc889b620ab750a8322d6c03dd5f76c46912bdc481d5f0df89e5e"
            "cc235a8a9dc1abdd71d9b3fe123f70c24a41ad369579ebd1b6834ca40759d650"
            "1e5032a11e1e02527e52365a87371d2164218cd2dd0592a0b046a5c55d6a04ec"
            "8758f8"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("943658a289e2ebeee92342363ec38212"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("63e1c62226df5825c32eceb32e9f318316f54d8b56a12f764c88ec4f4b4ed80c"),
    },
];
/// KDFe vectors for Sm3_256.
pub(crate) const KDFE_SM3_256: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "827a0366f48ff665b0acffceeebdf0cc3a2a1e748ad3675c1ad74fa0c6293f92"
            "f44ccc1b2e9eb0a7f886529b8acbe567b2669ffe18523427adb86af5ef252bfa"
            "a4aaca"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("f3315bebf642a7794f1a4694ec5bc66a"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("78b1239e1f7d21581a1b6952b0d60d3a35b6ba6a16c9275324300cf3b01c2f8d"),
    },
];
/// KDFe vectors for Sha3_256.
pub(crate) const KDFE_SHA3_256: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "2e96ed851c4830b6b931ebe1865a22c27e86672f01ccfa3f2d36dc08c03176c8"
            "4cfef7ac7e6de92f829a1f339d7df3066f19c1b880ff4b3d64105c351fd97e6c"
            "c16a27"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("d309cae9fcc162799a93b17b87a35c8b"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("149433e7ebfb188ecb94331a66d54742e89ce081fa4a9c466eb89187ab6bcacf"),
    },
];
/// KDFe vectors for Sha3_384.
pub(crate) const KDFE_SHA3_384: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "59f194dd2a34bdf495038877b4fd1f1ba8055841a9eb154d0d294eceefde9267"
            "9a8ef46aa0fbc71ad1f483a0d24e8d497f0294e4295f4822ddb6795d69f5a51b"
            "1cc9331e82cb14fd79bcecda2425d13259b1a1a26992191d5b60955278b200bf"
            "75601c"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("460e0d1382dc38a9d3b486a1b78c45c0"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("794b8e059ca6a38990fb4821f9349b71b52325b460062e251f71e86f54470bf9"),
    },
];
/// KDFe vectors for Sha3_512.
pub(crate) const KDFE_SHA3_512: [KdfKat; 3] = [
    KdfKat {
        key: KEY,
        label: c"STORAGE",
        context_u: CONTEXT_U,
        context_v: CONTEXT_V,
        out: &hex!(
            "b58bae4acaf472062255b36563fea044335300714d14194c7fd4e9d0c2e030ba"
            "1e5372cd25eab7f4d610bec81df290a88dc1508229107206e9ed0ed57082a400"
            "04286f08454d98a447f73d91cf907f6367aa8ceb727d5e6221e7e7fcc9271a11"
            "ccf89f05dd25754cba0c7c772b2152ad6708c2d56555d0ed043ef78bfc0a4b12"
            "e4d262"
        ),
    },
    KdfKat {
        key: KEY,
        label: c"ATH",
        context_u: CONTEXT_U,
        context_v: &[],
        out: &hex!("76bd1b20577b13b3494029fa2e32b2aa"),
    },
    KdfKat {
        key: &[],
        label: c"",
        context_u: &[],
        context_v: &[],
        out: &hex!("82eb181b712fd76d05125080ef5a554315408986425a12e0f1ec3b5b3fdf2cda"),
    },
];
