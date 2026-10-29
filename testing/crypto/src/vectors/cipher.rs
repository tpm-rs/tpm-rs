// Known-answer test vectors. See the crate documentation for sources.

use hex_literal::hex;

/// 128-bit key of NIST SP 800-38A/B (also used for SM4 and Camellia-128).
pub(crate) const KEY128: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
/// 192-bit key of NIST SP 800-38A/B (also used for Camellia-192).
pub(crate) const KEY192: [u8; 24] = hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
/// 256-bit key of NIST SP 800-38A/B (also used for Camellia-256).
pub(crate) const KEY256: [u8; 32] =
    hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
/// Four-block plaintext of NIST SP 800-38A (and message of SP 800-38B).
pub(crate) const PLAINTEXT: [u8; 64] = hex!(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
);
/// IV used for CBC, CFB, and OFB (NIST SP 800-38A).
pub(crate) const IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
/// Initial counter block used for CTR (NIST SP 800-38A).
pub(crate) const CTR_IV: [u8; 16] = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

/// CMAC of `PLAINTEXT[..len]` for `len` in `CMAC_LENS` (SP 800-38B lengths).
pub(crate) const CMAC_LENS: [usize; 4] = [0, 16, 40, 64];

/// CMAC-Aes128 of `PLAINTEXT[..len]` for each `len` in [`CMAC_LENS`].
pub(crate) const CMAC_AES128: [[u8; 16]; 4] = [
    hex!("bb1d6929e95937287fa37d129b756746"),
    hex!("070a16b46b4d4144f79bdd9dd04a287c"),
    hex!("dfa66747de9ae63030ca32611497c827"),
    hex!("51f0bebf7e3b9d92fc49741779363cfe"),
];
/// CMAC-Aes192 of `PLAINTEXT[..len]` for each `len` in [`CMAC_LENS`].
pub(crate) const CMAC_AES192: [[u8; 16]; 4] = [
    hex!("d17ddf46adaacde531cac483de7a9367"),
    hex!("9e99a7bf31e710900662f65e617c5184"),
    hex!("8a1de5be2eb31aad089a82e6ee908b0e"),
    hex!("a1d5df0eed790f794d77589659f39a11"),
];
/// CMAC-Aes256 of `PLAINTEXT[..len]` for each `len` in [`CMAC_LENS`].
pub(crate) const CMAC_AES256: [[u8; 16]; 4] = [
    hex!("028962f61b7bf89efc6b551f4667d983"),
    hex!("28a7023f452e8f82bd4bf28d8c37c35c"),
    hex!("aaf3d8f1de5640c232f5b169b9c911e6"),
    hex!("e1992190549f6ed5696a2c056c315410"),
];
/// CMAC-Sm4_128 of `PLAINTEXT[..len]` for each `len` in [`CMAC_LENS`].
pub(crate) const CMAC_SM4_128: [[u8; 16]; 4] = [
    hex!("399a9c930964a3d4e38c59da47f0b309"),
    hex!("4e4c2a4417e567fef081e0fab55a5762"),
    hex!("8e31701927d50b28d53787513b69dd75"),
    hex!("cc2b4f3d2c5aaf8a4ac30e28650eddc0"),
];
/// CMAC-Camellia128 of `PLAINTEXT[..len]` for each `len` in [`CMAC_LENS`].
pub(crate) const CMAC_CAMELLIA128: [[u8; 16]; 4] = [
    hex!("ba925782aaa1f5d9a00f89648094fc71"),
    hex!("6d962854a3b9fda56d7d45a95ee17993"),
    hex!("5c18d119ccd6766144ac1866131d9f22"),
    hex!("c2699a6eba55ce9d939a8a4e19466ee9"),
];
/// CMAC-Camellia192 of `PLAINTEXT[..len]` for each `len` in [`CMAC_LENS`].
pub(crate) const CMAC_CAMELLIA192: [[u8; 16]; 4] = [
    hex!("f87e2a2b29b172145ccb43a6fee89439"),
    hex!("8b3435b103fda8748e1fba527a00ff15"),
    hex!("4e298456ecbd04c733de2677fd8c915c"),
    hex!("b86277c0dffcbaaf402a56229af54fb7"),
];
/// CMAC-Camellia256 of `PLAINTEXT[..len]` for each `len` in [`CMAC_LENS`].
pub(crate) const CMAC_CAMELLIA256: [[u8; 16]; 4] = [
    hex!("01e1f2fdac3a30055b3dbafdea119078"),
    hex!("aa5decec4af41291df4b6fe726167c79"),
    hex!("7800be582ad62caee6a02ec68c5ecd67"),
    hex!("07472d6ba0b2af3bcb235a701606a07a"),
];

/// `(ciphertext, iv_out)` of `PLAINTEXT` with Aes128 for CTR, OFB, CBC, CFB, and ECB.
pub(crate) const MODES_AES128: [([u8; 64], [u8; 16]); 5] = [
    // Ctr
    (
        hex!(
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee"
        ),
        hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03"),
    ),
    // Ofb
    (
        hex!(
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "7789508d16918f03f53c52dac54ed825"
            "9740051e9c5fecf64344f7a82260edcc"
            "304c6528f659c77866a510d9c1d6ae5e"
        ),
        hex!("c6d3416d29165c6fcb8e51a227ba994e"),
    ),
    // Cbc
    (
        hex!(
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        ),
        hex!("3ff1caa1681fac09120eca307586e1a7"),
    ),
    // Cfb
    (
        hex!(
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "c8a64537a0b3a93fcde3cdad9f1ce58b"
            "26751f67a3cbb140b1808cf187a4f4df"
            "c04b05357c5d1c0eeac4c66f9ff7f2e6"
        ),
        hex!("c04b05357c5d1c0eeac4c66f9ff7f2e6"),
    ),
    // Ecb
    (
        hex!(
            "3ad77bb40d7a3660a89ecaf32466ef97"
            "f5d3d58503b9699de785895a96fdbaaf"
            "43b1cd7f598ece23881b00e3ed030688"
            "7b0c785e27e8ad3f8223207104725dd4"
        ),
        hex!("00000000000000000000000000000000"),
    ),
];
/// `(ciphertext, iv_out)` of `PLAINTEXT` with Aes192 for CTR, OFB, CBC, CFB, and ECB.
pub(crate) const MODES_AES192: [([u8; 64], [u8; 16]); 5] = [
    // Ctr
    (
        hex!(
            "1abc932417521ca24f2b0459fe7e6e0b"
            "090339ec0aa6faefd5ccc2c6f4ce8e94"
            "1e36b26bd1ebc670d1bd1d665620abf7"
            "4f78a7f6d29809585a97daec58c6b050"
        ),
        hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03"),
    ),
    // Ofb
    (
        hex!(
            "cdc80d6fddf18cab34c25909c99a4174"
            "fcc28b8d4c63837c09e81700c1100401"
            "8d9a9aeac0f6596f559c6d4daf59a5f2"
            "6d9f200857ca6c3e9cac524bd9acc92a"
        ),
        hex!("9b00044d8885f729318713303fc0fe3a"),
    ),
    // Cbc
    (
        hex!(
            "4f021db243bc633d7178183a9fa071e8"
            "b4d9ada9ad7dedf4e5e738763f69145a"
            "571b242012fb7ae07fa9baac3df102e0"
            "08b0e27988598881d920a9e64f5615cd"
        ),
        hex!("08b0e27988598881d920a9e64f5615cd"),
    ),
    // Cfb
    (
        hex!(
            "cdc80d6fddf18cab34c25909c99a4174"
            "67ce7f7f81173621961a2b70171d3d7a"
            "2e1e8a1dd59b88b1c8e60fed1efac4c9"
            "c05f9f9ca9834fa042ae8fba584b09ff"
        ),
        hex!("c05f9f9ca9834fa042ae8fba584b09ff"),
    ),
    // Ecb
    (
        hex!(
            "bd334f1d6e45f25ff712a214571fa5cc"
            "974104846d0ad3ad7734ecb3ecee4eef"
            "ef7afd2270e2e60adce0ba2face6444e"
            "9a4b41ba738d6c72fb16691603c18e0e"
        ),
        hex!("00000000000000000000000000000000"),
    ),
];
/// `(ciphertext, iv_out)` of `PLAINTEXT` with Aes256 for CTR, OFB, CBC, CFB, and ECB.
pub(crate) const MODES_AES256: [([u8; 64], [u8; 16]); 5] = [
    // Ctr
    (
        hex!(
            "601ec313775789a5b7a7f504bbf3d228"
            "f443e3ca4d62b59aca84e990cacaf5c5"
            "2b0930daa23de94ce87017ba2d84988d"
            "dfc9c58db67aada613c2dd08457941a6"
        ),
        hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03"),
    ),
    // Ofb
    (
        hex!(
            "dc7e84bfda79164b7ecd8486985d3860"
            "4febdc6740d20b3ac88f6ad82a4fb08d"
            "71ab47a086e86eedf39d1c5bba97c408"
            "0126141d67f37be8538f5a8be740e484"
        ),
        hex!("f7b93058b8bce0fffea41bf0012cd394"),
    ),
    // Cbc
    (
        hex!(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
            "9cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461"
            "b2eb05e2c39be9fcda6c19078c6a9d1b"
        ),
        hex!("b2eb05e2c39be9fcda6c19078c6a9d1b"),
    ),
    // Cfb
    (
        hex!(
            "dc7e84bfda79164b7ecd8486985d3860"
            "39ffed143b28b1c832113c6331e5407b"
            "df10132415e54b92a13ed0a8267ae2f9"
            "75a385741ab9cef82031623d55b1e471"
        ),
        hex!("75a385741ab9cef82031623d55b1e471"),
    ),
    // Ecb
    (
        hex!(
            "f3eed1bdb5d2a03c064b5a7e3db181f8"
            "591ccb10d410ed26dc5ba74a31362870"
            "b6ed21b99ca6f4f9f153e7b1beafed1d"
            "23304b7a39f9f3ff067d8d8f9e24ecc7"
        ),
        hex!("00000000000000000000000000000000"),
    ),
];
/// `(ciphertext, iv_out)` of `PLAINTEXT` with Sm4_128 for CTR, OFB, CBC, CFB, and ECB.
pub(crate) const MODES_SM4_128: [([u8; 64], [u8; 16]); 5] = [
    // Ctr
    (
        hex!(
            "14ae4a72b97a93ce1216ccd998e371c1"
            "60f7ef8b6344bd6da1992505e5fc219b"
            "0bf057f86c5d75103c0f46519c7fb2e7"
            "292805035adb9a90ecef145359d7cf0e"
        ),
        hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03"),
    ),
    // Ofb
    (
        hex!(
            "bc710d762d070b26361da82b54565e46"
            "07a0c62834740ad3240d239125e11621"
            "d476b21cc9f04951f0741d2ef9e09498"
            "1584fc142bf13aa626b82f9d7d076cce"
        ),
        hex!("e31bd851f4bea1b18b936ee69b6b5bde"),
    ),
    // Cbc
    (
        hex!(
            "ac529af989a62fce9cddc5ffb84125ca"
            "b168dd69db3c0eea1ab16de6aea43c59"
            "2c15567bff8f707486c202c7be59101f"
            "74a629b350cd7e11be99998af5206d6c"
        ),
        hex!("74a629b350cd7e11be99998af5206d6c"),
    ),
    // Cfb
    (
        hex!(
            "bc710d762d070b26361da82b54565e46"
            "a4cd42786a3a5293a3c6cbc123f0b354"
            "407055b1c1a5d9982c187d5c3ee0ced8"
            "4b82c40f2f0a4e0341797f1f307b8047"
        ),
        hex!("4b82c40f2f0a4e0341797f1f307b8047"),
    ),
    // Ecb
    (
        hex!(
            "a51411ff04a711443891fce7ab842a29"
            "d5b50f46a9a730a0f590ffa776d99855"
            "c9a86a4d71447f4e873ada4f388af9b9"
            "2b25557b50514d155939e6ec940ad90e"
        ),
        hex!("00000000000000000000000000000000"),
    ),
];
/// `(ciphertext, iv_out)` of `PLAINTEXT` with Camellia128 for CTR, OFB, CBC, CFB, and ECB.
pub(crate) const MODES_CAMELLIA128: [([u8; 64], [u8; 16]); 5] = [
    // Ctr
    (
        hex!(
            "b809140877dd16c076780904f83ded11"
            "bb41e64e9bf176ce05d4186b2586d4c9"
            "49e82fdc5d6e78ab781363e51781fc9b"
            "731a3c0583979a926e7fe0b8a205ac29"
        ),
        hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03"),
    ),
    // Ofb
    (
        hex!(
            "14f7646187817eb586599146b82bd719"
            "973291716c4d82d01a079e6df700e6eb"
            "0ef0603e2ee534c174f44a8678a01f5b"
            "a9978a354c35c7a052c38218183cbe71"
        ),
        hex!("5f08ae70937a5cb7ffe8c363fe508961"),
    ),
    // Cbc
    (
        hex!(
            "1607cf494b36bbf00daeb0b503c831ab"
            "a2f2cf671629ef7840c5a5dfb5074887"
            "0f06165008cf8b8b5a63586362543e54"
            "e7208a2ca89cc21aacd56aaa6fb98259"
        ),
        hex!("e7208a2ca89cc21aacd56aaa6fb98259"),
    ),
    // Cfb
    (
        hex!(
            "14f7646187817eb586599146b82bd719"
            "a53d28bb82df741103ea4f921a44880b"
            "9c2157a664626d1def9ea420fde69b96"
            "742a25f0542340c7baef24ca8482bb09"
        ),
        hex!("742a25f0542340c7baef24ca8482bb09"),
    ),
    // Ecb
    (
        hex!(
            "432fc5dcd628115b7c388d770b270c96"
            "0be1f14023782a22e8384c5abb7fab2b"
            "a0a1abcd1893ab6fe0fe5b65df5f8636"
            "e61925e0d5dfaa9bb29f815b3076e51a"
        ),
        hex!("00000000000000000000000000000000"),
    ),
];
/// `(ciphertext, iv_out)` of `PLAINTEXT` with Camellia192 for CTR, OFB, CBC, CFB, and ECB.
pub(crate) const MODES_CAMELLIA192: [([u8; 64], [u8; 16]); 5] = [
    // Ctr
    (
        hex!(
            "564617f8ea0938bb25dc9d199ca57e2a"
            "277412da1a840117bb1291458757c37c"
            "c766846c319f0aa11963588babdc9d5f"
            "955441063efc3f046c805e938ebda91b"
        ),
        hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03"),
    ),
    // Ofb
    (
        hex!(
            "c832bb9780677daa82d9b6860dcd565e"
            "3c2d4dd917844e919c637a3ab938b451"
            "e5a9fb948bc3a757057d3d8ef304ef43"
            "2c6670555bbdd6c8f89e25df337ca849"
        ),
        hex!("daf9541084f24ddf55b564a4d5109f59"),
    ),
    // Cbc
    (
        hex!(
            "2a4830ab5ac4a1a2405955fd2195cf93"
            "5d5a869bd14ce54264f892a6dd2ec3d5"
            "37d359c3349836d884e310addf68c449"
            "01faaa930b4ab9916e9668e1428c6b08"
        ),
        hex!("01faaa930b4ab9916e9668e1428c6b08"),
    ),
    // Cfb
    (
        hex!(
            "c832bb9780677daa82d9b6860dcd565e"
            "86f8491627906d780c7a6d46ea331f98"
            "69511cce594cf710cb98bb63d7221f01"
            "d5b5378a3abed55803f25565d8907b84"
        ),
        hex!("d5b5378a3abed55803f25565d8907b84"),
    ),
    // Ecb
    (
        hex!(
            "cccc6c4e138b45848514d48d0d3439d3"
            "5713c62c14b2ec0f8393b6afd6f5785a"
            "b40ed2b60eb54d09d030cf511feef366"
            "909dbd95799096748cb27357e73e1d26"
        ),
        hex!("00000000000000000000000000000000"),
    ),
];
/// `(ciphertext, iv_out)` of `PLAINTEXT` with Camellia256 for CTR, OFB, CBC, CFB, and ECB.
pub(crate) const MODES_CAMELLIA256: [([u8; 64], [u8; 16]); 5] = [
    // Ctr
    (
        hex!(
            "47ba6eea51b438fcf21c3cc988762817"
            "1a7bbbfc7f6e9ee58646c3ef8dabc540"
            "fad5121ba9aec78ab1005f0a1480aa96"
            "f23000ae0286650906ae9e51eae924eb"
        ),
        hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03"),
    ),
    // Ofb
    (
        hex!(
            "cf6107bb0cea7d7fb1bd31f5e7b06c93"
            "85521db2f6bb677f1eb2244658418340"
            "23272685ae6049c788114b3c21ca205c"
            "5ee78c39291e114699050e3d20db0c4a"
        ),
        hex!("a878a87cf6518a51342e4f46c6b73b5a"),
    ),
    // Cbc
    (
        hex!(
            "e6cfa35fc02b134a4d2c0b6737ac3eda"
            "36cbeb73bd504b4070b1b7de2b21eb50"
            "e31a6055297d96ca3330cdf1b1860a83"
            "5d563f6d1cccf236051c0c5c1c58f28f"
        ),
        hex!("5d563f6d1cccf236051c0c5c1c58f28f"),
    ),
    // Cfb
    (
        hex!(
            "cf6107bb0cea7d7fb1bd31f5e7b06c93"
            "89bedb4ccdd864ea11ba4cbe849b5e2b"
            "555fc3f34bdd2d54c62d9e3bf338c1c4"
            "5953adce14db8c7f39f1bd39f359bffa"
        ),
        hex!("5953adce14db8c7f39f1bd39f359bffa"),
    ),
    // Ecb
    (
        hex!(
            "befd219b112fa00098919cd101c9ccfa"
            "c91d3a8f1aea08a9386cf4b66c0169ea"
            "a623d711dc5f25a51bb8a80d56397d28"
            "7960109fb6dc42947fcfe59ea3c5eb6b"
        ),
        hex!("00000000000000000000000000000000"),
    ),
];
