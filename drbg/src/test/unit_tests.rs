use crate::HashDrbg;
use digest::generic_array::GenericArray;
use hex_literal::hex;
use sha1::Sha1;
use tpm2_rs_server::platform::crypto::Drbg;

/// this test is one where all buffers are used.
/// It is one of the tests from nist.
/// We put it here for miri because the full test vectors take forever to run
/// so we only miri check this one.
#[test]
fn test_sha1() {
    let entropy = GenericArray::from_slice(&hex!("48a1a97ccc49d7ccf6e378a2f16b0fcd"));
    let nonce = GenericArray::from_slice(&hex!("b091d2ec12a839fe"));
    let mut drbg: HashDrbg<Sha1> =
        HashDrbg::instantiate(entropy, nonce, &hex!("3dc16c1add9cac4ebbb0b889e43b9e12")).unwrap();
    let entropy = GenericArray::from_slice(&hex!("ba5da6791237243fea6050f5b99ecdf5"));

    drbg.reseed(entropy, &hex!("d123e38e4c97e82994a9717ac6f17c08"))
        .unwrap();
    let mut out = [0; 80];
    drbg.fill_bytes(&hex!("800bed9729cfade6680dfe53ba0c1e28"), &mut out)
        .unwrap();
    drbg.fill_bytes(&hex!("251e66b9e385ac1c17fb771b5dc76cf2"), &mut out)
        .unwrap();
    assert_eq!(
        out,
        hex!("a1b2ee86a0f1dab79383133a62279908953a1c9a987760121119cc78b8512bd537a19db973ca397add9233786d5d41fffae98059048521e25284bc6fdb97f34e6a127acd410f50682846be569e9a6bc8"));
    assert_eq!(
        drbg.v.as_slice(),
        &hex!("70fce7f541a28137df24451f6253983caf1ef6c1f5925ac40548b832bd4a9679e06b599177335777392ba52b092428f0a2aac1262d56fe"));
    assert_eq!(
        drbg.c.as_slice(),
        &hex!("831c9876e6fbf21e61948ea6fa02b667f1f14171148f95e5df0f576e9a19e3bab0e5710178adeff97055506d9b3ce70e7e7ec51b8d2ddb"));
    assert_eq!(drbg.reseed_counter, 3);
}
