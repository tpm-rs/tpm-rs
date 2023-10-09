use crate::constants;
use open_enum::open_enum;

/// Nice in-memory view of `TpmDigest`. This would point to memory from
/// an arena or the original request after it has been parsed.
pub enum TpmDigest<'a> {
    Sha(&'a [u8; constants::TPM2_SHA_DIGEST_SIZE]),
    Sha1(&'a [u8; constants::TPM2_SHA1_DIGEST_SIZE]),
    Sha256(&'a [u8; constants::TPM2_SHA256_DIGEST_SIZE]),
}

/// Valid Algorithm IDs. This is an open enum that can be treated as an enum in
/// match statements, but always requires handing the unknown variant. There is
/// less overhead during parse time using this enum style, but more overhead when
/// using in rust program (since one always needs to handle unknown variant)
#[allow(non_camel_case_types)]
#[open_enum]
#[repr(u16)]
pub enum Tpm2AlgId {
    RSA = 0x0001,
    SHA1 = 0x0004,
    HMAC = 0x0005,
    AES = 0x0006,
    MGF1 = 0x0007,
    KEYEDHASH = 0x0008,
    XOR = 0x000A,
    SHA256 = 0x000B,
    SHA384 = 0x000C,
    SHA512 = 0x000D,
    NONE = 0x0010,
    SM3_256 = 0x0012,
    SM4 = 0x0013,
    RSASSA = 0x0014,
    RSAES = 0x0015,
    RSAPSS = 0x0016,
    OAEP = 0x0017,
    ECDSA = 0x0018,
    ECDH = 0x0019,
    ECDAA = 0x001A,
    SM2 = 0x001B,
    ECSCHNORR = 0x001C,
    ECMQV = 0x001D,
    KDF1_SP800_56A = 0x0020,
    KDF2 = 0x0021,
    KDF1_SP800_108 = 0x0022,
    ECC = 0x0023,
    SYMCIPHER = 0x0025,
    CAMELLIA = 0x0026,
}
