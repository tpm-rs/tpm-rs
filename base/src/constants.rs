pub const TPM2_SHA_DIGEST_SIZE: usize = 20;
pub const TPM2_SHA1_DIGEST_SIZE: usize = 20;
pub const TPM2_SHA256_DIGEST_SIZE: usize = 32;
pub const TPM2_SHA384_DIGEST_SIZE: usize = 48;
pub const TPM2_SHA512_DIGEST_SIZE: usize = 64;
pub const TPM2_SM3_256_DIGEST_SIZE: usize = 32;

pub const TPM2_MAX_DIGEST_BUFFER: u32 = 1024;
pub const TPM2_MAX_NV_BUFFER_SIZE: u32 = 2048;
pub const TPM2_MAX_CAP_BUFFER: u32 = 1024;
pub const TPM2_NUM_PCR_BANKS: u32 = 16;
pub const TPM2_MAX_PCRS: u32 = 32;
pub const TPM2_PCR_SELECT_MAX: u32 = (TPM2_MAX_PCRS + 7) / 8;
pub const TPM2_LABEL_MAX_BUFFER: u32 = 32;

/* Encryption block sizes */
pub const TPM2_MAX_SYM_BLOCK_SIZE: u32 = 16;
pub const TPM2_MAX_SYM_DATA: u32 = 256;
pub const TPM2_MAX_ECC_KEY_BYTES: u32 = 128;
pub const TPM2_MAX_SYM_KEY_BYTES: u32 = 32;
pub const TPM2_MAX_RSA_KEY_BYTES: u32 = 512;

pub const TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES: u32 = (TPM2_MAX_RSA_KEY_BYTES / 2) * (3 + 2);

pub const TPM2_MAX_CONTEXT_SIZE: u32 = 5120;

/* Algorithm IDs */
pub const TPM2_ALG_RSA: u16 = 0x0001;
pub const TPM2_ALG_SHA1: u16 = 0x0004;
pub const TPM2_ALG_HMAC: u16 = 0x0005;
pub const TPM2_ALG_AES: u16 = 0x0006;
pub const TPM2_ALG_MGF1: u16 = 0x0007;
pub const TPM2_ALG_KEYEDHASH: u16 = 0x0008;
pub const TPM2_ALG_XOR: u16 = 0x000A;
pub const TPM2_ALG_SHA256: u16 = 0x000B;
pub const TPM2_ALG_SHA384: u16 = 0x000C;
pub const TPM2_ALG_SHA512: u16 = 0x000D;
pub const TPM2_ALG_NONE: u16 = 0x0010;
pub const TPM2_ALG_SM3_256: u16 = 0x0012;
pub const TPM2_ALG_SM4: u16 = 0x0013;
pub const TPM2_ALG_RSASSA: u16 = 0x0014;
pub const TPM2_ALG_RSAES: u16 = 0x0015;
pub const TPM2_ALG_RSAPSS: u16 = 0x0016;
pub const TPM2_ALG_OAEP: u16 = 0x0017;
pub const TPM2_ALG_ECDSA: u16 = 0x0018;
pub const TPM2_ALG_ECDH: u16 = 0x0019;
pub const TPM2_ALG_ECDAA: u16 = 0x001A;
pub const TPM2_ALG_SM2: u16 = 0x001B;
pub const TPM2_ALG_ECSCHNORR: u16 = 0x001C;
pub const TPM2_ALG_ECMQV: u16 = 0x001D;
pub const TPM2_ALG_KDF1_SP800_56A: u16 = 0x0020;
pub const TPM2_ALG_KDF2: u16 = 0x0021;
pub const TPM2_ALG_KDF1_SP800_108: u16 = 0x0022;
pub const TPM2_ALG_ECC: u16 = 0x0023;
pub const TPM2_ALG_SYMCIPHER: u16 = 0x0025;
pub const TPM2_ALG_CAMELLIA: u16 = 0x0026;

/* Structure Tags */
pub const TPM2_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM2_ST_SESSIONS: u16 = 0x8002;
pub const TPM2_ST_ATTEST_NV: u16 = 0x8014;
pub const TPM2_ST_ATTEST_COMMAND_AUDIT: u16 = 0x8015;
pub const TPM2_ST_ATTEST_SESSION_AUDIT: u16 = 0x8016;
pub const TPM2_ST_ATTEST_CERTIFY: u16 = 0x8017;
pub const TPM2_ST_ATTEST_QUOTE: u16 = 0x8018;
pub const TPM2_ST_ATTEST_TIME: u16 = 0x8019;
pub const TPM2_ST_ATTEST_CREATION: u16 = 0x801A;

/* Capabilities */
pub const TPM2_CAP_FIRST: u32 = 0x00000000;
pub const TPM2_CAP_ALGS: u32 = 0x00000000;
pub const TPM2_CAP_HANDLES: u32 = 0x00000001;
pub const TPM2_CAP_COMMANDS: u32 = 0x00000002;
pub const TPM2_CAP_PP_COMMANDS: u32 = 0x00000003;
pub const TPM2_CAP_AUDIT_COMMANDS: u32 = 0x00000004;
pub const TPM2_CAP_PCRS: u32 = 0x00000005;
pub const TPM2_CAP_TPM_PROPERTIES: u32 = 0x00000006;
pub const TPM2_CAP_PCR_PROPERTIES: u32 = 0x00000007;
pub const TPM2_CAP_ECC_CURVES: u32 = 0x00000008;
pub const TPM2_CAP_AUTH_POLICIES: u32 = 0x00000009;
pub const TPM2_CAP_LAST: u32 = 0x0000000A;
