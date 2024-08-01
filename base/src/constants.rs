// =============================================================================
// USES
// =============================================================================

use crate::types::{
    TPM2Cap, TPM2ECCCurve, TPM2Handle, TpmsAlgProperty, TpmsTaggedPcrSelect, TpmsTaggedPolicy,
    TpmsTaggedProperty, TPM2CC,
};
use core::mem::size_of;

// =============================================================================
// CONSTANTS
// =============================================================================

// -----------------------------------------------------------------------------
pub const TPM2_SHA_DIGEST_SIZE: u32 = 20;
pub const TPM2_SHA1_DIGEST_SIZE: u32 = 20;
pub const TPM2_SHA256_DIGEST_SIZE: u32 = 32;
pub const TPM2_SHA384_DIGEST_SIZE: u32 = 48;
pub const TPM2_SHA512_DIGEST_SIZE: u32 = 64;
pub const TPM2_SM3_256_DIGEST_SIZE: u32 = 32;

// -----------------------------------------------------------------------------
pub const TPM2_MAX_DIGEST_BUFFER: u32 = 1024;
pub const TPM2_MAX_NV_BUFFER_SIZE: u32 = 2048;
pub const TPM2_MAX_CAP_BUFFER: u32 = 1024;
pub const TPM2_NUM_PCR_BANKS: u32 = 16;
pub const TPM2_MAX_PCRS: u32 = 32;
pub const TPM2_PCR_SELECT_MAX: u32 = (TPM2_MAX_PCRS + 7) / 8;
pub const TPM2_LABEL_MAX_BUFFER: u32 = 32;

// -----------------------------------------------------------------------------
// Encryption block sizes
// -----------------------------------------------------------------------------
pub const TPM2_MAX_SYM_BLOCK_SIZE: u32 = 16;
pub const TPM2_MAX_SYM_DATA: u32 = 256;
pub const TPM2_MAX_ECC_KEY_BYTES: u32 = 128;
pub const TPM2_MAX_SYM_KEY_BYTES: u32 = 32;
pub const TPM2_MAX_RSA_KEY_BYTES: u32 = 512;

// -----------------------------------------------------------------------------
pub const TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES: u32 = (TPM2_MAX_RSA_KEY_BYTES / 2) * (3 + 2);

// -----------------------------------------------------------------------------
pub const TPM2_MAX_CONTEXT_SIZE: u32 = 5120;
pub const TPM2_MAX_ACTIVE_SESSIONS: u32 = 64;

// -----------------------------------------------------------------------------
pub const TPM2_MAX_CAP_DATA: usize =
    TPM2_MAX_CAP_BUFFER as usize - size_of::<TPM2Cap>() - size_of::<u32>();
pub const TPM2_MAX_CAP_ALGS: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsAlgProperty>();
pub const TPM2_MAX_CAP_HANDLES: usize = TPM2_MAX_CAP_DATA / size_of::<TPM2Handle>();
pub const TPM2_MAX_CAP_CC: usize = TPM2_MAX_CAP_DATA / size_of::<TPM2CC>();
pub const TPM2_MAX_TPM_PROPERTIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedProperty>();
pub const TPM2_MAX_PCR_PROPERTIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedPcrSelect>();
pub const TPM2_MAX_ECC_CURVES: usize = TPM2_MAX_CAP_DATA / size_of::<TPM2ECCCurve>();
pub const TPM2_MAX_TAGGED_POLICIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedPolicy>();
pub const TPML_DIGEST_MAX_DIGESTS: usize = 8;
