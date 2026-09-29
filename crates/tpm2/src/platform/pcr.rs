//! PCR (Platform Configuration Register) state model.

/// Returns the default initial value for a 24-PCR bank of size `N`.
///
/// According to the TCG PC Client Platform Firmware Profile (PFP) Specification
/// (v1.04–v1.06, Section 3.3.4 "PCR Initial Values"; PTP Specification, Section 4.2):
/// - PCR 0..=16 are initialized to `0x00`.
/// - PCR 17..=22 (DRTM PCRs) are initialized to `0xFF`.
/// - PCR 23 is initialized to `0x00`.
#[inline]
const fn initial_pcr_bank<const N: usize>() -> [[u8; N]; 24] {
    let mut bank = [[0u8; N]; 24];
    let mut i = 17;
    while i <= 22 {
        bank[i] = [0xFF; N];
        i += 1;
    }
    bank
}

/// Detailed PCR state supporting 24 PCRs across supported hash algorithm banks.
#[derive(Clone, Copy, Debug)]
pub struct PcrState {
    /// SHA-1 PCR bank (24 PCRs, 20 bytes each).
    #[cfg(feature = "sha1")]
    pub sha1: [[u8; 20]; 24],
    /// SHA-256 PCR bank (24 PCRs, 32 bytes each).
    #[cfg(feature = "sha256")]
    pub sha256: [[u8; 32]; 24],
    /// SHA-384 PCR bank (24 PCRs, 48 bytes each).
    #[cfg(feature = "sha384")]
    pub sha384: [[u8; 48]; 24],
    /// SHA-512 PCR bank (24 PCRs, 64 bytes each).
    #[cfg(feature = "sha512")]
    pub sha512: [[u8; 64]; 24],
    /// SM3-256 PCR bank (24 PCRs, 32 bytes each).
    #[cfg(feature = "sm3_256")]
    pub sm3_256: [[u8; 32]; 24],
    /// SHA3-256 PCR bank (24 PCRs, 32 bytes each).
    #[cfg(feature = "sha3_256")]
    pub sha3_256: [[u8; 32]; 24],
    /// SHA3-384 PCR bank (24 PCRs, 48 bytes each).
    #[cfg(feature = "sha3_384")]
    pub sha3_384: [[u8; 48]; 24],
    /// SHA3-512 PCR bank (24 PCRs, 64 bytes each).
    #[cfg(feature = "sha3_512")]
    pub sha3_512: [[u8; 64]; 24],
    /// Increments upon every extend, event, or reset operation.
    pub update_counter: u32,
    /// Active PCR allocation selections across supported hash algorithms.
    pub pcr_allocation: crate::TpmlPcrSelection,
}

impl Default for PcrState {
    fn default() -> Self {
        let pcr_allocation = crate::TpmlPcrSelection::from_slice(&[
            #[cfg(feature = "sha1")]
            crate::TpmsPcrSelection::new(crate::TpmiAlgHash::Sha1, &[0xFF, 0xFF, 0xFF]).unwrap(),
            #[cfg(feature = "sha256")]
            crate::TpmsPcrSelection::new(crate::TpmiAlgHash::Sha256, &[0xFF, 0xFF, 0xFF]).unwrap(),
            #[cfg(feature = "sha384")]
            crate::TpmsPcrSelection::new(crate::TpmiAlgHash::Sha384, &[0x00, 0x00, 0x00]).unwrap(),
            #[cfg(feature = "sha512")]
            crate::TpmsPcrSelection::new(crate::TpmiAlgHash::Sha512, &[0x00, 0x00, 0x00]).unwrap(),
            #[cfg(feature = "sm3_256")]
            crate::TpmsPcrSelection::new(crate::TpmiAlgHash::Sm3_256, &[0x00, 0x00, 0x00]).unwrap(),
            #[cfg(feature = "sha3_256")]
            crate::TpmsPcrSelection::new(crate::TpmiAlgHash::Sha3_256, &[0x00, 0x00, 0x00])
                .unwrap(),
            #[cfg(feature = "sha3_384")]
            crate::TpmsPcrSelection::new(crate::TpmiAlgHash::Sha3_384, &[0x00, 0x00, 0x00])
                .unwrap(),
            #[cfg(feature = "sha3_512")]
            crate::TpmsPcrSelection::new(crate::TpmiAlgHash::Sha3_512, &[0x00, 0x00, 0x00])
                .unwrap(),
        ])
        .unwrap();

        Self {
            #[cfg(feature = "sha1")]
            sha1: initial_pcr_bank(),
            #[cfg(feature = "sha256")]
            sha256: initial_pcr_bank(),
            #[cfg(feature = "sha384")]
            sha384: initial_pcr_bank(),
            #[cfg(feature = "sha512")]
            sha512: initial_pcr_bank(),
            #[cfg(feature = "sm3_256")]
            sm3_256: initial_pcr_bank(),
            #[cfg(feature = "sha3_256")]
            sha3_256: initial_pcr_bank(),
            #[cfg(feature = "sha3_384")]
            sha3_384: initial_pcr_bank(),
            #[cfg(feature = "sha3_512")]
            sha3_512: initial_pcr_bank(),
            update_counter: 0,
            pcr_allocation,
        }
    }
}

impl PcrState {
    /// Resets the PCR register values to their default initial values and clears the update counter,
    /// while preserving any configured persistent PCR bank allocation (`pcr_allocation`).
    ///
    /// Per TPM 2.0 Spec Part 1 Section 14.8 and Part 3 Section 22.5 (`TPM2_PCR_Allocate`),
    /// bank allocations configured in NV persist across resets and are not wiped by `_TPM_Init`
    /// or `TPM2_Startup(TPM_SU_CLEAR)`. Therefore, this method only resets register values
    /// (PCR 0..=16 and 23 to `0x00`, PCR 17..=22 to `0xFF`) and sets `update_counter` to `0`.
    pub fn reset(&mut self) {
        #[cfg(feature = "sha1")]
        {
            self.sha1 = initial_pcr_bank();
        }
        #[cfg(feature = "sha256")]
        {
            self.sha256 = initial_pcr_bank();
        }
        #[cfg(feature = "sha384")]
        {
            self.sha384 = initial_pcr_bank();
        }
        #[cfg(feature = "sha512")]
        {
            self.sha512 = initial_pcr_bank();
        }
        #[cfg(feature = "sm3_256")]
        {
            self.sm3_256 = initial_pcr_bank();
        }
        #[cfg(feature = "sha3_256")]
        {
            self.sha3_256 = initial_pcr_bank();
        }
        #[cfg(feature = "sha3_384")]
        {
            self.sha3_384 = initial_pcr_bank();
        }
        #[cfg(feature = "sha3_512")]
        {
            self.sha3_512 = initial_pcr_bank();
        }
        self.update_counter = 0;
    }
}
