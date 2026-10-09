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

    /// Hash algorithms for which this build implements a PCR bank, in ascending algorithm-ID
    /// order (the order of `CryptHashGetAlgByIndex` in the C reference implementation).
    pub const IMPLEMENTED_BANKS: &'static [crate::TpmiAlgHash] = &[
        #[cfg(feature = "sha1")]
        crate::TpmiAlgHash::Sha1,
        #[cfg(feature = "sha256")]
        crate::TpmiAlgHash::Sha256,
        #[cfg(feature = "sha384")]
        crate::TpmiAlgHash::Sha384,
        #[cfg(feature = "sha512")]
        crate::TpmiAlgHash::Sha512,
        #[cfg(feature = "sm3_256")]
        crate::TpmiAlgHash::Sm3_256,
        #[cfg(feature = "sha3_256")]
        crate::TpmiAlgHash::Sha3_256,
        #[cfg(feature = "sha3_384")]
        crate::TpmiAlgHash::Sha3_384,
        #[cfg(feature = "sha3_512")]
        crate::TpmiAlgHash::Sha3_512,
    ];

    /// Returns the raw value of PCR `pcr` in the bank of `alg`, regardless of whether the PCR is
    /// currently allocated (`GetPcrPointerFromPcrArray` in the C reference). Returns `None` if
    /// `pcr` is not an implemented PCR index.
    pub fn value(&self, alg: crate::TpmiAlgHash, pcr: usize) -> Option<&[u8]> {
        if pcr >= 24 {
            return None;
        }
        Some(match alg {
            #[cfg(feature = "sha1")]
            crate::TpmiAlgHash::Sha1 => &self.sha1[pcr][..],
            #[cfg(feature = "sha256")]
            crate::TpmiAlgHash::Sha256 => &self.sha256[pcr][..],
            #[cfg(feature = "sha384")]
            crate::TpmiAlgHash::Sha384 => &self.sha384[pcr][..],
            #[cfg(feature = "sha512")]
            crate::TpmiAlgHash::Sha512 => &self.sha512[pcr][..],
            #[cfg(feature = "sm3_256")]
            crate::TpmiAlgHash::Sm3_256 => &self.sm3_256[pcr][..],
            #[cfg(feature = "sha3_256")]
            crate::TpmiAlgHash::Sha3_256 => &self.sha3_256[pcr][..],
            #[cfg(feature = "sha3_384")]
            crate::TpmiAlgHash::Sha3_384 => &self.sha3_384[pcr][..],
            #[cfg(feature = "sha3_512")]
            crate::TpmiAlgHash::Sha3_512 => &self.sha3_512[pcr][..],
        })
    }

    /// Mutable variant of [`PcrState::value`].
    pub fn value_mut(&mut self, alg: crate::TpmiAlgHash, pcr: usize) -> Option<&mut [u8]> {
        if pcr >= 24 {
            return None;
        }
        Some(match alg {
            #[cfg(feature = "sha1")]
            crate::TpmiAlgHash::Sha1 => &mut self.sha1[pcr][..],
            #[cfg(feature = "sha256")]
            crate::TpmiAlgHash::Sha256 => &mut self.sha256[pcr][..],
            #[cfg(feature = "sha384")]
            crate::TpmiAlgHash::Sha384 => &mut self.sha384[pcr][..],
            #[cfg(feature = "sha512")]
            crate::TpmiAlgHash::Sha512 => &mut self.sha512[pcr][..],
            #[cfg(feature = "sm3_256")]
            crate::TpmiAlgHash::Sm3_256 => &mut self.sm3_256[pcr][..],
            #[cfg(feature = "sha3_256")]
            crate::TpmiAlgHash::Sha3_256 => &mut self.sha3_256[pcr][..],
            #[cfg(feature = "sha3_384")]
            crate::TpmiAlgHash::Sha3_384 => &mut self.sha3_384[pcr][..],
            #[cfg(feature = "sha3_512")]
            crate::TpmiAlgHash::Sha3_512 => &mut self.sha3_512[pcr][..],
        })
    }

    /// Returns `true` if PCR `pcr` of the bank `alg` is allocated in the active allocation
    /// (`PcrIsAllocated` in the C reference).
    pub fn is_allocated(&self, alg: crate::TpmiAlgHash, pcr: usize) -> bool {
        if pcr >= 24 {
            return false;
        }
        self.pcr_allocation
            .pcr_selections()
            .find(|sel| sel.hash() == alg)
            .is_some_and(|sel| {
                sel.pcr_select()
                    .get(pcr / 8)
                    .is_some_and(|b| b & (1 << (pcr % 8)) != 0)
            })
    }

    /// Returns `selection` with every PCR bit cleared that is not allocated in the active
    /// allocation (`FilterPcr` in the C reference). The `sizeofSelect` of the input is kept; a
    /// bank that is not part of the allocation yields an all-zero selection.
    pub fn filter_selection(&self, selection: &crate::TpmsPcrSelection) -> crate::TpmsPcrSelection {
        let allocated = self
            .pcr_allocation
            .pcr_selections()
            .find(|sel| sel.hash() == selection.hash());
        let mut bits = [0u8; crate::TPM2_PCR_SELECT_MAX as usize];
        let input = selection.pcr_select();
        for (i, out) in bits.iter_mut().enumerate().take(input.len()) {
            let mask = allocated
                .and_then(|a| a.pcr_select().get(i).copied())
                .unwrap_or(0);
            *out = input[i] & mask;
        }
        crate::TpmsPcrSelection::new(selection.hash(), &bits[..input.len()]).unwrap_or(*selection)
    }
}
