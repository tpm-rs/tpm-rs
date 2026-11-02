//! Hierarchies: the base hierarchies (`TPM_RH_OWNER`, `TPM_RH_ENDORSEMENT`, `TPM_RH_PLATFORM`,
//! `TPM_RH_NULL`) and the firmware-limited and SVN-limited hierarchies derived from them.
//!
//! TPM 2.0 Part 1, "Firmware-limited and SVN-limited hierarchy seeds and proof values":
//! "Firmware-limited and SVN-limited hierarchies are referred to by reserved permanent handles.
//! Each such hierarchy has an associated base hierarchy (which specifies a primary seed and proof
//! value) and additional secret entropy." (Table "Additional Secrets for Firmware- and
//! SVN-limited Hierarchy Proof Values":)
//!
//! | Limited hierarchy                 | Base hierarchy       | Additional secret            |
//! |-----------------------------------|----------------------|------------------------------|
//! | `TPM_RH_FW_OWNER`                 | `TPM_RH_OWNER`       | Firmware Secret              |
//! | `TPM_RH_FW_ENDORSEMENT`           | `TPM_RH_ENDORSEMENT` | Firmware Secret              |
//! | `TPM_RH_FW_PLATFORM`              | `TPM_RH_PLATFORM`    | Firmware Secret              |
//! | `TPM_RH_FW_NULL`                  | `TPM_RH_NULL`        | Firmware Secret              |
//! | `TPM_RH_SVN_OWNER_BASE + SVN`       | `TPM_RH_OWNER`       | Firmware SVN Secret of SVN   |
//! | `TPM_RH_SVN_ENDORSEMENT_BASE + SVN` | `TPM_RH_ENDORSEMENT` | Firmware SVN Secret of SVN   |
//! | `TPM_RH_SVN_PLATFORM_BASE + SVN`    | `TPM_RH_PLATFORM`    | Firmware SVN Secret of SVN   |
//! | `TPM_RH_SVN_NULL_BASE + SVN`        | `TPM_RH_NULL`        | Firmware SVN Secret of SVN   |
//!
//! A limited hierarchy is available while its base hierarchy is enabled and (SVN-limited) its
//! SVN is not larger than the firmware's current SVN ([`TpmEngine::validate_hierarchy`]); its
//! authorization is that of its base hierarchy (Part 1, "Primary Seed Authorizations"); its seed
//! and proof are derived with Part 1, Equation "seed-proof-limited-hierarchy"
//! ([`TpmEngine::hierarchy_primary_seed`], [`TpmEngine::hierarchy_proof`]).
//!
//! The firmware secrets come from the platform ([`tpm2::platform::TpmFirmware`]); a platform
//! without them does not support limited hierarchies (`TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED`).

use crate::TpmEngine;
use crate::handler::{context_integrity_hash_alg, provisioned_secret};
use crate::self_test::kdfa_bits;
use tpm2::Handle;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Fmt1, TpmRc};
use tpm2::platform::{NvStorage, TpmTimer};

/// The `bSecretLabel` of a seed derivation (Part 1, Equation "seed-proof-limited-hierarchy",
/// note: "The Reference Code uses "H_SEED_SECRET" and "H_PROOF_SECRET" for deriving seeds and
/// proofs, respectively"), with its terminating NUL like the reference's `TPM2B_STRING`.
const SEED_SECRET_LABEL: &[u8] = b"H_SEED_SECRET\0";
/// The `bSecretLabel` of a proof derivation.
const PROOF_SECRET_LABEL: &[u8] = b"H_PROOF_SECRET\0";
/// The `aSecretLabel` of a firmware-limited hierarchy ("For aSecretLabel, the Reference Code uses
/// "H_FW_SECRET" and "H_SVN_SECRET""), with its terminating NUL (it is the KDFa's `contextV`,
/// which the reference passes as a `TPM2B_STRING` including the NUL).
const FW_SECRET_LABEL: &[u8] = b"H_FW_SECRET\0";
/// The `aSecretLabel` of an SVN-limited hierarchy.
const SVN_SECRET_LABEL: &[u8] = b"H_SVN_SECRET\0";

/// The size of the additional secret the TPM requests from the platform: the capacity of a
/// Primary Seed (`sizeof(TPM2B_SEED.buffer)`, 64 octets), for seeds and proofs alike.
const ADDITIONAL_SECRET_SIZE: usize = 64;

/// How a hierarchy handle modifies its base hierarchy (the reference's
/// `HIERARCHY_MODIFIER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Modifier {
    /// A base hierarchy (or any handle that is not a limited hierarchy).
    None,
    /// A firmware-limited hierarchy (`TPM_RH_FW_*`).
    Firmware,
    /// An SVN-limited hierarchy (`TPM_RH_SVN_*_BASE + svn`) limited to the minimum SVN `svn`.
    Svn(u16),
}

/// Splits a hierarchy handle into its base hierarchy and its [`Modifier`] (the reference's
/// `DecomposeHandle`). Any handle that is not a limited hierarchy is returned unchanged with
/// [`Modifier::None`].
pub(crate) fn decompose(handle: u32) -> (u32, Modifier) {
    let fw_base = match handle {
        h if h == Handle::RH_FW_OWNER.0 => Some(Handle::RH_OWNER.0),
        h if h == Handle::RH_FW_ENDORSEMENT.0 => Some(Handle::RH_ENDORSEMENT.0),
        h if h == Handle::RH_FW_PLATFORM.0 => Some(Handle::RH_PLATFORM.0),
        h if h == Handle::RH_FW_NULL.0 => Some(Handle::RH_NULL.0),
        _ => None,
    };
    if let Some(base) = fw_base {
        return (base, Modifier::Firmware);
    }
    let svn_base = match handle & 0xFFFF_0000 {
        b if b == Handle::RH_SVN_OWNER_BASE.0 => Some(Handle::RH_OWNER.0),
        b if b == Handle::RH_SVN_ENDORSEMENT_BASE.0 => Some(Handle::RH_ENDORSEMENT.0),
        b if b == Handle::RH_SVN_PLATFORM_BASE.0 => Some(Handle::RH_PLATFORM.0),
        b if b == Handle::RH_SVN_NULL_BASE.0 => Some(Handle::RH_NULL.0),
        _ => None,
    };
    match svn_base {
        Some(base) => (base, Modifier::Svn(handle as u16)),
        None => (handle, Modifier::None),
    }
}

/// The base hierarchy of a hierarchy handle; any other handle unchanged (the reference's
/// `HierarchyNormalizeHandle`).
pub(crate) fn normalize(handle: u32) -> u32 {
    decompose(handle).0
}

/// Whether `handle` is a firmware-limited hierarchy (`TPM_RH_FW_*`).
pub(crate) fn is_firmware_limited(handle: u32) -> bool {
    decompose(handle).1 == Modifier::Firmware
}

/// Whether `handle` is an SVN-limited hierarchy (`TPM_RH_SVN_*_BASE + svn`).
pub(crate) fn is_svn_limited(handle: u32) -> bool {
    matches!(decompose(handle).1, Modifier::Svn(_))
}

/// Whether `handle` is a firmware-limited or SVN-limited hierarchy.
pub(crate) fn is_limited(handle: u32) -> bool {
    decompose(handle).1 != Modifier::None
}

/// A hierarchy's Primary Seed or proof (64 octets at most), derived for a limited hierarchy.
#[derive(Clone)]
pub struct HierarchySecret {
    buf: [u8; 64],
    len: usize,
}

impl HierarchySecret {
    /// The secret's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn copy_of(bytes: &[u8]) -> Self {
        let mut buf = [0u8; 64];
        buf[..bytes.len()].copy_from_slice(bytes);
        Self {
            buf,
            len: bytes.len(),
        }
    }
}

impl Drop for HierarchySecret {
    fn drop(&mut self) {
        self.buf.fill(0);
    }
}

impl core::fmt::Debug for HierarchySecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HierarchySecret")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl<'a, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync> TpmEngine<'a, C, S, T, R> {
    /// Whether the base hierarchy `base` is enabled (`TPM_RH_NULL` always is); `None` if `base`
    /// is not a base hierarchy.
    pub(crate) fn base_hierarchy_enabled(&self, base: u32) -> Option<bool> {
        match base {
            h if h == Handle::RH_OWNER.0 => Some(self.state.sh_enable),
            h if h == Handle::RH_ENDORSEMENT.0 => Some(self.state.eh_enable),
            h if h == Handle::RH_PLATFORM.0 => Some(self.state.ph_enable),
            h if h == Handle::RH_NULL.0 => Some(true),
            _ => None,
        }
    }

    /// Checks that the hierarchy `handle` is available (the reference's `ValidateHierarchy`):
    ///
    /// * `TPM_RC_FW_LIMITED`: a firmware-limited hierarchy of a TPM without a Firmware Secret
    ///   (Part 2: "the hierarchy is firmware-limited but the Firmware Secret is unavailable").
    /// * `TPM_RC_SVN_LIMITED`: an SVN-limited hierarchy of a TPM without Firmware SVN Secrets, or
    ///   whose SVN is larger than the firmware's current SVN (Part 1, "Enrollment of SVN-Limited
    ///   Objects": "Creation or loading of such objects shall fail if the given SVN is greater
    ///   than the TPM firmware's current SVN").
    /// * `TPM_RC_HIERARCHY`: the (base) hierarchy is disabled.
    /// * `TPM_RC_VALUE`: `handle` is not a hierarchy.
    pub(crate) fn validate_hierarchy(&self, handle: u32) -> Result<(), Fmt1> {
        let (base, modifier) = decompose(handle);
        match modifier {
            Modifier::None => {}
            Modifier::Firmware => {
                if self.platform.firmware.is_none() {
                    return Err(TpmRc::FW_LIMITED);
                }
            }
            Modifier::Svn(svn) => match self.platform.firmware {
                Some(firmware) if svn <= firmware.firmware_svn() => {}
                _ => return Err(TpmRc::SVN_LIMITED),
            },
        }
        match self.base_hierarchy_enabled(base) {
            Some(true) => Ok(()),
            Some(false) => Err(TpmRc::HIERARCHY),
            None => Err(TpmRc::VALUE),
        }
    }

    /// Whether the hierarchy `handle` is available ([`TpmEngine::validate_hierarchy`] succeeds;
    /// the reference's `HierarchyIsEnabled`).
    pub(crate) fn hierarchy_is_enabled(&self, handle: u32) -> bool {
        self.validate_hierarchy(handle).is_ok()
    }

    /// Whether the TPM supports limited hierarchies (its platform has a firmware identity).
    pub(crate) fn supports_limited_hierarchies(&self) -> bool {
        self.platform.firmware.is_some()
    }

    /// The proof of hierarchy `handle` (the reference's `HierarchyGetProof`): `shProof`,
    /// `ehProof`, `phProof` of the base hierarchy (any other base selects `nullProof`), mixed with
    /// the additional secret of a limited hierarchy.
    ///
    /// Fails with `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED` if the additional secret is
    /// unavailable, and with `TPM_RC_FAILURE` if the base proof is not provisioned.
    pub(crate) fn hierarchy_proof(&self, handle: u32) -> Result<HierarchySecret, TpmRc> {
        let (base, modifier) = decompose(handle);
        let gs = &self.state;
        let (proof, size) = match base {
            h if h == Handle::RH_PLATFORM.0 => (&gs.ph_proof, gs.ph_proof_size),
            h if h == Handle::RH_ENDORSEMENT.0 => (&gs.eh_proof, gs.eh_proof_size),
            h if h == Handle::RH_OWNER.0 => (&gs.sh_proof, gs.sh_proof_size),
            _ => (&gs.null_proof, gs.null_proof_size),
        };
        self.mix_additional_secret(modifier, PROOF_SECRET_LABEL, proof, size)
    }

    /// The Primary Seed of hierarchy `handle` (the reference's `HierarchyGetPrimarySeed`): the
    /// PPS, SPS, EPS of the base hierarchy (any other base selects the null seed), mixed with the
    /// additional secret of a limited hierarchy.
    ///
    /// Fails like [`TpmEngine::hierarchy_proof`].
    pub(crate) fn hierarchy_primary_seed(&self, handle: u32) -> Result<HierarchySecret, TpmRc> {
        let (base, modifier) = decompose(handle);
        let gs = &self.state;
        let (seed, size) = match base {
            h if h == Handle::RH_PLATFORM.0 => (&gs.pp_seed, gs.pp_seed_size),
            h if h == Handle::RH_OWNER.0 => (&gs.sp_seed, gs.sp_seed_size),
            h if h == Handle::RH_ENDORSEMENT.0 => (&gs.ep_seed, gs.ep_seed_size),
            _ => (&gs.null_seed, gs.null_seed_size),
        };
        self.mix_additional_secret(modifier, SEED_SECRET_LABEL, seed, size)
    }

    /// Mixes the additional secret of `modifier` into a base seed or proof (the reference's
    /// `MixAdditionalSecret`), Part 1, Equation "seed-proof-limited-hierarchy":
    ///
    /// `value := KDFa(hashAlg, bSecret, bSecretLabel, aSecret, aSecretLabel, bits)`
    ///
    /// with `hashAlg` the context integrity hash ("a hash algorithm chosen by the vendor"; the
    /// reference's `CONTEXT_INTEGRITY_HASH_ALG`) and `bits` the size of the base value. A base
    /// hierarchy, or an empty additional secret, keeps the base value.
    fn mix_additional_secret(
        &self,
        modifier: Modifier,
        base_label: &[u8],
        base: &[u8; 64],
        base_size: u16,
    ) -> Result<HierarchySecret, TpmRc> {
        let mut additional = [0u8; ADDITIONAL_SECRET_SIZE];
        let (additional_len, additional_label) = match modifier {
            Modifier::None => (0, &[][..]),
            Modifier::Firmware => {
                let firmware = self.platform.firmware.ok_or(TpmRc::FW_LIMITED.to_rc())?;
                let len = firmware
                    .firmware_secret(&mut additional)
                    .map_err(|_| TpmRc::FW_LIMITED.to_rc())?;
                (len, FW_SECRET_LABEL)
            }
            Modifier::Svn(svn) => {
                let firmware = self.platform.firmware.ok_or(TpmRc::SVN_LIMITED.to_rc())?;
                let len = firmware
                    .firmware_svn_secret(svn, &mut additional)
                    .map_err(|_| TpmRc::SVN_LIMITED.to_rc())?;
                (len, SVN_SECRET_LABEL)
            }
        };
        let additional_len = core::cmp::min(additional_len, additional.len());
        let result = (|| {
            let base = provisioned_secret(base, base_size)?;
            if additional_len == 0 {
                return Ok(HierarchySecret::copy_of(base));
            }
            let mut out = HierarchySecret::copy_of(&[0u8; 64][..base.len()]);
            kdfa_bits(
                &self.crypto(),
                context_integrity_hash_alg(),
                base,
                base_label,
                &additional[..additional_len],
                additional_label,
                (base.len() * 8) as u32,
                &mut out.buf[..base.len()],
            )
            .map_err(|_| TpmRc::FAILURE)?;
            Ok(out)
        })();
        additional.fill(0);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompose_firmware_limited_handles() {
        assert_eq!(
            decompose(Handle::RH_FW_OWNER.0),
            (Handle::RH_OWNER.0, Modifier::Firmware)
        );
        assert_eq!(
            decompose(Handle::RH_FW_ENDORSEMENT.0),
            (Handle::RH_ENDORSEMENT.0, Modifier::Firmware)
        );
        assert_eq!(
            decompose(Handle::RH_FW_PLATFORM.0),
            (Handle::RH_PLATFORM.0, Modifier::Firmware)
        );
        assert_eq!(
            decompose(Handle::RH_FW_NULL.0),
            (Handle::RH_NULL.0, Modifier::Firmware)
        );
    }

    #[test]
    fn decompose_svn_limited_handles() {
        assert_eq!(
            decompose(0x4001_0000),
            (Handle::RH_OWNER.0, Modifier::Svn(0))
        );
        assert_eq!(
            decompose(0x4002_1234),
            (Handle::RH_ENDORSEMENT.0, Modifier::Svn(0x1234))
        );
        assert_eq!(
            decompose(0x4003_FFFF),
            (Handle::RH_PLATFORM.0, Modifier::Svn(0xFFFF))
        );
        assert_eq!(
            decompose(0x4004_000A),
            (Handle::RH_NULL.0, Modifier::Svn(10))
        );
    }

    #[test]
    fn other_handles_are_unchanged() {
        for h in [
            Handle::RH_OWNER.0,
            Handle::RH_NULL.0,
            Handle::RH_LOCKOUT.0,
            Handle::RH_PLATFORM_NV.0,
            0x4000_0144,
            0x4005_0000,
            0x4000_FFFF,
            0x8000_0000,
            0x0100_0000,
        ] {
            assert_eq!(decompose(h), (h, Modifier::None));
            assert_eq!(normalize(h), h);
            assert!(!is_limited(h));
        }
    }

    #[test]
    fn predicates() {
        assert!(is_firmware_limited(Handle::RH_FW_NULL.0));
        assert!(!is_svn_limited(Handle::RH_FW_NULL.0));
        assert!(is_svn_limited(0x4003_0007));
        assert!(!is_firmware_limited(0x4003_0007));
        assert!(is_limited(0x4001_0000) && is_limited(Handle::RH_FW_OWNER.0));
        assert_eq!(normalize(0x4002_0005), Handle::RH_ENDORSEMENT.0);
        assert_eq!(normalize(Handle::RH_FW_PLATFORM.0), Handle::RH_PLATFORM.0);
    }
}
