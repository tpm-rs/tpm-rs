//! The unmarshal profile of a TPM: which algorithms, ECC curves and RSA key sizes it implements,
//! and the sizes of its profile-dependent buffers and lists.
//!
//! The types of this crate accept every value of the algorithms enabled by its Cargo features.
//! A TPM implements a narrower *profile*, and unmarshaling a command must fail as soon as a value
//! outside the profile is read (for example a `TPMI_ALG_HASH` of an unimplemented hash is
//! `TPM_RC_HASH` at its parameter, before any later parameter is read; a `TPM2B` larger than
//! the profile's buffer is `TPM_RC_SIZE`). The Cargo features cannot express the profile of a
//! TPM built in a workspace: features are unified across the whole build, and other crates of the
//! `tpm-rs` workspace need more algorithms than the TPM implements (the crypto backends and their
//! tests exercise SM3 and RSA-4096, and a client may talk to other TPMs).
//!
//! The specification requires it: TPM 2.0 Part 3, "Parameter Unmarshaling": "it is required
//! that the TPM validate that the parameters meet the requirements of the expected data type as
//! defined in TPM 2.0 Part 2", whose interface types are per TPM, e.g. Part 2, `TPMI_ALG_HASH`:
//! "`TPMI_ALG_HASH` is an interface type of all the hash algorithms implemented on a specific
//! TPM", and Table "Definition of TPM2B_PRIVATE Structure": "buffer\[size\] {:sizeof(_PRIVATE)}".
//!
//! A TPM engine therefore installs its [`Profile`] once with [`install`]. From then on, in the
//! whole process:
//!
//! * the algorithm interface types ([`TpmiAlgHash`], [`TpmiAlgKdf`], [`TpmiAlgCipherMode`],
//!   [`TpmiAlgSymMode`], [`TpmiAlgMacScheme`], [`TpmiAlgSigScheme`], [`TpmiEccKeyExchange`],
//!   [`TpmiAlgPublic`] and the symmetric algorithms of [`AlgSym`]) reject algorithms that are not
//!   in [`Profile::algorithms`], with the type's usual error;
//! * [`TpmEccCurve`] rejects curves that are not in [`Profile::curves`] (`TPM_RC_CURVE`);
//! * [`TpmiRsaKeyBits`] rejects key sizes that are not in [`Profile::rsa_key_bits`]
//!   (`TPM_RC_VALUE`), and the `keyBits` of a symmetric block cipher ([`AlgSym`]) the sizes that
//!   are not in [`Profile::sym_key_bits`] (`TPM_RC_VALUE`, Part 2 Table "Definition of
//!   Types for Symmetric Cipher Key Sizes": "TPMI_AES_KEY_BITS | {128, 192, 256}");
//! * the profile-dependent sized buffers ([`Tpm2bPublicKeyRsa`], [`Tpm2bPrivateKeyRsa`],
//!   [`Tpm2bEncryptedSecret`], [`Tpm2bPrivate`], [`Tpm2bTemplate`] and [`Tpm2bEccParameter`])
//!   hold at most the sizes of [`Profile::buffer_limits`] (`TPM_RC_SIZE`);
//! * the lists bounded by `HASH_COUNT` ([`TpmlPcrSelection`] and [`TpmlDigestValues`]) hold at
//!   most as many entries as [`Profile::algorithms`] lists hash algorithms (`TPM_RC_SIZE`; Part 2,
//!   Table "Definition of TPML_PCR_SELECTION Structure": "pcrSelections\[count\]{:HASH_COUNT}"
//!   and "#TPM_RC_SIZE | response code when *count* is greater than the possible number of
//!   banks");
//! * [`PcrState::default`](crate::platform::pcr::PcrState) allocates all PCRs of the banks of
//!   [`Profile::default_pcr_banks`] and no PCR of the other implemented banks (without a profile,
//!   the banks of [`DEFAULT_PCR_BANKS`]).
//!
//! Without an installed profile (the default, e.g. in clients and in the crypto tests) nothing
//! changes (apart from the default PCR allocation, see [`DEFAULT_PCR_BANKS`]). The profile is a `&'static` value installed at most once per process: installing an
//! equal profile again is a no-op, a different one is rejected
//! ([`InstallError::ProfileAlreadyInstalled`]).
//! Code in the same process that unmarshals TPM structures (e.g. the test client of an in-process
//! TPM) is subject to the profile too, which is correct for everything the TPM produces or
//! accepts.
//!
//! The crate forbids `unsafe` and is `no_std`, so the installed profile is kept as a copy in
//! atomics (bitmaps of the algorithm IDs, curves, key sizes and default PCR banks, and the buffer
//! limits).

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};

use crate::*;

/// The unmarshal profile of a TPM (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The implemented algorithms (`TPM_CAP_ALGS`). Only IDs below `0x0100` can be listed.
    pub algorithms: &'static [Alg],
    /// The implemented ECC curves (`TPM_CAP_ECC_CURVES`). Only IDs below `0x0080` can be listed.
    pub curves: &'static [TpmEccCurve],
    /// The implemented RSA key sizes in bits (multiples of 1024 up to 8192).
    pub rsa_key_bits: &'static [u16],
    /// The implemented key sizes of the symmetric block ciphers in bits (128, 192 or 256).
    pub sym_key_bits: &'static [u16],
    /// The capacities of the profile-dependent sized buffers.
    pub buffer_limits: BufferLimits,
    /// The hash algorithms whose PCR banks are allocated (all PCRs) when the TPM is manufactured;
    /// the banks of the other implemented hash algorithms start with no PCR allocated and can be
    /// allocated with `TPM2_PCR_Allocate`. Each must be a hash algorithm listed in
    /// [`Profile::algorithms`].
    ///
    /// The default allocation is a platform choice (TPM 2.0 Part 1, "PCR Allocation"). The TCG
    /// reference platform (`DefaultActivePcrBanks` in `PlatformPcr.c`) allocates the SHA-256
    /// and SHA-384 banks ([`DEFAULT_PCR_BANKS`]).
    pub default_pcr_banks: &'static [Alg],
}

/// The banks allocated by [`PcrState::default`](crate::platform::pcr::PcrState) without an
/// installed profile: SHA-256 and SHA-384, like the TCG reference platform
/// (`DefaultActivePcrBanks` in `PlatformPcr.c`).
pub const DEFAULT_PCR_BANKS: &[Alg] = &[Alg::SHA256, Alg::SHA384];

/// The capacities (in bytes) of a profile's profile-dependent sized buffers (the `sizeof()` of
/// their buffers in the TPM's profile).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferLimits {
    /// `TPM2B_PUBLIC_KEY_RSA` (`MAX_RSA_KEY_BYTES`).
    pub public_key_rsa: usize,
    /// `TPM2B_PRIVATE_KEY_RSA` (`RSA_PRIVATE_SIZE`).
    pub private_key_rsa: usize,
    /// `TPM2B_ENCRYPTED_SECRET` (`sizeof(TPMU_ENCRYPTED_SECRET)`).
    pub encrypted_secret: usize,
    /// `TPM2B_PRIVATE` (`sizeof(_PRIVATE)`).
    pub private: usize,
    /// `TPM2B_TEMPLATE` (`sizeof(TPMT_PUBLIC)`).
    pub template: usize,
    /// `TPM2B_ECC_PARAMETER` (`MAX_ECC_KEY_BYTES`).
    pub ecc_parameter: usize,
}

/// The buffers [`BufferLimits`] bounds (see [`crate::limits::Tag::PROFILE_LIMITED`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitedBuffer {
    /// `TPM2B_PUBLIC_KEY_RSA`.
    PublicKeyRsa,
    /// `TPM2B_PRIVATE_KEY_RSA`.
    PrivateKeyRsa,
    /// `TPM2B_ENCRYPTED_SECRET`.
    EncryptedSecret,
    /// `TPM2B_PRIVATE`.
    Private,
    /// `TPM2B_TEMPLATE`.
    Template,
    /// `TPM2B_ECC_PARAMETER`.
    EccParameter,
}

/// [`install`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    /// A different profile is already installed.
    ProfileAlreadyInstalled,
    /// The profile lists an algorithm, curve or key size outside the representable range (see
    /// the field docs of [`Profile`]).
    Unrepresentable,
    /// [`Profile::default_pcr_banks`] lists an algorithm that is not a hash algorithm of
    /// [`Profile::algorithms`].
    InvalidDefaultPcrBank,
}

impl core::fmt::Display for InstallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ProfileAlreadyInstalled => {
                "a different TPM unmarshal profile is already installed"
            }
            Self::Unrepresentable => "the TPM unmarshal profile cannot be represented",
            Self::InvalidDefaultPcrBank => {
                "a default PCR bank of the TPM profile is not an implemented hash algorithm"
            }
        })
    }
}

impl core::error::Error for InstallError {}

/// No profile installed.
const EMPTY: u8 = 0;
/// [`install`] is copying a profile into the atomics.
const INSTALLING: u8 = 1;
/// A profile is installed.
const INSTALLED: u8 = 2;

/// The installation state ([`EMPTY`], [`INSTALLING`] or [`INSTALLED`]).
static STATE: AtomicU8 = AtomicU8::new(EMPTY);
/// Bitmap of the installed algorithm IDs (`0x0000..0x0100`).
static ALGORITHMS: [AtomicU32; 8] = [const { AtomicU32::new(0) }; 8];
/// Bitmap of the installed curve IDs (`0x0000..0x0080`).
static CURVES: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
/// Bitmap of the installed RSA key sizes (bit `n`: `1024 * (n + 1)` bits).
static RSA_KEY_BITS: AtomicU8 = AtomicU8::new(0);
/// Bitmap of the installed symmetric key sizes (bit `n`: `64 * (n + 2)` bits).
static SYM_KEY_BITS: AtomicU8 = AtomicU8::new(0);
/// Bitmap of the installed default PCR banks' algorithm IDs (`0x0000..0x0100`).
static DEFAULT_PCR_BANK_BITS: [AtomicU32; 8] = [const { AtomicU32::new(0) }; 8];
/// The installed [`BufferLimits`], in the order of [`LimitedBuffer`].
static LIMITS: [AtomicUsize; LIMIT_COUNT] = [const { AtomicUsize::new(0) }; LIMIT_COUNT];
/// The number of [`LimitedBuffer`]s, followed in [`LIMITS`] by the hash count.
const BUFFER_COUNT: usize = 6;
/// The number of values in [`LIMITS`]: the [`BufferLimits`] and the hash count.
const LIMIT_COUNT: usize = BUFFER_COUNT + 1;
/// The index of the hash count (`HASH_COUNT`) in [`LIMITS`].
const HASH_COUNT_INDEX: usize = BUFFER_COUNT;

/// The bitmaps of a [`Profile`].
#[derive(Clone, Copy, PartialEq, Eq)]
struct Bitmaps {
    /// [`Profile::algorithms`] (see [`ALGORITHMS`]).
    algorithms: [u32; 8],
    /// [`Profile::curves`] (see [`CURVES`]).
    curves: [u32; 4],
    /// [`Profile::rsa_key_bits`] (see [`RSA_KEY_BITS`]).
    rsa_key_bits: u8,
    /// [`Profile::sym_key_bits`] (see [`SYM_KEY_BITS`]).
    sym_key_bits: u8,
    /// [`Profile::default_pcr_banks`] (see [`DEFAULT_PCR_BANK_BITS`]).
    default_pcr_banks: [u32; 8],
}

/// Sets the bit of `alg` in an algorithm ID bitmap; `None` if its ID is `0x0100` or above.
fn set_alg_bit(bitmap: &mut [u32; 8], alg: Alg) -> Option<()> {
    let id = usize::from(alg.id());
    *bitmap.get_mut(id / 32)? |= 1 << (id % 32);
    Some(())
}

/// Whether the bit of `alg` is set in an atomic algorithm ID bitmap.
fn has_alg_bit(bitmap: &[AtomicU32; 8], alg: Alg) -> bool {
    let id = usize::from(alg.id());
    bitmap
        .get(id / 32)
        .is_some_and(|w| w.load(Ordering::Acquire) & (1 << (id % 32)) != 0)
}

/// The bitmaps of `profile`.
fn bitmaps(profile: &Profile) -> Result<Bitmaps, InstallError> {
    let maps = representable_bitmaps(profile).ok_or(InstallError::Unrepresentable)?;
    let mut default_pcr_banks = [0u32; 8];
    for &alg in profile.default_pcr_banks {
        if !is_hash(alg) || !profile.algorithms.contains(&alg) {
            return Err(InstallError::InvalidDefaultPcrBank);
        }
        set_alg_bit(&mut default_pcr_banks, alg).ok_or(InstallError::InvalidDefaultPcrBank)?;
    }
    Ok(Bitmaps {
        default_pcr_banks,
        ..maps
    })
}

/// The bitmaps of `profile` without the default PCR banks; `None` if a value is outside the
/// representable range.
fn representable_bitmaps(profile: &Profile) -> Option<Bitmaps> {
    let mut algorithms = [0u32; 8];
    for &alg in profile.algorithms {
        set_alg_bit(&mut algorithms, alg)?;
    }
    let mut curves = [0u32; 4];
    for &curve in profile.curves {
        let id = usize::from(u16::from(curve));
        *curves.get_mut(id / 32)? |= 1 << (id % 32);
    }
    let mut rsa = 0u8;
    for &bits in profile.rsa_key_bits {
        if bits == 0 || !bits.is_multiple_of(1024) || bits > 8192 {
            return None;
        }
        rsa |= 1 << (bits / 1024 - 1);
    }
    let mut sym = 0u8;
    for &bits in profile.sym_key_bits {
        sym |= 1 << sym_key_bits_index(bits)?;
    }
    Some(Bitmaps {
        algorithms,
        curves,
        rsa_key_bits: rsa,
        sym_key_bits: sym,
        default_pcr_banks: [0; 8],
    })
}

/// The bit of a symmetric key size in [`SYM_KEY_BITS`].
fn sym_key_bits_index(bits: u16) -> Option<u8> {
    match bits {
        128 => Some(0),
        192 => Some(1),
        256 => Some(2),
        _ => None,
    }
}

/// The limits of `profile` in the order of [`LIMITS`]: the [`BufferLimits`] in the order of
/// [`LimitedBuffer`], then the number of hash algorithms (`HASH_COUNT`).
fn limit_values(profile: &Profile) -> [usize; LIMIT_COUNT] {
    let limits = &profile.buffer_limits;
    [
        limits.public_key_rsa,
        limits.private_key_rsa,
        limits.encrypted_secret,
        limits.private,
        limits.template,
        limits.ecc_parameter,
        profile
            .algorithms
            .iter()
            .filter(|&&alg| is_hash(alg))
            .count(),
    ]
}

/// Whether `alg` is a hash algorithm (TPM 2.0 Part 2, Table "Definition of (TPM_ALG_ID)
/// TPMI_ALG_HASH Type"), independent of the Cargo features and of an installed profile.
fn is_hash(alg: Alg) -> bool {
    matches!(
        alg,
        Alg::SHA1
            | Alg::SHA256
            | Alg::SHA384
            | Alg::SHA512
            | Alg::SM3_256
            | Alg::SHA3_256
            | Alg::SHA3_384
            | Alg::SHA3_512
    )
}

/// Whether the installed profile equals the given bitmaps and limits.
fn installed_equals(maps: &Bitmaps, limits: &[usize; LIMIT_COUNT]) -> bool {
    ALGORITHMS
        .iter()
        .zip(maps.algorithms)
        .all(|(a, v)| a.load(Ordering::Acquire) == v)
        && CURVES
            .iter()
            .zip(maps.curves)
            .all(|(a, v)| a.load(Ordering::Acquire) == v)
        && RSA_KEY_BITS.load(Ordering::Acquire) == maps.rsa_key_bits
        && SYM_KEY_BITS.load(Ordering::Acquire) == maps.sym_key_bits
        && DEFAULT_PCR_BANK_BITS
            .iter()
            .zip(maps.default_pcr_banks)
            .all(|(a, v)| a.load(Ordering::Acquire) == v)
        && LIMITS
            .iter()
            .zip(limits)
            .all(|(a, &v)| a.load(Ordering::Acquire) == v)
}

/// Installs `profile` for the whole process (see the module docs).
///
/// Installing a profile equal to the installed one is a no-op.
pub fn install(profile: &'static Profile) -> Result<(), InstallError> {
    let maps = bitmaps(profile)?;
    let limits = limit_values(profile);
    loop {
        match STATE.compare_exchange(EMPTY, INSTALLING, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                for (a, v) in ALGORITHMS.iter().zip(maps.algorithms) {
                    a.store(v, Ordering::Release);
                }
                for (a, v) in CURVES.iter().zip(maps.curves) {
                    a.store(v, Ordering::Release);
                }
                RSA_KEY_BITS.store(maps.rsa_key_bits, Ordering::Release);
                SYM_KEY_BITS.store(maps.sym_key_bits, Ordering::Release);
                for (a, v) in DEFAULT_PCR_BANK_BITS.iter().zip(maps.default_pcr_banks) {
                    a.store(v, Ordering::Release);
                }
                for (a, v) in LIMITS.iter().zip(limits) {
                    a.store(v, Ordering::Release);
                }
                STATE.store(INSTALLED, Ordering::Release);
                return Ok(());
            }
            Err(INSTALLED) => {
                return if installed_equals(&maps, &limits) {
                    Ok(())
                } else {
                    Err(InstallError::ProfileAlreadyInstalled)
                };
            }
            // Another thread is installing: wait for it.
            Err(_) => core::hint::spin_loop(),
        }
    }
}

/// Whether a profile is installed.
pub fn is_installed() -> bool {
    STATE.load(Ordering::Acquire) == INSTALLED
}

/// Whether `alg` is allowed: no profile is installed, or it lists `alg`.
pub fn allows_algorithm(alg: Alg) -> bool {
    if !is_installed() {
        return true;
    }
    has_alg_bit(&ALGORITHMS, alg)
}

/// Whether the PCR bank of `hash` is allocated by default: the installed profile lists it in
/// [`Profile::default_pcr_banks`], or no profile is installed and [`DEFAULT_PCR_BANKS`] lists it.
pub fn is_default_pcr_bank(hash: Alg) -> bool {
    if !is_installed() {
        return DEFAULT_PCR_BANKS.contains(&hash);
    }
    has_alg_bit(&DEFAULT_PCR_BANK_BITS, hash)
}

/// Whether `curve` is allowed: no profile is installed, or it lists `curve`.
pub fn allows_curve(curve: TpmEccCurve) -> bool {
    if !is_installed() {
        return true;
    }
    let id = usize::from(u16::from(curve));
    CURVES
        .get(id / 32)
        .is_some_and(|w| w.load(Ordering::Acquire) & (1 << (id % 32)) != 0)
}

/// Whether an RSA key of `bits` bits is allowed: no profile is installed, or it lists `bits`.
pub fn allows_rsa_key_bits(bits: u16) -> bool {
    if !is_installed() {
        return true;
    }
    bits != 0
        && bits.is_multiple_of(1024)
        && bits <= 8192
        && RSA_KEY_BITS.load(Ordering::Acquire) & (1 << (bits / 1024 - 1)) != 0
}

/// Whether a symmetric block cipher key of `bits` bits is allowed: no profile is installed, or
/// it lists `bits`.
pub fn allows_sym_key_bits(bits: u16) -> bool {
    if !is_installed() {
        return true;
    }
    sym_key_bits_index(bits).is_some_and(|i| SYM_KEY_BITS.load(Ordering::Acquire) & (1 << i) != 0)
}

/// The capacity of `buffer`: `cap` (its compile-time capacity), lowered to the installed
/// profile's limit.
pub(crate) fn buffer_cap(buffer: LimitedBuffer, cap: usize) -> usize {
    if !is_installed() {
        return cap;
    }
    cap.min(LIMITS[buffer as usize].load(Ordering::Acquire))
}

/// The most entries of a list bounded by `HASH_COUNT` ([`TpmlPcrSelection`],
/// [`TpmlDigestValues`]): `cap` (its compile-time capacity), lowered to the number of hash
/// algorithms of the installed profile.
pub(crate) fn hash_count_cap(cap: usize) -> usize {
    if !is_installed() {
        return cap;
    }
    cap.min(LIMITS[HASH_COUNT_INDEX].load(Ordering::Acquire))
}
