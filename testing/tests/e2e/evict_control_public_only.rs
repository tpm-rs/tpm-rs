//! TPM2_EvictControl of public-only objects (TPM2_LoadExternal without a sensitive area).
//!
//! TPM 2.0 Part 3 (revision 185), TPM2_EvictControl: "Older versions of the specification did
//! not allow an object to be persisted when only the public portion of the object was loaded
//! (for NV space efficiency). Support for persisting public-only objects was added in version
//! 185." Only objects "in the hierarchy of `TPM_RH_NULL`" (or a firmware-/SVN-limited one) or
//! with *stClear* SET are still rejected with `TPM_RC_ATTRIBUTES`. The persistent copy is still
//! a public-only object: it has the same Name, and its authValue is not available.

use crate::_common::{
    ECC_X, ECC_Y, ST_SESSIONS, build_raw_cmd, evict_control, flush_context, load_external,
    make_ecc_public_area, mssim_rc_of, read_public,
};
use testing::tpm::Tpm;
use tpm2::{Handle, TpmaObject};

/// `TPM_RC_ATTRIBUTES + TPM_RC_H + TPM_RC_2` (objectHandle).
const RC_ATTRIBUTES_H2: u32 = 0x282;
/// `TPM_RC_AUTH_UNAVAILABLE`.
const RC_AUTH_UNAVAILABLE: u32 = 0x12F;
/// An empty password session (`TPM_RS_PW`, no nonce, continueSession, empty password).
const PW_SESSION: &[u8] = &[0x40, 0, 0, 0x09, 0, 0, 0x01, 0, 0];
/// The owner persistent handle the tests use.
const OWNER_PERSISTENT: Handle = Handle(0x8100_0300);
/// The platform persistent handle the tests use.
const PLATFORM_PERSISTENT: Handle = Handle(0x8180_0300);

/// Loads the public-only ECC P-256 signing key (`ECC_X`, `ECC_Y`) into `hierarchy`.
fn load_public_only_key(tpm: &mut Tpm, hierarchy: Handle) -> Handle {
    load_external(
        tpm,
        make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT),
        None,
        hierarchy,
    )
    .unwrap_or_else(|rc| panic!("TPM2_LoadExternal failed: {rc:#x}"))
}

/// TPM2_Sign(`key`) with an empty password session; returns the response code.
fn sign_rc(tpm: &mut Tpm, key: Handle) -> u32 {
    let mut params = vec![0x00, 0x20];
    params.extend_from_slice(&[0x5a; 32]); // digest
    params.extend_from_slice(&[0x00, 0x10]); // inScheme: TPM_ALG_NULL
    // validation: TPMT_TK_HASHCHECK { TPM_ST_HASHCHECK, TPM_RH_NULL, empty digest }.
    params.extend_from_slice(&[0x80, 0x24, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00]);
    let cmd = build_raw_cmd(ST_SESSIONS, 0x15D, &[key.0], Some(PW_SESSION), &params);
    mssim_rc_of(tpm, &cmd)
}

/// The owner can make a public-only key of the owner hierarchy persistent; the persistent copy
/// has the same public area and Name as the transient object, which stays loaded.
#[test]
fn owner_persists_public_only_key() {
    let mut tpm = Tpm::new();
    let key = load_public_only_key(&mut tpm, Handle::RH_OWNER);
    evict_control(&mut tpm, Handle::RH_OWNER, key, OWNER_PERSISTENT).unwrap();

    let transient = read_public(&mut tpm, key).unwrap();
    let persistent = read_public(&mut tpm, OWNER_PERSISTENT).unwrap();
    assert_eq!(persistent.name, transient.name);
    assert_eq!(persistent.qualified_name, transient.qualified_name);
    assert_eq!(persistent.out_public.0, transient.out_public.0);
    flush_context(&mut tpm, key).unwrap();
    assert!(read_public(&mut tpm, OWNER_PERSISTENT).is_ok());
}

/// The platform can make a public-only key of the platform hierarchy persistent.
#[test]
fn platform_persists_public_only_key() {
    let mut tpm = Tpm::new();
    let key = load_public_only_key(&mut tpm, Handle::RH_PLATFORM);
    evict_control(&mut tpm, Handle::RH_PLATFORM, key, PLATFORM_PERSISTENT).unwrap();
    assert_eq!(
        read_public(&mut tpm, PLATFORM_PERSISTENT).unwrap().name,
        read_public(&mut tpm, key).unwrap().name
    );
}

/// The persistent copy of a public-only key is still public-only: like the transient object,
/// it has no authValue available (TPM_RC_AUTH_UNAVAILABLE for a password session).
#[test]
fn persistent_public_only_key_has_no_auth_value() {
    let mut tpm = Tpm::new();
    let key = load_public_only_key(&mut tpm, Handle::RH_OWNER);
    assert_eq!(sign_rc(&mut tpm, key), RC_AUTH_UNAVAILABLE);
    evict_control(&mut tpm, Handle::RH_OWNER, key, OWNER_PERSISTENT).unwrap();
    flush_context(&mut tpm, key).unwrap();
    assert_eq!(sign_rc(&mut tpm, OWNER_PERSISTENT), RC_AUTH_UNAVAILABLE);
}

/// A persisted public-only key can be evicted again, after which its handle is gone.
#[test]
fn persistent_public_only_key_can_be_evicted() {
    let mut tpm = Tpm::new();
    let key = load_public_only_key(&mut tpm, Handle::RH_ENDORSEMENT);
    evict_control(&mut tpm, Handle::RH_OWNER, key, OWNER_PERSISTENT).unwrap();
    evict_control(
        &mut tpm,
        Handle::RH_OWNER,
        OWNER_PERSISTENT,
        OWNER_PERSISTENT,
    )
    .unwrap();
    assert!(read_public(&mut tpm, OWNER_PERSISTENT).is_err());
    // The transient object is unaffected and can be persisted again.
    evict_control(&mut tpm, Handle::RH_OWNER, key, OWNER_PERSISTENT).unwrap();
}

/// A public-only key of the NULL hierarchy still cannot be made persistent ("it is in the
/// hierarchy of `TPM_RH_NULL`": TPM_RC_ATTRIBUTES on objectHandle).
#[test]
fn null_hierarchy_public_only_key_is_not_persisted() {
    let mut tpm = Tpm::new();
    let key = load_public_only_key(&mut tpm, Handle::RH_NULL);
    assert_eq!(
        evict_control(&mut tpm, Handle::RH_OWNER, key, OWNER_PERSISTENT).unwrap_err(),
        RC_ATTRIBUTES_H2
    );
}
