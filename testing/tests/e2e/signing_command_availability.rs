//! The version 185 signing commands TPM2_SignDigest, TPM2_VerifyDigestSignature,
//! TPM2_SignSequenceStart/Complete and TPM2_VerifySequenceStart/Complete in `TPM_CAP_COMMANDS`
//! (with their `TPMA_CC`: handle counts, *rHandle*, *flushed*) when their `cc-*` profile
//! feature implements them, and `TPM_RC_COMMAND_CODE` when it does not.

use crate::_common::{CAP_COMMANDS, build_raw_cmd, get_cap, send_with_rc};
use testing::tpm::Tpm;
use tpm2::TpmCc;
use tpm2::errors::TpmRc;

/// `TPMA_CC.rHandle`.
const R_HANDLE: u32 = 1 << 28;
/// `TPMA_CC.flushed`.
const FLUSHED: u32 = 1 << 24;

/// Each command, whether its profile feature implements it, and its expected `TPMA_CC` bits
/// above `commandIndex` (`cHandles` in bits 25..=27, `rHandle`, `flushed`).
fn commands() -> [(TpmCc, bool, u32); 6] {
    [
        (TpmCc::SignDigest, cfg!(feature = "cc-sign-digest"), 1 << 25),
        (
            TpmCc::VerifyDigestSignature,
            cfg!(feature = "cc-verify-digest-signature"),
            1 << 25,
        ),
        (
            TpmCc::SignSequenceStart,
            cfg!(feature = "cc-sign-sequence-start"),
            (1 << 25) | R_HANDLE,
        ),
        (
            TpmCc::VerifySequenceStart,
            cfg!(feature = "cc-verify-sequence-start"),
            (1 << 25) | R_HANDLE,
        ),
        (
            TpmCc::SignSequenceComplete,
            cfg!(feature = "cc-sign-sequence-complete"),
            (2 << 25) | FLUSHED,
        ),
        (
            TpmCc::VerifySequenceComplete,
            cfg!(feature = "cc-verify-sequence-complete"),
            (2 << 25) | FLUSHED,
        ),
    ]
}

/// An implemented command is listed in `TPM_CAP_COMMANDS` with its `TPMA_CC` (TPM 2.0 Part 3
/// marks TPM2_SignSequenceComplete and TPM2_VerifySequenceComplete `{F}`); an unimplemented
/// one is not listed.
#[test]
fn listed_in_capability_when_implemented() {
    let mut sim = Tpm::new();
    for (cc, implemented, bits) in commands() {
        let (_, data) = get_cap(&mut sim, CAP_COMMANDS, cc.code(), 1).unwrap();
        let count = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let first = (count > 0).then(|| u32::from_be_bytes(data[4..8].try_into().unwrap()));
        let listed = first.filter(|attr| attr & 0xFFFF == cc.code());
        if implemented {
            let attr = listed.unwrap_or_else(|| panic!("{cc:?} not in TPM_CAP_COMMANDS"));
            assert_eq!(attr & !0xFFFF, bits, "TPMA_CC of {cc:?}: {attr:#010x}");
        } else {
            assert_eq!(listed, None, "{cc:?} listed but not implemented");
        }
    }
}

/// An unimplemented command is rejected with `TPM_RC_COMMAND_CODE`.
#[test]
fn unimplemented_command_rejected() {
    let mut sim = Tpm::new();
    for (cc, implemented, _) in commands() {
        if implemented {
            continue;
        }
        let cmd = build_raw_cmd(0x8001, cc.code(), &[], None, &[]);
        let (rc, _) = send_with_rc(&mut sim, &cmd);
        assert_eq!(rc, TpmRc::COMMAND_CODE.get(), "{cc:?}");
    }
}
