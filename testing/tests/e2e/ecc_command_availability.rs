//! Availability of the ECC key-exchange and ECC-encryption features: TPM2_EC_Ephemeral,
//! TPM2_ZGen_2Phase, TPM2_ECC_Encrypt and TPM2_ECC_Decrypt are implemented (in
//! `TPM_CAP_COMMANDS` with their `TPMA_CC`) exactly when their `cc-*` feature is enabled and
//! fail with TPM_RC_COMMAND_CODE otherwise, and `TPM_ALG_ECMQV` is in `TPM_CAP_ALGS` exactly
//! with the `ecmqv` feature.

use crate::_common::{
    CAP_ALGS, CAP_COMMANDS, ST_NO_SESSIONS, build_raw_cmd, get_cap, send_with_rc,
};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;
use tpm2::{Alg, Handle, TpmaAlgorithm};

/// The commands with their number of handles and whether this build implements them.
const COMMANDS: [(u32, u32, bool); 4] = [
    (0x18E, 0, cfg!(feature = "cc-ec-ephemeral")),
    (0x18D, 1, cfg!(feature = "cc-zgen-2phase")),
    (0x199, 1, cfg!(feature = "cc-ecc-encrypt")),
    (0x19A, 1, cfg!(feature = "cc-ecc-decrypt")),
];

/// `TPM_CAP_COMMANDS` starting at `cc`: the first `TPMA_CC` it returns, if any.
fn first_command_attributes(sim: &mut Tpm, cc: u32) -> Option<u32> {
    let (_, data) = get_cap(sim, CAP_COMMANDS, cc, 1).unwrap();
    let count = u32::from_be_bytes(data[0..4].try_into().unwrap());
    (count > 0).then(|| u32::from_be_bytes(data[4..8].try_into().unwrap()))
}

/// An implemented command is listed in `TPM_CAP_COMMANDS` with `commandIndex` = its code,
/// `cHandles` = its number of handles and no other attribute (Part 3: none of these commands
/// has `nv`, `extensive`, `flushed` or `rHandle`); an unimplemented one is not listed.
#[test]
fn commands_listed_exactly_when_enabled() {
    let mut sim = Tpm::new();
    for (cc, handles, enabled) in COMMANDS {
        let attributes = first_command_attributes(&mut sim, cc);
        if enabled {
            assert_eq!(attributes, Some(cc | (handles << 25)), "{cc:#x}");
        } else {
            assert_ne!(attributes.map(|a| a & 0xFFFF), Some(cc), "{cc:#x}");
        }
    }
}

/// An unimplemented command fails with TPM_RC_COMMAND_CODE; an implemented one gets past the
/// command-code check.
#[test]
fn unimplemented_commands_rejected_with_command_code() {
    let mut sim = Tpm::new();
    for (cc, handles, enabled) in COMMANDS {
        let handle_area = [Handle::RH_NULL.0; 1];
        let cmd = build_raw_cmd(
            ST_NO_SESSIONS,
            cc,
            &handle_area[..handles as usize],
            None,
            &[],
        );
        let (rc, _) = send_with_rc(&mut sim, &cmd);
        if enabled {
            assert_ne!(rc, TpmRc::COMMAND_CODE.get(), "{cc:#x}");
        } else {
            assert_eq!(rc, TpmRc::COMMAND_CODE.get(), "{cc:#x}");
        }
    }
}

/// `TPM_ALG_ECMQV` is in `TPM_CAP_ALGS` as an asymmetric method (`AlgorithmCap.c`:
/// `asymmetric`, `method`) exactly with the `ecmqv` feature.
#[test]
fn ecmqv_listed_exactly_when_enabled() {
    let mut sim = Tpm::new();
    let (_, data) = get_cap(&mut sim, CAP_ALGS, u32::from(Alg::ECMQV.id()), 1).unwrap();
    let count = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let first = (count > 0).then(|| {
        (
            u16::from_be_bytes(data[4..6].try_into().unwrap()),
            u32::from_be_bytes(data[6..10].try_into().unwrap()),
        )
    });
    if cfg!(feature = "ecmqv") {
        assert_eq!(
            first,
            Some((
                Alg::ECMQV.id(),
                (TpmaAlgorithm::ASYMMETRIC | TpmaAlgorithm::METHOD).bits()
            ))
        );
    } else {
        assert_ne!(first.map(|(alg, _)| alg), Some(Alg::ECMQV.id()));
    }
}
