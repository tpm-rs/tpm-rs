//! TPM2_PCR_Reset: resettable PCRs, locality and handle checks.

use crate::_common::{
    ALG_SHA256, ALG_SHA384, exec_command as exec,
    execute_tpm_command_at_locality0 as execute_tpm_command,
    pcr_extend_at_no_continue as pcr_extend_at, pcr_read_selection as pcr_read,
    pcr_reset_at_no_continue as pcr_reset_at, pw, read_pcr_by_alg_id as read_pcr,
};
use testing::tpm::Tpm;
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

/// PCRs 16 and 23 reset to zero at locality 0 after extend; PCR 0 fails with TPM_RC_LOCALITY
///
/// PCRs 16 and 23 can be reset at locality 0 after being extended; PCR 0
/// cannot (`TPM_RC_LOCALITY`).
#[test]
fn pcr_reset_resettable_pcrs_at_locality_zero() {
    let mut sim = Tpm::new();

    for (pcr, select, fill) in [(16u32, [0u8, 0, 1], 0xaau8), (23, [0, 0, 128], 0xbb)] {
        let digest = [fill; 32];
        let mut digests = TpmlDigestValues::default();
        digests.add(&TpmtHa::Sha256(&digest)).unwrap();
        exec(
            &mut sim,
            &PCRExtend {
                pcr_handle: Handle(pcr),
                digests,
            },
            &[pw()],
        )
        .unwrap();

        let mut selection = TpmlPcrSelection::default();
        selection
            .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select).unwrap())
            .unwrap();

        // Verify the PCR has changed
        let read = pcr_read(&mut sim, selection).unwrap();
        assert_ne!(read.pcr_values.digests()[0].get_buffer(), &[0u8; 32]);

        // Reset the PCR
        exec(
            &mut sim,
            &PCRReset {
                pcr_handle: Handle(pcr),
            },
            &[pw()],
        )
        .unwrap();

        // Verify the PCR has reset to 0
        let read = pcr_read(&mut sim, selection).unwrap();
        assert_eq!(read.pcr_values.digests()[0].get_buffer(), &[0u8; 32]);
    }

    // 3. Reset PCR 0 (should fail with Locality)
    let res = exec(
        &mut sim,
        &PCRReset {
            pcr_handle: Handle(0),
        },
        &[pw()],
    );
    assert_eq!(res.err(), Some(TpmRc::LOCALITY.get()));
}

// 3. Correctness of PCR_Reset
/// PCR_Reset clears PCR 16/23; PCR 0 and DRTM PCR 17 cannot be reset (LOCALITY).
#[test]
fn reset_resettable_pcrs_only() {
    let mut sim = Tpm::new();

    // Extend non-zero values into PCR 16 and PCR 23
    let digests = [(ALG_SHA384, vec![0x55u8; 48])];
    assert_eq!(pcr_extend_at(&mut sim, 0, 16, &digests), 0);
    assert_eq!(pcr_extend_at(&mut sim, 0, 23, &digests), 0);

    assert_ne!(read_pcr(&mut sim, ALG_SHA384, 16).unwrap(), vec![0u8; 48]);
    assert_ne!(read_pcr(&mut sim, ALG_SHA384, 23).unwrap(), vec![0u8; 48]);

    // Reset PCR 16
    assert_eq!(pcr_reset_at(&mut sim, 0, 16), 0);
    assert_eq!(read_pcr(&mut sim, ALG_SHA384, 16).unwrap(), vec![0u8; 48]);
    assert_eq!(read_pcr(&mut sim, ALG_SHA256, 16).unwrap(), vec![0u8; 32]);

    // Reset PCR 23
    assert_eq!(pcr_reset_at(&mut sim, 0, 23), 0);
    assert_eq!(read_pcr(&mut sim, ALG_SHA384, 23).unwrap(), vec![0u8; 48]);
    assert_eq!(read_pcr(&mut sim, ALG_SHA256, 23).unwrap(), vec![0u8; 32]);

    // PCR 0 cannot be reset -> should fail with TpmRc::LOCALITY (0x907)
    assert_eq!(pcr_reset_at(&mut sim, 0, 0), TpmRc::LOCALITY.get());

    // PCR 17 (DRTM) cannot be reset via PCR_Reset -> should fail with TpmRc::LOCALITY (0x907)
    assert_eq!(pcr_reset_at(&mut sim, 0, 17), TpmRc::LOCALITY.get());
}

/// PCR_Reset with TPM_RH_NULL fails with VALUE+H1.
#[test]
fn reset_rh_null_rejected() {
    let mut sim = Tpm::new();

    let reset_cmd = PCRReset {
        pcr_handle: Handle::RH_NULL,
    };
    let res = execute_tpm_command(&mut sim, &reset_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );
}
