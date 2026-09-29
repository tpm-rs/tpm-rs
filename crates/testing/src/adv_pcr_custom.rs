#![allow(unused_imports, dead_code)]
use crate::test_utils::{execute_with_password_sessions, execute_with_password_sessions_status};
use tpm2::commands::{
    PCREvent, PCREventHandles, PCRExtend, PCRExtendHandles, PCRRead, PCRReset, PCRResetHandles,
};
use tpm2::{
    Handle, TPM2_PCR_SELECT_MAX, Tpm2bEvent, TpmiAlgHash, TpmlDigestValues, TpmlPcrSelection,
    TpmsPcrSelection, TpmtHa,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn pcr_selection(hash: TpmiAlgHash, pcrs: &[u32]) -> TpmsPcrSelection {
    let mut pcr_select = [0u8; TPM2_PCR_SELECT_MAX as usize];
    let mut max_pcr = 0;
    for &pcr in pcrs {
        if pcr < 32 {
            let byte_idx = (pcr / 8) as usize;
            let bit_idx = (pcr % 8) as usize;
            pcr_select[byte_idx] |= 1 << bit_idx;
            if pcr > max_pcr {
                max_pcr = pcr;
            }
        }
    }
    let sizeof_select = if pcrs.is_empty() {
        3
    } else {
        std::cmp::max(3, (max_pcr / 8) + 1) as u8
    };
    TpmsPcrSelection::new(hash, &pcr_select[..sizeof_select as usize]).unwrap()
}

fn pcr_selections(hash: TpmiAlgHash, pcrs: &[u32]) -> TpmlPcrSelection {
    TpmlPcrSelection::from_slice(&[pcr_selection(hash, pcrs)]).unwrap()
}

#[test]
fn test_pcr_read_empty() {
    let mut sim = create_simulator!();
    let cmd = PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    };
    let resp = sim.execute(cmd).unwrap();
    assert_eq!(resp.pcr_values.count(), 0);
}

#[test]
fn test_pcr_extend_sha256() {
    let mut sim = create_simulator!();
    let auth_handle = Handle(16);
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&[0xaa; 32])).unwrap();
    let cmd = PCRExtend { digests };
    let handles = PCRExtendHandles {
        pcr_handle: auth_handle,
    };
    let _ = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();
}

#[test]
fn test_srtm_boot_sequence() {
    let mut sim = create_simulator!();
    for &pcr in &[0, 1, 2, 4, 5] {
        let auth_handle = Handle(pcr);
        let cmd = PCREvent {
            event_data: Tpm2bEvent::from_bytes(b"measurement").unwrap(),
        };
        let handles = PCREventHandles {
            pcr_handle: auth_handle,
        };
        execute_with_password_sessions_status(&mut sim, &cmd, handles, 1, &[]).unwrap();
    }
}
