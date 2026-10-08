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

// Original Go test: pcr_test.go - TestPCRs
#[test]
fn test_pcrs() {
    let cases = vec![
        (vec![], vec![0x00, 0x00, 0x00]),
        (vec![0], vec![0x01, 0x00, 0x00]),
        (vec![0, 1, 2], vec![0x07, 0x00, 0x00]),
        (vec![0, 7], vec![0x81, 0x00, 0x00]),
        (vec![8], vec![0x00, 0x01, 0x00]),
        (vec![1, 8, 9], vec![0x02, 0x03, 0x00]),
        ((0..24).collect::<Vec<u32>>(), vec![0xff, 0xff, 0xff]),
    ];

    for (pcrs, want_select) in cases {
        let selection = pcr_selection(TpmiAlgHash::Sha256, &pcrs);
        assert_eq!(selection.pcr_select(), &want_select[..]);
    }
}

// Original Go test: pcr_test.go - TestPCRReset
#[test]
fn test_pcr_reset() {
    let mut sim = create_simulator!();
    let debug_pcr = 16;
    let hashalgs = vec![TpmiAlgHash::Sha1, TpmiAlgHash::Sha256, TpmiAlgHash::Sha384];

    for hash in hashalgs {
        let auth_handle = Handle(debug_pcr);

        // Extend PCR
        let mut digests = TpmlDigestValues::default();
        let digest_data = match hash {
            TpmiAlgHash::Sha1 => TpmtHa::Sha1(&[0x01; 20]),
            TpmiAlgHash::Sha256 => TpmtHa::Sha256(&[0x01; 32]),
            TpmiAlgHash::Sha384 => TpmtHa::Sha384(&[0x01; 48]),
            _ => panic!("unsupported hash"),
        };
        digests.add(&digest_data).unwrap();

        let extend_cmd = PCRExtend { digests };
        let extend_handles = PCRExtendHandles {
            pcr_handle: auth_handle,
        };
        let _ =
            execute_with_password_sessions(&mut sim, &extend_cmd, extend_handles, 1, &[]).unwrap();

        // Read PCR
        let read_cmd = PCRRead {
            pcr_selection_in: pcr_selections(hash, &[debug_pcr]),
        };
        let read_resp = sim.execute(read_cmd).unwrap();
        assert!(read_resp.pcr_values.count() > 0);
        let val = read_resp.pcr_values.digests()[0];
        assert!(!val.as_ref().iter().all(|&b| b == 0));

        // Reset PCR
        let reset_cmd = PCRReset {};
        let reset_handles = PCRResetHandles {
            pcr_handle: auth_handle,
        };
        let _ =
            execute_with_password_sessions(&mut sim, &reset_cmd, reset_handles, 1, &[]).unwrap();

        // Read PCR again and verify it is all zeros
        let read_resp = sim.execute(read_cmd).unwrap();
        let val = read_resp.pcr_values.digests()[0];
        assert!(val.as_ref().iter().all(|&b| b == 0));
    }
}

// Original Go test: pcr_test.go - TestPCREvent
#[test]
fn test_pcr_event() {
    let mut sim = create_simulator!();
    let hashalgs = vec![TpmiAlgHash::Sha1, TpmiAlgHash::Sha256, TpmiAlgHash::Sha384];

    for hash in hashalgs {
        for i in 0..17 {
            let auth_handle = Handle(i);
            let event_cmd = PCREvent {
                event_data: Tpm2bEvent::from_bytes(b"hello").unwrap(),
            };
            let event_handles = PCREventHandles {
                pcr_handle: auth_handle,
            };
            execute_with_password_sessions_status(&mut sim, &event_cmd, event_handles, 1, &[])
                .unwrap();

            // read PCR and verify it is not all zeros
            let read_cmd = PCRRead {
                pcr_selection_in: pcr_selections(hash, &[i]),
            };
            let read_resp = sim.execute(read_cmd).unwrap();
            assert!(read_resp.pcr_values.count() > 0);
            let val = read_resp.pcr_values.digests()[0];
            assert!(!val.as_ref().iter().all(|&b| b == 0));
        }
    }
}
