use tpm2::Handle;
use tpm2::Unmarshal;
use tpm2::commands::{Clear, ClearHandles, CreatePrimary, CreatePrimaryHandles, FlushContext};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

// Original Go test: clear_test.go - TestClear
#[test]
fn test_clear() {
    let mut sim = create_simulator!();

    let sensitive_bytes = [0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
    let mut sens_slice = &sensitive_bytes[..];
    let in_sensitive = tpm2::Tpm2bSensitiveCreate::unmarshal(&mut sens_slice).unwrap();
    let public_bytes = [
        0x00, 0x0E, 0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00,
    ];
    let mut pub_slice = &public_bytes[..];
    let in_public = tpm2::Tpm2bPublic::unmarshal(&mut pub_slice).unwrap();

    let create_cmd = || CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (srk_create_rsp, _) = sim
        .execute_with_handles(create_cmd(), create_handles)
        .expect("could not generate SRK");
    let srk_name1 = srk_create_rsp.name;

    let cmd = Clear {};
    let cmd_handles = ClearHandles {
        auth_handle: Handle::RH_LOCKOUT,
    };
    sim.execute_with_handles(cmd, cmd_handles)
        .expect("could not clear TPM");

    let create_handles2 = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (srk_create_rsp2, rsp2_h) = sim
        .execute_with_handles(create_cmd(), create_handles2)
        .expect("could not generate SRK");

    let srk_name2 = srk_create_rsp2.name;

    sim.execute(FlushContext {
        flush_handle: rsp2_h.object_handle,
    })
    .expect("could not flush SRK");

    if srk_name1 == srk_name2 {
        panic!(
            "SRK Name did not change across clear, was {:?} both times",
            srk_name1
        );
    }
}
