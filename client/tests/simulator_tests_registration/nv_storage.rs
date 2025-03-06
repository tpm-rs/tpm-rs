use crate::get_started_tpm;
use tpm2_rs_base::{
    commands::NvReadCmd, constants::TPM2_MAX_NV_BUFFER_SIZE, Tpm2bMaxNvBuffer, TpmiRhNvIndex,
};
use tpm2_rs_client::run_command;

#[test]
fn test_nv_read() {
    let (_sim_lifeline, mut tpm) = get_started_tpm();

    let command = NvReadCmd {
        nv_index: TpmiRhNvIndex::try_from(0x01c00004).unwrap(), // Low range RSA 2048 EK template.
        size: 1,
        offset: 0,
    };

    // TODO
    let resp = run_command(&command, &mut tpm).expect("Failed running command.");
    let received = resp.data;
    let expected = Tpm2bMaxNvBuffer {
        size: 2,
        buffer: {
            let mut b = [0u8; TPM2_MAX_NV_BUFFER_SIZE as usize];
            b[..].copy_from_slice(&[b'h', b'i']);
            b
        },
    };

    assert_eq!(
        received, expected,
        "Received did not match the expected response."
    );
}
