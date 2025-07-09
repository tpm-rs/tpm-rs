use crate::get_started_tpm;
use tpm2_rs_base::{
    commands::{NvDefineSpaceCmd, NvWriteCmd, NvWriteHandles, NvReadCmd},
    constants::{TPM2_MAX_NV_BUFFER_SIZE, TpmHandle}, Tpm2bMaxNvBuffer, TpmiRhNvIndex, TpmiRhNvAuth, TpmiAlgHash,
    Tpm2bDigest, TpmtHa, TpmaNv, TpmsNvPublic, Tpm2bNvPublic, Tpm2bAuth
};
use tpm2_rs_marshalable::Marshalable;
use tpm2_rs_client::{run_command, run_command_with_handles};

#[test]
fn test_nv_read() {
    let (_sim_lifeline, mut tpm) = get_started_tpm();

    // Low range RSA 2048 EK template.
    let nv_index = TpmiRhNvIndex::try_from(0x01c00004).expect("standard NV index");

    let data: Vec<u8> = [b'h', b'i'].to_vec();
    let data_size = data.len() as u16;
    let c_command = NvDefineSpaceCmd {
	auth: Tpm2bAuth{size: 0, buffer: [0; size_of::<TpmtHa::UNION_SIZE>()]},
	public_info: Tpm2bNvPublic{size: 0, nv_public: [0; size_of::<TpmsNvPublic>()]},
    };
    let to_write = TpmsNvPublic {
	nv_index: nv_index,
	name_alg: TpmiAlgHash::SHA256,
	attributes: TpmaNv::PPWRITE | TpmaNv::WRITEDEFINE | TpmaNv::PPREAD | TpmaNv::OWNERREAD | TpmaNv::AUTHREAD | TpmaNv::PLATFORMCREATE | TpmaNv::NO_DA,
	auth_policy: Tpm2bDigest{size: 0, buffer: [0; TpmtHa::UNION_SIZE]},
	data_size: data_size,
    };
    c_command.public_info.size = to_write.try_marshal(&mut c_command.public_info.nv_public[..]).expect("TpmsNvPublic marshal") as u16;

    run_command(&c_command, &mut tpm).expect("Failed running definespace command.");

    let expected = Tpm2bMaxNvBuffer {
        size: data_size,
        buffer: {
            let mut b = [0u8; TPM2_MAX_NV_BUFFER_SIZE as usize];
            b[..].copy_from_slice(&data);
            b
        },
    };
    let w_command = NvWriteCmd {
	data: expected.clone(),
	offset: 0,
    };
    let mut w_handles = NvWriteHandles {
	auth: TpmiRhNvAuth::try_from(TpmHandle::RHOwner)?,
	nv_index: nv_index,
    };
    run_command_with_handles(&w_command, w_handles, (), &mut tpm).expect("Failed running nvwrite command.");

    let r_command = NvReadCmd {
        nv_index: nv_index,
        size: 1,
        offset: 0,
    };

    let r_resp = run_command(&r_command, &mut tpm).expect("Failed running nvread command.");
    let received = r_resp.data;

    assert_eq!(
        received, expected,
        "Received did not match the expected response."
    );
}
