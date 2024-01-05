#![forbid(unsafe_code)]
use core::mem::size_of;
use core::num::NonZeroU32;
use tpm2_rs_base::commands::*;
use tpm2_rs_base::constants::{TPM2CC, TPM2ST};
use tpm2_rs_base::errors::{TpmError, TpmResult};
use tpm2_rs_base::marshal::{Marshal, Marshalable, UnmarshalBuf};
use tpm2_rs_base::TpmiStCommandTag;

const MAX_CMD_SIZE: usize = 4096 - CmdHeader::wire_size();
const MAX_RESP_SIZE: usize = 4096 - RespHeader::wire_size();

pub trait Tpm {
    fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TpmResult<()>;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct CmdHeader {
    tag: TpmiStCommandTag,
    size: u32,
    code: TPM2CC,
}
impl CmdHeader {
    // This could be generated, but it won't work once we add sessions.
    const fn wire_size() -> usize {
        size_of::<TpmiStCommandTag>() + size_of::<u32>() + size_of::<TPM2CC>()
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal, Debug)]
pub struct RespHeader {
    tag: TPM2ST,
    size: u32,
    rc: u32,
}
impl RespHeader {
    // This could be generated, but it won't work once we add sessions.
    const fn wire_size() -> usize {
        size_of::<TPM2ST>() + size_of::<u32>() + size_of::<u32>()
    }
}

pub fn run_command<CmdT, T>(cmd: &CmdT, tpm: &mut T) -> TpmResult<CmdT::RespT>
where
    CmdT: TpmCommand,
    T: Tpm,
{
    let mut cmd_buffer = [0u8; MAX_CMD_SIZE + CmdHeader::wire_size()];
    let (hdr_space, cmd_space) = cmd_buffer.split_at_mut(CmdHeader::wire_size());
    let cmd_size = cmd.try_marshal(cmd_space)? + CmdHeader::wire_size();
    let header = CmdHeader {
        tag: TpmiStCommandTag(TPM2ST::NoSessions),
        size: cmd_size as u32,
        code: CmdT::CMD_CODE,
    };
    let _ = header.try_marshal(hdr_space)?;
    let mut resp_buffer = [0u8; MAX_RESP_SIZE + RespHeader::wire_size()];
    tpm.transact(&cmd_buffer[..cmd_size], &mut resp_buffer)?;
    let (hdr, resp) = resp_buffer.split_at(RespHeader::wire_size());
    let mut unmarsh = UnmarshalBuf::new(hdr);
    let rh = RespHeader::try_unmarshal(&mut unmarsh)?;
    if let Ok(value) = NonZeroU32::try_from(rh.rc) {
        return TpmResult::Err(value.into());
    }
    let resp_size = rh.size as usize - hdr.len();
    if resp_size > resp.len() {
        return TpmResult::Err(TpmError::TSS2_MU_RC_BAD_SIZE);
    }
    unmarsh = UnmarshalBuf::new(&resp[..(rh.size as usize - hdr.len())]);
    CmdT::RespT::try_unmarshal(&mut unmarsh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2_rs_base::errors::TpmError;
    // A Tpm that just returns a general failure error.
    struct ErrorTpm();
    impl Tpm for ErrorTpm {
        fn transact(&mut self, _: &[u8], _: &mut [u8]) -> TpmResult<()> {
            return Err(TpmError::TSS2_BASE_RC_GENERAL_FAILURE);
        }
    }

    #[derive(Marshal)]
    #[repr(C)]
    // Larger than the maximum size.
    struct HugeFakeCommand([u8; MAX_CMD_SIZE + 1]);
    impl TpmCommand for HugeFakeCommand {
        const CMD_CODE: TPM2CC = TPM2CC::NVUndefineSpaceSpecial;
        type RespT = u8;
    }
    #[test]
    fn test_command_too_large() {
        let mut fake_tpm = ErrorTpm();
        let too_large = HugeFakeCommand([0; MAX_CMD_SIZE + 1]);
        assert_eq!(
            run_command(&too_large, &mut fake_tpm),
            Err(TpmError::TSS2_MU_RC_INSUFFICIENT_BUFFER)
        );
    }

    #[derive(Marshal)]
    #[repr(C)]
    struct TestCommand(u32);
    impl TpmCommand for TestCommand {
        const CMD_CODE: TPM2CC = TPM2CC::NVUndefineSpaceSpecial;
        type RespT = u32;
    }

    #[test]
    fn test_tpm_error() {
        let mut fake_tpm = ErrorTpm();
        let cmd = TestCommand(56789);
        assert_eq!(
            run_command(&cmd, &mut fake_tpm),
            Err(TpmError::TSS2_BASE_RC_GENERAL_FAILURE)
        );
    }

    // FakeU32LoopbackTpm reads/stores the command header and a u32 "command".
    // It responds with a response header and the same u32 "response".
    struct FakeU32LoopbackTpm {
        rxed_header: Option<CmdHeader>,
        rxed_bytes: usize,
    }
    impl Tpm for FakeU32LoopbackTpm {
        fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TpmResult<()> {
            self.rxed_bytes = command.len();
            let mut buf = UnmarshalBuf::new(command);
            self.rxed_header = Some(CmdHeader::try_unmarshal(&mut buf)?);
            let rxed_value = u32::try_unmarshal(&mut buf)?;

            let tx_header = RespHeader {
                tag: TPM2ST::NoSessions,
                size: (RespHeader::wire_size() + size_of::<u32>()) as u32,
                rc: 0,
            };
            let written = tx_header.try_marshal(response)?;
            rxed_value.try_marshal(&mut response[written..])?;
            Ok(())
        }
    }

    #[test]
    fn test_fake_command() {
        let mut fake_tpm = FakeU32LoopbackTpm {
            rxed_header: None,
            rxed_bytes: 0,
        };
        let cmd = TestCommand(56789);
        let result = run_command(&cmd, &mut fake_tpm);
        assert_eq!(fake_tpm.rxed_header.unwrap().code, TestCommand::CMD_CODE);
        assert_eq!(
            fake_tpm.rxed_bytes,
            CmdHeader::wire_size() + size_of::<u32>()
        );
        assert_eq!(result.unwrap(), cmd.0);
    }

    // EvilSizeTpm writes a reponse header with a size value that is larger than the reponse buffer.
    struct EvilSizeTpm();
    impl Tpm for EvilSizeTpm {
        fn transact(&mut self, _: &[u8], response: &mut [u8]) -> TpmResult<()> {
            let tx_header = RespHeader {
                tag: TPM2ST::NoSessions,
                size: response.len() as u32 + 2,
                rc: 0,
            };
            tx_header.try_marshal(response)?;
            Ok(())
        }
    }

    #[test]
    fn test_bad_response_size() {
        let mut fake_tpm = EvilSizeTpm();
        let cmd = TestCommand(2);
        assert_eq!(
            run_command(&cmd, &mut fake_tpm),
            Err(TpmError::TSS2_MU_RC_BAD_SIZE)
        );
    }
}
