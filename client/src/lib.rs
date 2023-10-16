use core::mem::size_of;
use core::num::NonZeroU32;
use tpm2_rs_base::constants::{TPM2AlgID, TPM2Cap, TPM2PT, TPM2ST};
use tpm2_rs_base::errors::{TpmError, TpmResult};
use tpm2_rs_base::marshal::{Marshalable, UnmarshalBuf};
use tpm2_rs_base::TpmiStCommandTag;
use tpm2_rs_base::{commands::*, TpmsCapabilityData};
use zerocopy::byteorder::big_endian::{U16, U32};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

const MAX_CMD_SIZE: usize = 4096 - size_of::<CmdHeader>();
const MAX_RESP_SIZE: usize = 4096 - size_of::<RespHeader>();

pub trait Tpm {
    fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TpmResult<()>;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, AsBytes, FromBytes, FromZeroes)]
pub struct CmdHeader {
    tag: TpmiStCommandTag,
    size: U32,
    code: U32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, AsBytes, FromBytes, FromZeroes)]
pub struct RespHeader {
    tag: TPM2ST,
    size: U32,
    rc: U32,
}

pub fn is_algorithm_supported<T>(tpm: &mut T, algorithm: TPM2AlgID) -> TpmResult<bool>
where
    T: Tpm,
{
    let cmd: GetCapabilityCmd = GetCapabilityCmd {
        capability: to_be_u32(TPM2Cap::Algs.0),
        property: to_be_u32(algorithm.0 as u32),
        property_count: to_be_u32(1),
    };
    let resp = run_command(&cmd, tpm)?;

    if let TpmsCapabilityData::Algorithms(prop) = resp.capability_data {
        if prop.count.get() == 1 {
            Ok(prop.alg_properties[0].alg.get() == algorithm.0)
        } else {
            Err(TpmError::TPM2_RC_SIZE)
        }
    } else {
        Err(TpmError::TPM2_RC_SELECTOR)
    }
}

pub fn get_manufacturer_id<T>(tpm: &mut T) -> TpmResult<u32>
where
    T: Tpm,
{
    let cmd: GetCapabilityCmd = GetCapabilityCmd {
        capability: to_be_u32(TPM2Cap::TPMProperties.0),
        property: to_be_u32(TPM2PT::Manufacturer.0),
        property_count: to_be_u32(1),
    };
    let resp = run_command(&cmd, tpm)?;

    if let TpmsCapabilityData::TpmProperties(prop) = resp.capability_data {
        if prop.count.get() == 1 {
            Ok(prop.tpm_property[0].value.get())
        } else {
            Err(TpmError::TPM2_RC_SIZE)
        }
    } else {
        Err(TpmError::TPM2_RC_SELECTOR)
    }
}

pub fn run_command<CmdT, T>(cmd: &CmdT, tpm: &mut T) -> TpmResult<CmdT::RespT>
where
    CmdT: TpmCommand,
    T: Tpm,
{
    let mut cmd_buffer = [0u8; MAX_CMD_SIZE + size_of::<CmdHeader>()];
    let (hdr_space, cmd_space) = cmd_buffer.split_at_mut(size_of::<CmdHeader>());
    let cmd_size = cmd.try_marshal(cmd_space)? + size_of::<CmdHeader>();
    let header = CmdHeader {
        tag: TpmiStCommandTag(U16::new(TPM2ST::NoSessions.0)),
        size: U32::new(cmd_size as u32),
        code: U32::new(CmdT::CMD_CODE.0),
    };
    let _ = header.try_marshal(hdr_space)?;

    let mut resp_buffer = [0u8; MAX_RESP_SIZE + size_of::<RespHeader>()];
    tpm.transact(&cmd_buffer[..cmd_size], &mut resp_buffer)?;
    let (hdr, resp) = resp_buffer.split_at(size_of::<RespHeader>());
    let mut unmarsh = UnmarshalBuf::new(hdr);
    let rh = RespHeader::try_unmarshal(&mut unmarsh)?;
    if let Ok(value) = NonZeroU32::try_from(rh.rc.get()) {
        return TpmResult::Err(value.into());
    }
    let resp_size = rh.size.get() as usize - hdr.len();
    if resp_size > resp.len() {
        return TpmResult::Err(TpmError::TSS2_MU_RC_BAD_SIZE);
    }
    unmarsh = UnmarshalBuf::new(&resp[..(rh.size.get() as usize - hdr.len())]);
    CmdT::RespT::try_unmarshal(&mut unmarsh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2_rs_base::{
        constants::TPM2CC, errors::TpmError, TpmaAlgorithm, TpmiYesNo, TpmlAlgProperty,
        TpmlTaggedTpmProperty, TpmsAlgProperty, TpmsTaggedProperty,
    };

    // A Tpm that just returns a general failure error.
    struct ErrorTpm();
    impl Tpm for ErrorTpm {
        fn transact(&mut self, _: &[u8], _: &mut [u8]) -> TpmResult<()> {
            return Err(TpmError::TSS2_BASE_RC_GENERAL_FAILURE);
        }
    }

    #[derive(AsBytes, FromBytes, FromZeroes)]
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

    #[derive(AsBytes, FromBytes, FromZeroes)]
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
                size: U32::new((size_of::<RespHeader>() + size_of::<u32>()) as u32),
                rc: U32::ZERO,
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
        assert_eq!(
            fake_tpm.rxed_header.unwrap().code.get(),
            TestCommand::CMD_CODE.0 as u32
        );
        assert_eq!(
            fake_tpm.rxed_bytes,
            size_of::<CmdHeader>() + size_of::<u32>()
        );
        assert_eq!(result.unwrap(), cmd.0);
    }

    // EvilSizeTpm writes a reponse header with a size value that is larger than the reponse buffer.
    struct EvilSizeTpm();
    impl Tpm for EvilSizeTpm {
        fn transact(&mut self, _: &[u8], response: &mut [u8]) -> TpmResult<()> {
            let tx_header = RespHeader {
                tag: TPM2ST::NoSessions,
                size: U32::new(response.len() as u32 + 2),
                rc: U32::ZERO,
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

    // FixedResponseTpm returns a set value for all requests to the TPM.
    struct FixedResponseTpm<CmdT: TpmCommand> {
        resp: CmdT::RespT,
    }
    impl<CmdT: TpmCommand> Tpm for FixedResponseTpm<CmdT> {
        fn transact(&mut self, _command: &[u8], response: &mut [u8]) -> TpmResult<()> {
            let tx_header = RespHeader {
                tag: TPM2ST::NoSessions,
                size: U32::new((size_of::<RespHeader>() + size_of::<CmdT::RespT>()) as u32),
                rc: U32::ZERO,
            };
            let written = tx_header.try_marshal(response)?;
            self.resp.try_marshal(&mut response[written..])?;
            Ok(())
        }
    }

    #[test]
    fn test_is_algorithm_not_supported() {
        let response: GetCapabilityResp = GetCapabilityResp {
            more_data: TpmiYesNo(0),
            capability_data: crate::TpmsCapabilityData::Algorithms(TpmlAlgProperty {
                count: to_be_u32(1),
                alg_properties: [TpmsAlgProperty {
                    alg: to_be_u16(3),
                    alg_properties: TpmaAlgorithm(to_be_u32(3)),
                }; 169],
            }),
        };
        let mut fake_tpm: FixedResponseTpm<GetCapabilityCmd> = FixedResponseTpm { resp: response };

        assert_eq!(
            is_algorithm_supported(&mut fake_tpm, TPM2AlgID::SHA256),
            Ok(false)
        );
    }

    #[test]
    fn test_is_algorithm_supported() {
        let response: GetCapabilityResp = GetCapabilityResp {
            more_data: TpmiYesNo(0),
            capability_data: crate::TpmsCapabilityData::Algorithms(TpmlAlgProperty {
                count: to_be_u32(1),
                alg_properties: [TpmsAlgProperty {
                    alg: to_be_u16(11),
                    alg_properties: TpmaAlgorithm(to_be_u32(11)),
                }; 169],
            }),
        };
        let mut fake_tpm: FixedResponseTpm<GetCapabilityCmd> = FixedResponseTpm { resp: response };

        assert_eq!(
            is_algorithm_supported(&mut fake_tpm, TPM2AlgID::SHA256),
            Ok(true)
        );
    }

    #[test]
    fn test_get_manufactuer_id() {
        let response: GetCapabilityResp = GetCapabilityResp {
            more_data: TpmiYesNo(0),
            capability_data: crate::TpmsCapabilityData::TpmProperties(TpmlTaggedTpmProperty {
                count: to_be_u32(1),
                tpm_property: [TpmsTaggedProperty {
                    property: TPM2PT::Manufacturer,
                    value: to_be_u32(12345),
                }; 127],
            }),
        };
        let mut fake_tpm: FixedResponseTpm<GetCapabilityCmd> = FixedResponseTpm { resp: response };

        assert_eq!(get_manufacturer_id(&mut fake_tpm), Ok(12345));
    }
}
