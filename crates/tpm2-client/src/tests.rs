use super::*;
use crate::sessions::{PasswordSession, ResponseData, Session};
use tpm2::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct TransportError;

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport error")
    }
}

impl core::error::Error for TransportError {}

// A Tpm that just returns a transport failure error.
struct ErrorTpm();
impl Connection for ErrorTpm {
    type Error = TransportError;
    fn transact<'a>(&mut self, _: &[u8], _: &'a mut [u8]) -> Result<&'a mut [u8], TransportError> {
        Err(TransportError)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TestCommand(u32);
impl Message for TestCommand {
    const NUM_HANDLES: usize = 0;
    type Handles<'a> = [NamedHandle<'a>; Self::NUM_HANDLES];
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for TestCommand {
    const MAX_SIZE: usize = 4;
    type MaxBuffer = [u8; 4];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for TestCommand {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        let val = u32::unmarshal(src)?;
        Ok(Self(val))
    }
}
impl Command for TestCommand {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
    type Response<'a> = TestCommand;
}

#[test]
fn test_tpm_error() {
    let mut fake_tpm = ErrorTpm();
    let cmd = TestCommand(56789);
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command(&cmd, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::Connection(TransportError))
    );
}

// FakeU32LoopbackTpm reads/stores the command header and a u32 "command".
// It responds with a response header and the same u32 "response".
struct FakeU32LoopbackTpm {
    rxed_header: Option<CommandHeader>,
    rxed_bytes: usize,
}
impl Connection for FakeU32LoopbackTpm {
    type Error = !;
    fn transact<'a>(&mut self, command: &[u8], response: &'a mut [u8]) -> Result<&'a mut [u8], !> {
        self.rxed_bytes = command.len();
        let mut slice = command;
        self.rxed_header = Some(CommandHeader::unmarshal(&mut slice).unwrap());
        let rxed_value = u32::unmarshal(&mut slice).unwrap();

        let mut tx_header = ResponseHeader {
            tag: tpm2::TpmiStCommandTag::NoSessions,
            size: 0,
            rc: Ok(()),
        };
        let mut written = tx_header.marshal(
            (&mut response[0..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        written += rxed_value.marshal((&mut response[written..written + 4]).try_into().unwrap());
        tx_header.size = written as u32;
        // Update the size.
        tx_header.marshal(
            (&mut response[0..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        Ok(&mut response[..written])
    }
}

#[test]
fn test_fake_command() {
    let mut fake_tpm = FakeU32LoopbackTpm {
        rxed_header: None,
        rxed_bytes: 0,
    };
    let cmd = TestCommand(56789);
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    let result = run_command(&cmd, &mut fake_tpm, &mut resp_buffer);
    assert_eq!(fake_tpm.rxed_header.unwrap().code, TestCommand::CMD_CODE);
    assert_eq!(result.unwrap(), cmd);
}

// EvilSizeTpm writes a response header whose size does not match the returned slice length.
struct EvilSizeTpm();
impl Connection for EvilSizeTpm {
    type Error = !;
    fn transact<'a>(&mut self, _: &[u8], response: &'a mut [u8]) -> Result<&'a mut [u8], !> {
        let tx_header = ResponseHeader {
            tag: tpm2::TpmiStCommandTag::NoSessions,
            size: response.len() as u32 + 2,
            rc: Ok(()),
        };
        let written = tx_header.marshal(
            (&mut response[0..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        // Return the slice of the response that was written.
        Ok(&mut response[..written])
    }
}

#[test]
fn test_bad_response_size() {
    let mut fake_tpm = EvilSizeTpm();
    let cmd = TestCommand(2);
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command(&cmd, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::InvalidResponseSize)
    );
}

pub struct FakeTpm {
    len: usize,
    response: [u8; RESP_BUFFER_SIZE],
    header: ResponseHeader,
}
impl Default for FakeTpm {
    fn default() -> Self {
        FakeTpm {
            len: 0,
            response: [0; RESP_BUFFER_SIZE],
            header: ResponseHeader {
                tag: tpm2::TpmiStCommandTag::NoSessions,
                size: 0,
                rc: Ok(()),
            },
        }
    }
}
impl Connection for FakeTpm {
    type Error = !;
    fn transact<'a>(&mut self, _: &[u8], response: &'a mut [u8]) -> Result<&'a mut [u8], !> {
        let off = self.header.marshal(
            (&mut response[0..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        let length = off + self.len;
        response[off..length].copy_from_slice(&self.response[..self.len]);
        self.header.size = length as u32;
        self.header.marshal(
            (&mut response[0..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        Ok(&mut response[..length])
    }
}
impl FakeTpm {
    fn add_to_response<M: Marshal<MaxBuffer = [u8; N]>, const N: usize>(&mut self, val: &M) {
        let mut tmp = [0u8; N];
        let written = val.marshal(&mut tmp);
        self.response[self.len..self.len + written].copy_from_slice(&tmp[..written]);
        self.len += written;
    }
}

struct TestSessionsCommand();
impl Message for TestSessionsCommand {
    const NUM_HANDLES: usize = 0;
    type Handles<'a> = [NamedHandle<'a>; Self::NUM_HANDLES];
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for TestSessionsCommand {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for TestSessionsCommand {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self())
    }
}
impl Command for TestSessionsCommand {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
    type Response<'a> = ();
}

#[test]
fn test_response_missing_sessions() {
    let mut fake_tpm = FakeTpm::default();
    let cmd = TestSessionsCommand();
    let mut session = PasswordSession::default();
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command_with_sessions(&cmd, &[], &mut session, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::UnexpectedTag)
    );
}

#[test]
fn test_response_session_fails_validation() {
    let mut fake_tpm = FakeTpm::default();
    fake_tpm.header.tag = tpm2::TpmiStCommandTag::Sessions;
    fake_tpm.add_to_response(&0u32);
    let invalid_auth = TpmsAuthResponse {
        session_attributes: TpmaSession(0xf),
        ..Default::default()
    };
    let rsp_data = ResponseData {
        code: TestSessionsCommand::CMD_CODE,
        params: &[],
    };
    let validation_failure =
        PasswordSession::default().validate_auth_response(&rsp_data, &invalid_auth);
    assert!(validation_failure.is_err());
    fake_tpm.add_to_response(&invalid_auth);

    let cmd = TestSessionsCommand();
    let mut session = PasswordSession::default();
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command_with_sessions(&cmd, &[], &mut session, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::Auth(validation_failure.err().unwrap()))
    );
}

#[test]
fn test_marshal_named_handle_and_unmarshal_response_handle() {
    use crate::protocol::{CMD_BUFFER_SIZE, marshal_command, unmarshal_response};
    use tpm2::commands::{ReadPublic, responses};

    // Marshal a command carrying a NamedHandle with a digest Name; the wire
    // format must contain only the 4-byte handle value, not the Name bytes.
    let raw_handle = Handle(0x8000_0042);
    let name = Tpm2bName::new(&[0x00, 0x0b, 0x11, 0x22, 0x33, 0x44]).unwrap();
    let cmd = ReadPublic {
        object_handle: NamedHandle::new(raw_handle, name),
    };
    let mut cmd_buf = [0u8; CMD_BUFFER_SIZE];
    let written = marshal_command(&cmd, &(), &mut cmd_buf);
    assert_eq!(written, CommandHeader::MAX_SIZE + Handle::MAX_SIZE);

    let mut slice = &cmd_buf[..written];
    let header = CommandHeader::unmarshal(&mut slice).unwrap();
    assert_eq!(header.tag, TpmiStCommandTag::NoSessions);
    assert_eq!(header.size as usize, written);
    assert_eq!(header.code, TpmCc::ReadPublic);
    assert_eq!(Handle::unmarshal(&mut slice).unwrap(), raw_handle);
    assert!(slice.is_empty());

    // Unmarshal Load response and verify named_handle() pairs wire handle + Name.
    let mut fake_tpm = FakeTpm::default();
    fake_tpm.add_to_response(&raw_handle);
    fake_tpm.add_to_response(&name);
    let mut resp_buf = [0u8; RESP_BUFFER_SIZE];
    let raw_resp = fake_tpm.transact(&[], &mut resp_buf).unwrap();
    let load_rsp: responses::Load<'_> = unmarshal_response::<_, !>(&(), raw_resp).unwrap();
    assert_eq!(load_rsp.object_handle, raw_handle);
    assert_eq!(load_rsp.name, name);
    assert_eq!(load_rsp.named_handle(), NamedHandle::new(raw_handle, name));

    // Unmarshal HashSequenceStart response into SequenceHandle.
    let seq_handle = Handle(0x8000_0099);
    let mut fake_seq_tpm = FakeTpm::default();
    fake_seq_tpm.add_to_response(&seq_handle);
    let mut seq_buf = [0u8; RESP_BUFFER_SIZE];
    let raw_seq_resp = fake_seq_tpm.transact(&[], &mut seq_buf).unwrap();
    let seq_rsp: responses::HashSequenceStart =
        unmarshal_response::<_, !>(&(), raw_seq_resp).unwrap();
    assert_eq!(seq_rsp.sequence_handle, SequenceHandle(seq_handle));
}

#[test]
fn test_marshal_command_with_sessions() {
    let cmd = TestCommand(0x11223344);
    let mut session = PasswordSession::new("pw").unwrap();
    let mut buf = [0u8; CMD_BUFFER_SIZE];
    let written = marshal_command(&cmd, &[], &mut session, &mut buf).unwrap();

    // TPMS_AUTH_COMMAND: handle (4) + nonce (2 + 0) + attributes (1) + hmac (2 + 2)
    let auth_size = 4 + 2 + 1 + 2 + 2;
    assert_eq!(written, CommandHeader::MAX_SIZE + 4 + auth_size + 4);

    let mut src = &buf[..written];
    let header = CommandHeader::unmarshal(&mut src).unwrap();
    assert_eq!(header.tag, TpmiStCommandTag::Sessions);
    assert_eq!(header.size as usize, written);
    assert_eq!(u32::unmarshal(&mut src).unwrap() as usize, auth_size);
    let auth = TpmsAuthCommand::unmarshal(&mut src).unwrap();
    assert_eq!(auth.session_handle, Handle::RS_PW);
    assert_eq!(auth.hmac.as_slice(), b"pw");
    // The parameters directly follow the authorization area.
    assert_eq!(src, 0x11223344u32.to_be_bytes());
}
