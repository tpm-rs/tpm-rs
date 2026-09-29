use tpm2::commands::{
    GetTestResult, GetTestResultRsp, IncrementalSelfTest, IncrementalSelfTestRsp, SelfTest,
    responses,
};
use tpm2::errors::{TpmRc, UnmarshalError};
use tpm2::*;

fn verify_command_trait<C: Command>() -> TpmCc
where
    for<'a> &'a mut C::MaxBuffer: TryFrom<&'a mut [u8]>,
    for<'a> &'a mut <C::Handles as Marshal>::MaxBuffer: TryFrom<&'a mut [u8]>,
{
    C::CMD_CODE
}

#[test]
fn test_testing_commands_implement_command_trait() {
    assert_eq!(verify_command_trait::<SelfTest>(), TpmCc::SelfTest);
    assert_eq!(
        verify_command_trait::<IncrementalSelfTest>(),
        TpmCc::IncrementalSelfTest
    );
    assert_eq!(
        verify_command_trait::<GetTestResult>(),
        TpmCc::GetTestResult
    );

    // Verify type aliases in `responses` module match the command Response associated types.
    let _inc_rsp: <IncrementalSelfTest as Command>::Response<'static> =
        responses::IncrementalSelfTest::default();
    let _get_rsp: <GetTestResult as Command>::Response<'static> =
        responses::GetTestResult::default();
}

#[test]
fn test_self_test_command_roundtrip_and_errors() {
    for full_test in [false, true] {
        let cmd = SelfTest { full_test };
        let mut buf = [0u8; SelfTest::MAX_SIZE];
        let len = cmd.marshal(&mut buf);
        assert_eq!(len, 1);
        assert_eq!(buf[0], u8::from(full_test));

        let mut slice = &buf[..len];
        let unmarshaled = SelfTest::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshaled, cmd);
        assert!(slice.is_empty());
    }

    // Empty buffer error
    let mut empty: &[u8] = &[];
    assert_eq!(
        SelfTest::unmarshal(&mut empty).unwrap_err(),
        UnmarshalError::INSUFFICIENT.in_parameter(1)
    );

    // Invalid boolean value (e.g. 2)
    let invalid_bool = [2u8];
    let mut slice = &invalid_bool[..];
    assert_eq!(
        SelfTest::unmarshal(&mut slice).unwrap_err(),
        UnmarshalError::VALUE.in_parameter(1)
    );
}

#[test]
fn test_incremental_self_test_command_and_response_roundtrip() {
    let algs = [Alg::RSA, Alg::SHA256, Alg::AES];
    let to_test = TpmlAlg::from_slice(&algs).unwrap();
    let cmd = IncrementalSelfTest { to_test };

    let mut buf = [0u8; IncrementalSelfTest::MAX_SIZE];
    let len = cmd.marshal(&mut buf);
    assert_eq!(len, 4 + algs.len() * 2);

    let mut slice = &buf[..len];
    let unmarshaled = IncrementalSelfTest::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, cmd);
    assert!(slice.is_empty());

    // Response roundtrip
    let to_do_list = TpmlAlg::from_slice(&[Alg::ECC]).unwrap();
    let rsp = IncrementalSelfTestRsp { to_do_list };
    let mut rsp_buf = [0u8; IncrementalSelfTestRsp::MAX_SIZE];
    let rsp_len = rsp.marshal(&mut rsp_buf);
    assert_eq!(rsp_len, 4 + 2);

    let mut rsp_slice = &rsp_buf[..rsp_len];
    let unmarshaled_rsp = IncrementalSelfTestRsp::unmarshal(&mut rsp_slice).unwrap();
    assert_eq!(unmarshaled_rsp, rsp);
    assert!(rsp_slice.is_empty());

    // Command unmarshal error should be attributed to parameter 1
    let mut short_cmd: &[u8] = &[0, 0];
    assert_eq!(
        IncrementalSelfTest::unmarshal(&mut short_cmd).unwrap_err(),
        UnmarshalError::INSUFFICIENT.in_parameter(1)
    );

    // Response unmarshal error on truncated buffer
    let mut short_rsp: &[u8] = &[0, 0, 0, 1]; // claims 1 algorithm (2 bytes), but 0 bytes follow
    assert_eq!(
        IncrementalSelfTestRsp::unmarshal(&mut short_rsp).unwrap_err(),
        UnmarshalError::INSUFFICIENT
    );
}

#[test]
fn test_get_test_result_command_and_response_roundtrip() {
    let cmd = GetTestResult {};
    let mut cmd_buf = [0u8; GetTestResult::MAX_SIZE];
    assert_eq!(cmd.marshal(&mut cmd_buf), 0);

    let mut cmd_slice: &[u8] = &[];
    assert_eq!(GetTestResult::unmarshal(&mut cmd_slice).unwrap(), cmd);

    // Default response (empty out_data, TPM_RC_SUCCESS)
    let default_rsp = GetTestResultRsp::default();
    assert_eq!(default_rsp.test_result, Ok(()));
    assert_eq!(default_rsp.out_data.get_buffer(), &[]);

    let mut rsp_buf = [0u8; GetTestResultRsp::MAX_SIZE];
    let len = default_rsp.marshal(&mut rsp_buf);
    assert_eq!(len, 2 + 4);
    assert_eq!(&rsp_buf[..len], &[0, 0, 0, 0, 0, 0]);

    let mut slice = &rsp_buf[..len];
    let unmarshaled = GetTestResultRsp::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, default_rsp);
    assert!(slice.is_empty());

    // Non-empty out_data and various test_result status codes
    let statuses = [
        Ok(()),
        Err(TpmRc::FAILURE),
        Err(TpmRc::NEEDS_TEST),
        Err(TpmRc::TESTING),
    ];

    for status in statuses {
        let diag_data = [0xDE, 0xAD, 0xBE, 0xEF];
        let rsp = GetTestResultRsp {
            out_data: Tpm2bMaxBuffer::from_bytes(&diag_data).unwrap(),
            test_result: status,
        };

        let len = rsp.marshal(&mut rsp_buf);
        assert_eq!(len, 2 + diag_data.len() + 4);

        let mut slice = &rsp_buf[..len];
        let unmarshaled = GetTestResultRsp::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshaled, rsp);
        assert!(slice.is_empty());
    }

    // Truncated response buffer error
    let short_buf = [0u8; 4]; // needs at least 2 (out_data size) + 4 (test_result) = 6 bytes
    let mut short_slice = &short_buf[..];
    assert_eq!(
        GetTestResultRsp::unmarshal(&mut short_slice).unwrap_err(),
        UnmarshalError::INSUFFICIENT
    );
}
