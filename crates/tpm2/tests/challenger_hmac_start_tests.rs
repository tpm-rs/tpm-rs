use tpm2::commands::{HMACStart, responses};
use tpm2::errors::UnmarshalError;
use tpm2::*;

/// Unmarshals the `TPM2_HMAC_Start` handle area (one `TPMI_DH_OBJECT` handle).
///
/// Handles are plain [`Handle`]s in the command structs, so the `TPMI_DH_OBJECT`
/// check that the handle-area unmarshalling used to perform (now done by the
/// TPM implementation before it unmarshals the parameters) is done here with
/// the same interface type, attributing failures to handle 1.
fn unmarshal_command_handle(src: &mut &[u8]) -> Result<Handle, UnmarshalError> {
    TpmiDhObject::<false>::unmarshal(src)
        .map(Handle::from)
        .map_err(|e| e.in_handle(1))
}

/// Unmarshals the `TPM2_HMAC_Start` response handle area (one `TPMI_DH_OBJECT`
/// handle), without a handle position, as for every response.
fn unmarshal_response_handle(src: &mut &[u8]) -> Result<Handle, UnmarshalError> {
    TpmiDhObject::<false>::unmarshal(src).map(Handle::from)
}

#[test]
fn test_hmac_start_handles_roundtrip() {
    let handles = [
        Handle(0x80000000), // Transient
        Handle(0x80000001), // Transient
        Handle(0x81000000), // Persistent
        Handle(0x81000001), // Persistent
    ];

    for &h in &handles {
        let cmd = HMACStart {
            handle: h,
            ..Default::default()
        };
        let [cmd_h] = cmd.handles();
        assert_eq!(cmd_h, h);
        let mut buf = [0u8; Handle::MAX_SIZE];
        let len = cmd_h.marshal(&mut buf);
        assert_eq!(len, 4);
        assert_eq!(&buf[..], &h.0.to_be_bytes()[..]);

        let mut slice = &buf[..];
        let unmarshaled = unmarshal_command_handle(&mut slice).unwrap();
        assert_eq!(unmarshaled, cmd_h);
        assert!(slice.is_empty());
    }
}

#[test]
fn test_hmac_start_handles_errors() {
    // Truncated buffer
    for size in 0..4 {
        let buf = vec![0u8; size];
        let mut slice = &buf[..];
        assert_eq!(
            unmarshal_command_handle(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::INSUFFICIENT.in_handle(1)
        );
    }

    // Out-of-range / invalid handle values for TPMI_DH_OBJECT (non-nullable)
    let invalid_handles = [
        Handle(0),
        Handle(1),
        Handle(0x40000007), // RHNull
        Handle(0xFFFFFFFF),
    ];
    for &h in &invalid_handles {
        let buf = h.0.to_be_bytes();
        let mut slice = &buf[..];
        assert_eq!(
            unmarshal_command_handle(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::VALUE.in_handle(1)
        );
    }
}

#[test]
fn test_hmac_start_cmd_roundtrip() {
    let test_auths = [
        vec![],
        vec![1, 2, 3, 4],
        vec![0xAA; 32], // Max size
    ];

    let test_algs = [
        #[cfg(feature = "sha1")]
        TpmiAlgHash::Sha1,
        #[cfg(feature = "sha256")]
        TpmiAlgHash::Sha256,
        #[cfg(feature = "sha384")]
        TpmiAlgHash::Sha384,
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512,
    ];

    for auth_bytes in &test_auths {
        for &alg in &test_algs {
            let auth = Tpm2bAuth::from_bytes(auth_bytes).unwrap();
            let cmd = HMACStart {
                handle: Handle(0x80000000),
                auth,
                hash_alg: Some(alg),
            };

            let expected_len = 2 + auth_bytes.len() + 2;
            let mut buf = [0u8; HMACStart::MAX_SIZE];
            let len = cmd.marshal(&mut buf);
            assert_eq!(len, expected_len);

            // Verify byte layout
            assert_eq!(
                u16::from_be_bytes([buf[0], buf[1]]),
                auth_bytes.len() as u16
            );
            assert_eq!(&buf[2..2 + auth_bytes.len()], auth_bytes.as_slice());
            assert_eq!(
                u16::from_be_bytes([buf[expected_len - 2], buf[expected_len - 1]]),
                Alg::from(alg).id()
            );

            let mut slice = &buf[..len];
            let unmarshaled = HMACStart::unmarshal_with_handles(cmd.handles(), &mut slice).unwrap();
            assert_eq!(unmarshaled, cmd);
            assert!(slice.is_empty());
        }
    }
}

#[test]
fn test_hmac_start_cmd_errors() {
    let handles = [Handle(0x80000000)];

    // 1. Truncated before auth size (requires at least 2 bytes)
    for size in 0..2 {
        let buf = vec![0u8; size];
        let mut slice = &buf[..];
        assert_eq!(
            HMACStart::unmarshal_with_handles(handles, &mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::INSUFFICIENT.in_parameter(1)
        );
    }

    // 2. Declared auth size > actual remaining buffer
    {
        let mut buf = [0u8; 10];
        buf[0..2].copy_from_slice(&20u16.to_be_bytes()); // declared 20, buffer total 10
        let mut slice = &buf[..];
        assert_eq!(
            HMACStart::unmarshal_with_handles(handles, &mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::INSUFFICIENT.in_parameter(1)
        );
    }

    // 3. Auth size field says 32, but missing hash_alg
    {
        let mut buf = [0u8; 34];
        buf[0..2].copy_from_slice(&32u16.to_be_bytes()); // declared 32, buffer total 34 (leaving 0 bytes for hash_alg)
        let mut slice = &buf[..];
        assert_eq!(
            HMACStart::unmarshal_with_handles(handles, &mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::INSUFFICIENT.in_parameter(2)
        );
    }

    // 4. Declared auth size > max allowed (64 bytes for Tpm2bAuth/Tpm2bDigest)
    {
        let mut buf = [0u8; 100];
        buf[0..2].copy_from_slice(&65u16.to_be_bytes()); // declared 65 (max is 64)
        let mut slice = &buf[..];
        assert_eq!(
            HMACStart::unmarshal_with_handles(handles, &mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::SIZE.in_parameter(1)
        );
    }
}

#[test]
fn test_hmac_start_resp_handles_roundtrip() {
    let handles = [
        Handle(0x80000000),
        Handle(0x80000002),
        Handle(0x81000000),
        Handle(0x81000001),
    ];

    for &h in &handles {
        let rsp = responses::HMACStart { sequence_handle: h };
        let [resp_h] = rsp.handles();
        assert_eq!(resp_h, h);
        let mut buf = [0u8; Handle::MAX_SIZE];
        let len = resp_h.marshal(&mut buf);
        assert_eq!(len, 4);
        assert_eq!(&buf[..], &h.0.to_be_bytes()[..]);

        let mut slice = &buf[..];
        let unmarshaled = unmarshal_response_handle(&mut slice).unwrap();
        assert_eq!(unmarshaled, resp_h);
        assert!(slice.is_empty());

        // The response has no parameters: the handle area alone rebuilds it.
        let mut params: &[u8] = &[];
        assert_eq!(
            responses::HMACStart::unmarshal_with_handles([unmarshaled], &mut params),
            Ok(rsp)
        );
    }
}

#[test]
fn test_hmac_start_resp_handles_errors() {
    // Truncated buffer (response handles do not attach command handle modifier in_handle(1))
    for size in 0..4 {
        let buf = vec![0u8; size];
        let mut slice = &buf[..];
        assert_eq!(
            unmarshal_response_handle(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::INSUFFICIENT
        );
    }

    // Invalid TPMI_DH_OBJECT handles
    for h in [Handle(0), Handle(1), Handle::RH_NULL, Handle(0xFFFFFFFF)] {
        let buf = h.0.to_be_bytes();
        let mut slice = &buf[..];
        assert_eq!(
            unmarshal_response_handle(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::VALUE
        );
    }
}

#[test]
fn test_hmac_start_cmd_trailing_data() {
    let auth_bytes = [1, 2, 3];
    let auth = Tpm2bAuth::from_bytes(&auth_bytes).unwrap();
    let cmd = HMACStart {
        handle: Handle(0x80000000),
        auth,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let mut buf = Vec::new();
    buf.extend_from_slice(&(auth_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(&auth_bytes);
    buf.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    buf.extend_from_slice(&[0x99, 0x99]); // trailing

    let mut slice = &buf[..];
    let unmarshaled = HMACStart::unmarshal_with_handles(cmd.handles(), &mut slice).unwrap();
    assert_eq!(unmarshaled, cmd);
    assert_eq!(slice, &[0x99, 0x99]);
}
