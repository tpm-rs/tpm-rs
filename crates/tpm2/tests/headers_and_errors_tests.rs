use tpm2::errors::{Position, TpmRc, UnmarshalError};
use tpm2::*;

// =========================================================================
// Tests from src/structures/headers.rs
// =========================================================================

#[test]
fn test_response_header_unmarshal_rsp_command() {
    let bytes = [
        0x00, 0xC4, // tag: TPM_ST_RSP_COMMAND
        0x00, 0x00, 0x00, 0x0A, // size: 10
        0x00, 0x00, 0x00, 0x1E, // rc: TPM_RC_BAD_TAG
    ];
    let mut src = &bytes[..];
    let hdr = ResponseHeader::unmarshal(&mut src).expect("should unmarshal TPM_ST_RSP_COMMAND");
    assert!(src.is_empty());
    assert_eq!(hdr.tag, TpmSt::RSP_COMMAND);
    assert_eq!(hdr.size, 10);
    assert_eq!(hdr.rc, Err(TpmRc::BAD_TAG));

    let mut dst = [0u8; ResponseHeader::MAX_SIZE];
    let written = hdr.marshal(&mut dst);
    assert_eq!(written, 10);
    assert_eq!(dst, bytes);
}

#[test]
fn test_response_header_valid_tags_roundtrip() {
    for tag in [TpmSt::NO_SESSIONS, TpmSt::SESSIONS, TpmSt::RSP_COMMAND] {
        let hdr = ResponseHeader {
            tag,
            size: 10,
            rc: Ok(()),
        };
        let mut buf = [0u8; ResponseHeader::MAX_SIZE];
        let len = hdr.marshal(&mut buf);
        assert_eq!(len, 10);
        let mut slice = &buf[..];
        let unmarshaled = ResponseHeader::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshaled, hdr);
        assert!(slice.is_empty());
    }
}

#[test]
fn test_response_header_invalid_tags_rejected() {
    for bad_tag in [0x0000u16, 0x8000, 0x8021, 0x9999, 0xFFFF] {
        let mut bytes = [0u8; 10];
        bytes[0..2].copy_from_slice(&bad_tag.to_be_bytes());
        bytes[2..6].copy_from_slice(&10u32.to_be_bytes());
        let mut src = &bytes[..];
        assert_eq!(
            ResponseHeader::unmarshal(&mut src),
            Err(UnmarshalError::BAD_TAG)
        );
    }
}

#[test]
fn test_tpm_st_command_tag_equality() {
    assert_eq!(TpmSt::NO_SESSIONS, TpmiStCommandTag::NoSessions);
    assert_eq!(TpmiStCommandTag::NoSessions, TpmSt::NO_SESSIONS);
    assert_eq!(TpmSt::SESSIONS, TpmiStCommandTag::Sessions);
    assert_eq!(TpmiStCommandTag::Sessions, TpmSt::SESSIONS);
    assert_ne!(TpmSt::RSP_COMMAND, TpmiStCommandTag::NoSessions);
    assert_ne!(TpmSt::RSP_COMMAND, TpmiStCommandTag::Sessions);
}

#[test]
fn test_response_header_truncated_and_precedence() {
    // 0 or 1 byte: INSUFFICIENT when unmarshalling tag
    for len in 0..2 {
        let bytes = [0x00, 0xC4];
        let mut src = &bytes[..len];
        assert_eq!(
            ResponseHeader::unmarshal(&mut src),
            Err(UnmarshalError::INSUFFICIENT)
        );
    }

    // 2 bytes with invalid tag: BAD_TAG precedes INSUFFICIENT on subsequent fields
    let bad_tag_short = [0x80, 0x00];
    let mut src = &bad_tag_short[..];
    assert_eq!(
        ResponseHeader::unmarshal(&mut src),
        Err(UnmarshalError::BAD_TAG)
    );

    // 2..10 bytes with valid tag (0x00C4): INSUFFICIENT on size or rc
    let valid_bytes = [0x00, 0xC4, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x1E];
    for len in 2..10 {
        let mut src = &valid_bytes[..len];
        assert_eq!(
            ResponseHeader::unmarshal(&mut src),
            Err(UnmarshalError::INSUFFICIENT)
        );
    }
}

// =========================================================================
// Tests from src/errors/mod.rs
// =========================================================================

#[test]
fn test_unmarshal_error_new_normalizes_rc_and_preserves_partial_eq() {
    let pos_p1 = Position::parameter(1);
    let positioned_rc = TpmRc::VALUE.with(pos_p1);

    let via_new = UnmarshalError::new(positioned_rc);
    let via_from = UnmarshalError::from(positioned_rc);
    let via_builder = UnmarshalError::VALUE.in_parameter(1);

    assert_eq!(via_new.rc, TpmRc::VALUE.to_rc());
    assert_eq!(via_new.position, Some(pos_p1));
    assert_eq!(via_new, via_builder);
    assert_eq!(via_from, via_builder);
    assert_eq!(via_new.to_rc(), positioned_rc);

    // Unspecified parameter (TPM_RC_P) and session (TPM_RC_S)
    let rc_unspec_p = TpmRc::INSUFFICIENT.with(Position::unspecified_parameter());
    let err_unspec_p = UnmarshalError::new(rc_unspec_p);
    assert_eq!(err_unspec_p.rc, TpmRc::INSUFFICIENT.to_rc());
    assert_eq!(
        err_unspec_p.position,
        Some(Position::unspecified_parameter())
    );
    assert_eq!(
        err_unspec_p,
        UnmarshalError::INSUFFICIENT.in_unspecified_parameter()
    );

    let rc_unspec_s = TpmRc::SIZE.with(Position::unspecified_session());
    let err_unspec_s = UnmarshalError::new(rc_unspec_s);
    assert_eq!(err_unspec_s.rc, TpmRc::SIZE.to_rc());
    assert_eq!(err_unspec_s.position, Some(Position::unspecified_session()));
    assert_eq!(err_unspec_s, UnmarshalError::SIZE.in_unspecified_session());
}

// =========================================================================
// Tests from src/errors/tpm_rc.rs
// =========================================================================

#[test]
fn test_bad_tag_is_fmt0_and_legacy() {
    assert_eq!(TpmRc::BAD_TAG.get(), 0x01E);
    assert!(TpmRc::BAD_TAG.is_fmt0());
    assert!(!TpmRc::BAD_TAG.is_fmt1());
    assert!(TpmRc::BAD_TAG.is_legacy());
    assert!(!TpmRc::BAD_TAG.is_ver1());
    assert!(!TpmRc::BAD_TAG.is_warning());
    assert!(!TpmRc::BAD_TAG.is_vendor());
}

#[test]
fn test_fmt0_ver1_errors_and_warnings() {
    assert!(TpmRc::INITIALIZE.is_fmt0());
    assert!(!TpmRc::INITIALIZE.is_fmt1());
    assert!(TpmRc::INITIALIZE.is_ver1());
    assert!(!TpmRc::INITIALIZE.is_legacy());
    assert!(!TpmRc::INITIALIZE.is_warning());
    assert!(!TpmRc::INITIALIZE.is_vendor());

    assert!(TpmRc::RETRY.is_fmt0());
    assert!(!TpmRc::RETRY.is_fmt1());
    assert!(TpmRc::RETRY.is_ver1());
    assert!(!TpmRc::RETRY.is_legacy());
    assert!(TpmRc::RETRY.is_warning());
    assert!(!TpmRc::RETRY.is_vendor());

    let vendor_err = TpmRc::vendor_error(0x05);
    assert!(vendor_err.is_fmt0());
    assert!(vendor_err.is_ver1());
    assert!(!vendor_err.is_legacy());
    assert!(!vendor_err.is_warning());
    assert!(vendor_err.is_vendor());

    let vendor_warn = TpmRc::vendor_warning(0x05);
    assert!(vendor_warn.is_fmt0());
    assert!(vendor_warn.is_ver1());
    assert!(!vendor_warn.is_legacy());
    assert!(vendor_warn.is_warning());
    assert!(vendor_warn.is_vendor());
}

#[test]
fn test_fmt1_codes_are_not_fmt0() {
    let bare_fmt1 = TpmRc::VALUE.to_rc();
    assert!(!bare_fmt1.is_fmt0());
    assert!(bare_fmt1.is_fmt1());
    assert!(!bare_fmt1.is_ver1());
    assert!(!bare_fmt1.is_legacy());

    let positioned_fmt1 = TpmRc::VALUE.with(Position::handle(1));
    assert!(!positioned_fmt1.is_fmt0());
    assert!(positioned_fmt1.is_fmt1());
    assert!(!positioned_fmt1.is_ver1());
    assert!(!positioned_fmt1.is_legacy());
}

#[test]
fn test_reserved_bits_rejected_by_is_fmt0() {
    let reserved_bit9 = TpmRc::new(0x200).unwrap();
    assert!(!reserved_bit9.is_fmt0());
    assert!(!reserved_bit9.is_fmt1());

    let reserved_upper = TpmRc::new(0x1000 | 0x100).unwrap();
    assert!(!reserved_upper.is_fmt0());
    assert!(!reserved_upper.is_fmt1());
}
