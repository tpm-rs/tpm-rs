#![forbid(unsafe_code)]

//! Comprehensive tests for TPM 2.0 unmarshalling error codes (`TPM_RC`) and parameter/handle/session positions.
//!
//! Verifies that unmarshalling failures across structures and commands preserve spec-mandated
//! Format-1 error codes (`TPM_RC_INSUFFICIENT`, `TPM_RC_SIZE`, `TPM_RC_VALUE`, `TPM_RC_RESERVED_BITS`,
//! `TPM_RC_TYPE`, `TPM_RC_TAG`, `TPM_RC_SCHEME`, `TPM_RC_SYMMETRIC`, `TPM_RC_HASH`, `TPM_RC_MODE`,
//! `TPM_RC_CURVE`, `TPM_RC_SELECTOR`) and attach appropriate position modifiers.

use tpm2::commands::{
    ClearControl, ClockRateAdjust, HierarchyControl, PCRExtend, PolicySigned, VerifySignature,
};
use tpm2::errors::{Position, TpmRc, UnmarshalError};
use tpm2::{
    Alg, Handle, Marshal, PublicParmsAndId, Tpm2bAuth, TpmaSession, TpmsAuthCommand,
    TpmsAuthResponse, TpmsContext, TpmtPublic, TpmtSensitive, TpmtTkAuth, TpmtTkCreation,
    TpmtTkHashcheck, TpmtTkVerified, TpmuSensitiveComposite, Unmarshal,
};

#[test]
fn test_tpms_auth_command_unmarshal_errors() {
    // 1. Truncated buffer (< 4 bytes for session handle) -> INSUFFICIENT
    let buf_short = [0x02, 0x00, 0x00];
    let mut slice = &buf_short[..];
    assert_eq!(
        TpmsAuthCommand::unmarshal(&mut slice),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // 2. Invalid session handle (neither TPM_RS_PW (0x40000009) nor HMAC (0x02xxxxxx) nor Policy (0x03xxxxxx)) -> VALUE
    // E.g. transient handle 0x80000000
    let buf_bad_handle = [
        0x80, 0x00, 0x00, 0x00, // sessionHandle = 0x80000000 (invalid)
        0x00, 0x00, // nonce size = 0
        0x01, // sessionAttributes = continueSession
        0x00, 0x00, // hmac size = 0
    ];
    let mut slice = &buf_bad_handle[..];
    assert_eq!(
        TpmsAuthCommand::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE)
    );

    // Hierarchy handle 0x40000001 (RH_OWNER) is also invalid as a session handle -> VALUE
    let buf_owner_handle = [
        0x40, 0x00, 0x00, 0x01, // sessionHandle = RH_OWNER (invalid)
        0x00, 0x00, // nonce size = 0
        0x01, // sessionAttributes = continueSession
        0x00, 0x00, // hmac size = 0
    ];
    let mut slice = &buf_owner_handle[..];
    assert_eq!(
        TpmsAuthCommand::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE)
    );

    // 3. Valid session handle (TPM_RS_PW = 0x40000009) but reserved bits set in TpmaSession (0x08) -> RESERVED_BITS
    let buf_reserved_bits = [
        0x40, 0x00, 0x00, 0x09, // sessionHandle = TPM_RS_PW
        0x00, 0x00, // nonce size = 0
        0x08, // sessionAttributes with bit 3 (reserved) set
        0x00, 0x00, // hmac size = 0
    ];
    let mut slice = &buf_reserved_bits[..];
    assert_eq!(
        TpmsAuthCommand::unmarshal(&mut slice),
        Err(UnmarshalError::RESERVED_BITS)
    );

    // 4. Valid HMAC session handle (0x02000000) roundtrips cleanly
    let buf_valid = [
        0x02,
        0x00,
        0x00,
        0x00, // sessionHandle = HMAC session 0
        0x00,
        0x00, // nonce size = 0
        TpmaSession::CONTINUE_SESSION.bits(),
        0x00,
        0x00, // hmac size = 0
    ];
    let mut slice = &buf_valid[..];
    let auth = TpmsAuthCommand::unmarshal(&mut slice).expect("valid TpmsAuthCommand");
    assert_eq!(auth.session_handle, Handle(0x02000000));
    assert_eq!(auth.session_attributes, TpmaSession::CONTINUE_SESSION);
}

#[test]
fn test_tpms_auth_response_hmac_size_limit() {
    // Verify MAX_SIZE matches Tpm2bNonce::MAX_SIZE (66) + TpmaSession::MAX_SIZE (1) + Tpm2bAuth::MAX_SIZE (66) = 133
    assert_eq!(TpmsAuthResponse::MAX_SIZE, 66 + 1 + 66);
    assert_eq!(Tpm2bAuth::MAX_BUFFER_SIZE, 64);

    // 1. 64-byte HMAC buffer (max allowed by TPM2B_AUTH / TPMU_HA) succeeds and roundtrips
    let mut buf_64 = [0u8; 2 + 1 + 2 + 64];
    buf_64[0..2].copy_from_slice(&0u16.to_be_bytes()); // nonce size = 0
    buf_64[2] = TpmaSession::CONTINUE_SESSION.bits();
    buf_64[3..5].copy_from_slice(&64u16.to_be_bytes()); // hmac size = 64
    buf_64[5..69].fill(0xAA);

    let mut slice = &buf_64[..];
    let resp = TpmsAuthResponse::unmarshal(&mut slice).expect("64-byte HMAC should succeed");
    assert_eq!(resp.hmac.get_size(), 64);
    assert_eq!(resp.hmac.get_buffer(), &[0xAA; 64]);

    let mut out_buf = [0u8; TpmsAuthResponse::MAX_SIZE];
    let written = resp.marshal(&mut out_buf);
    assert_eq!(&out_buf[..written], &buf_64[..]);

    // 2. 65-byte HMAC buffer exceeds TPM2B_AUTH max (64 bytes) and must fail with SIZE
    let mut buf_65 = [0u8; 2 + 1 + 2 + 65];
    buf_65[0..2].copy_from_slice(&0u16.to_be_bytes());
    buf_65[2] = TpmaSession::CONTINUE_SESSION.bits();
    buf_65[3..5].copy_from_slice(&65u16.to_be_bytes()); // hmac size = 65
    let mut slice = &buf_65[..];
    assert_eq!(
        TpmsAuthResponse::unmarshal(&mut slice),
        Err(UnmarshalError::SIZE)
    );

    // 3. 66-byte HMAC buffer (the max size of TPM2B_DATA / TPMT_HA) must also fail with SIZE
    let mut buf_66 = [0u8; 2 + 1 + 2 + 66];
    buf_66[0..2].copy_from_slice(&0u16.to_be_bytes());
    buf_66[2] = TpmaSession::CONTINUE_SESSION.bits();
    buf_66[3..5].copy_from_slice(&66u16.to_be_bytes()); // hmac size = 66
    let mut slice = &buf_66[..];
    assert_eq!(
        TpmsAuthResponse::unmarshal(&mut slice),
        Err(UnmarshalError::SIZE)
    );
}

#[test]
fn test_tpmt_public_and_sensitive_selector_validation() {
    // TpmtPublic with invalid selector (0x0010 = Alg::NULL, not a valid object type)
    // Even if buffer is only 2 bytes, selector is validated first and returns TYPE (not INSUFFICIENT).
    let buf_invalid_type = [0x00, 0x10];
    let mut slice = &buf_invalid_type[..];
    assert_eq!(TpmtPublic::unmarshal(&mut slice), Err(UnmarshalError::TYPE));

    // TpmtPublic with valid selector (0x0001 = Alg::RSA) but truncated buffer returns INSUFFICIENT.
    let buf_valid_type_truncated = [0x00, 0x01];
    let mut slice = &buf_valid_type_truncated[..];
    assert_eq!(
        TpmtPublic::unmarshal(&mut slice),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // TpmtSensitive with invalid selector (0x000B = Alg::SHA256) returns TYPE even on 2-byte buffer.
    let buf_sens_invalid_type = [0x00, 0x0B];
    let mut slice = &buf_sens_invalid_type[..];
    assert_eq!(
        TpmtSensitive::unmarshal(&mut slice),
        Err(UnmarshalError::TYPE)
    );

    // TpmtSensitive with valid selector (0x0008 = Alg::KEYEDHASH) but truncated buffer returns INSUFFICIENT.
    let buf_sens_truncated = [0x00, 0x08];
    let mut slice = &buf_sens_truncated[..];
    assert_eq!(
        TpmtSensitive::unmarshal(&mut slice),
        Err(UnmarshalError::INSUFFICIENT)
    );
}

#[test]
fn test_ticket_structures_tag_and_hierarchy_validation() {
    use tpm2::TpmSt;

    // 1. TpmtTkCreation
    // Wrong tag -> TAG
    let bad_tag = [0x00, 0x00, 0x40, 0x00, 0x00, 0x01, 0x00, 0x00];
    let mut slice = &bad_tag[..];
    assert_eq!(
        TpmtTkCreation::unmarshal(&mut slice),
        Err(UnmarshalError::TAG)
    );

    // Correct tag (TpmSt::CREATION) but invalid hierarchy (0x80000000) -> VALUE
    let [t0, t1] = TpmSt::CREATION.id().to_be_bytes();
    let bad_hierarchy = [t0, t1, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut slice = &bad_hierarchy[..];
    assert_eq!(
        TpmtTkCreation::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE)
    );

    // 2. TpmtTkVerified
    // Correct tag (TpmSt::VERIFIED) but invalid hierarchy (0x02000000) -> VALUE
    let [v0, v1] = TpmSt::VERIFIED.id().to_be_bytes();
    let verified_bad_hier = [v0, v1, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut slice = &verified_bad_hier[..];
    assert_eq!(
        TpmtTkVerified::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE)
    );

    // 3. TpmtTkAuth
    // Correct tag (TpmSt::AUTH_SIGNED) but invalid hierarchy (0xFFFFFFFF) -> VALUE
    let [a0, a1] = TpmSt::AUTH_SIGNED.id().to_be_bytes();
    let auth_bad_hier = [a0, a1, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00];
    let mut slice = &auth_bad_hier[..];
    assert_eq!(
        TpmtTkAuth::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE)
    );

    // 4. TpmtTkHashcheck
    // Correct tag (TpmSt::HASHCHECK) but invalid hierarchy (0x12345678) -> VALUE
    let [h0, h1] = TpmSt::HASHCHECK.id().to_be_bytes();
    let hashcheck_bad_hier = [h0, h1, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00];
    let mut slice = &hashcheck_bad_hier[..];
    assert_eq!(
        TpmtTkHashcheck::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE)
    );
}

#[test]
fn test_command_parameter_positions_on_unmarshal() {
    // 1. PCRExtend: parameter 1 is digests (TpmlDigestValues)
    // Truncated buffer at parameter 1 -> INSUFFICIENT + P1
    let empty: [u8; 0] = [];
    let mut slice = &empty[..];
    let err = PCRExtend::unmarshal(&mut slice).unwrap_err();
    assert_eq!(
        err.to_rc(),
        TpmRc::INSUFFICIENT.with(Position::parameter(1))
    );

    // 2. VerifySignature: parameter 1 is digest (Tpm2bDigest), parameter 2 is signature (TpmtSignature)
    // Valid parameter 1 (size 0), invalid signature scheme (0xFFFF) in parameter 2 -> SCHEME + P2
    let verify_sig_bytes = [
        0x00, 0x00, // param 1: digest size = 0
        0xFF, 0xFF, // param 2: sig scheme = 0xFFFF (invalid)
    ];
    let mut slice = &verify_sig_bytes[..];
    let err = VerifySignature::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err.to_rc(), TpmRc::SCHEME.with(Position::parameter(2)));

    // 3. PolicySigned: parameter 5 is auth (TpmtSignature)
    // Params 1..=3 are empty 2B buffers (0x0000), param 4 is expiration i32 (0x00000000), param 5 has invalid scheme -> SCHEME + P5
    let policy_signed_bytes = [
        0x00, 0x00, // param 1: nonceTPM
        0x00, 0x00, // param 2: cpHashA
        0x00, 0x00, // param 3: policyRef
        0x00, 0x00, 0x00, 0x00, // param 4: expiration
        0xFF, 0xFF, // param 5: auth signature scheme = 0xFFFF
    ];
    let mut slice = &policy_signed_bytes[..];
    let err = PolicySigned::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err.to_rc(), TpmRc::SCHEME.with(Position::parameter(5)));

    // 4. ClockRateAdjust: parameter 1 is rate_adjust (u8 mapped to TpmClockAdjust)
    // Value 4 is out of range (valid are -3..=3 in i8, or 0..=3, 0xFD..=0xFF) -> VALUE + P1
    let bad_clock_adjust = [0x04];
    let mut slice = &bad_clock_adjust[..];
    let err = ClockRateAdjust::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err.to_rc(), TpmRc::VALUE.with(Position::parameter(1)));

    // 5. HierarchyControl: parameter 1 is enable (Handle), parameter 2 is state (u8 TpmiYesNo)
    // Invalid hierarchy handle in parameter 1 (0x40000007 = RH_NULL is not allowed as enable) -> VALUE + P1
    let bad_hier_enable = [
        0x40, 0x00, 0x00, 0x07, // enable = RH_NULL
        0x01, // state = YES
    ];
    let mut slice = &bad_hier_enable[..];
    let err = HierarchyControl::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err.to_rc(), TpmRc::VALUE.with(Position::parameter(1)));

    // Valid enable (0x40000001 = RH_OWNER) but invalid state (2) in parameter 2 -> VALUE + P2
    let bad_hier_state = [
        0x40, 0x00, 0x00, 0x01, // enable = RH_OWNER
        0x02, // state = 2 (invalid TpmiYesNo)
    ];
    let mut slice = &bad_hier_state[..];
    let err = HierarchyControl::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err.to_rc(), TpmRc::VALUE.with(Position::parameter(2)));

    // 6. ClearControl: parameter 1 is disable (u8 TpmiYesNo)
    // Invalid disable (0xFF) -> VALUE + P1
    let bad_clear_disable = [0xFF];
    let mut slice = &bad_clear_disable[..];
    let err = ClearControl::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err.to_rc(), TpmRc::VALUE.with(Position::parameter(1)));
}

#[test]
fn test_union_unmarshal_variant_returns_selector_error() {
    let dummy_bytes = [0u8; 8];
    let mut slice = &dummy_bytes[..];
    let err = TpmuSensitiveComposite::unmarshal_variant(Alg::SHA256, &mut slice).unwrap_err();
    assert_eq!(err, UnmarshalError::SELECTOR);
    assert_eq!(err.to_rc(), TpmRc::SELECTOR.to_rc());

    let mut slice = &dummy_bytes[..];
    let err = PublicParmsAndId::unmarshal_variant(Alg::SHA256, &mut slice).unwrap_err();
    assert_eq!(err, UnmarshalError::SELECTOR);
    assert_eq!(err.to_rc(), TpmRc::SELECTOR.to_rc());
}

#[test]
fn test_tpms_context_and_context_load_unmarshal_validation() {
    use tpm2::commands::ContextLoad;

    // 1. Invalid saved_handle (0x0000_0001 is not a valid TPMI_DH_SAVED handle) -> VALUE + P1
    let bad_saved_handle = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence: 1
        0x00, 0x00, 0x00, 0x01, // saved_handle: 0x00000001 (invalid)
        0x40, 0x00, 0x00, 0x01, // hierarchy: RH_OWNER
        0x00, 0x00, // context_blob size: 0
    ];
    let mut slice = &bad_saved_handle[..];
    let err = TpmsContext::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err, UnmarshalError::VALUE);

    let mut slice = &bad_saved_handle[..];
    let err = ContextLoad::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err.to_rc(), TpmRc::VALUE.with(Position::parameter(1)));

    // 2. Valid saved_handle (0x8000_0000) but invalid hierarchy (0x4000_000A = RH_LOCKOUT) -> VALUE + P1
    let bad_hierarchy = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence: 1
        0x80, 0x00, 0x00, 0x00, // saved_handle: 0x80000000 (transient object)
        0x40, 0x00, 0x00, 0x0A, // hierarchy: RH_LOCKOUT (invalid for TPMS_CONTEXT)
        0x00, 0x00, // context_blob size: 0
    ];
    let mut slice = &bad_hierarchy[..];
    let err = TpmsContext::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err, UnmarshalError::VALUE);

    let mut slice = &bad_hierarchy[..];
    let err = ContextLoad::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err.to_rc(), TpmRc::VALUE.with(Position::parameter(1)));
}

#[test]
fn test_tpm_rc_with_position_helper() {
    let unpositioned = TpmRc::INSUFFICIENT.to_rc();
    let positioned = unpositioned.with_position(Position::parameter(2));
    assert_eq!(positioned, TpmRc::INSUFFICIENT.with(Position::parameter(2)));

    // Already positioned Format-1 code is not overwritten
    let already_pos = positioned.with_position(Position::handle(1));
    assert_eq!(
        already_pos,
        TpmRc::INSUFFICIENT.with(Position::parameter(2))
    );

    // Format-1 code with TPM_RC_P (unspecified parameter) is not overwritten
    let unspecified_p = TpmRc::VALUE.with(Position::unspecified_parameter());
    let attempt_overwrite_p = unspecified_p.with_position(Position::parameter(1));
    assert_eq!(attempt_overwrite_p, unspecified_p);
    let attempt_overwrite_p_handle = unspecified_p.with_position(Position::handle(2));
    assert_eq!(attempt_overwrite_p_handle, unspecified_p);

    // Format-1 code with TPM_RC_S (unspecified session) is not overwritten
    let unspecified_s = TpmRc::VALUE.with(Position::unspecified_session());
    let attempt_overwrite_s = unspecified_s.with_position(Position::session(1));
    assert_eq!(attempt_overwrite_s, unspecified_s);
    let attempt_overwrite_s_param = unspecified_s.with_position(Position::parameter(1));
    assert_eq!(attempt_overwrite_s_param, unspecified_s);

    // Format-0 code is unchanged
    let fmt0 = TpmRc::COMMAND_SIZE.with_position(Position::parameter(1));
    assert_eq!(fmt0, TpmRc::COMMAND_SIZE);
}

#[test]
fn test_tpm_rc_fmt1_unspecified_parameter_and_session_preservation() {
    // 1. Position constants and constructors
    assert_eq!(Position::UNSPECIFIED_PARAMETER.get(), 0x040);
    assert_eq!(Position::UNSPECIFIED_SESSION.get(), 0x800);
    assert_eq!(Position::parameter(0), Position::UNSPECIFIED_PARAMETER);
    assert_eq!(Position::session(0), Position::UNSPECIFIED_SESSION);
    assert_eq!(
        Position::unspecified_parameter(),
        Position::UNSPECIFIED_PARAMETER
    );
    assert_eq!(
        Position::unspecified_session(),
        Position::UNSPECIFIED_SESSION
    );

    // 2. Accessors
    assert!(Position::UNSPECIFIED_PARAMETER.is_unspecified());
    assert!(Position::UNSPECIFIED_SESSION.is_unspecified());
    assert!(!Position::parameter(1).is_unspecified());
    assert!(!Position::session(1).is_unspecified());
    assert!(!Position::handle(1).is_unspecified());

    assert_eq!(Position::UNSPECIFIED_PARAMETER.parameter_num(), Some(0));
    assert_eq!(Position::UNSPECIFIED_PARAMETER.session_num(), None);
    assert_eq!(Position::UNSPECIFIED_PARAMETER.handle_num(), None);

    assert_eq!(Position::UNSPECIFIED_SESSION.session_num(), Some(0));
    assert_eq!(Position::UNSPECIFIED_SESSION.parameter_num(), None);
    assert_eq!(Position::UNSPECIFIED_SESSION.handle_num(), None);

    assert_eq!(Position::parameter(3).parameter_num(), Some(3));
    assert_eq!(Position::session(2).session_num(), Some(2));
    assert_eq!(Position::handle(1).handle_num(), Some(1));

    // 3. TpmRc::to_fmt1 preserves TPM_RC_P and TPM_RC_S modifiers
    // TPM_RC_VALUE (0x084) | TPM_RC_P (0x040) = 0x0C4
    let rc_p = TpmRc::new(0x0C4).unwrap();
    let (fmt1, pos) = rc_p.to_fmt1().expect("0x0C4 must be Format-1");
    assert_eq!(fmt1, TpmRc::VALUE);
    assert_eq!(pos, Some(Position::unspecified_parameter()));

    // TPM_RC_VALUE (0x084) | TPM_RC_S (0x800) = 0x884
    let rc_s = TpmRc::new(0x884).unwrap();
    let (fmt1, pos) = rc_s.to_fmt1().expect("0x884 must be Format-1");
    assert_eq!(fmt1, TpmRc::VALUE);
    assert_eq!(pos, Some(Position::unspecified_session()));

    // Bare Format-1 code (0x084) maps to None position
    let (fmt1, pos) = TpmRc::VALUE.to_rc().to_fmt1().unwrap();
    assert_eq!(fmt1, TpmRc::VALUE);
    assert_eq!(pos, None);

    // Format-0 code returns None
    assert_eq!(TpmRc::COMMAND_SIZE.to_fmt1(), None);

    // 4. Display implementation for Position
    assert_eq!(
        format!("{}", Position::unspecified_parameter()),
        "Position::unspecified_parameter()"
    );
    assert_eq!(
        format!("{}", Position::unspecified_session()),
        "Position::unspecified_session()"
    );
    assert_eq!(
        format!("{}", Position::parameter(1)),
        "Position::parameter(1)"
    );
    assert_eq!(format!("{}", Position::session(1)), "Position::session(1)");
    assert_eq!(format!("{}", Position::handle(1)), "Position::handle(1)");
}

#[test]
fn test_unmarshal_error_preserves_existing_positions_and_unspecified_indicators() {
    // 1. UnmarshalError::new extracts existing unspecified parameter position and normalizes rc
    let rc_p = TpmRc::VALUE.with(Position::unspecified_parameter());
    let err_p = UnmarshalError::new(rc_p);
    assert_eq!(err_p.rc, TpmRc::VALUE.to_rc());
    assert_eq!(err_p.position, Some(Position::unspecified_parameter()));
    assert_eq!(err_p, UnmarshalError::VALUE.in_unspecified_parameter());
    assert_eq!(err_p.to_rc(), rc_p);

    // Outer positioning does not overwrite existing unspecified parameter position
    let attempted_overwrite = err_p.in_parameter(2);
    assert_eq!(
        attempted_overwrite.position,
        Some(Position::unspecified_parameter())
    );
    assert_eq!(attempted_overwrite.to_rc(), rc_p);

    let attempted_handle_overwrite = err_p.in_handle(1);
    assert_eq!(
        attempted_handle_overwrite.position,
        Some(Position::unspecified_parameter())
    );
    assert_eq!(attempted_handle_overwrite.to_rc(), rc_p);

    // 2. UnmarshalError::new extracts existing unspecified session position and normalizes rc
    let rc_s = TpmRc::VALUE.with(Position::unspecified_session());
    let err_s = UnmarshalError::new(rc_s);
    assert_eq!(err_s.rc, TpmRc::VALUE.to_rc());
    assert_eq!(err_s.position, Some(Position::unspecified_session()));
    assert_eq!(err_s, UnmarshalError::VALUE.in_unspecified_session());
    assert_eq!(err_s.to_rc(), rc_s);

    let attempted_session_overwrite = err_s.in_session(3);
    assert_eq!(
        attempted_session_overwrite.position,
        Some(Position::unspecified_session())
    );
    assert_eq!(attempted_session_overwrite.to_rc(), rc_s);

    // 3. UnmarshalError::new extracts existing index-based position and normalizes rc
    let rc_p1 = TpmRc::VALUE.with(Position::parameter(1));
    let err_p1 = UnmarshalError::new(rc_p1);
    assert_eq!(err_p1.rc, TpmRc::VALUE.to_rc());
    assert_eq!(err_p1.position, Some(Position::parameter(1)));
    assert_eq!(err_p1, UnmarshalError::VALUE.in_parameter(1));
    assert_eq!(err_p1.to_rc(), rc_p1);

    let attempted_p2 = err_p1.in_parameter(2);
    assert_eq!(attempted_p2.position, Some(Position::parameter(1)));
    assert_eq!(attempted_p2.to_rc(), rc_p1);

    // 4. in_unspecified_parameter and in_unspecified_session attach to unpositioned errors
    let unpositioned = UnmarshalError::VALUE;
    assert_eq!(unpositioned.position, None);

    let unspec_p = unpositioned.in_unspecified_parameter();
    assert_eq!(unspec_p.position, Some(Position::unspecified_parameter()));
    assert_eq!(
        unspec_p.to_rc(),
        TpmRc::VALUE.with(Position::unspecified_parameter())
    );

    let unspec_s = unpositioned.in_unspecified_session();
    assert_eq!(unspec_s.position, Some(Position::unspecified_session()));
    assert_eq!(
        unspec_s.to_rc(),
        TpmRc::VALUE.with(Position::unspecified_session())
    );

    // 5. in_parameter(0) behaves like in_unspecified_parameter()
    let param_zero = unpositioned.in_parameter(0);
    assert_eq!(param_zero.position, Some(Position::unspecified_parameter()));
    assert_eq!(
        param_zero.to_rc(),
        TpmRc::VALUE.with(Position::unspecified_parameter())
    );

    // 6. in_session(0) behaves like in_unspecified_session()
    let session_zero = unpositioned.in_session(0);
    assert_eq!(session_zero.position, Some(Position::unspecified_session()));
    assert_eq!(
        session_zero.to_rc(),
        TpmRc::VALUE.with(Position::unspecified_session())
    );

    // 7. Format-0 code preserves value and ignores position
    let fmt0_err = UnmarshalError::new(TpmRc::COMMAND_SIZE).in_parameter(1);
    assert_eq!(fmt0_err.to_rc(), TpmRc::COMMAND_SIZE);
}

#[test]
fn test_tpms_attest_and_capability_data_unmarshal_errors() {
    use tpm2::{TpmsAttest, TpmsCapabilityData};

    // 1. TpmsAttest with invalid magic -> VALUE
    let bad_magic = [0x00, 0x00, 0x00, 0x00, 0x80, 0x17];
    let mut slice = &bad_magic[..];
    assert_eq!(
        TpmsAttest::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE)
    );

    // 2. TpmsAttest with valid magic (0xff544347) but invalid type tag (0x8000 = TPM_ST_NULL)
    // Even if buffer is truncated at 6 bytes, field 2 (TPMI_ST_ATTEST) fails with VALUE before field 3 (INSUFFICIENT).
    let bad_type_truncated = [0xff, 0x54, 0x43, 0x47, 0x80, 0x00];
    let mut slice = &bad_type_truncated[..];
    assert_eq!(
        TpmsAttest::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE),
        "TpmsAttest with invalid TPMI_ST_ATTEST must return VALUE even if truncated after tag"
    );

    // 3. TpmsAttest with valid magic (0xff544347) and valid type tag (0x8017 = ATTEST_CERTIFY)
    // but truncated buffer -> INSUFFICIENT
    let valid_type_truncated = [0xff, 0x54, 0x43, 0x47, 0x80, 0x17];
    let mut slice = &valid_type_truncated[..];
    assert_eq!(
        TpmsAttest::unmarshal(&mut slice),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // 4. TpmsCapabilityData with invalid TPM_CAP (0x99999999) -> VALUE
    let bad_cap = [0x99, 0x99, 0x99, 0x99, 0x00, 0x00, 0x00, 0x00];
    let mut slice = &bad_cap[..];
    assert_eq!(
        TpmsCapabilityData::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE),
        "TpmsCapabilityData with invalid TPM_CAP must return VALUE"
    );

    // 5. TpmsCapabilityData with valid TPM_CAP (0x0000000A = TpmCap::ACT) and count = 0 succeeds,
    // while truncated buffer returns INSUFFICIENT.
    let valid_act_cap = [0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00];
    let mut slice = &valid_act_cap[..];
    assert!(TpmsCapabilityData::unmarshal(&mut slice).is_ok());
    assert!(slice.is_empty());

    let truncated_act_cap = [0x00, 0x00, 0x00, 0x0A, 0x00, 0x00];
    let mut slice = &truncated_act_cap[..];
    assert_eq!(
        TpmsCapabilityData::unmarshal(&mut slice),
        Err(UnmarshalError::INSUFFICIENT),
        "TpmsCapabilityData with valid TPM_CAP but truncated payload must return INSUFFICIENT"
    );
}

#[test]
fn test_alg_unmarshal_accepts_all_constants_and_tpmi_validates() {
    use tpm2::{TpmiAlgHash, TpmlAlg, TpmsAlgProperty, TpmtSymDefObject};

    // 1. Direct Alg::unmarshal and Alg::from accept any u16 (including reserved 0x0000,
    // 0x00C1..=0x00C6, and 0x8000..=0xFFFF) per TPM 2.0 Part 2 Table 9 (TPM_ALG_ID Constants).
    for reserved_id in [0x0000u16, 0x00C1, 0x00C4, 0x00C6, 0x8000, 0x8001, 0xFFFF] {
        assert_eq!(Alg::from(reserved_id).id(), reserved_id);
        let bytes = reserved_id.to_be_bytes();
        let mut slice = &bytes[..];
        assert_eq!(Alg::unmarshal(&mut slice), Ok(Alg::from(reserved_id)));
    }

    // 2. TpmlAlg containing a reserved Alg ID unmarshals successfully as UINT16 elements;
    // when truncated on a subsequent element, it returns INSUFFICIENT (not VALUE).
    let tpml_alg_reserved = [
        0x00, 0x00, 0x00, 0x01, // count = 1
        0x00, 0x00, // alg[0] = 0x0000
    ];
    let mut slice = &tpml_alg_reserved[..];
    let list = TpmlAlg::unmarshal(&mut slice).expect("TpmlAlg with reserved u16 succeeds");
    assert_eq!(list.count(), 1);
    assert_eq!(list.algorithms()[0], Alg::from(0x0000));

    let tpml_alg_truncated = [
        0x00, 0x00, 0x00, 0x02, // count = 2
        0x00, 0x00, // alg[0] = 0x0000 (reserved)
        0x00, // alg[1] truncated (only 1 byte)
    ];
    let mut slice = &tpml_alg_truncated[..];
    assert_eq!(
        TpmlAlg::unmarshal(&mut slice),
        Err(UnmarshalError::INSUFFICIENT),
        "TpmlAlg truncated after reserved alg[0] must return INSUFFICIENT, not VALUE"
    );

    // 3. TpmsAlgProperty with reserved Alg ID (0x00C4) unmarshals successfully (alg is TPM_ALG_ID)
    let tpms_alg_prop_reserved = [
        0x00, 0xC4, // alg = 0x00C4 (reserved)
        0x00, 0x00, 0x00, 0x01, // algProperties = ASYMMETRIC
    ];
    let mut slice = &tpms_alg_prop_reserved[..];
    let prop =
        TpmsAlgProperty::unmarshal(&mut slice).expect("TpmsAlgProperty unmarshals any u16 alg");
    assert_eq!(prop.alg, Alg::from(0x00C4));

    // 4. Interface/tagged types (TPMI_*, TPMT_*) preserve their spec-mandated error codes for 0x0000 or 0x8000
    let zero_buf = [0x00, 0x00];
    let mut slice = &zero_buf[..];
    assert_eq!(
        TpmiAlgHash::unmarshal(&mut slice),
        Err(UnmarshalError::HASH)
    );

    let mut slice = &zero_buf[..];
    assert_eq!(
        Option::<TpmiAlgHash>::unmarshal(&mut slice),
        Err(UnmarshalError::HASH)
    );

    let mut slice = &zero_buf[..];
    assert_eq!(
        TpmtSymDefObject::unmarshal(&mut slice),
        Err(UnmarshalError::SYMMETRIC)
    );

    let mut slice = &zero_buf[..];
    assert_eq!(TpmtPublic::unmarshal(&mut slice), Err(UnmarshalError::TYPE));

    let mut slice = &zero_buf[..];
    assert_eq!(
        TpmtSensitive::unmarshal(&mut slice),
        Err(UnmarshalError::TYPE)
    );
}

#[test]
fn test_tpms_command_audit_info_digest_alg_validation() {
    use tpm2::{Marshal, Tpm2bDigest, TpmsCommandAuditInfo};

    // Valid TpmsCommandAuditInfo with digest_alg = Alg::SHA256 roundtrips cleanly
    let valid_info = TpmsCommandAuditInfo {
        audit_counter: 0x0102030405060708,
        digest_alg: Alg::SHA256,
        audit_digest: Tpm2bDigest::default(),
        command_digest: Tpm2bDigest::default(),
    };
    let mut buf = [0u8; TpmsCommandAuditInfo::MAX_SIZE];
    let len = valid_info.marshal(&mut buf);
    let mut slice = &buf[..len];
    let unmarshaled =
        TpmsCommandAuditInfo::unmarshal(&mut slice).expect("valid TpmsCommandAuditInfo");
    assert_eq!(unmarshaled, valid_info);
    assert!(slice.is_empty());

    // Per TPM 2.0 Part 2 Table 140, digestAlg in TPMS_COMMAND_AUDIT_INFO is TPM_ALG_ID (UINT16 Constants),
    // so any u16 value unmarshals cleanly without value validation during unmarshalling.
    for raw_alg in [0x0000u16, 0x00C4, 0x8000, 0xFFFF] {
        let mut raw_buf = buf;
        raw_buf[8..10].copy_from_slice(&raw_alg.to_be_bytes());
        let mut slice = &raw_buf[..len];
        let info = TpmsCommandAuditInfo::unmarshal(&mut slice)
            .expect("TpmsCommandAuditInfo unmarshals any u16 TPM_ALG_ID");
        assert_eq!(info.digest_alg, Alg::from(raw_alg));
    }
}

#[test]
fn test_non_null_scheme_structures_reject_tpm_alg_null_inner_algorithms() {
    use tpm2::{
        TpmiAlgKdf, TpmsSchemeXor, TpmtEccScheme, TpmtKdfScheme, TpmtKeyedHashScheme,
        TpmtRsaDecrypt, TpmtRsaScheme, TpmtSigScheme, TpmtSymDef,
    };

    // 1. TpmiAlgKdf directly must reject TPM_ALG_NULL (0x0010) with KDF
    let mut slice = &[0x00, 0x10][..];
    assert_eq!(TpmiAlgKdf::unmarshal(&mut slice), Err(UnmarshalError::KDF));

    // 2. TpmsSchemeXor must reject TPM_ALG_NULL (0x0010) for hash_alg with HASH,
    // permit TPM_ALG_NULL (0x0010) for kdf (since kdf is TPMI_ALG_KDF+ in Table 166),
    // and reject non-null invalid KDF algorithms (e.g., 0x000B SHA256) with KDF.
    let mut slice = &[0x00, 0x10, 0x00, 0x22][..];
    assert_eq!(
        TpmsSchemeXor::unmarshal(&mut slice),
        Err(UnmarshalError::HASH)
    );
    let mut slice = &[0x00, 0x0B, 0x00, 0x10][..];
    assert_eq!(
        TpmsSchemeXor::unmarshal(&mut slice),
        Ok(TpmsSchemeXor {
            hash_alg: tpm2::TpmiAlgHash::Sha256,
            kdf: None,
        })
    );
    let mut slice = &[0x00, 0x0B, 0x00, 0x0B][..];
    assert_eq!(
        TpmsSchemeXor::unmarshal(&mut slice),
        Err(UnmarshalError::KDF)
    );

    // 3. TpmtKeyedHashScheme: Alg::HMAC (0x0005) with inner 0x0010 -> HASH
    let mut slice = &[0x00, 0x05, 0x00, 0x10][..];
    assert_eq!(
        <Option<TpmtKeyedHashScheme>>::unmarshal(&mut slice),
        Err(UnmarshalError::HASH)
    );
    // Alg::XOR (0x000A) with inner hash 0x0010 -> HASH, inner kdf 0x0010 -> Ok(None), invalid kdf 0x000B -> KDF
    let mut slice = &[0x00, 0x0A, 0x00, 0x10, 0x00, 0x22][..];
    assert_eq!(
        <Option<TpmtKeyedHashScheme>>::unmarshal(&mut slice),
        Err(UnmarshalError::HASH)
    );
    let mut slice = &[0x00, 0x0A, 0x00, 0x0B, 0x00, 0x10][..];
    assert_eq!(
        <Option<TpmtKeyedHashScheme>>::unmarshal(&mut slice),
        Ok(Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
            hash_alg: tpm2::TpmiAlgHash::Sha256,
            kdf: None,
        })))
    );
    let mut slice = &[0x00, 0x0A, 0x00, 0x0B, 0x00, 0x0B][..];
    assert_eq!(
        <Option<TpmtKeyedHashScheme>>::unmarshal(&mut slice),
        Err(UnmarshalError::KDF)
    );

    // 4. TpmtSymDef::Xor (0x000A) with inner 0x0010 -> HASH
    let mut slice = &[0x00, 0x0A, 0x00, 0x10][..];
    assert_eq!(
        <Option<TpmtSymDef>>::unmarshal(&mut slice),
        Err(UnmarshalError::HASH)
    );

    // 5. TpmtSigScheme non-null variants with inner 0x0010 -> HASH
    for scheme_alg in [
        #[cfg(feature = "rsassa")]
        0x0014u16, // RSASSA
        #[cfg(feature = "rsapss")]
        0x0016, // RSAPSS
        #[cfg(feature = "ecdsa")]
        0x0018, // ECDSA
        #[cfg(feature = "sm2")]
        0x001B, // SM2
        #[cfg(feature = "ecschnorr")]
        0x001C, // ECSCHNORR
        0x0005, // HMAC
    ] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&scheme_alg.to_be_bytes());
        buf[2..4].copy_from_slice(&0x0010u16.to_be_bytes());
        let mut slice = &buf[..];
        assert_eq!(
            <Option<TpmtSigScheme>>::unmarshal(&mut slice),
            Err(UnmarshalError::HASH),
            "TpmtSigScheme 0x{:04X} with inner TPM_ALG_NULL must return HASH",
            scheme_alg
        );
    }
    // ECDAA (0x001A) with inner 0x0010 -> HASH
    #[cfg(feature = "ecdaa")]
    {
        let mut slice = &[0x00, 0x1A, 0x00, 0x10, 0x00, 0x00][..];
        assert_eq!(
            <Option<TpmtSigScheme>>::unmarshal(&mut slice),
            Err(UnmarshalError::HASH)
        );
    }

    // 6. TpmtRsaScheme non-null hash variants with inner 0x0010 -> HASH
    let rsa_hash_schemes: &[u16] = &[
        #[cfg(feature = "rsassa")]
        0x0014u16, // RSASSA
        #[cfg(feature = "rsapss")]
        0x0016, // RSAPSS
        #[cfg(feature = "oaep")]
        0x0017, // OAEP
    ];
    for &scheme_alg in rsa_hash_schemes {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&scheme_alg.to_be_bytes());
        buf[2..4].copy_from_slice(&0x0010u16.to_be_bytes());
        let mut slice = &buf[..];
        assert_eq!(
            <Option<TpmtRsaScheme>>::unmarshal(&mut slice),
            Err(UnmarshalError::HASH),
            "TpmtRsaScheme 0x{:04X} with inner TPM_ALG_NULL must return HASH",
            scheme_alg
        );
    }

    // 6b. TpmtRsaDecrypt rejects signature schemes (RSASSA 0x0014, RSAPSS 0x0016) with VALUE,
    // and OAEP (0x0017) with inner 0x0010 returns HASH
    for sig_alg in [0x0014u16, 0x0016] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&sig_alg.to_be_bytes());
        buf[2..4].copy_from_slice(&0x000Bu16.to_be_bytes());
        let mut slice = &buf[..];
        assert_eq!(
            <Option<TpmtRsaDecrypt>>::unmarshal(&mut slice),
            Err(UnmarshalError::VALUE),
            "Option<TpmtRsaDecrypt> must reject signature scheme 0x{:04X} with VALUE",
            sig_alg
        );
        let mut slice = &buf[..];
        assert_eq!(
            TpmtRsaDecrypt::unmarshal(&mut slice),
            Err(UnmarshalError::VALUE),
            "TpmtRsaDecrypt must reject signature scheme 0x{:04X} with VALUE",
            sig_alg
        );
    }
    #[cfg(feature = "oaep")]
    {
        let oaep_null_hash = [0x00, 0x17, 0x00, 0x10];
        let mut slice = &oaep_null_hash[..];
        assert_eq!(
            <Option<TpmtRsaDecrypt>>::unmarshal(&mut slice),
            Err(UnmarshalError::HASH)
        );
        let mut slice = &oaep_null_hash[..];
        assert_eq!(
            TpmtRsaDecrypt::unmarshal(&mut slice),
            Err(UnmarshalError::HASH)
        );
    }

    // 7. TpmtEccScheme non-null variants with inner 0x0010 -> HASH
    let ecc_hash_schemes: &[u16] = &[
        #[cfg(feature = "ecdsa")]
        0x0018u16, // ECDSA
        #[cfg(feature = "sm2")]
        0x001B, // SM2
        #[cfg(feature = "ecschnorr")]
        0x001C, // ECSCHNORR
        #[cfg(feature = "ecdh")]
        0x0019, // ECDH
        #[cfg(feature = "ecmqv")]
        0x001D, // ECMQV
    ];
    for &scheme_alg in ecc_hash_schemes {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&scheme_alg.to_be_bytes());
        buf[2..4].copy_from_slice(&0x0010u16.to_be_bytes());
        let mut slice = &buf[..];
        assert_eq!(
            <Option<TpmtEccScheme>>::unmarshal(&mut slice),
            Err(UnmarshalError::HASH),
            "TpmtEccScheme 0x{:04X} with inner TPM_ALG_NULL must return HASH",
            scheme_alg
        );
    }
    // ECDAA (0x001A) with inner 0x0010 -> HASH
    #[cfg(feature = "ecdaa")]
    {
        let mut slice = &[0x00, 0x1A, 0x00, 0x10, 0x00, 0x00][..];
        assert_eq!(
            <Option<TpmtEccScheme>>::unmarshal(&mut slice),
            Err(UnmarshalError::HASH)
        );
    }

    // 8. TpmtKdfScheme non-null variants with inner 0x0010 -> HASH
    for kdf_alg in [
        0x0007u16, // MGF1
        0x001F,    // HKDF
        0x0020,    // KDF1_SP800_56A
        0x0021,    // KDF2
        0x0022,    // KDF1_SP800_108
    ] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&kdf_alg.to_be_bytes());
        buf[2..4].copy_from_slice(&0x0010u16.to_be_bytes());
        let mut slice = &buf[..];
        assert_eq!(
            <Option<TpmtKdfScheme>>::unmarshal(&mut slice),
            Err(UnmarshalError::HASH),
            "TpmtKdfScheme 0x{:04X} with inner TPM_ALG_NULL must return HASH",
            kdf_alg
        );
    }
}

#[test]
fn test_tpmt_signature_unmarshal_rejects_null_and_option_handles_attestation() {
    use tpm2::commands::responses::{
        Certify, CertifyCreation, GetCommandAuditDigest, GetSessionAuditDigest, GetTime, NVCertify,
        Quote,
    };
    use tpm2::{Marshal, Tpm2b, Tpm2bAttest, TpmsAttest, TpmtSignature};

    // 1. TpmtSignature::unmarshal MUST reject TPM_ALG_NULL (0x0010) with SCHEME
    let null_bytes = [0x00, 0x10];
    let mut slice = &null_bytes[..];
    assert_eq!(
        TpmtSignature::unmarshal(&mut slice),
        Err(UnmarshalError::SCHEME)
    );

    // 2. Option<TpmtSignature>::unmarshal MUST accept TPM_ALG_NULL as Ok(None)
    let mut slice = &null_bytes[..];
    assert_eq!(<Option<TpmtSignature>>::unmarshal(&mut slice), Ok(None));
    assert!(slice.is_empty());

    // Marshal None -> [0x00, 0x10]
    let none_sig: Option<TpmtSignature> = None;
    let mut buf = [0u8; <Option<TpmtSignature>>::MAX_SIZE];
    let len = none_sig.marshal(&mut buf);
    assert_eq!(&buf[..len], &[0x00, 0x10]);

    // 3. VerifySignature::unmarshal with TPM_ALG_NULL signature -> SCHEME at parameter 2
    let verify_null_bytes = [
        0x00, 0x04, 0x01, 0x02, 0x03, 0x04, // digest (TPM2B_DIGEST size 4)
        0x00, 0x10, // signature = TPM_ALG_NULL
    ];
    let mut slice = &verify_null_bytes[..];
    assert_eq!(
        VerifySignature::unmarshal(&mut slice),
        Err(UnmarshalError::SCHEME.in_parameter(2))
    );

    // 4. PolicySigned::unmarshal with TPM_ALG_NULL auth -> SCHEME at parameter 5
    let policy_signed_null_bytes = [
        0x00, 0x00, // nonce_tpm (size 0)
        0x00, 0x00, // cp_hash_a (size 0)
        0x00, 0x00, // policy_ref (size 0)
        0x00, 0x00, 0x00, 0x00, // expiration (0)
        0x00, 0x10, // auth = TPM_ALG_NULL
    ];
    let mut slice = &policy_signed_null_bytes[..];
    assert_eq!(
        PolicySigned::unmarshal(&mut slice),
        Err(UnmarshalError::SCHEME.in_parameter(5))
    );

    // 5. All 7 attestation response structures unmarshal TPM_ALG_NULL signature as None
    let default_attest = Tpm2b(TpmsAttest::default());
    let mut attest_buf = [0u8; Tpm2bAttest::MAX_SIZE];
    let attest_len = default_attest.marshal(&mut attest_buf);
    let mut attest_rsp_buf = [0u8; Tpm2bAttest::MAX_SIZE + 2];
    attest_rsp_buf[..attest_len].copy_from_slice(&attest_buf[..attest_len]);
    attest_rsp_buf[attest_len..attest_len + 2].copy_from_slice(&[0x00, 0x10]); // signature = TPM_ALG_NULL
    let attest_rsp_bytes = &attest_rsp_buf[..attest_len + 2];

    let mut s = attest_rsp_bytes;
    let certify_rsp = Certify::unmarshal(&mut s).expect("CertifyRsp with null signature");
    assert_eq!(certify_rsp.signature, None);
    assert_eq!(certify_rsp.certify_info, default_attest);

    let mut s = &attest_rsp_bytes[..];
    assert_eq!(
        CertifyCreation::unmarshal(&mut s)
            .expect("CertifyCreationRsp")
            .signature,
        None
    );

    let mut s = &attest_rsp_bytes[..];
    assert_eq!(Quote::unmarshal(&mut s).expect("QuoteRsp").signature, None);

    let mut s = &attest_rsp_bytes[..];
    assert_eq!(
        GetSessionAuditDigest::unmarshal(&mut s)
            .expect("GetSessionAuditDigestRsp")
            .signature,
        None
    );

    let mut s = &attest_rsp_bytes[..];
    assert_eq!(
        GetCommandAuditDigest::unmarshal(&mut s)
            .expect("GetCommandAuditDigestRsp")
            .signature,
        None
    );

    let mut s = &attest_rsp_bytes[..];
    assert_eq!(
        GetTime::unmarshal(&mut s).expect("GetTimeRsp").signature,
        None
    );

    let mut s = &attest_rsp_bytes[..];
    assert_eq!(
        NVCertify::unmarshal(&mut s)
            .expect("NVCertifyRsp")
            .signature,
        None
    );
}

#[test]
fn test_finding_1_and_2_ground_truth_constants_and_slice_advancement() {
    use tpm2::{TpmtKdfScheme, TpmtSignature, TpmtSymDef, TpmtSymDefObject};

    // Finding 1 ground truth:
    // - TPM_RC_MODE is 0x089 (RC_FMT1 + 0x009)
    // - TPM_RC_TYPE is 0x08A (RC_FMT1 + 0x00A)
    // - TPM_RC_KDF is 0x08C (RC_FMT1 + 0x00C), and TPMT_KDF_SCHEME_Unmarshal returns TPM_RC_KDF
    assert_eq!(TpmRc::MODE.to_rc().get(), 0x089);
    assert_eq!(UnmarshalError::MODE.to_rc().get(), 0x089);
    assert_eq!(TpmRc::TYPE.to_rc().get(), 0x08A);
    assert_eq!(UnmarshalError::TYPE.to_rc().get(), 0x08A);
    assert_eq!(TpmRc::KDF.to_rc().get(), 0x08C);
    assert_eq!(UnmarshalError::KDF.to_rc().get(), 0x08C);

    let invalid_kdf_buf = [0x00, 0x0B, 0x00, 0x0B]; // 0x000B (SHA256) is not a valid KDF algorithm
    let mut slice_kdf = &invalid_kdf_buf[..];
    let err_kdf = <Option<TpmtKdfScheme>>::unmarshal(&mut slice_kdf).unwrap_err();
    assert_eq!(err_kdf, UnmarshalError::KDF);
    assert_eq!(err_kdf.to_rc().get(), 0x08C);

    // Finding 2 ground truth:
    // Unmarshaling advances *src sequentially before checking constraints and leaves *src advanced on error.
    let invalid_alg_buf = [0x00, 0x00, 0xAA, 0xBB]; // 0x0000 = TPM_ALG_ERROR

    let mut slice_sym_obj = &invalid_alg_buf[..];
    assert_eq!(
        <Option<TpmtSymDefObject>>::unmarshal(&mut slice_sym_obj),
        Err(UnmarshalError::SYMMETRIC)
    );
    assert_eq!(slice_sym_obj, &[0xAA, 0xBB]);

    let mut slice_sym_def = &invalid_alg_buf[..];
    assert_eq!(
        <Option<TpmtSymDef>>::unmarshal(&mut slice_sym_def),
        Err(UnmarshalError::SYMMETRIC)
    );
    assert_eq!(slice_sym_def, &[0xAA, 0xBB]);

    let mut slice_sig = &invalid_alg_buf[..];
    assert_eq!(
        <Option<TpmtSignature>>::unmarshal(&mut slice_sig),
        Err(UnmarshalError::SCHEME)
    );
    assert_eq!(slice_sig, &[0xAA, 0xBB]);
}

#[test]
fn test_tpmt_public_and_tpm2b_public_null_name_alg_validation() {
    use tpm2::commands::responses::ReadPublic as ReadPublicRsp;
    use tpm2::commands::{Create, CreatePrimary, Import, Load, LoadExternal};
    use tpm2::{
        Marshal, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bPrivate,
        Tpm2bPublic, Tpm2bSensitiveCreate, TpmaObject, TpmlPcrSelection, Unmarshal,
    };

    // Construct a TPMT_PUBLIC with name_alg == None (TPM_ALG_NULL = 0x0010)
    let pub_null_alg = TpmtPublic {
        name_alg: None,
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    };

    let mut raw_pub_buf = [0u8; TpmtPublic::MAX_SIZE];
    let pub_len = pub_null_alg.marshal(&mut raw_pub_buf);
    let raw_pub_slice = &raw_pub_buf[..pub_len];

    // 1. Standard TpmtPublic::unmarshal must reject TPM_ALG_NULL with UnmarshalError::HASH (0x083)
    let mut s = raw_pub_slice;
    assert_eq!(TpmtPublic::unmarshal(&mut s), Err(UnmarshalError::HASH));

    // 2. Nullable TpmtPublic::unmarshal_nullable must accept TPM_ALG_NULL as None
    let mut s = raw_pub_slice;
    let unmarshaled_pub = TpmtPublic::unmarshal_nullable(&mut s).expect("nullable TPMT_PUBLIC");
    assert_eq!(unmarshaled_pub.name_alg, None);

    // Construct wire bytes for TPM2B_PUBLIC wrapping the null-nameAlg TPMT_PUBLIC
    let pub_2b = Tpm2bPublic::from_struct(&pub_null_alg).unwrap();
    let mut raw_2b_buf = [0u8; Tpm2bPublic::MAX_SIZE];
    let len_2b = pub_2b.marshal(&mut raw_2b_buf);
    let raw_2b_slice = &raw_2b_buf[..len_2b];

    // 3. Standard Tpm2bPublic::unmarshal must reject TPM_ALG_NULL with UnmarshalError::HASH
    let mut s = raw_2b_slice;
    assert_eq!(Tpm2bPublic::unmarshal(&mut s), Err(UnmarshalError::HASH));

    // 4. Tpm2bPublic::unmarshal_nullable must accept TPM_ALG_NULL, and reject size == 0 with SIZE
    let mut s = raw_2b_slice;
    let unmarshaled_2b = Tpm2bPublic::unmarshal_nullable(&mut s).expect("nullable TPM2B_PUBLIC+");
    assert_eq!(unmarshaled_2b.to_struct_nullable().unwrap().name_alg, None);
    let mut empty_2b = &[0x00u8, 0x00][..];
    assert_eq!(
        Tpm2bPublic::unmarshal_nullable(&mut empty_2b),
        Err(UnmarshalError::SIZE)
    );

    // 5. Create::unmarshal with null name_alg in in_public (param 2) -> TPM_RC_HASH + P2 (0x2C3)
    let mut create_buf = [0u8; Create::MAX_SIZE];
    let sens_create =
        Tpm2bSensitiveCreate::from_struct(&tpm2::TpmsSensitiveCreate::default()).unwrap();
    let mut tmp = [0u8; Tpm2bSensitiveCreate::MAX_SIZE];
    let mut offset = sens_create.marshal(&mut tmp);
    create_buf[..offset].copy_from_slice(&tmp[..offset]);
    create_buf[offset..offset + len_2b].copy_from_slice(raw_2b_slice);
    offset += len_2b;
    let mut tmp_data = [0u8; Tpm2bData::MAX_SIZE];
    let data_len = Tpm2bData::default().marshal(&mut tmp_data);
    create_buf[offset..offset + data_len].copy_from_slice(&tmp_data[..data_len]);
    offset += data_len;
    let mut tmp_pcr = [0u8; TpmlPcrSelection::MAX_SIZE];
    let pcr_len = TpmlPcrSelection::default().marshal(&mut tmp_pcr);
    create_buf[offset..offset + pcr_len].copy_from_slice(&tmp_pcr[..pcr_len]);
    offset += pcr_len;

    let mut s = &create_buf[..offset];
    let err = Create::unmarshal(&mut s).unwrap_err();
    assert_eq!(err, UnmarshalError::HASH.in_parameter(2));
    assert_eq!(err.to_rc().get(), 0x2C3);

    // 6. CreatePrimary::unmarshal with null name_alg in in_public (param 2) -> TPM_RC_HASH + P2 (0x2C3)
    let mut s = &create_buf[..offset];
    let err = CreatePrimary::unmarshal(&mut s).unwrap_err();
    assert_eq!(err, UnmarshalError::HASH.in_parameter(2));
    assert_eq!(err.to_rc().get(), 0x2C3);

    // 7. Load::unmarshal with null name_alg in in_public (param 2) -> TPM_RC_HASH + P2 (0x2C3)
    let mut load_buf = [0u8; Load::MAX_SIZE];
    let mut tmp_priv = [0u8; Tpm2bPrivate::MAX_SIZE];
    let priv_len = Tpm2bPrivate::default().marshal(&mut tmp_priv);
    load_buf[..priv_len].copy_from_slice(&tmp_priv[..priv_len]);
    load_buf[priv_len..priv_len + len_2b].copy_from_slice(raw_2b_slice);
    let mut s = &load_buf[..priv_len + len_2b];
    let err = Load::unmarshal(&mut s).unwrap_err();
    assert_eq!(err, UnmarshalError::HASH.in_parameter(2));
    assert_eq!(err.to_rc().get(), 0x2C3);

    // 8. Import::unmarshal with null name_alg in object_public (param 2) -> TPM_RC_HASH + P2 (0x2C3)
    let mut import_buf = [0u8; Import::MAX_SIZE];
    let mut off = 0;
    import_buf[off..off + data_len].copy_from_slice(&tmp_data[..data_len]);
    off += data_len;
    import_buf[off..off + len_2b].copy_from_slice(raw_2b_slice);
    off += len_2b;
    import_buf[off..off + priv_len].copy_from_slice(&tmp_priv[..priv_len]);
    off += priv_len;
    let mut tmp_seed = [0u8; Tpm2bEncryptedSecret::MAX_SIZE];
    let seed_len = Tpm2bEncryptedSecret::default().marshal(&mut tmp_seed);
    import_buf[off..off + seed_len].copy_from_slice(&tmp_seed[..seed_len]);
    off += seed_len;
    // symmetric_alg = Alg::NULL (0x0010)
    import_buf[off..off + 2].copy_from_slice(&0x0010u16.to_be_bytes());
    off += 2;
    let mut s = &import_buf[..off];
    let err = Import::unmarshal(&mut s).unwrap_err();
    assert_eq!(err, UnmarshalError::HASH.in_parameter(2));
    assert_eq!(err.to_rc().get(), 0x2C3);

    // 9. LoadExternal::unmarshal with null name_alg in in_public (param 2) -> SUCCEEDS (TPM2B_PUBLIC+)
    let cmd_le = LoadExternal {
        in_private: None,
        in_public: pub_2b,
        hierarchy: Handle::RH_NULL,
    };
    let mut le_buf = [0u8; LoadExternal::MAX_SIZE];
    let le_len = cmd_le.marshal(&mut le_buf);
    let mut s = &le_buf[..le_len];
    let unmarshaled_le = LoadExternal::unmarshal(&mut s).expect("LoadExternal allows null nameAlg");
    assert_eq!(
        unmarshaled_le
            .in_public
            .to_struct_nullable()
            .unwrap()
            .name_alg,
        None
    );

    // 10. ReadPublicRsp::unmarshal with null name_alg in out_public -> SUCCEEDS
    let rsp_rp = ReadPublicRsp {
        out_public: pub_2b,
        name: Tpm2bName::default(),
        qualified_name: Tpm2bName::default(),
    };
    let mut rp_buf = [0u8; ReadPublicRsp::MAX_SIZE];
    let rp_len = rsp_rp.marshal(&mut rp_buf);
    let mut s = &rp_buf[..rp_len];
    let unmarshaled_rp =
        ReadPublicRsp::unmarshal(&mut s).expect("ReadPublicRsp allows null nameAlg");
    assert_eq!(
        unmarshaled_rp
            .out_public
            .to_struct_nullable()
            .unwrap()
            .name_alg,
        None
    );

    // 11. Mismatched or oversized TPM2B size prefix with inner name_alg == TPM_ALG_NULL
    // must return UnmarshalError::HASH (not SIZE), matching C TPM TPM2B_PUBLIC_Unmarshal.
    let mut oversized_2b = [0u8; 20];
    oversized_2b[0..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    oversized_2b[2..2 + pub_len].copy_from_slice(raw_pub_slice);
    let mut s = &oversized_2b[..2 + pub_len];
    assert_eq!(Tpm2bPublic::unmarshal(&mut s), Err(UnmarshalError::HASH));

    let mut undersized_2b = [0u8; 20];
    undersized_2b[0..2].copy_from_slice(&0x0002u16.to_be_bytes());
    undersized_2b[2..2 + pub_len].copy_from_slice(raw_pub_slice);
    let mut s = &undersized_2b[..2 + pub_len];
    assert_eq!(Tpm2bPublic::unmarshal(&mut s), Err(UnmarshalError::HASH));

    // 12. Tpm2bPublic::to_struct rejects null name_alg with HASH, whereas to_struct_nullable accepts it
    let pub_2b = Tpm2bPublic::from_struct(&pub_null_alg).unwrap();
    assert_eq!(pub_2b.to_struct(), Err(UnmarshalError::HASH));
    assert_eq!(pub_2b.to_struct_nullable().unwrap().name_alg, None);

    // 13. Tpm2bTemplate::to_struct and unmarshal_to_public reject null name_alg with HASH
    let mut tmpl_buf = [0u8; TpmtPublic::MAX_SIZE];
    let tmpl = tpm2::Tpm2bTemplate::from_struct_in(&pub_null_alg, &mut tmpl_buf).unwrap();
    assert_eq!(tmpl.to_struct(), Err(UnmarshalError::HASH));
    assert_eq!(tmpl.unmarshal_to_public(false), Err(UnmarshalError::HASH));
}

#[test]
fn test_command_handle_and_parameter_tpmi_unmarshalling() {
    use tpm2::{
        TpmiRhAc, TpmiRhAct, TpmsNvPublic,
        commands::{
            ClearHandles, ContextSaveHandles, CreateHandles, CreatePrimaryHandles,
            DictionaryAttackLockResetHandles, EvictControl, EvictControlHandles, FlushContext,
            Hash, HierarchyChangeAuthHandles, HierarchyControlHandles, LoadExternal,
            NVDefineSpaceHandles, NVReadHandles, NVUndefineSpaceHandles,
            NVUndefineSpaceSpecialHandles, PCRResetHandles, PCRSetAuthPolicy, PolicyRestartHandles,
            SequenceComplete, SetPrimaryPolicyHandles, StartAuthSessionHandles,
        },
    };

    // --- 1. Command *Handles unmarshalling ---

    // CreatePrimaryHandles: auth_handle is TpmiRhHierarchy
    let mut s = &0x8000_0001u32.to_be_bytes()[..];
    assert_eq!(
        CreatePrimaryHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &Handle::RH_OWNER.0.to_be_bytes()[..];
    assert!(CreatePrimaryHandles::unmarshal(&mut s).is_ok());

    // CreateHandles: parent_handle is TpmiDhObject::<false> (rejects RH_NULL and hierarchies)
    let mut s = &Handle::RH_NULL.0.to_be_bytes()[..];
    assert_eq!(
        CreateHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &Handle::RH_OWNER.0.to_be_bytes()[..];
    assert_eq!(
        CreateHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &0x8000_0001u32.to_be_bytes()[..];
    assert!(CreateHandles::unmarshal(&mut s).is_ok());

    // StartAuthSessionHandles: tpm_key (TpmiDhObject::<true>), bind (TpmiDhEntity::<true>)
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&0x0100_0001u32.to_be_bytes()); // NV index invalid for tpm_key
    buf[4..8].copy_from_slice(&Handle::RH_NULL.0.to_be_bytes());
    let mut s = &buf[..];
    assert_eq!(
        StartAuthSessionHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    buf[0..4].copy_from_slice(&Handle::RH_NULL.0.to_be_bytes());
    buf[4..8].copy_from_slice(&0x0200_0001u32.to_be_bytes()); // session invalid for bind
    let mut s = &buf[..];
    assert_eq!(
        StartAuthSessionHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(2))
    );

    // PolicyRestartHandles: session_handle is TpmiShPolicy (rejects HMAC session)
    let mut s = &0x0200_0001u32.to_be_bytes()[..];
    assert_eq!(
        PolicyRestartHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &0x0300_0001u32.to_be_bytes()[..];
    assert!(PolicyRestartHandles::unmarshal(&mut s).is_ok());

    // ContextSaveHandles: TpmiDhContext (rejects persistent 0x81000000)
    let mut s = &0x8100_0001u32.to_be_bytes()[..];
    assert_eq!(
        ContextSaveHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &0x8000_0001u32.to_be_bytes()[..];
    assert!(ContextSaveHandles::unmarshal(&mut s).is_ok());

    // EvictControlHandles: auth (TpmiRhProvision), object_handle (TpmiDhObject::<false>)
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&Handle::RH_ENDORSEMENT.0.to_be_bytes()); // not owner/platform
    buf[4..8].copy_from_slice(&0x8000_0001u32.to_be_bytes());
    let mut s = &buf[..];
    assert_eq!(
        EvictControlHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    buf[0..4].copy_from_slice(&Handle::RH_OWNER.0.to_be_bytes());
    buf[4..8].copy_from_slice(&Handle::RH_NULL.0.to_be_bytes()); // null object invalid
    let mut s = &buf[..];
    assert_eq!(
        EvictControlHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(2))
    );

    // ClearHandles: TpmiRhClear (only LOCKOUT or PLATFORM)
    let mut s = &Handle::RH_OWNER.0.to_be_bytes()[..];
    assert_eq!(
        ClearHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &Handle::RH_LOCKOUT.0.to_be_bytes()[..];
    assert!(ClearHandles::unmarshal(&mut s).is_ok());

    // HierarchyChangeAuthHandles: TpmiRhHierarchyAuth::<false> (rejects RH_NULL)
    let mut s = &Handle::RH_NULL.0.to_be_bytes()[..];
    assert_eq!(
        HierarchyChangeAuthHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );

    // HierarchyControlHandles: TpmiRhBaseHierarchy (accepts OWNER, PLATFORM, ENDORSEMENT; rejects NULL and LOCKOUT)
    let mut s = &Handle::RH_NULL.0.to_be_bytes()[..];
    assert_eq!(
        HierarchyControlHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &Handle::RH_LOCKOUT.0.to_be_bytes()[..];
    assert_eq!(
        HierarchyControlHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &Handle::RH_OWNER.0.to_be_bytes()[..];
    assert!(HierarchyControlHandles::unmarshal(&mut s).is_ok());

    // PCRResetHandles: TpmiDhPcr::<false> (rejects non-PCR handles including RH_NULL and PCR >= 24; accepts valid PCRs)
    let mut s = &Handle::RH_NULL.0.to_be_bytes()[..];
    assert_eq!(
        PCRResetHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &Handle::RH_OWNER.0.to_be_bytes()[..];
    assert_eq!(
        PCRResetHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &24u32.to_be_bytes()[..];
    assert_eq!(
        PCRResetHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    let mut s = &16u32.to_be_bytes()[..];
    assert!(PCRResetHandles::unmarshal(&mut s).is_ok());

    // SetPrimaryPolicyHandles: TpmiRhHierarchyPolicy (accepts ACT handles, rejects RH_NULL)
    let mut s = &0x4000_0110u32.to_be_bytes()[..];
    assert!(SetPrimaryPolicyHandles::unmarshal(&mut s).is_ok());
    let mut s = &Handle::RH_NULL.0.to_be_bytes()[..];
    assert_eq!(
        SetPrimaryPolicyHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );

    // DictionaryAttackLockResetHandles: TpmiRhLockout
    let mut s = &Handle::RH_OWNER.0.to_be_bytes()[..];
    assert_eq!(
        DictionaryAttackLockResetHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );

    // NVDefineSpaceHandles: TpmiRhProvision
    let mut s = &Handle::RH_ENDORSEMENT.0.to_be_bytes()[..];
    assert_eq!(
        NVDefineSpaceHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );

    // NVUndefineSpaceHandles: auth_handle (TpmiRhProvision), nv_index (TpmiRhNvDefinedIndex)
    // Rejects permanent NV index (0x12000001) at handle 2
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&Handle::RH_OWNER.0.to_be_bytes());
    buf[4..8].copy_from_slice(&0x1200_0001u32.to_be_bytes());
    let mut s = &buf[..];
    assert_eq!(
        NVUndefineSpaceHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(2))
    );

    // NVUndefineSpaceSpecialHandles: nv_index (TpmiRhNvDefinedIndex), platform (TpmiRhPlatform)
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&0x1200_0001u32.to_be_bytes()); // permanent NV rejected
    buf[4..8].copy_from_slice(&Handle::RH_PLATFORM.0.to_be_bytes());
    let mut s = &buf[..];
    assert_eq!(
        NVUndefineSpaceSpecialHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );
    buf[0..4].copy_from_slice(&0x0100_0001u32.to_be_bytes());
    buf[4..8].copy_from_slice(&Handle::RH_OWNER.0.to_be_bytes()); // owner rejected (platform required)
    let mut s = &buf[..];
    assert_eq!(
        NVUndefineSpaceSpecialHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(2))
    );

    // NVReadHandles: auth_handle (TpmiRhNvAuth), nv_index (TpmiRhNvIndex)
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&Handle::RH_ENDORSEMENT.0.to_be_bytes()); // not owner/platform/nv
    buf[4..8].copy_from_slice(&0x0100_0001u32.to_be_bytes());
    let mut s = &buf[..];
    assert_eq!(
        NVReadHandles::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_handle(1))
    );

    // TpmiRhAct and TpmiRhAc unmarshalling
    let mut s = &0x4000_0120u32.to_be_bytes()[..];
    assert_eq!(TpmiRhAct::unmarshal(&mut s), Err(UnmarshalError::VALUE));
    let mut s = &0x4000_0110u32.to_be_bytes()[..];
    assert!(TpmiRhAct::unmarshal(&mut s).is_ok());

    let mut s = &0x9001_0000u32.to_be_bytes()[..];
    assert_eq!(TpmiRhAc::unmarshal(&mut s), Err(UnmarshalError::VALUE));
    let mut s = &0x9000_0001u32.to_be_bytes()[..];
    assert!(TpmiRhAc::unmarshal(&mut s).is_ok());

    // --- 2. Command handle-typed parameters unmarshalling ---

    // Hash: param 1 = data (Tpm2bMaxBuffer), param 2 = hash_alg (TpmiAlgHash), param 3 = hierarchy (TpmiRhHierarchy)
    let mut hash_buf = [0u8; 8];
    hash_buf[0..2].copy_from_slice(&0u16.to_be_bytes()); // empty data
    hash_buf[2..4].copy_from_slice(&0x000Bu16.to_be_bytes()); // SHA256
    hash_buf[4..8].copy_from_slice(&0x8000_0001u32.to_be_bytes()); // invalid hierarchy
    let mut s = &hash_buf[..];
    assert_eq!(
        Hash::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_parameter(3))
    );

    // SequenceComplete: param 1 = buffer (Tpm2bMaxBuffer), param 2 = hierarchy (TpmiRhHierarchy)
    let mut seq_buf = [0u8; 6];
    seq_buf[0..2].copy_from_slice(&0u16.to_be_bytes()); // empty buffer
    seq_buf[2..6].copy_from_slice(&0x0100_0001u32.to_be_bytes()); // invalid hierarchy
    let mut s = &seq_buf[..];
    assert_eq!(
        SequenceComplete::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_parameter(2))
    );

    // LoadExternal: param 1 = in_private, param 2 = in_public, param 3 = hierarchy (TpmiRhHierarchy)
    // When in_public size = 0, unmarshalling must fail at parameter 2 with TPM_RC_SIZE + P2
    // (both when hierarchy is invalid and when hierarchy is truncated/missing)
    let mut le_zero_pub = [0u8; 8];
    le_zero_pub[0..2].copy_from_slice(&0u16.to_be_bytes()); // in_private size = 0
    le_zero_pub[2..4].copy_from_slice(&0u16.to_be_bytes()); // in_public size = 0 (invalid)
    le_zero_pub[4..8].copy_from_slice(&0x8000_0001u32.to_be_bytes()); // invalid hierarchy
    let mut s = &le_zero_pub[..];
    assert_eq!(
        LoadExternal::unmarshal(&mut s),
        Err(UnmarshalError::SIZE.in_parameter(2))
    );
    let mut s_truncated = &le_zero_pub[..4]; // hierarchy missing completely
    assert_eq!(
        LoadExternal::unmarshal(&mut s_truncated),
        Err(UnmarshalError::SIZE.in_parameter(2))
    );

    // When in_public is valid and hierarchy is invalid, unmarshalling fails at parameter 3 with TPM_RC_VALUE + P3
    let valid_pub_2b = tpm2::Tpm2bPublic::from_struct(&TpmtPublic {
        name_alg: None,
        object_attributes: tpm2::TpmaObject::default(),
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    })
    .unwrap();
    let mut le_bad = [0u8; LoadExternal::MAX_SIZE];
    le_bad[0..2].copy_from_slice(&0u16.to_be_bytes()); // in_private size = 0
    let mut pub_tmp = [0u8; tpm2::Tpm2bPublic::MAX_SIZE];
    let pub_tmp_len = valid_pub_2b.marshal(&mut pub_tmp);
    le_bad[2..2 + pub_tmp_len].copy_from_slice(&pub_tmp[..pub_tmp_len]);
    le_bad[2 + pub_tmp_len..6 + pub_tmp_len].copy_from_slice(&0x8000_0001u32.to_be_bytes()); // invalid hierarchy
    let mut s = &le_bad[..6 + pub_tmp_len];
    assert_eq!(
        LoadExternal::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_parameter(3))
    );

    // PCRSetAuthPolicy: param 1 = auth_policy, param 2 = hash_alg, param 3 = pcr_num (TpmiDhPcr::<false>)
    let mut pcr_pol_buf = [0u8; 8];
    pcr_pol_buf[0..2].copy_from_slice(&0u16.to_be_bytes()); // empty digest
    pcr_pol_buf[2..4].copy_from_slice(&0x0010u16.to_be_bytes()); // Alg::NULL
    pcr_pol_buf[4..8].copy_from_slice(&Handle::RH_NULL.0.to_be_bytes()); // RH_NULL not allowed for pcr_num
    let mut s = &pcr_pol_buf[..];
    assert_eq!(
        PCRSetAuthPolicy::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_parameter(3))
    );
    pcr_pol_buf[4..8].copy_from_slice(&24u32.to_be_bytes()); // PCR 24 out of range
    let mut s = &pcr_pol_buf[..];
    assert_eq!(
        PCRSetAuthPolicy::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_parameter(3))
    );

    // EvictControl: param 1 = persistent_handle (TpmiDhPersistent)
    let mut s = &0x8000_0001u32.to_be_bytes()[..]; // transient handle rejected
    assert_eq!(
        EvictControl::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_parameter(1))
    );
    let mut s = &0x8100_0001u32.to_be_bytes()[..];
    assert!(EvictControl::unmarshal(&mut s).is_ok());

    // FlushContext: cHandles = 0 (type Handles = ()), param 1 = flush_handle (TpmiDhContext)
    assert_eq!(
        <<FlushContext as tpm2::commands::Command>::Handles as Marshal>::MAX_SIZE,
        0
    );
    let mut short_buf = &[0x80u8, 0x00][..];
    assert_eq!(
        FlushContext::unmarshal(&mut short_buf),
        Err(UnmarshalError::INSUFFICIENT.in_parameter(1))
    );
    for invalid_handle in [
        0x8100_0001u32,
        0x4000_0001,
        0x4000_0007,
        0x4000_0009,
        0x0100_0001,
    ] {
        let bytes = invalid_handle.to_be_bytes();
        let mut s = &bytes[..];
        assert_eq!(
            FlushContext::unmarshal(&mut s),
            Err(UnmarshalError::VALUE.in_parameter(1)),
            "FlushContext must reject invalid handle 0x{:08X} with parameter(1) modifier",
            invalid_handle
        );
    }
    for valid_handle in [0x8000_0001u32, 0x0200_0005, 0x0300_0006] {
        let cmd = FlushContext {
            flush_handle: Handle(valid_handle),
        };
        let mut buf = [0u8; FlushContext::MAX_SIZE];
        let written = cmd.marshal(&mut buf);
        assert_eq!(written, 4);
        let mut s = &buf[..];
        assert_eq!(FlushContext::unmarshal(&mut s), Ok(cmd));
        assert!(s.is_empty());
    }

    // HierarchyControl: param 1 = enable (TpmiRhEnables::<false>), param 2 = state (bool)
    let mut hc_buf = [0u8; 5];
    hc_buf[0..4].copy_from_slice(&Handle::RH_NULL.0.to_be_bytes()); // RH_NULL rejected for enable
    hc_buf[4] = 1;
    let mut s = &hc_buf[..];
    assert_eq!(
        HierarchyControl::unmarshal(&mut s),
        Err(UnmarshalError::VALUE.in_parameter(1))
    );
    hc_buf[0..4].copy_from_slice(&Handle::RH_PLATFORM_NV.0.to_be_bytes()); // RH_PLATFORM_NV accepted
    let mut s = &hc_buf[..];
    assert!(HierarchyControl::unmarshal(&mut s).is_ok());

    // --- 3. TpmsNvPublic::nv_index (TpmiRhNvLegacyIndex) ---
    let mut nv_pub_buf = [0u8; 14];
    // nv_index = 0x11000001 (extended NV index - rejected by TpmiRhNvLegacyIndex)
    nv_pub_buf[0..4].copy_from_slice(&0x1100_0001u32.to_be_bytes());
    nv_pub_buf[4..6].copy_from_slice(&0x000Bu16.to_be_bytes()); // SHA256
    nv_pub_buf[6..10].copy_from_slice(&0u32.to_be_bytes()); // attributes
    nv_pub_buf[10..12].copy_from_slice(&0u16.to_be_bytes()); // auth_policy len
    nv_pub_buf[12..14].copy_from_slice(&0u16.to_be_bytes()); // data_size
    let mut s = &nv_pub_buf[..];
    assert_eq!(TpmsNvPublic::unmarshal(&mut s), Err(UnmarshalError::VALUE));
}

#[test]
fn test_tpmt_ha_unmarshal_rejects_null_and_option_tpmt_ha_handles_tagged_policy() {
    use tpm2::commands::GetCapabilityRsp;
    use tpm2::{TpmlTaggedPolicy, TpmsCapabilityData, TpmsTaggedPolicy, TpmtHa};

    // 1. TpmtHa::unmarshal MUST reject TPM_ALG_NULL (0x0010) with HASH error
    let null_bytes = [0x00, 0x10];
    let mut slice = &null_bytes[..];
    assert_eq!(TpmtHa::unmarshal(&mut slice), Err(UnmarshalError::HASH));

    // 2. Option<TpmtHa>::unmarshal MUST accept TPM_ALG_NULL as Ok(None)
    let mut slice = &null_bytes[..];
    assert_eq!(<Option<TpmtHa>>::unmarshal(&mut slice), Ok(None));
    assert!(slice.is_empty());

    // 3. Option<TpmtHa>::marshal with None MUST emit exactly 2 bytes [0x00, 0x10]
    let none_ha: Option<TpmtHa> = None;
    let mut buf = [0u8; <Option<TpmtHa>>::MAX_SIZE];
    let len = none_ha.marshal(&mut buf);
    assert_eq!(len, 2);
    assert_eq!(&buf[..len], &[0x00, 0x10]);

    // 4. Option<TpmtHa>::unmarshal with valid SHA256 digest
    let dummy_digest = [0xabu8; 32];
    let mut valid_bytes = [0u8; 34];
    valid_bytes[0..2].copy_from_slice(&0x000Bu16.to_be_bytes()); // TPM_ALG_SHA256
    valid_bytes[2..34].copy_from_slice(&dummy_digest);
    let mut slice = &valid_bytes[..];
    let parsed_opt = <Option<TpmtHa>>::unmarshal(&mut slice).expect("valid SHA256 TpmtHa");
    assert_eq!(parsed_opt, Some(TpmtHa::Sha256(&dummy_digest)));
    assert!(slice.is_empty());

    // 5. Option<TpmtHa>::marshal with Some(ha) emits 34 bytes and matches valid_bytes
    let mut some_buf = [0u8; <Option<TpmtHa>>::MAX_SIZE];
    let some_len = parsed_opt.marshal(&mut some_buf);
    assert_eq!(some_len, 34);
    assert_eq!(&some_buf[..some_len], &valid_bytes[..]);

    // 6. Option<TpmtHa>::unmarshal with insufficient digest bytes returns INSUFFICIENT
    let truncated_bytes = [0x00, 0x0B, 0x01, 0x02, 0x03]; // SHA256 but only 3 bytes
    let mut slice = &truncated_bytes[..];
    assert_eq!(
        <Option<TpmtHa>>::unmarshal(&mut slice),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // 7. Option<TpmtHa>::unmarshal with invalid/unknown alg returns HASH
    let invalid_alg_bytes = [0x00, 0x01]; // TPM_ALG_RSA is not a hash
    let mut slice = &invalid_alg_bytes[..];
    assert_eq!(
        <Option<TpmtHa>>::unmarshal(&mut slice),
        Err(UnmarshalError::HASH)
    );

    // 8. TpmsTaggedPolicy with policy_hash: None marshals to 6 bytes (4 handle + 2 alg_null)
    let null_policy = TpmsTaggedPolicy {
        handle: Handle::RH_OWNER,
        policy_hash: None,
    };
    let mut tp_buf = [0u8; TpmsTaggedPolicy::MAX_SIZE];
    let tp_len = null_policy.marshal(&mut tp_buf);
    assert_eq!(tp_len, 6);
    let expected_tp_bytes = [0x40, 0x00, 0x00, 0x01, 0x00, 0x10];
    assert_eq!(&tp_buf[..tp_len], &expected_tp_bytes);

    // 9. TpmsTaggedPolicy unmarshals 6-byte null policy correctly
    let mut slice = &expected_tp_bytes[..];
    let parsed_tp = TpmsTaggedPolicy::unmarshal(&mut slice).expect("unmarshal null policy");
    assert_eq!(parsed_tp, null_policy);
    assert!(slice.is_empty());

    // 10. TpmsTaggedPolicy with Some(ha) roundtrip
    let some_policy = TpmsTaggedPolicy {
        handle: Handle::RH_ENDORSEMENT,
        policy_hash: Some(TpmtHa::Sha256(&dummy_digest)),
    };
    let mut tp_buf2 = [0u8; TpmsTaggedPolicy::MAX_SIZE];
    let tp_len2 = some_policy.marshal(&mut tp_buf2);
    assert_eq!(tp_len2, 38);
    let mut slice = &tp_buf2[..tp_len2];
    let parsed_tp2 = TpmsTaggedPolicy::unmarshal(&mut slice).expect("unmarshal some policy");
    assert_eq!(parsed_tp2, some_policy);

    // 11. TpmlTaggedPolicy containing both null and non-null policies
    let mut list = TpmlTaggedPolicy::default();
    list.add(&null_policy).unwrap();
    list.add(&some_policy).unwrap();
    let mut list_buf = [0u8; TpmlTaggedPolicy::MAX_SIZE];
    let list_len = list.marshal(&mut list_buf);
    assert_eq!(list_len, 4 + 6 + 38); // 4 count + 6 + 38 = 48
    let mut slice = &list_buf[..list_len];
    let parsed_list =
        TpmlTaggedPolicy::unmarshal(&mut slice).expect("unmarshal tagged policies list");
    assert_eq!(parsed_list.count(), 2);
    assert_eq!(parsed_list.as_slice()[0], null_policy);
    assert_eq!(parsed_list.as_slice()[1], some_policy);

    // 12. GetCapabilityRsp containing AuthPolicies with null policy hash roundtrips
    let cap_rsp = GetCapabilityRsp {
        more_data: false,
        capability_data: TpmsCapabilityData::AuthPolicies(list),
    };
    let mut rsp_buf = [0u8; GetCapabilityRsp::MAX_SIZE];
    let rsp_len = cap_rsp.marshal(&mut rsp_buf);
    let mut slice = &rsp_buf[..rsp_len];
    let parsed_rsp = GetCapabilityRsp::unmarshal(&mut slice).expect("unmarshal GetCapabilityRsp");
    assert_eq!(parsed_rsp, cap_rsp);
}

#[test]
fn test_attestation_command_handles_tpmi_validation() {
    use tpm2::commands::{
        GetCommandAuditDigestHandles, GetSessionAuditDigestHandles, GetTimeHandles,
    };

    // 1. GetSessionAuditDigestHandles:
    // Handle 1 (@privacyAdminHandle): TPMI_RH_ENDORSEMENT (non-nullable, only TPM_RH_ENDORSEMENT)
    // Handle 2 (@signHandle): TPMI_DH_OBJECT+ (transient, persistent, or TPM_RH_NULL)
    // Handle 3 (sessionHandle): TPMI_SH_HMAC (HMAC sessions 0x02000000..=0x02FFFFFF only)
    let valid_sad_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle::RH_NULL,
        session_handle: Handle(0x0200_0000),
    };
    let mut sad_buf = [0u8; GetSessionAuditDigestHandles::MAX_SIZE];
    let sad_len = valid_sad_handles.marshal(&mut sad_buf);
    let mut slice = &sad_buf[..sad_len];
    assert_eq!(
        GetSessionAuditDigestHandles::unmarshal(&mut slice),
        Ok(valid_sad_handles)
    );

    // Reject TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM in handle 1 with VALUE in handle 1
    for bad_privacy_handle in [Handle::RH_NULL, Handle::RH_OWNER, Handle::RH_PLATFORM] {
        let bad = GetSessionAuditDigestHandles {
            privacy_admin_handle: bad_privacy_handle,
            ..valid_sad_handles
        };
        let len = bad.marshal(&mut sad_buf);
        let mut s = &sad_buf[..len];
        assert_eq!(
            GetSessionAuditDigestHandles::unmarshal(&mut s),
            Err(UnmarshalError::VALUE.in_handle(1)),
            "GetSessionAuditDigestHandles should reject privacy_admin_handle {bad_privacy_handle:?}"
        );
    }

    // Reject Policy session (0x03000000), TPM_RS_PW (0x40000009), TPM_RH_NULL, and transient object in handle 3
    for bad_session_handle in [
        Handle(0x0300_0000),
        Handle(0x03FF_FFFF),
        Handle::RS_PW,
        Handle::RH_NULL,
        Handle(0x8000_0000),
    ] {
        let bad = GetSessionAuditDigestHandles {
            session_handle: bad_session_handle,
            ..valid_sad_handles
        };
        let len = bad.marshal(&mut sad_buf);
        let mut s = &sad_buf[..len];
        assert_eq!(
            GetSessionAuditDigestHandles::unmarshal(&mut s),
            Err(UnmarshalError::VALUE.in_handle(3)),
            "GetSessionAuditDigestHandles should reject session_handle {bad_session_handle:?}"
        );
    }

    // 2. GetCommandAuditDigestHandles:
    // Handle 1 (@privacyHandle): TPMI_RH_ENDORSEMENT (non-nullable, only TPM_RH_ENDORSEMENT)
    // Handle 2 (@signHandle): TPMI_DH_OBJECT+
    let valid_cad_handles = GetCommandAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle::RH_NULL,
    };
    let mut cad_buf = [0u8; GetCommandAuditDigestHandles::MAX_SIZE];
    let cad_len = valid_cad_handles.marshal(&mut cad_buf);
    let mut slice = &cad_buf[..cad_len];
    assert_eq!(
        GetCommandAuditDigestHandles::unmarshal(&mut slice),
        Ok(valid_cad_handles)
    );

    for bad_privacy_handle in [Handle::RH_OWNER, Handle::RH_PLATFORM, Handle::RH_NULL] {
        let bad = GetCommandAuditDigestHandles {
            privacy_admin_handle: bad_privacy_handle,
            ..valid_cad_handles
        };
        let len = bad.marshal(&mut cad_buf);
        let mut s = &cad_buf[..len];
        assert_eq!(
            GetCommandAuditDigestHandles::unmarshal(&mut s),
            Err(UnmarshalError::VALUE.in_handle(1)),
            "GetCommandAuditDigestHandles should reject privacy_admin_handle {bad_privacy_handle:?}"
        );
    }

    // 3. GetTimeHandles:
    // Handle 1 (@privacyAdminHandle): TPMI_RH_ENDORSEMENT (non-nullable, only TPM_RH_ENDORSEMENT)
    // Handle 2 (@signHandle): TPMI_DH_OBJECT+
    let valid_gt_handles = GetTimeHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle::RH_NULL,
    };
    let mut gt_buf = [0u8; GetTimeHandles::MAX_SIZE];
    let gt_len = valid_gt_handles.marshal(&mut gt_buf);
    let mut slice = &gt_buf[..gt_len];
    assert_eq!(GetTimeHandles::unmarshal(&mut slice), Ok(valid_gt_handles));

    for bad_privacy_handle in [Handle::RH_OWNER, Handle::RH_PLATFORM, Handle::RH_NULL] {
        let bad = GetTimeHandles {
            privacy_admin_handle: bad_privacy_handle,
            ..valid_gt_handles
        };
        let len = bad.marshal(&mut gt_buf);
        let mut s = &gt_buf[..len];
        assert_eq!(
            GetTimeHandles::unmarshal(&mut s),
            Err(UnmarshalError::VALUE.in_handle(1)),
            "GetTimeHandles should reject privacy_admin_handle {bad_privacy_handle:?}"
        );
    }
}

#[test]
fn test_tpmi_alg_kdf_and_tpmt_kdf_scheme_hkdf_support() {
    use tpm2::{
        Marshal, TpmEccCurve, TpmiAlgHash, TpmiAlgKdf, TpmsEccParms, TpmsSchemeXor, TpmtKdfScheme,
    };

    // 1. TpmiAlgKdf::Hkdf conversions and wire marshalling/unmarshalling (0x001F)
    assert_eq!(TpmiAlgKdf::try_from(Alg::HKDF), Ok(TpmiAlgKdf::Hkdf));
    assert_eq!(TpmiAlgKdf::try_from(0x001Fu16), Ok(TpmiAlgKdf::Hkdf));
    assert_eq!(Alg::from(TpmiAlgKdf::Hkdf), Alg::HKDF);

    let mut kdf_buf = [0u8; TpmiAlgKdf::MAX_SIZE];
    let len = TpmiAlgKdf::Hkdf.marshal(&mut kdf_buf);
    assert_eq!(&kdf_buf[..len], &[0x00, 0x1F]);
    let mut slice = &kdf_buf[..len];
    assert_eq!(TpmiAlgKdf::unmarshal(&mut slice), Ok(TpmiAlgKdf::Hkdf));
    assert!(slice.is_empty());

    let mut slice = &[0x00, 0x1F][..];
    assert_eq!(
        <Option<TpmiAlgKdf>>::unmarshal(&mut slice),
        Ok(Some(TpmiAlgKdf::Hkdf))
    );

    // 2. TpmtKdfScheme::Hkdf accessor methods and wire marshalling/unmarshalling
    let hkdf_scheme = TpmtKdfScheme::Hkdf(TpmiAlgHash::Sha256);
    assert_eq!(hkdf_scheme.scheme(), TpmiAlgKdf::Hkdf);
    assert_eq!(hkdf_scheme.hash_alg(), TpmiAlgHash::Sha256);

    let mut scheme_buf = [0u8; <Option<TpmtKdfScheme>>::MAX_SIZE];
    let len = Some(hkdf_scheme).marshal(&mut scheme_buf);
    assert_eq!(&scheme_buf[..len], &[0x00, 0x1F, 0x00, 0x0B]);
    let mut slice = &scheme_buf[..len];
    assert_eq!(
        <Option<TpmtKdfScheme>>::unmarshal(&mut slice),
        Ok(Some(hkdf_scheme))
    );
    assert!(slice.is_empty());

    let mut slice = &scheme_buf[..len];
    assert_eq!(TpmtKdfScheme::unmarshal(&mut slice), Ok(hkdf_scheme));
    assert!(slice.is_empty());

    // 3. TpmsEccParms with HKDF (RFC 9180 DHKEM) roundtrips cleanly
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: Some(TpmtKdfScheme::Hkdf(TpmiAlgHash::Sha256)),
    };
    let mut ecc_buf = [0u8; TpmsEccParms::MAX_SIZE];
    let ecc_len = ecc_parms.marshal(&mut ecc_buf);
    let mut slice = &ecc_buf[..ecc_len];
    assert_eq!(TpmsEccParms::unmarshal(&mut slice), Ok(ecc_parms));
    assert!(slice.is_empty());

    // 4. TpmsSchemeXor with HKDF roundtrips cleanly
    let xor_scheme = TpmsSchemeXor {
        hash_alg: TpmiAlgHash::Sha384,
        kdf: Some(TpmiAlgKdf::Hkdf),
    };
    let mut xor_buf = [0u8; TpmsSchemeXor::MAX_SIZE];
    let xor_len = xor_scheme.marshal(&mut xor_buf);
    let mut slice = &xor_buf[..xor_len];
    assert_eq!(TpmsSchemeXor::unmarshal(&mut slice), Ok(xor_scheme));
    assert!(slice.is_empty());
}
