use tpm2::errors::UnmarshalError;
use tpm2::*;

#[test]
fn test_tpm_eo_size_and_conversions() {
    assert_eq!(core::mem::size_of::<TpmEo>(), 1);
    assert_eq!(u16::from(TpmEo::Eq), 0x0000);
    assert_eq!(u16::from(TpmEo::BitClear), 0x000B);
    assert_eq!(TpmEo::try_from(0x0000), Ok(TpmEo::Eq));
    assert_eq!(TpmEo::try_from(0x000B), Ok(TpmEo::BitClear));
    assert!(TpmEo::try_from(0x000C).is_err());
}

#[test]
fn test_tpm_cap_size_and_conversions() {
    assert_eq!(core::mem::size_of::<TpmCap>(), 2);
    assert_eq!(TpmCap::FIRST, TpmCap::Algs);
    assert_eq!(u32::from(TpmCap::FIRST), 0x00000000);
    assert_eq!(u32::from(TpmCap::Algs), 0x00000000);
    assert_eq!(u32::from(TpmCap::ACT), 0x0000000A);
    assert_eq!(u32::from(TpmCap::PubKeys), 0x0000000B);
    assert_eq!(TpmCap::LAST, TpmCap::SpdmSessionInfo);
    assert_eq!(u32::from(TpmCap::LAST), 0x0000000C);
    assert_eq!(u32::from(TpmCap::SpdmSessionInfo), 0x0000000C);
    assert_eq!(u32::from(TpmCap::VendorProperty), 0x00000100);

    assert_eq!(TpmCap::try_from(0x00000000), Ok(TpmCap::Algs));
    assert_eq!(TpmCap::try_from(0x0000000C), Ok(TpmCap::SpdmSessionInfo));
    assert_eq!(TpmCap::try_from(0x00000100), Ok(TpmCap::VendorProperty));
    assert!(TpmCap::try_from(0x0000000D).is_err());
    assert!(TpmCap::try_from(0x00000101).is_err());
}

#[test]
fn test_tpm_cap_marshal_unmarshal() {
    let mut buf = [0u8; 4];
    let len = TpmCap::SpdmSessionInfo.marshal(&mut buf);
    assert_eq!(len, 4);
    assert_eq!(buf, [0x00, 0x00, 0x00, 0x0C]);

    let mut slice: &[u8] = &buf;
    let cap = TpmCap::unmarshal(&mut slice).unwrap();
    assert_eq!(cap, TpmCap::SpdmSessionInfo);
    assert!(slice.is_empty());

    let len = TpmCap::VendorProperty.marshal(&mut buf);
    assert_eq!(len, 4);
    assert_eq!(buf, [0x00, 0x00, 0x01, 0x00]);
    let mut slice: &[u8] = &buf;
    let cap = TpmCap::unmarshal(&mut slice).unwrap();
    assert_eq!(cap, TpmCap::VendorProperty);
    assert!(slice.is_empty());
}

#[test]
fn test_alg_debug_formatting() {
    assert_eq!(format!("{:?}", Alg::RSA), "Alg::RSA");
    assert_eq!(format!("{:?}", Alg::SHA256), "Alg::SHA256");
    assert_eq!(format!("{:?}", Alg::NULL), "Alg::NULL");
    assert_eq!(format!("{:?}", Alg::KEYEDHASH), "Alg::KEYEDHASH");
    assert_eq!(format!("{:?}", Alg::SYMCIPHER), "Alg::SYMCIPHER");
    assert_eq!(format!("{:?}", Alg::SM3_256), "Alg::SM3_256");
    assert_eq!(format!("{:?}", Alg::KDF1_SP800_56A), "Alg::KDF1_SP800_56A");
    assert_eq!(format!("{:?}", Alg::ECSCHNORR), "Alg::ECSCHNORR");
    assert_eq!(format!("{:?}", Alg::MLKEM), "Alg::MLKEM");
    assert_eq!(format!("{:?}", Alg::MLDSA), "Alg::MLDSA");
    assert_eq!(format!("{:?}", Alg::HASH_MLDSA), "Alg::HASH_MLDSA");
    assert_eq!(format!("{:?}", Alg::EDDSA), "Alg::EDDSA");
    assert_eq!(format!("{:?}", Alg::HASH_EDDSA), "Alg::HASH_EDDSA");
    assert_eq!(format!("{:?}", Alg::new(0x1234)), "Alg(0x1234)");
}

#[test]
fn test_tpm_ecc_curve_conversions() {
    assert_eq!(core::mem::size_of::<TpmEccCurve>(), 2);
    assert_eq!(u16::from(TpmEccCurve::None), 0x0000);
    assert_eq!(TpmEccCurve::try_from(0x0000), Ok(TpmEccCurve::None));
    assert_eq!(TpmEccCurve::None.parameter_size(), 0);
    let mut none_slice: &[u8] = &[0x00, 0x00];
    assert_eq!(
        TpmEccCurve::unmarshal(&mut none_slice),
        Err(UnmarshalError::CURVE)
    );
    let mut opt_slice: &[u8] = &[0x00, 0x00];
    assert_eq!(Option::<TpmEccCurve>::unmarshal(&mut opt_slice), Ok(None));
    #[cfg(feature = "ecc_curve_nist_p192")]
    {
        assert_eq!(u16::from(TpmEccCurve::NistP192), 0x0001);
        assert_eq!(TpmEccCurve::try_from(0x0001), Ok(TpmEccCurve::NistP192));
    }
    #[cfg(feature = "ecc_curve_nist_p256")]
    {
        assert_eq!(u16::from(TpmEccCurve::NistP256), 0x0003);
        assert_eq!(TpmEccCurve::try_from(0x0003), Ok(TpmEccCurve::NistP256));
    }
    #[cfg(feature = "ecc_curve_bp_p256_r1")]
    {
        assert_eq!(u16::from(TpmEccCurve::BpP256R1), 0x0030);
        assert_eq!(TpmEccCurve::try_from(0x0030), Ok(TpmEccCurve::BpP256R1));
    }
    #[cfg(feature = "ecc_curve_curve448")]
    {
        assert_eq!(u16::from(TpmEccCurve::Curve448), 0x0041);
        assert_eq!(TpmEccCurve::try_from(0x0041), Ok(TpmEccCurve::Curve448));
    }
    assert!(TpmEccCurve::try_from(0x0042).is_err());
}

#[test]
#[allow(clippy::unnecessary_fallible_conversions)]
fn test_tpm_pt_pcr_conversions() {
    assert_eq!(core::mem::size_of::<TpmPtPcr>(), 4);
    assert_eq!(TpmPtPcr::FIRST, TpmPtPcr::SAVE);
    assert_eq!(TpmPtPcr::LAST, TpmPtPcr::AUTH);
    assert_eq!(u32::from(TpmPtPcr::SAVE), 0x00000000);
    assert_eq!(u32::from(TpmPtPcr::DRTM_RESET), 0x00000012);
    assert_eq!(u32::from(TpmPtPcr::AUTH), 0x00000014);
    assert_eq!(TpmPtPcr::try_from(0x00000000), Ok(TpmPtPcr::SAVE));
    assert_eq!(TpmPtPcr::try_from(0x00000012), Ok(TpmPtPcr::DRTM_RESET));
    assert_eq!(TpmPtPcr::try_from(0x00000014), Ok(TpmPtPcr::AUTH));

    // Extended locality properties (0x0B..=0x10), additional policy/auth sets (0x15..=0x0212),
    // and future/vendor PCR property tags must be accepted without error.
    for tag in [
        0x0000000Bu32,
        0x00000010,
        0x00000015,
        0x00000211,
        0x00000212,
        0x00000213,
        0xFFFFFFFF,
    ] {
        let pcr_pt = TpmPtPcr::from(tag);
        assert_eq!(pcr_pt.tag(), tag);
        assert_eq!(u32::from(pcr_pt), tag);
        let mut buf = [0u8; 4];
        assert_eq!(pcr_pt.marshal(&mut buf), 4);
        let mut reader = &buf[..];
        assert_eq!(TpmPtPcr::unmarshal(&mut reader), Ok(pcr_pt));
    }
}

#[test]
#[allow(clippy::unnecessary_fallible_conversions)]
fn test_tpm_pt_conversions() {
    assert_eq!(core::mem::size_of::<TpmPt>(), 4);
    assert_eq!(TpmPt::default(), TpmPt::NONE);
    assert_eq!(u32::from(TpmPt::NONE), 0x00000000);
    assert_eq!(u32::from(TpmPt::PT_GROUP), 0x00000100);
    assert_eq!(u32::from(TpmPt::PT_FIXED), 0x00000100);
    assert_eq!(u32::from(TpmPt::FAMILY_INDICATOR), 0x00000100);
    assert_eq!(u32::from(TpmPt::ERRATA), 0x00000103);
    assert_eq!(u32::from(TpmPt::DAY_OF_YEAR), 0x00000103);
    assert_eq!(u32::from(TpmPt::FIRMWARE_SVN), 0x0000012F);
    assert_eq!(u32::from(TpmPt::FIRMWARE_MAX_SVN), 0x00000130);
    assert_eq!(u32::from(TpmPt::ML_PARAMETER_SETS), 0x00000131);
    assert_eq!(u32::from(TpmPt::PT_VAR), 0x00000200);
    assert_eq!(u32::from(TpmPt::PERMANENT), 0x00000200);
    assert_eq!(u32::from(TpmPt::AUDIT_COUNTER_1), 0x00000214);

    assert_eq!(TpmPt::try_from(0x00000000), Ok(TpmPt::NONE));
    assert_eq!(TpmPt::try_from(0x00000100), Ok(TpmPt::FAMILY_INDICATOR));
    assert_eq!(TpmPt::try_from(0x0000012F), Ok(TpmPt::FIRMWARE_SVN));
    assert_eq!(TpmPt::try_from(0x00000130), Ok(TpmPt::FIRMWARE_MAX_SVN));
    assert_eq!(TpmPt::try_from(0x00000131), Ok(TpmPt::ML_PARAMETER_SETS));
    assert_eq!(TpmPt::try_from(0x00000214), Ok(TpmPt::AUDIT_COUNTER_1));

    // Reserved, future, and vendor property tags in PT_FIXED, PT_VAR, and beyond
    // must be accepted without error.
    for prop in [
        0x00000000u32,
        0x00000115,
        0x0000012F,
        0x00000130,
        0x00000131,
        0x000001FF,
        0x00000215,
        0x000002FF,
        0x80000001,
    ] {
        let pt = TpmPt::from(prop);
        assert_eq!(pt.tag(), prop);
        let mut buf = [0u8; 4];
        assert_eq!(pt.marshal(&mut buf), 4);
        let mut reader = &buf[..];
        assert_eq!(TpmPt::unmarshal(&mut reader), Ok(pt));
    }

    // Test core::fmt::Debug format strings
    assert_eq!(
        std::format!("{:?}", TpmPt::FAMILY_INDICATOR),
        "TpmPt::FAMILY_INDICATOR"
    );
    assert_eq!(
        std::format!("{:?}", TpmPt::HR_TRANSIENT_MIN),
        "TpmPt::HR_TRANSIENT_MIN"
    );
    assert_eq!(std::format!("{:?}", TpmPt::ERRATA), "TpmPt::ERRATA");
    assert_eq!(std::format!("{:?}", TpmPt::PERMANENT), "TpmPt::PERMANENT");
    assert_eq!(std::format!("{:?}", TpmPt(0x99999999)), "TpmPt(0x99999999)");

    assert_eq!(std::format!("{:?}", TpmPtPcr::SAVE), "TpmPtPcr::SAVE");
    assert_eq!(
        std::format!("{:?}", TpmPtPcr::EXTEND_L0),
        "TpmPtPcr::EXTEND_L0"
    );
    assert_eq!(std::format!("{:?}", TpmPtPcr::AUTH), "TpmPtPcr::AUTH");
    assert_eq!(
        std::format!("{:?}", TpmPtPcr(0x99999999)),
        "TpmPtPcr(0x99999999)"
    );
}

#[test]
fn test_tpm_nt_and_clock_adjust_conversions() {
    assert_eq!(core::mem::size_of::<TpmNt>(), 1);
    assert_eq!(u8::from(TpmNt::Ordinary), 0x0);
    assert_eq!(u8::from(TpmNt::PinPass), 0x9);
    assert_eq!(TpmNt::try_from(0x0), Ok(TpmNt::Ordinary));
    assert_eq!(TpmNt::try_from(0x9), Ok(TpmNt::PinPass));
    assert!(TpmNt::try_from(0x3).is_err());

    assert_eq!(core::mem::size_of::<TpmClockAdjust>(), 1);
    assert_eq!(i8::from(TpmClockAdjust::CoarseSlower), -3);
    assert_eq!(i8::from(TpmClockAdjust::NoChange), 0);
    assert_eq!(i8::from(TpmClockAdjust::CoarseFaster), 3);
    assert_eq!(
        TpmClockAdjust::try_from(-3),
        Ok(TpmClockAdjust::CoarseSlower)
    );
    assert_eq!(TpmClockAdjust::try_from(0), Ok(TpmClockAdjust::NoChange));
    assert_eq!(
        TpmClockAdjust::try_from(3),
        Ok(TpmClockAdjust::CoarseFaster)
    );
    assert!(TpmClockAdjust::try_from(4).is_err());
}

#[test]
fn test_handle_and_tpm_st_constants() {
    assert_eq!(Handle::RH_OWNER.0, 0x40000001);
    assert_eq!(Handle::RH_OWNER.handle_type(), Some(TpmHt::Permanent));
    assert_eq!(Handle(0x00000001).handle_type(), Some(TpmHt::PCR));
    assert_eq!(Handle(0x01000001).handle_type(), Some(TpmHt::NVIndex));
    assert_eq!(Handle(0x02000001).handle_type(), Some(TpmHt::HMACSession));
    assert_eq!(Handle(0x03000001).handle_type(), Some(TpmHt::PolicySession));
    assert_eq!(Handle(0x80000001).handle_type(), Some(TpmHt::Transient));
    assert_eq!(Handle(0x81000001).handle_type(), Some(TpmHt::Persistent));
    assert_eq!(Handle(0x90000001).handle_type(), Some(TpmHt::AC));
    assert_eq!(Handle(0xFF000001).handle_type(), None);

    assert_eq!(TpmSt::RSP_COMMAND.id(), 0x00C4);
    assert_eq!(TpmSt::NULL.id(), 0x8000);
    assert_eq!(TpmSt::NO_SESSIONS.id(), 0x8001);
    assert_eq!(TpmSt::SESSIONS.id(), 0x8002);
    assert_eq!(TpmSt::MESSAGE_VERIFIED.id(), 0x8026);
    assert_eq!(TpmSt::DIGEST_VERIFIED.id(), 0x8027);
    assert_eq!(TpmSt::FU_MANIFEST.id(), 0x8029);

    assert_eq!(Alg::default(), Alg::NULL);
    assert_eq!(TpmSt::default(), TpmSt::NULL);
    assert_eq!(TpmPtPcr::default(), TpmPtPcr::SAVE);
    assert_eq!(TpmHt::default(), TpmHt::PCR);
}

#[test]
#[allow(clippy::unnecessary_fallible_conversions)]
fn test_alg_try_from_and_unmarshal_validation() {
    let test_ids = [
        0x0000u16, 0x0001, 0x000B, 0x00C0, 0x00C1, 0x00C4, 0x00C6, 0x00C7, 0x7FFF, 0x8000, 0x8001,
        0x8014, 0x8021, 0xFFFF,
    ];
    for id in test_ids {
        let alg = Alg::from(id);
        assert_eq!(alg.id(), id);
        assert_eq!(u16::from(alg), id);
        assert_eq!(Alg::try_from(id), Ok(alg));

        let bytes = [id.to_be_bytes()[0], id.to_be_bytes()[1], 0xFF];
        let mut slice = &bytes[..];
        assert_eq!(Alg::unmarshal(&mut slice), Ok(alg));
        assert_eq!(slice, &[0xFF]);
    }

    let short = [0x00];
    let mut slice = &short[..];
    assert_eq!(
        Alg::unmarshal(&mut slice),
        Err(UnmarshalError::INSUFFICIENT)
    );
    assert_eq!(slice, &short[..]);
}

#[test]
fn test_tpm_ht_and_handle_rh_constants() {
    assert_eq!(u8::from(TpmHt::PCR), 0x00);
    assert_eq!(u8::from(TpmHt::NVIndex), 0x01);
    assert_eq!(u8::from(TpmHt::HMACSession), 0x02);
    assert_eq!(u8::from(TpmHt::PolicySession), 0x03);
    assert_eq!(u8::from(TpmHt::ExternalNv), 0x11);
    assert_eq!(u8::from(TpmHt::PermanentNv), 0x12);
    assert_eq!(u8::from(TpmHt::Permanent), 0x40);
    assert_eq!(u8::from(TpmHt::Transient), 0x80);
    assert_eq!(u8::from(TpmHt::Persistent), 0x81);
    assert_eq!(u8::from(TpmHt::AC), 0x90);

    assert_eq!(TpmHt::try_from(0x11), Ok(TpmHt::ExternalNv));
    assert_eq!(TpmHt::try_from(0x12), Ok(TpmHt::PermanentNv));
    assert_eq!(TpmHt::try_from(0x10), Err(UnmarshalError::VALUE));
    assert_eq!(TpmHt::try_from(0x13), Err(UnmarshalError::VALUE));

    assert_eq!(Handle(0x11000000).handle_type(), Some(TpmHt::ExternalNv));
    assert_eq!(Handle(0x11ABCDEF).handle_type(), Some(TpmHt::ExternalNv));
    assert_eq!(Handle(0x12000000).handle_type(), Some(TpmHt::PermanentNv));
    assert_eq!(Handle(0x12ABCDEF).handle_type(), Some(TpmHt::PermanentNv));

    assert_eq!(Handle::RH_FIRST.0, 0x40000000);
    assert_eq!(Handle::RH_SRK.0, 0x40000000);
    assert_eq!(Handle::RH_OWNER.0, 0x40000001);
    assert_eq!(Handle::RH_REVOKE.0, 0x40000002);
    assert_eq!(Handle::RH_TRANSPORT.0, 0x40000003);
    assert_eq!(Handle::RH_OPERATOR.0, 0x40000004);
    assert_eq!(Handle::RH_ADMIN.0, 0x40000005);
    assert_eq!(Handle::RH_EK.0, 0x40000006);
    assert_eq!(Handle::RH_NULL.0, 0x40000007);
    assert_eq!(Handle::RH_UNASSIGNED.0, 0x40000008);
    assert_eq!(Handle::RS_PW.0, 0x40000009);
    assert_eq!(Handle::RH_LOCKOUT.0, 0x4000000A);
    assert_eq!(Handle::RH_ENDORSEMENT.0, 0x4000000B);
    assert_eq!(Handle::RH_PLATFORM.0, 0x4000000C);
    assert_eq!(Handle::RH_PLATFORM_NV.0, 0x4000000D);
    assert_eq!(Handle::RH_AUTH_00.0, 0x40000010);
    assert_eq!(Handle::RH_AUTH_FF.0, 0x4000010F);

    let act_handles = [
        (Handle::RH_ACT_0, 0x40000110),
        (Handle::RH_ACT_1, 0x40000111),
        (Handle::RH_ACT_2, 0x40000112),
        (Handle::RH_ACT_3, 0x40000113),
        (Handle::RH_ACT_4, 0x40000114),
        (Handle::RH_ACT_5, 0x40000115),
        (Handle::RH_ACT_6, 0x40000116),
        (Handle::RH_ACT_7, 0x40000117),
        (Handle::RH_ACT_8, 0x40000118),
        (Handle::RH_ACT_9, 0x40000119),
        (Handle::RH_ACT_A, 0x4000011A),
        (Handle::RH_ACT_B, 0x4000011B),
        (Handle::RH_ACT_C, 0x4000011C),
        (Handle::RH_ACT_D, 0x4000011D),
        (Handle::RH_ACT_E, 0x4000011E),
        (Handle::RH_ACT_F, 0x4000011F),
    ];
    for (i, &(act_handle, expected_val)) in act_handles.iter().enumerate() {
        assert_eq!(act_handle.0, expected_val);
        assert_eq!(act_handle.0, 0x40000110 + i as u32);
        assert_eq!(act_handle.handle_type(), Some(TpmHt::Permanent));
    }

    assert_eq!(Handle::RH_FW_OWNER.0, 0x40000140);
    assert_eq!(Handle::RH_FW_ENDORSEMENT.0, 0x40000141);
    assert_eq!(Handle::RH_FW_PLATFORM.0, 0x40000142);
    assert_eq!(Handle::RH_FW_NULL.0, 0x40000143);
    assert_eq!(Handle::RH_SVN_OWNER_BASE.0, 0x40010000);
    assert_eq!(Handle::RH_SVN_ENDORSEMENT_BASE.0, 0x40020000);
    assert_eq!(Handle::RH_SVN_PLATFORM_BASE.0, 0x40030000);
    assert_eq!(Handle::RH_SVN_NULL_BASE.0, 0x40040000);
    assert_eq!(Handle::RH_LAST.0, 0x4004FFFF);

    assert_eq!(Handle::RH_UNASSIGNED.handle_type(), Some(TpmHt::Permanent));
    assert_eq!(Handle::RH_FIRST.handle_type(), Some(TpmHt::Permanent));
    assert_eq!(Handle::RH_LAST.handle_type(), Some(TpmHt::Permanent));
}

#[test]
fn test_tpm_cc_constants_and_marshalling() {
    assert_eq!(core::mem::size_of::<TpmCc>(), 4);
    assert_eq!(TpmCc::FIRST, TpmCc::NVUndefineSpaceSpecial);
    assert_eq!(TpmCc::LAST, TpmCc::SignSequenceStart);
    assert_eq!(TpmCc::VEND.code(), 0x20000000);

    let expected_codes: &[(TpmCc, u32)] = &[
        (TpmCc::ECCEncrypt, 0x00000199),
        (TpmCc::ECCDecrypt, 0x0000019A),
        (TpmCc::PolicyCapability, 0x0000019B),
        (TpmCc::PolicyParameters, 0x0000019C),
        (TpmCc::NVDefineSpace2, 0x0000019D),
        (TpmCc::NVReadPublic2, 0x0000019E),
        (TpmCc::SetCapability, 0x0000019F),
        (TpmCc::ReadOnlyControl, 0x000001A0),
        (TpmCc::PolicyTransportSPDM, 0x000001A1),
        (TpmCc::VerifySequenceComplete, 0x000001A3),
        (TpmCc::SignSequenceComplete, 0x000001A4),
        (TpmCc::VerifyDigestSignature, 0x000001A5),
        (TpmCc::SignDigest, 0x000001A6),
        (TpmCc::Encapsulate, 0x000001A7),
        (TpmCc::Decapsulate, 0x000001A8),
        (TpmCc::VerifySequenceStart, 0x000001A9),
        (TpmCc::SignSequenceStart, 0x000001AA),
        (TpmCc::VendorTcgTest, 0x20000000),
        (TpmCc::VEND, 0x20000000),
    ];

    for &(cc, expected_val) in expected_codes {
        assert_eq!(cc.code(), expected_val);
        assert_eq!(u32::from(cc), expected_val);
        assert_eq!(TpmCc::from(expected_val), cc);

        let mut buf = [0u8; 4];
        let len = cc.marshal(&mut buf);
        assert_eq!(len, 4);
        assert_eq!(buf, expected_val.to_be_bytes());

        let mut slice: &[u8] = &buf;
        let unmarshalled = TpmCc::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshalled, cc);
        assert!(slice.is_empty());
    }

    assert_eq!(tpm2::commands::ECCEncrypt::CMD_CODE, TpmCc::ECCEncrypt);
    assert_eq!(tpm2::commands::ECCDecrypt::CMD_CODE, TpmCc::ECCDecrypt);
    assert_eq!(
        tpm2::commands::PolicyCapability::CMD_CODE,
        TpmCc::PolicyCapability
    );
    assert_eq!(
        tpm2::commands::PolicyParameters::CMD_CODE,
        TpmCc::PolicyParameters
    );
    assert_eq!(
        tpm2::commands::NVDefineSpace2::CMD_CODE,
        TpmCc::NVDefineSpace2
    );
    assert_eq!(
        tpm2::commands::NVReadPublic2::CMD_CODE,
        TpmCc::NVReadPublic2
    );
    assert_eq!(
        tpm2::commands::SetCapability::CMD_CODE,
        TpmCc::SetCapability
    );
    assert_eq!(
        tpm2::commands::ReadOnlyControl::CMD_CODE,
        TpmCc::ReadOnlyControl
    );
    assert_eq!(
        tpm2::commands::PolicyTransportSPDM::CMD_CODE,
        TpmCc::PolicyTransportSPDM
    );
    assert_eq!(
        tpm2::commands::VerifySequenceComplete::CMD_CODE,
        TpmCc::VerifySequenceComplete
    );
    assert_eq!(
        tpm2::commands::SignSequenceComplete::CMD_CODE,
        TpmCc::SignSequenceComplete
    );
    assert_eq!(
        tpm2::commands::VerifyDigestSignature::CMD_CODE,
        TpmCc::VerifyDigestSignature
    );
    assert_eq!(tpm2::commands::SignDigest::CMD_CODE, TpmCc::SignDigest);
    assert_eq!(tpm2::commands::Encapsulate::CMD_CODE, TpmCc::Encapsulate);
    assert_eq!(tpm2::commands::Decapsulate::CMD_CODE, TpmCc::Decapsulate);
    assert_eq!(
        tpm2::commands::VerifySequenceStart::CMD_CODE,
        TpmCc::VerifySequenceStart
    );
    assert_eq!(
        tpm2::commands::SignSequenceStart::CMD_CODE,
        TpmCc::SignSequenceStart
    );
    assert_eq!(
        tpm2::commands::VendorTcgTest::CMD_CODE,
        TpmCc::VendorTcgTest
    );
}

#[test]
fn test_tpm_ps_tpm_pub_key_and_tpm_ae_constants_and_marshalling() {
    assert_eq!(core::mem::size_of::<TpmPs>(), 4);
    assert_eq!(TpmPs::default(), TpmPs::MAIN);
    let expected_ps: &[(TpmPs, u32)] = &[
        (TpmPs::MAIN, 0x00000000),
        (TpmPs::PC, 0x00000001),
        (TpmPs::PDA, 0x00000002),
        (TpmPs::CELL_PHONE, 0x00000003),
        (TpmPs::SERVER, 0x00000004),
        (TpmPs::PERIPHERAL, 0x00000005),
        (TpmPs::TSS, 0x00000006),
        (TpmPs::STORAGE, 0x00000007),
        (TpmPs::AUTHENTICATION, 0x00000008),
        (TpmPs::EMBEDDED, 0x00000009),
        (TpmPs::HARDCOPY, 0x0000000A),
        (TpmPs::INFRASTRUCTURE, 0x0000000B),
        (TpmPs::VIRTUALIZATION, 0x0000000C),
        (TpmPs::TNC, 0x0000000D),
        (TpmPs::MULTI_TENANT, 0x0000000E),
        (TpmPs::TC, 0x0000000F),
    ];
    for &(ps, val) in expected_ps {
        assert_eq!(ps.0, val);
        assert_eq!(ps.raw(), val);
        assert_eq!(ps.id(), val);
        assert_eq!(ps.code(), val);
        assert_eq!(ps.as_u32(), val);
        assert_eq!(TpmPs::new(val), ps);
        assert_eq!(TpmPs::from(val), ps);
        assert_eq!(u32::from(ps), val);

        let mut buf = [0u8; 4];
        assert_eq!(ps.marshal(&mut buf), 4);
        assert_eq!(buf, val.to_be_bytes());
        let mut slice = &buf[..];
        assert_eq!(TpmPs::unmarshal(&mut slice), Ok(ps));
        assert!(slice.is_empty());
    }
    let short = [0x00, 0x01, 0x02];
    let mut short_slice = &short[..];
    assert_eq!(
        TpmPs::unmarshal(&mut short_slice),
        Err(UnmarshalError::INSUFFICIENT)
    );

    assert_eq!(core::mem::size_of::<TpmPubKey>(), 4);
    assert_eq!(TpmPubKey::default(), TpmPubKey::TPM_SPDM_00);
    assert_eq!(TpmPubKey::TPM_SPDM_00.0, 0x00000000);
    assert_eq!(TpmPubKey::TPM_SPDM_FF.0, 0x000000FF);
    assert_eq!(TpmPubKey::SPDM_00, TpmPubKey::TPM_SPDM_00);
    assert_eq!(TpmPubKey::SPDM_FF, TpmPubKey::TPM_SPDM_FF);
    assert_eq!(TpmPubKey::tpm_spdm(0x00), TpmPubKey::TPM_SPDM_00);
    assert_eq!(TpmPubKey::tpm_spdm(0x42).0, 0x00000042);
    assert_eq!(TpmPubKey::tpm_spdm(0xFF), TpmPubKey::TPM_SPDM_FF);
    assert!(TpmPubKey::TPM_SPDM_00.is_tpm_spdm());
    assert!(TpmPubKey::TPM_SPDM_FF.is_tpm_spdm());
    assert!(!TpmPubKey(0x00000100).is_tpm_spdm());

    for val in [0x00000000u32, 0x00000001, 0x000000FF, 0x00000100] {
        let pk = TpmPubKey::new(val);
        assert_eq!(pk.raw(), val);
        assert_eq!(pk.id(), val);
        assert_eq!(pk.code(), val);
        assert_eq!(pk.as_u32(), val);
        assert_eq!(TpmPubKey::from(val), pk);
        assert_eq!(u32::from(pk), val);

        let mut buf = [0u8; 4];
        assert_eq!(pk.marshal(&mut buf), 4);
        assert_eq!(buf, val.to_be_bytes());
        let mut slice = &buf[..];
        assert_eq!(TpmPubKey::unmarshal(&mut slice), Ok(pk));
        assert!(slice.is_empty());
    }
    let mut short_slice = &short[..];
    assert_eq!(
        TpmPubKey::unmarshal(&mut short_slice),
        Err(UnmarshalError::INSUFFICIENT)
    );

    assert_eq!(core::mem::size_of::<TpmAe>(), 4);
    assert_eq!(TpmAe::default(), TpmAe::NONE);
    assert_eq!(TpmAe::NONE.0, 0x00000000);
    assert_eq!(TpmAe::NONE.raw(), 0x00000000);
    assert_eq!(TpmAe::NONE.id(), 0x00000000);
    assert_eq!(TpmAe::NONE.code(), 0x00000000);
    assert_eq!(TpmAe::NONE.as_u32(), 0x00000000);
    assert_eq!(TpmAe::new(0x00000000), TpmAe::NONE);
    assert_eq!(TpmAe::from(0x00000000), TpmAe::NONE);
    assert_eq!(u32::from(TpmAe::NONE), 0x00000000);

    let mut buf = [0u8; 4];
    assert_eq!(TpmAe::NONE.marshal(&mut buf), 4);
    assert_eq!(buf, [0, 0, 0, 0]);
    let mut slice = &buf[..];
    assert_eq!(TpmAe::unmarshal(&mut slice), Ok(TpmAe::NONE));
    assert!(slice.is_empty());

    let mut short_slice = &short[..];
    assert_eq!(
        TpmAe::unmarshal(&mut short_slice),
        Err(UnmarshalError::INSUFFICIENT)
    );

    assert_eq!(core::mem::size_of::<TpmHc>(), 4);
    assert_eq!(TPM2_MAX_LOADED_OBJECTS, 16);
    assert_eq!(Handle::HR_HANDLE_MASK, 0x00FF_FFFF);
    assert_eq!(Handle::HR_RANGE_MASK, 0xFF00_0000);
    assert_eq!(Handle::HR_SHIFT, 24);
    assert_eq!(Handle::HR_PCR.0, 0x0000_0000);
    assert_eq!(Handle::HR_HMAC_SESSION.0, 0x0200_0000);
    assert_eq!(Handle::HR_LOADED_SESSION.0, 0x0200_0000);
    assert_eq!(Handle::HR_POLICY_SESSION.0, 0x0300_0000);
    assert_eq!(Handle::HR_SAVED_SESSION.0, 0x0300_0000);
    assert_eq!(Handle::HR_TRANSIENT.0, 0x8000_0000);
    assert_eq!(Handle::HR_PERSISTENT.0, 0x8100_0000);
    assert_eq!(Handle::HR_NV_INDEX.0, 0x0100_0000);
    assert_eq!(Handle::HR_EXTERNAL_NV.0, 0x1100_0000);
    assert_eq!(Handle::HR_PERMANENT_NV.0, 0x1200_0000);
    assert_eq!(Handle::HR_PERMANENT.0, 0x4000_0000);
    assert_eq!(Handle::PCR_FIRST.0, 0x0000_0000);
    assert_eq!(Handle::PCR_LAST.0, 0x0000_0017);
    assert_eq!(Handle::HMAC_SESSION_FIRST.0, 0x0200_0000);
    assert_eq!(Handle::HMAC_SESSION_LAST.0, 0x0200_003F);
    assert_eq!(Handle::LOADED_SESSION_FIRST.0, 0x0200_0000);
    assert_eq!(Handle::LOADED_SESSION_LAST.0, 0x0200_003F);
    assert_eq!(Handle::POLICY_SESSION_FIRST.0, 0x0300_0000);
    assert_eq!(Handle::POLICY_SESSION_LAST.0, 0x0300_003F);
    assert_eq!(Handle::SAVED_SESSION_FIRST.0, 0x0300_0000);
    assert_eq!(Handle::SAVED_SESSION_LAST.0, 0x0300_003F);
    assert_eq!(Handle::ACTIVE_SESSION_FIRST.0, 0x0300_0000);
    assert_eq!(Handle::ACTIVE_SESSION_LAST.0, 0x0300_003F);
    assert_eq!(Handle::TRANSIENT_FIRST.0, 0x8000_0000);
    assert_eq!(
        Handle::TRANSIENT_LAST.0,
        0x8000_0000 + TPM2_MAX_LOADED_OBJECTS - 1
    );
    assert_eq!(Handle::PERSISTENT_FIRST.0, 0x8100_0000);
    assert_eq!(Handle::PERSISTENT_LAST.0, 0x81FF_FFFF);
    assert_eq!(Handle::PLATFORM_PERSISTENT.0, 0x8180_0000);
    assert_eq!(Handle::NV_INDEX_FIRST.0, 0x0100_0000);
    assert_eq!(Handle::NV_INDEX_LAST.0, 0x01FF_FFFF);
    assert_eq!(Handle::EXTERNAL_NV_FIRST.0, 0x1100_0000);
    assert_eq!(Handle::EXTERNAL_NV_LAST.0, 0x11FF_FFFF);
    assert_eq!(Handle::PERMANENT_NV_FIRST.0, 0x1200_0000);
    assert_eq!(Handle::PERMANENT_NV_LAST.0, 0x12FF_FFFF);
    assert_eq!(Handle::PERMANENT_FIRST.0, Handle::RH_FIRST.0);
    assert_eq!(Handle::PERMANENT_LAST.0, Handle::RH_LAST.0);
    assert_eq!(Handle::SVN_OWNER_FIRST.0, 0x4001_0000);
    assert_eq!(Handle::SVN_OWNER_LAST.0, 0x4001_FFFF);
    assert_eq!(Handle::SVN_ENDORSEMENT_FIRST.0, 0x4002_0000);
    assert_eq!(Handle::SVN_ENDORSEMENT_LAST.0, 0x4002_FFFF);
    assert_eq!(Handle::SVN_PLATFORM_FIRST.0, 0x4003_0000);
    assert_eq!(Handle::SVN_PLATFORM_LAST.0, 0x4003_FFFF);
    assert_eq!(Handle::SVN_NULL_FIRST.0, 0x4004_0000);
    assert_eq!(Handle::SVN_NULL_LAST.0, 0x4004_FFFF);
    assert_eq!(Handle::HR_NV_AC.0, 0x01D0_0000);
    assert_eq!(Handle::NV_AC_FIRST.0, 0x01D0_0000);
    assert_eq!(Handle::NV_AC_LAST.0, 0x01D0_FFFF);
    assert_eq!(Handle::HR_AC.0, 0x9000_0000);
    assert_eq!(Handle::AC_FIRST.0, 0x9000_0000);
    assert_eq!(Handle::AC_LAST.0, 0x9000_FFFF);
    assert_eq!(TRANSIENT_LAST, Handle::TRANSIENT_LAST.0);
    assert_eq!(HMAC_SESSION_LAST, Handle::HMAC_SESSION_LAST.0);
    assert_eq!(POLICY_SESSION_LAST, Handle::POLICY_SESSION_LAST.0);
    assert_eq!(LOADED_SESSION_LAST, Handle::LOADED_SESSION_LAST.0);
    assert_eq!(SAVED_SESSION_LAST, Handle::SAVED_SESSION_LAST.0);
}

#[test]
fn test_tpm_ht_loaded_and_saved_session_constants() {
    assert_eq!(TpmHt::LOADED_SESSION as u8, 0x02);
    assert_eq!(TpmHt::LoadedSession as u8, 0x02);
    assert_eq!(TpmHt::HMAC_SESSION as u8, 0x02);
    assert_eq!(TpmHt::HMACSession as u8, 0x02);
    assert_eq!(TpmHt::LOADED_SESSION, TpmHt::HMACSession);
    assert_eq!(TpmHt::LoadedSession, TpmHt::HMACSession);
    assert_eq!(TpmHt::LOADED_SESSION.raw(), 0x02);
    assert_eq!(TpmHt::LOADED_SESSION.as_u8(), 0x02);
    assert_eq!(u8::from(TpmHt::LOADED_SESSION), 0x02);
    assert_eq!(TpmHt::try_from(0x02), Ok(TpmHt::LOADED_SESSION));

    assert_eq!(TpmHt::SAVED_SESSION as u8, 0x03);
    assert_eq!(TpmHt::SavedSession as u8, 0x03);
    assert_eq!(TpmHt::POLICY_SESSION as u8, 0x03);
    assert_eq!(TpmHt::PolicySession as u8, 0x03);
    assert_eq!(TpmHt::SAVED_SESSION, TpmHt::PolicySession);
    assert_eq!(TpmHt::SavedSession, TpmHt::PolicySession);
    assert_eq!(TpmHt::SAVED_SESSION.raw(), 0x03);
    assert_eq!(TpmHt::SAVED_SESSION.as_u8(), 0x03);
    assert_eq!(u8::from(TpmHt::SAVED_SESSION), 0x03);
    assert_eq!(TpmHt::try_from(0x03), Ok(TpmHt::SAVED_SESSION));

    assert_eq!(
        Handle(0x0200_0000).handle_type(),
        Some(TpmHt::LOADED_SESSION)
    );
    assert_eq!(
        Handle(0x0300_0000).handle_type(),
        Some(TpmHt::SAVED_SESSION)
    );

    let mut buf = [0u8; 1];
    assert_eq!(TpmHt::LOADED_SESSION.marshal(&mut buf), 1);
    assert_eq!(buf, [0x02]);
    let mut slice = &buf[..];
    assert_eq!(TpmHt::unmarshal(&mut slice), Ok(TpmHt::LOADED_SESSION));

    assert_eq!(TpmHt::SAVED_SESSION.marshal(&mut buf), 1);
    assert_eq!(buf, [0x03]);
    let mut slice = &buf[..];
    assert_eq!(TpmHt::unmarshal(&mut slice), Ok(TpmHt::SAVED_SESSION));
}

#[test]
fn test_tpm_spec_constants() {
    assert_eq!(TPM_SPEC_FAMILY, 0x322E_3000);
    assert_eq!(TPM_SPEC_FAMILY.to_be_bytes(), *b"2.0\0");
    assert_eq!(TPM_SPEC_LEVEL, 0);
    assert_eq!(TPM_SPEC_VERSION, 185);
    assert_eq!(TPM_SPEC_YEAR, 0);
    assert_eq!(TPM_SPEC_ERRATA, 0);
    assert_eq!(TPM_SPEC_DAY_OF_YEAR, TPM_SPEC_ERRATA);

    assert_eq!(SPEC_FAMILY, TPM_SPEC_FAMILY);
    assert_eq!(SPEC_LEVEL, TPM_SPEC_LEVEL);
    assert_eq!(SPEC_VERSION, TPM_SPEC_VERSION);
    assert_eq!(SPEC_YEAR, TPM_SPEC_YEAR);
    assert_eq!(SPEC_ERRATA, TPM_SPEC_ERRATA);
    assert_eq!(SPEC_DAY_OF_YEAR, TPM_SPEC_DAY_OF_YEAR);

    assert_eq!(core::mem::size_of::<TpmSpec>(), 4);
    assert_eq!(TpmSpec::FAMILY, 0x322E_3000);
    assert_eq!(TpmSpec::FAMILY_BYTES, *b"2.0\0");
    assert_eq!(TpmSpec::LEVEL, 0);
    assert_eq!(TpmSpec::VERSION, 185);
    assert_eq!(TpmSpec::YEAR, 0);
    assert_eq!(TpmSpec::ERRATA, 0);
    assert_eq!(TpmSpec::DAY_OF_YEAR, 0);
    assert_eq!(TpmSpec::TPM_SPEC_FAMILY, TPM_SPEC_FAMILY);
    assert_eq!(TpmSpec::TPM_SPEC_LEVEL, TPM_SPEC_LEVEL);
    assert_eq!(TpmSpec::TPM_SPEC_VERSION, TPM_SPEC_VERSION);
    assert_eq!(TpmSpec::TPM_SPEC_YEAR, TPM_SPEC_YEAR);
    assert_eq!(TpmSpec::TPM_SPEC_ERRATA, TPM_SPEC_ERRATA);
    assert_eq!(TpmSpec::TPM_SPEC_DAY_OF_YEAR, TPM_SPEC_DAY_OF_YEAR);

    let spec = TpmSpec::new(TPM_SPEC_FAMILY);
    assert_eq!(spec.raw(), TPM_SPEC_FAMILY);
    assert_eq!(spec.id(), TPM_SPEC_FAMILY);
    assert_eq!(spec.code(), TPM_SPEC_FAMILY);
    assert_eq!(spec.as_u32(), TPM_SPEC_FAMILY);
    assert_eq!(u32::from(spec), TPM_SPEC_FAMILY);
    assert_eq!(TpmSpec::from(TPM_SPEC_FAMILY), spec);
    assert_eq!(spec, TPM_SPEC_FAMILY);
    assert_eq!(TPM_SPEC_FAMILY, spec);

    let mut buf = [0u8; 4];
    assert_eq!(spec.marshal(&mut buf), 4);
    assert_eq!(buf, *b"2.0\0");
    let mut slice = &buf[..];
    assert_eq!(TpmSpec::unmarshal(&mut slice), Ok(spec));
    assert!(slice.is_empty());
}

#[test]
fn test_tpm_constants32_and_max_derivation_bits() {
    assert_eq!(core::mem::size_of::<TpmConstants32>(), 4);
    assert_eq!(TPM_GENERATED_VALUE, 0xFF54_4347);
    assert_eq!(TPM2_GENERATED_VALUE, 0xFF54_4347);
    assert_eq!(TPM_GENERATED_VALUE.to_be_bytes(), *b"\xffTCG");
    assert_eq!(TPM_GENERATED_VALUE.to_be_bytes(), TpmGenerated::VALUE);
    assert_eq!(TpmGenerated::U32_VALUE, 0xFF54_4347);

    assert_eq!(TPM2_MAX_DERIVATION_BITS, 8192);
    assert_eq!(TPM_MAX_DERIVATION_BITS, 8192);
    assert_eq!(TPM_MAX_DERIVATION_BITS, TPM2_MAX_DERIVATION_BITS);
    assert_eq!(TpmGenerated::MAX_DERIVATION_BITS, 8192);
    assert_eq!(TPM2_MAX_DERIVATION_BITS / 8, 1024);

    let mut buf = [0u8; 4];
    assert_eq!(TpmGenerated.marshal(&mut buf), 4);
    assert_eq!(buf, TPM_GENERATED_VALUE.to_be_bytes());
    let mut slice = &buf[..];
    assert_eq!(TpmGenerated::unmarshal(&mut slice), Ok(TpmGenerated));
    assert!(slice.is_empty());
}
