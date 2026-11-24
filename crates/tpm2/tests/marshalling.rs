use tpm2::*;

#[test]
fn test_marshal_struct_derive() {
    let name_buffer: [u8; 4] = [1, 2, 3, 4];
    let index_name = Tpm2bName::new(&name_buffer).unwrap();
    let nv_buffer = [24u8; 10];
    let nv_contents = Tpm2bMaxNvBuffer::new(&nv_buffer).unwrap();
    let info: TpmsNvCertifyInfo = TpmsNvCertifyInfo {
        index_name,
        offset: 10,
        nv_contents,
    };
    let mut marshal_buffer = [0u8; TpmsNvCertifyInfo::MAX_SIZE];
    let bytes = info.marshal(&mut marshal_buffer);

    // Build the expected output manually.
    let mut expected = Vec::with_capacity(bytes);
    expected.extend_from_slice(&(index_name.as_slice().len() as u16).to_be_bytes());
    expected.extend_from_slice(&name_buffer);
    expected.extend_from_slice(&info.offset.to_be_bytes());
    expected.extend_from_slice(&(nv_contents.as_slice().len() as u16).to_be_bytes());
    expected.extend_from_slice(&nv_buffer);

    assert_eq!(expected.len(), bytes);
    assert_eq!(expected, marshal_buffer[..expected.len()]);

    let mut slice = &marshal_buffer[..];
    let unmarshaled = TpmsNvCertifyInfo::unmarshal(&mut slice);
    assert_eq!(unmarshaled.unwrap(), info);
}

#[test]
fn test_marshal_enum_override() {
    let scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    let mut buffer = [0u8; <Option<TpmtKeyedHashScheme>>::MAX_SIZE];
    assert!(scheme.marshal(&mut buffer) > 0);
}

#[test]
#[cfg(all(
    feature = "sha256",
    feature = "aes128",
    feature = "rsassa",
    feature = "rsa2048"
))]
fn test_marshal_tpmt_public() {
    let aes_sym_def_obj = Some(TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgCipherMode::Cfb.into()),
    });
    let mut buffer = [0u8; <Option<TpmtSymDefObject>>::MAX_SIZE];
    let marsh = aes_sym_def_obj.marshal(&mut buffer);
    assert_eq!(marsh, buffer.len());
    let rsa_scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));

    let rsa_parms = TpmsRsaParms {
        symmetric: aes_sym_def_obj,
        scheme: rsa_scheme,
        key_bits: TpmiRsaKeyBits::Rsa2048,
        exponent: 2,
    };

    let pubkey_buf = [9u8; 24];
    let pubkey = Tpm2bPublicKeyRsa::new(&pubkey_buf).unwrap();

    let example = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED | TpmaObject::SENSITIVE_DATA_ORIGIN,
        auth_policy: Tpm2bDigest::new(&[2, 2, 4, 4]).unwrap(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, pubkey),
    };

    // Test a round-trip marshaling and unmarshaling, confirm that we get the same output.
    let mut buffer = [0u8; TpmtPublic::MAX_SIZE];
    let marsh = example.marshal(&mut buffer);
    let expected: [u8; 56] = [
        0, 1, 0, 11, 0, 1, 0, 32, 0, 4, 2, 2, 4, 4, 0, 6, 0, 128, 0, 67, 0, 20, 0, 11, 8, 0, 0, 0,
        0, 2, 0, 24, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    ];
    assert_eq!(marsh, expected.len());
    assert_eq!(&buffer[..marsh], &expected[..]);
    let mut slice = &buffer[..];
    let mut unmarsh = TpmtPublic::unmarshal(&mut slice);
    let bytes_example = unmarsh.unwrap();
    assert_eq!(bytes_example.object_attributes, example.object_attributes);
    let mut remarsh_buffer = [1u8; TpmtPublic::MAX_SIZE];
    let remarsh = bytes_example.marshal(&mut remarsh_buffer);
    assert_eq!(remarsh, marsh);
    assert_eq!(remarsh_buffer[..marsh], buffer[..marsh]);

    // Test invalid selector value.
    let mut alg_buf = [0u8; Alg::MAX_SIZE];
    assert!(Alg::SHA256.marshal(&mut alg_buf) > 0);
    let mut alg_slice = &alg_buf[..];
    unmarsh = TpmtPublic::unmarshal(&mut alg_slice);
    assert_eq!(unmarsh.err(), Some(tpm2::errors::UnmarshalError));
}

#[test]
fn test_2b_struct() {
    let creation_data = TpmsCreationData {
        pcr_select: TpmlPcrSelection::new(&[TpmsPcrSelection {
            hash: TpmiAlgHash::Sha256,
            selection: TpmsPcrSelect::new(&[0xF, 0xF, 0xF]).unwrap(),
        }])
        .unwrap(),
        pcr_digest: Tpm2bDigest::new(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9]).unwrap(),
        locality: TpmaLocality(0xA),
        parent_name_alg: Some(TpmiAlgHash::Sha256),
        parent_name: Tpm2bName::new(&[0xA, 0xB, 0xC, 0xD, 0xE, 0xF]).unwrap(),
        parent_qualified_name: Tpm2bName::default(),
        outside_info: Tpm2bData::new(&[0x1; 32]).unwrap(),
    };
    let creation_data_2b: Tpm2bCreationData = Tpm2b(creation_data);
    let out_creation_data = creation_data_2b.0;
    assert_eq!(creation_data, out_creation_data);
}

#[test]
fn test_tpml_digest_values_marshalling() {
    let lp =
        TpmlDigestValues::new(&[TpmtHa::Sha256(&[0xaa; 32]), TpmtHa::Sha256(&[0xbb; 32])]).unwrap();

    let mut buf = [0u8; TpmlDigestValues::MAX_SIZE];
    let len = lp.marshal(&mut buf);

    let mut reader = &buf[..len];
    let unmarshaled = TpmlDigestValues::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, lp);

    // Test count > TpmiAlgHash::HASH_COUNT fails.
    let invalid_count = (TpmiAlgHash::HASH_COUNT + 1) as u32;
    let mut invalid_buf = [0u8; 512];
    invalid_buf[0..4].copy_from_slice(&invalid_count.to_be_bytes());
    let mut offset = 4;
    for _ in 0..invalid_count {
        invalid_buf[offset..offset + 2]
            .copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
        offset += 2 + 32; // 2 bytes alg ID + 32 bytes SHA256 digest
    }

    let mut reader = &invalid_buf[..offset];
    let err = TpmlDigestValues::unmarshal(&mut reader).unwrap_err();
    assert_eq!(err, tpm2::errors::UnmarshalError);
}

#[test]
fn test_tpml_pcr_selection_marshalling() {
    let selection = TpmsPcrSelection {
        hash: TpmiAlgHash::Sha256,
        selection: TpmsPcrSelect::new(&[0xF; TpmsPcrSelect::MIN]).unwrap(),
    };
    let lp = TpmlPcrSelection::new(&[selection]).unwrap();

    let mut buf = [0u8; TpmlPcrSelection::MAX_SIZE];
    let len = lp.marshal(&mut buf);

    let mut reader = &buf[..len];
    let unmarshaled = TpmlPcrSelection::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, lp);

    // Test count > TpmiAlgHash::HASH_COUNT fails.
    let invalid_count = (TpmiAlgHash::HASH_COUNT + 1) as u32;
    let mut invalid_buf = [0u8; 512];
    invalid_buf[0..4].copy_from_slice(&invalid_count.to_be_bytes());
    let mut offset = 4;
    for _ in 0..invalid_count {
        invalid_buf[offset..offset + 2]
            .copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
        invalid_buf[offset + 2] = TpmsPcrSelect::MIN as u8; // sizeof_select
        invalid_buf[offset + 3..offset + 3 + TpmsPcrSelect::MIN]
            .copy_from_slice(&[0u8; TpmsPcrSelect::MIN]); // pcr_select
        offset += 3 + TpmsPcrSelect::MIN;
    }

    let mut reader = &invalid_buf[..offset];
    let err = TpmlPcrSelection::unmarshal(&mut reader).unwrap_err();
    assert_eq!(err, tpm2::errors::UnmarshalError);

    // Verifying constructing TpmsPcrSelect with invalid bounds (length > MAX or < MIN) fails
    assert!(TpmsPcrSelect::new(&[0xF; TpmsPcrSelect::MAX + 1]).is_none());
    assert!(TpmsPcrSelect::new(&[0xF; TpmsPcrSelect::MIN - 1]).is_none());

    // Verifying unmarshalling invalid bounds (sizeof_select > MAX) fails
    let mut invalid_select_buf = [0u8; 10];
    invalid_select_buf[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    invalid_select_buf[2] = (TpmsPcrSelect::MAX + 1) as u8;
    invalid_select_buf[3..3 + TpmsPcrSelect::MAX + 1]
        .copy_from_slice(&[0xF; TpmsPcrSelect::MAX + 1]);

    let mut reader = &invalid_select_buf[..3 + TpmsPcrSelect::MAX + 1];
    let err = TpmsPcrSelection::unmarshal(&mut reader).unwrap_err();
    assert_eq!(err, tpm2::errors::UnmarshalError);
}

#[test]
#[cfg(all(feature = "sha256", feature = "aes128", feature = "nist_p256"))]
fn test_print_ecc_parent() {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgCipherMode::Cfb.into()),
                }),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    };
    let tpm2b_pub: Tpm2bPublic = Tpm2b(public_area);
    let mut buf = [0u8; Tpm2bPublic::MAX_SIZE];
    let len = tpm2b_pub.marshal(&mut buf);
    println!(
        "ECC Parent Tpm2bPublic bytes (len={}): {:02x?}",
        len,
        &buf[..len]
    );
}

#[test]
fn test_tpms_capability_data_marshalling() {
    let cap_data = TpmsCapabilityData::Algorithms(TpmlAlgProperty::default());
    assert_eq!(cap_data.capability(), TpmCap::Algs);

    let mut buf = [0u8; TpmsCapabilityData::MAX_SIZE];
    let len = cap_data.marshal(&mut buf);
    assert!(len > 0);

    let mut reader = &buf[..len];
    let unmarshaled = TpmsCapabilityData::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, cap_data);
    assert_eq!(unmarshaled.capability(), TpmCap::Algs);

    let act_data = TpmsActData {
        handle: Handle::RH_ACT_0,
        timeout: 30,
        attributes: TpmaAct::SIGNALED,
    };
    let cap_data = TpmsCapabilityData::ActData(TpmlActData::new(&[act_data]).unwrap());
    assert_eq!(cap_data.capability(), TpmCap::ACT);

    let len = cap_data.marshal(&mut buf);
    let mut reader = &buf[..len];
    let unmarshaled = TpmsCapabilityData::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, cap_data);
    assert_eq!(unmarshaled.capability(), TpmCap::ACT);
}

#[test]
fn test_tpmt_nv_public_2_marshalling() {
    let public = TpmsNvPublic {
        nv_index: Handle(0x01000001),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::from(TpmNt::Ordinary) | TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    };
    let nv_public = TpmtNvPublic2::NvIndex(public);
    assert_eq!(nv_public.handle_type(), TpmHt::NVIndex);
    assert_eq!(nv_public.nv_index(), public.nv_index);

    let mut buf = [0u8; TpmtNvPublic2::MAX_SIZE];
    let len = nv_public.marshal(&mut buf);
    let mut reader = &buf[..len];
    let unmarshaled = TpmtNvPublic2::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, nv_public);

    // Test a handle type that does not match the nvIndex handle fails.
    let mismatched = TpmtNvPublic2::PermanentNv(public);
    let len = mismatched.marshal(&mut buf);
    let mut reader = &buf[..len];
    let err = TpmtNvPublic2::unmarshal(&mut reader).unwrap_err();
    assert_eq!(err, tpm2::errors::UnmarshalError);
}

#[test]
fn test_unmarshal_tpma_reserved_bits() {
    // Reserved bits of TPM 2.0 Part 2: Structures (v185), Table 37 (TPMA_OBJECT),
    // Table 249 (TPMA_NV) and Table 250 (TPMA_NV_EXP).
    const TPMA_OBJECT_RESERVED: u32 = 0xFFF0_F009;
    const TPMA_NV_RESERVED: u32 = 0x01F0_0300;
    const TPMA_NV_EXP_RESERVED: u64 = 0xFFFF_FFF8_01F0_0300;

    // Each single bit unmarshals only if it is not reserved.
    for bit in 0..u32::BITS {
        let value = 1u32 << bit;
        assert_eq!(
            TpmaObject::unmarshal(&mut &value.to_be_bytes()[..]).is_ok(),
            value & TPMA_OBJECT_RESERVED == 0,
            "TPMA_OBJECT bit {bit}"
        );
        assert_eq!(
            TpmaNv::unmarshal(&mut &value.to_be_bytes()[..]).is_ok(),
            value & TPMA_NV_RESERVED == 0,
            "TPMA_NV bit {bit}"
        );
    }
    for bit in 0..u64::BITS {
        let value = 1u64 << bit;
        assert_eq!(
            TpmaNvExp::unmarshal(&mut &value.to_be_bytes()[..]).is_ok(),
            value & TPMA_NV_EXP_RESERVED == 0,
            "TPMA_NV_EXP bit {bit}"
        );
    }

    // All defined bits together still unmarshal.
    assert_eq!(
        TpmaObject::unmarshal(&mut &(!TPMA_OBJECT_RESERVED).to_be_bytes()[..]),
        Ok(TpmaObject(!TPMA_OBJECT_RESERVED))
    );
    assert_eq!(
        TpmaNv::unmarshal(&mut &(!TPMA_NV_RESERVED).to_be_bytes()[..]),
        Ok(TpmaNv(!TPMA_NV_RESERVED))
    );
    assert_eq!(
        TpmaNvExp::unmarshal(&mut &(!TPMA_NV_EXP_RESERVED).to_be_bytes()[..]),
        Ok(TpmaNvExp(!TPMA_NV_EXP_RESERVED))
    );

    // A reserved bit next to defined bits is rejected.
    let object = 0x0006_0072u32;
    assert!(TpmaObject::unmarshal(&mut &object.to_be_bytes()[..]).is_ok());
    for reserved in [1u32 << 0, 1 << 3] {
        let value = object | reserved;
        assert_eq!(
            TpmaObject::unmarshal(&mut &value.to_be_bytes()[..]),
            Err(tpm2::errors::UnmarshalError)
        );
    }
    assert_eq!(
        TpmaNv::unmarshal(&mut &0x0004_0104u32.to_be_bytes()[..]),
        Err(tpm2::errors::UnmarshalError)
    );
    assert_eq!(
        TpmaNvExp::unmarshal(&mut &0x0000_0008_0004_0004u64.to_be_bytes()[..]),
        Err(tpm2::errors::UnmarshalError)
    );
}

// Hierarchies that are and are not values of `TPMI_RH_HIERARCHY+`, defined in TPM 2.0 Part 2:
// Structures (v185), Section 9.13 (Table 59).
const HIERARCHIES: [Handle; 14] = [
    Handle::RH_OWNER,
    Handle::RH_ENDORSEMENT,
    Handle::RH_PLATFORM,
    Handle::RH_NULL,
    Handle::RH_FW_OWNER,
    Handle::RH_FW_ENDORSEMENT,
    Handle::RH_FW_PLATFORM,
    Handle::RH_FW_NULL,
    Handle::RH_SVN_OWNER_BASE,
    Handle(0x4001_FFFF),
    Handle::RH_SVN_ENDORSEMENT_BASE,
    Handle::RH_SVN_PLATFORM_BASE,
    Handle::RH_SVN_NULL_BASE,
    Handle(0x4004_FFFF),
];
const NOT_HIERARCHIES: [Handle; 8] = [
    Handle(0),
    Handle(0x4000_0002),
    Handle::RS_PW,
    Handle::RH_LOCKOUT,
    Handle::RH_PLATFORM_NV,
    Handle(0x4000_FFFF),
    Handle(0x4005_0000),
    Handle(0x8000_0000),
];

fn tpms_context_unmarshals(saved_handle: Handle, hierarchy: Handle) -> bool {
    let context = TpmsContext {
        sequence: 1,
        saved_handle,
        hierarchy,
        context_blob: Tpm2bContextData::new(&[1, 2, 3, 4]).unwrap(),
    };
    let mut buffer = [0u8; TpmsContext::MAX_SIZE];
    let len = context.marshal(&mut buffer);
    match TpmsContext::unmarshal(&mut &buffer[..len]) {
        Ok(unmarshaled) => {
            assert_eq!(unmarshaled, context);
            true
        }
        Err(_) => false,
    }
}

#[test]
fn test_unmarshal_tpms_context_handles() {
    // `savedHandle` is a `TPMI_DH_SAVED`, defined in Section 9.12 (Table 58).
    for saved_handle in [
        0x0200_0000,
        0x0200_0001,
        0x02FF_FFFF,
        0x0300_0000,
        0x03FF_FFFF,
        0x8000_0000,
        0x8000_0001,
        0x8000_0002,
    ] {
        assert!(
            tpms_context_unmarshals(Handle(saved_handle), Handle::RH_OWNER),
            "savedHandle {saved_handle:#010x}"
        );
    }
    for saved_handle in [
        0x0000_0000,
        0x0100_0000,
        0x0400_0000,
        0x4000_0001,
        0x7FFF_FFFF,
        0x8000_0003,
        0x80FF_FFFF,
        0x8100_0001,
    ] {
        assert!(
            !tpms_context_unmarshals(Handle(saved_handle), Handle::RH_OWNER),
            "savedHandle {saved_handle:#010x}"
        );
    }

    for hierarchy in HIERARCHIES {
        assert!(
            tpms_context_unmarshals(Handle(0x8000_0000), hierarchy),
            "hierarchy {hierarchy:?}"
        );
    }
    for hierarchy in NOT_HIERARCHIES {
        assert!(
            !tpms_context_unmarshals(Handle(0x8000_0000), hierarchy),
            "hierarchy {hierarchy:?}"
        );
    }
}

#[test]
fn test_unmarshal_ticket_hierarchy() {
    // A ticket is a tag, a hierarchy and a digest (Section 10.6, Tables 110, 113, 114 and 115).
    // The digest of `TPM_ST_DIGEST_VERIFIED` follows a hash algorithm.
    fn ticket_bytes(tag: TpmSt, hierarchy: Handle) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut tag_buffer = [0u8; TpmSt::MAX_SIZE];
        let len = tag.marshal(&mut tag_buffer);
        bytes.extend_from_slice(&tag_buffer[..len]);
        bytes.extend_from_slice(&hierarchy.0.to_be_bytes());
        if tag == TpmSt::DIGEST_VERIFIED {
            let mut alg_buffer = [0u8; Alg::MAX_SIZE];
            let len = Alg::SHA256.marshal(&mut alg_buffer);
            bytes.extend_from_slice(&alg_buffer[..len]);
        }
        bytes.extend_from_slice(&[0, 4, 1, 2, 3, 4]);
        bytes
    }
    fn ticket_unmarshals(tag: TpmSt, hierarchy: Handle) -> bool {
        let bytes = ticket_bytes(tag, hierarchy);
        let mut src = &bytes[..];
        let unmarshaled = match tag {
            TpmSt::CREATION => TpmtTkCreation::unmarshal(&mut src).is_ok(),
            TpmSt::VERIFIED | TpmSt::MESSAGE_VERIFIED | TpmSt::DIGEST_VERIFIED => {
                TpmtTkVerified::unmarshal(&mut src).is_ok()
            }
            TpmSt::AUTH_SIGNED | TpmSt::AUTH_SECRET => TpmtTkAuth::unmarshal(&mut src).is_ok(),
            _ => TpmtTkHashcheck::unmarshal(&mut src).is_ok(),
        };
        assert!(!unmarshaled || src.is_empty());
        unmarshaled
    }

    for (name, tag) in [
        ("CREATION", TpmSt::CREATION),
        ("VERIFIED", TpmSt::VERIFIED),
        ("MESSAGE_VERIFIED", TpmSt::MESSAGE_VERIFIED),
        ("DIGEST_VERIFIED", TpmSt::DIGEST_VERIFIED),
        ("AUTH_SIGNED", TpmSt::AUTH_SIGNED),
        ("AUTH_SECRET", TpmSt::AUTH_SECRET),
        ("HASHCHECK", TpmSt::HASHCHECK),
    ] {
        for hierarchy in HIERARCHIES {
            assert!(ticket_unmarshals(tag, hierarchy), "{name} {hierarchy:?}");
        }
        for hierarchy in NOT_HIERARCHIES {
            assert!(!ticket_unmarshals(tag, hierarchy), "{name} {hierarchy:?}");
        }
    }
}
