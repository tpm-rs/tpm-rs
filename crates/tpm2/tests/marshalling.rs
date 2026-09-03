use tpm2::*;

#[test]
fn test_marshal_struct_derive() {
    let name_buffer: [u8; 4] = [1, 2, 3, 4];
    let index_name = Tpm2bName::from_bytes(&name_buffer).unwrap();
    let nv_buffer = [24u8; 10];
    let nv_contents = Tpm2bMaxNvBuffer::from_bytes(&nv_buffer).unwrap();
    let info: TpmsNvCertifyInfo = TpmsNvCertifyInfo {
        index_name,
        offset: 10,
        nv_contents,
    };
    let mut marshal_buffer = [0u8; TpmsNvCertifyInfo::MAX_SIZE];
    let bytes = info.marshal(&mut marshal_buffer);

    // Build the expected output manually.
    let mut expected = Vec::with_capacity(bytes);
    expected.extend_from_slice(&index_name.get_size().to_be_bytes());
    expected.extend_from_slice(&name_buffer);
    expected.extend_from_slice(&info.offset.to_be_bytes());
    expected.extend_from_slice(&nv_contents.get_size().to_be_bytes());
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
fn test_marshal_tpmt_public() {
    let aes_sym_def_obj = Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)));
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
    let pubkey = Tpm2bPublicKeyRsa::from_bytes(&pubkey_buf).unwrap();

    let example = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED | TpmaObject::SENSITIVE_DATA_ORIGIN,
        auth_policy: Tpm2bDigest::from_bytes(&[2, 2, 4, 4]).unwrap(),
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
        pcr_digest: Tpm2bDigest::from_bytes(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9])
            .unwrap(),
        locality: TpmaLocality(0xA),
        parent_name_alg: Some(TpmiAlgHash::Sha256),
        parent_name: Tpm2bName::from_bytes(&[0xA, 0xB, 0xC, 0xD, 0xE, 0xF]).unwrap(),
        parent_qualified_name: Tpm2bName::default(),
        outside_info: Tpm2bData::from_bytes(&[0x1; 32]).unwrap(),
    };
    let creation_data_2b = Tpm2bCreationData::from_struct(&creation_data).unwrap();
    let out_creation_data = creation_data_2b.to_struct().unwrap();
    assert_eq!(creation_data, out_creation_data);
}

#[test]
fn test_tpml_digest_values_marshalling() {
    let mut lp = TpmlDigestValues::default();
    lp.add(&TpmtHa::Sha256(&[0xaa; 32])).unwrap();
    lp.add(&TpmtHa::Sha256(&[0xbb; 32])).unwrap();

    let mut buf = [0u8; TpmlDigestValues::MAX_SIZE];
    let len = lp.marshal(&mut buf);

    let mut reader = &buf[..len];
    let unmarshaled = TpmlDigestValues::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, lp);

    // Test count > TpmtHa::HASH_COUNT fails.
    let invalid_count = (TpmtHa::HASH_COUNT + 1) as u32;
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

    // Test count > TpmtHa::HASH_COUNT fails.
    let invalid_count = (TpmtHa::HASH_COUNT + 1) as u32;
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
    assert!(TpmsPcrSelect::new(&[0xF; TpmsPcrSelect::MAX + 1]).is_err());
    assert!(TpmsPcrSelect::new(&[0xF; TpmsPcrSelect::MIN - 1]).is_err());

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
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    };
    let tpm2b_pub = Tpm2bPublic::from_struct(&public_area).unwrap();
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
}
