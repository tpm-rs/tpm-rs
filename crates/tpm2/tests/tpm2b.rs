use tpm2::*;

macro_rules! impl_test_tpm2b_simple {
    ($T:ty) => {
        const SIZE_OF_U16: usize = u16::MAX_SIZE;
        const SIZE_OF_TYPE: usize = <$T>::MAX_SIZE;

        /*
         * Generate arrays that are:
         *   - too small
         *   - smaller than buffer limit
         *   - same size as buffer limit
         *   - exceeding buffer limit
         */
        let too_small_size_buf: [u8; 1] = [0x00; 1];
        let mut smaller_size_buf: [u8; SIZE_OF_TYPE - 8] = [0xFF; SIZE_OF_TYPE - 8];
        let mut same_size_buf: [u8; SIZE_OF_TYPE] = [0xFF; SIZE_OF_TYPE];
        let mut bigger_size_buf: [u8; SIZE_OF_TYPE + 8] = [0xFF; SIZE_OF_TYPE + 8];

        let mut s = (smaller_size_buf.len() - SIZE_OF_U16) as u16;
        s.marshal((&mut smaller_size_buf[0..2]).try_into().unwrap());

        s = (same_size_buf.len() - SIZE_OF_U16) as u16;
        s.marshal((&mut same_size_buf[0..2]).try_into().unwrap());

        s = (bigger_size_buf.len() - SIZE_OF_U16) as u16;
        s.marshal((&mut bigger_size_buf[0..2]).try_into().unwrap());

        // too small should fail
        let mut slice = &too_small_size_buf[..];
        let mut result: Result<$T, tpm2::errors::UnmarshalError> = <$T>::unmarshal(&mut slice);
        assert!(result.is_err());

        // bigger size should consume only the prefix
        let mut slice = &bigger_size_buf[..];
        result = <$T>::unmarshal(&mut slice);
        assert!(result.is_err());

        // small, should be good
        let mut slice = &smaller_size_buf[..];
        result = <$T>::unmarshal(&mut slice);
        assert!(result.is_ok());
        let digest = result.unwrap();
        assert_eq!(
            digest.as_slice().len(),
            smaller_size_buf.len() - SIZE_OF_U16
        );
        assert_eq!(digest.as_slice(), &smaller_size_buf[SIZE_OF_U16..]);

        // same size should be good
        let mut slice = &same_size_buf[..];
        result = <$T>::unmarshal(&mut slice);
        assert!(result.is_ok());
        let digest = result.unwrap();
        assert_eq!(digest.as_slice().len(), same_size_buf.len() - SIZE_OF_U16);
        assert_eq!(digest.as_slice(), &same_size_buf[SIZE_OF_U16..]);

        let mut mbuf = [0u8; <$T>::MAX_SIZE];
        let mres = digest.marshal(&mut mbuf);
        assert_eq!(mres, digest.as_slice().len() + SIZE_OF_U16);
        let mut slice = &mbuf[..mres];
        let new_digest = <$T>::unmarshal(&mut slice).unwrap();
        assert_eq!(digest, new_digest);
    };
}

#[test]
fn test_try_unmarshal_tpm2b_name() {
    impl_test_tpm2b_simple! {Tpm2bName};
}

#[test]
fn test_try_unmarshal_tpm2b_context_data() {
    impl_test_tpm2b_simple! {Tpm2bContextData};
}

#[test]
fn test_try_unmarshal_tpm2b_data() {
    impl_test_tpm2b_simple! {Tpm2bData};
}

#[test]
fn test_try_unmarshal_tpm2b_digest() {
    impl_test_tpm2b_simple! {Tpm2bDigest};
}

#[test]
fn test_try_unmarshal_tpm2b_ecc_parameter() {
    impl_test_tpm2b_simple! {Tpm2bEccParameter};
}

#[test]
fn test_try_unmarshal_tpm2b_encrypted_secret() {
    impl_test_tpm2b_simple! {Tpm2bEncryptedSecret};
}

#[test]
fn test_try_unmarshal_tpm2b_event() {
    impl_test_tpm2b_simple! {Tpm2bEvent};
}

#[test]
fn test_try_unmarshal_tpm2b_id_object() {
    impl_test_tpm2b_simple! {Tpm2bIdObject};
}

#[test]
fn test_try_unmarshal_tpm2b_iv() {
    impl_test_tpm2b_simple! {Tpm2bIv};
}

#[test]
fn test_try_unmarshal_tpm2b_max_buffer() {
    impl_test_tpm2b_simple! {Tpm2bMaxBuffer};
}

#[test]
fn test_try_unmarshal_tpm2b_max_nv_buffer() {
    impl_test_tpm2b_simple! {Tpm2bMaxNvBuffer};
}

#[test]
fn test_try_unmarshal_tpm2b_private() {
    impl_test_tpm2b_simple! {Tpm2bPrivate};
}

#[test]
fn test_try_unmarshal_tpm2b_private_key_rsa() {
    impl_test_tpm2b_simple! {Tpm2bPrivateKeyRsa};
}

#[test]
fn test_try_unmarshal_tpm2b_public_key_rsa() {
    impl_test_tpm2b_simple! {Tpm2bPublicKeyRsa};
}

#[test]
fn test_try_unmarshal_tpm2b_sensitive_data() {
    impl_test_tpm2b_simple! {Tpm2bSensitiveData};
}

#[test]
fn test_try_unmarshal_tpm2b_sensitive() {
    // 1. Empty TPM2B_SENSITIVE (size = 0) is None for Option<Tpm2bSensitive> (TPM2B_SENSITIVE+)
    let empty_buf = [0x00u8, 0x00];
    let mut slice = &empty_buf[..];
    let empty_opt: Option<Tpm2bSensitive> = tpm2::Unmarshal::unmarshal(&mut slice).unwrap();
    assert_eq!(empty_opt, None);

    let mut slice2 = &empty_buf[..];
    assert_eq!(
        Tpm2bSensitive::unmarshal(&mut slice2),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );

    // 2. Valid TpmtSensitive round-trip
    let sens = TpmtSensitive {
        auth_value: Tpm2bAuth::new(b"secret").unwrap(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::KeyedHash(Tpm2bSensitiveData::new(b"data").unwrap()),
    };
    let wrapped: Tpm2bSensitive = Tpm2b(sens);
    let mut mbuf = [0u8; Tpm2bSensitive::MAX_SIZE];
    let len = wrapped.marshal(&mut mbuf);
    let mut slice = &mbuf[..len];
    let unmarshaled = Tpm2bSensitive::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled.0, sens);

    // 3. Invalid inner sensitiveType (0xFFFF) fails unmarshalling with UnmarshalError::TYPE
    let bad_buf = [0x00u8, 0x04, 0xFF, 0xFF, 0x00, 0x00];
    let mut slice = &bad_buf[..];
    assert_eq!(
        Tpm2bSensitive::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::TYPE)
    );
}

#[test]
fn test_try_unmarshal_tpm2b_sym_key() {
    impl_test_tpm2b_simple! {Tpm2bSymKey};
}

#[test]
fn test_try_unmarshal_tpm2b_timeout() {
    impl_test_tpm2b_simple! {Tpm2bTimeout};
}

#[test]
fn test_try_unmarshal_tpm2b_public() {
    // 1. Empty TPM2B_PUBLIC (size = 0) must fail with UnmarshalError::SIZE
    let empty_buf = [0x00u8, 0x00];
    let mut slice = &empty_buf[..];
    assert_eq!(
        Tpm2bPublic::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );

    // 2. Valid TpmtPublic round-trip
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    };
    let wrapped: Tpm2bPublic = Tpm2b(pub_area);
    let mut mbuf = [0u8; Tpm2bPublic::MAX_SIZE];
    let len = wrapped.marshal(&mut mbuf);
    let mut slice = &mbuf[..len];
    let unmarshaled = Tpm2bPublic::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled.0, pub_area);

    // 3. Trailing bytes inside TPM2B_PUBLIC buffer fails with UnmarshalError::SIZE
    let mut trailing_buf = [0u8; Tpm2bPublic::MAX_SIZE];
    let inner_len = len - 2;
    let new_size = (inner_len + 1) as u16;
    trailing_buf[0..2].copy_from_slice(&new_size.to_be_bytes());
    trailing_buf[2..2 + inner_len].copy_from_slice(&mbuf[2..len]);
    trailing_buf[2 + inner_len] = 0xFF;
    let mut slice = &trailing_buf[..3 + inner_len];
    assert_eq!(
        Tpm2bPublic::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );

    // 4. name_alg == None (TPM_ALG_NULL) fails with UnmarshalError::HASH for Tpm2bPublic,
    //    but succeeds for Tpm2bPublic::unmarshal_nullable.
    let null_alg_pub = TpmtPublic {
        name_alg: None,
        ..pub_area
    };
    let wrapped_null: tpm2::Tpm2bPublic = Tpm2b(null_alg_pub);
    let len_null = wrapped_null.marshal(&mut mbuf);
    let mut slice_std = &mbuf[..len_null];
    assert_eq!(
        Tpm2bPublic::unmarshal(&mut slice_std),
        Err(tpm2::errors::UnmarshalError::HASH)
    );
    let mut slice_null = &mbuf[..len_null];
    let unmarshaled_null = Tpm2bPublic::unmarshal_nullable(&mut slice_null).unwrap();
    assert_eq!(unmarshaled_null.to_struct_nullable().unwrap(), null_alg_pub);

    // 5. Empty buffer (size = 0) fails with UnmarshalError::SIZE for both Tpm2bPublic and Tpm2bPublic::unmarshal_nullable
    let empty_buf = [0x00u8, 0x00];
    let mut slice_empty = &empty_buf[..];
    assert_eq!(
        Tpm2bPublic::unmarshal(&mut slice_empty),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );
    let mut slice_empty_null = &empty_buf[..];
    assert_eq!(
        Tpm2bPublic::unmarshal_nullable(&mut slice_empty_null),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );
}

#[test]
fn test_try_unmarshal_tpm2b_sensitive_create() {
    // 1. Empty TPM2B_SENSITIVE_CREATE (size = 0) must fail with UnmarshalError::SIZE
    let empty_buf = [0x00u8, 0x00];
    let mut slice = &empty_buf[..];
    assert_eq!(
        Tpm2bSensitiveCreate::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );

    // 2. Default Tpm2bSensitiveCreate marshals to valid empty TpmsSensitiveCreate (size = 4)
    let def = Tpm2bSensitiveCreate::default();
    assert_eq!(def.0, TpmsSensitiveCreate::default());
    let mut mbuf = [0u8; Tpm2bSensitiveCreate::MAX_SIZE];
    let len = def.marshal(&mut mbuf);
    assert_eq!(len - 2, 4);
    let mut slice = &mbuf[..len];
    let unmarshaled = Tpm2bSensitiveCreate::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, def);

    // 3. Trailing bytes inside TPM2B_SENSITIVE_CREATE fails with UnmarshalError::SIZE
    let bad_buf = [0x00u8, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF];
    let mut slice = &bad_buf[..];
    assert_eq!(
        Tpm2bSensitiveCreate::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );
}

#[test]
fn test_try_unmarshal_tpm2b_ecc_point() {
    // 1. Empty TPM2B_ECC_POINT (size = 0) must fail with UnmarshalError::SIZE
    let empty_buf = [0x00u8, 0x00];
    let mut slice = &empty_buf[..];
    assert_eq!(
        Tpm2bEccPoint::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );

    // 2. Default Tpm2bEccPoint wraps empty TpmsEccPoint (size = 4) and round-trips via Tpm2b
    let def = Tpm2bEccPoint::default();
    let pt = def.0;
    assert_eq!(pt, TpmsEccPoint::default());
    assert_eq!(Tpm2b(pt), def);

    // 3. Non-empty point round-trip
    let custom_pt = TpmsEccPoint {
        x: Tpm2bEccParameter::new(&[1, 2, 3, 4]).unwrap(),
        y: Tpm2bEccParameter::new(&[5, 6, 7, 8]).unwrap(),
    };
    let wrapped: Tpm2bEccPoint = Tpm2b(custom_pt);
    let mut mbuf = [0u8; Tpm2bEccPoint::MAX_SIZE];
    let len = wrapped.marshal(&mut mbuf);
    let mut slice = &mbuf[..len];
    let unmarshaled = Tpm2bEccPoint::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled.0, custom_pt);

    // 4. Trailing bytes inside TPM2B_ECC_POINT fails with UnmarshalError::SIZE
    let bad_buf = [0x00u8, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF];
    let mut slice = &bad_buf[..];
    assert_eq!(
        Tpm2bEccPoint::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );
}

#[test]
fn test_try_unmarshal_tpm2b_nv_public() {
    // 1. Empty TPM2B_NV_PUBLIC (size = 0) must fail with UnmarshalError::SIZE
    let empty_buf = [0x00u8, 0x00];
    let mut slice = &empty_buf[..];
    assert_eq!(
        Tpm2bNvPublic::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );

    // 2. Valid TpmsNvPublic round-trip
    let nv_pub = TpmsNvPublic {
        nv_index: Handle(0x01000001),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    };
    let wrapped: Tpm2bNvPublic = Tpm2b(nv_pub);
    let mut mbuf = [0u8; Tpm2bNvPublic::MAX_SIZE];
    let len = wrapped.marshal(&mut mbuf);
    let mut slice = &mbuf[..len];
    let unmarshaled = Tpm2bNvPublic::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled.0, nv_pub);

    // 3. Trailing bytes inside TPM2B_NV_PUBLIC fails with UnmarshalError::SIZE
    let mut trailing_buf = [0u8; Tpm2bNvPublic::MAX_SIZE];
    let inner_len = len - 2;
    let new_size = (inner_len + 1) as u16;
    trailing_buf[0..2].copy_from_slice(&new_size.to_be_bytes());
    trailing_buf[2..2 + inner_len].copy_from_slice(&mbuf[2..len]);
    trailing_buf[2 + inner_len] = 0xFF;
    let mut slice = &trailing_buf[..3 + inner_len];
    assert_eq!(
        Tpm2bNvPublic::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );
}

#[test]
fn test_tpm2b_nv_public_2_spec_structures_and_bounds() {
    use tpm2::commands::{NVDefineSpace2, NVReadPublic2Rsp};

    // Verify MAX_SIZE and CAP constants per TPM 2.0 Part 2 Tables 229-232:
    // - TpmsNvPublic::MAX_SIZE = 78 bytes (4 + 2 + 4 + 66 + 2)
    // - TpmsNvPublicExpAttr::MAX_SIZE = 82 bytes (4 + 2 + 8 + 66 + 2)
    // - TpmuNvPublic2::MAX_SIZE = 82 bytes
    // - TpmtNvPublic2::MAX_SIZE = 83 bytes (1 + 82)
    // - Tpm2bNvPublic2::CAP = 83 bytes, Tpm2bNvPublic2::MAX_SIZE = 85 bytes
    assert_eq!(TpmsNvPublic::MAX_SIZE, 78);
    assert_eq!(TpmsNvPublicExpAttr::MAX_SIZE, 82);
    assert_eq!(TpmuNvPublic2::MAX_SIZE, 82);
    assert_eq!(TpmtNvPublic2::MAX_SIZE, 83);
    assert_eq!(Tpm2bNvPublic2::CAP, 83);
    assert_eq!(Tpm2bNvPublic2::MAX_BUFFER_SIZE, 83);
    assert_eq!(Tpm2bNvPublic2::MAX_SIZE, 85);

    // 1. Empty TPM2B_NV_PUBLIC_2 (size = 0) must fail with UnmarshalError::SIZE
    let empty_buf = [0x00u8, 0x00];
    let mut slice = &empty_buf[..];
    assert_eq!(
        Tpm2bNvPublic2::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );

    // 2. Full-capacity TPM_HT_NV_INDEX (79-byte TPMT_NV_PUBLIC_2 with 64-byte SHA-512 policy)
    let max_policy = Tpm2bDigest::new(&[0xAAu8; 64]).unwrap();
    let nv_pub_legacy = TpmsNvPublic {
        nv_index: Handle(0x0100_0001),
        name_alg: TpmiAlgHash::Sha512,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: max_policy,
        data_size: 64,
    };
    let tpmt_legacy = TpmtNvPublic2::new(TpmuNvPublic2::NvIndex(nv_pub_legacy));
    assert_eq!(tpmt_legacy.handle_type(), TpmHt::NVIndex);
    let wrapped_legacy = Tpm2bNvPublic2::from_struct(&tpmt_legacy).unwrap();
    assert_eq!(wrapped_legacy.get_size(), 79);
    assert_eq!(wrapped_legacy.to_struct().unwrap(), tpmt_legacy);

    let mut mbuf_legacy = [0u8; Tpm2bNvPublic2::MAX_SIZE];
    let len_legacy = wrapped_legacy.marshal(&mut mbuf_legacy);
    assert_eq!(len_legacy, 2 + 79);
    let mut slice_legacy = &mbuf_legacy[..len_legacy];
    let unmarshaled_legacy = Tpm2bNvPublic2::unmarshal(&mut slice_legacy).unwrap();
    assert!(slice_legacy.is_empty());
    assert_eq!(unmarshaled_legacy.0, tpmt_legacy);

    // 3. Full-capacity TPM_HT_EXTERNAL_NV (83-byte TPMT_NV_PUBLIC_2 with 64-byte policy & 8-byte TPMA_NV_EXP)
    let nv_pub_exp = TpmsNvPublicExpAttr {
        nv_index: Handle(0x1100_0042),
        name_alg: TpmiAlgHash::Sha512,
        attributes: TpmaNvExp::OWNERWRITE
            | TpmaNvExp::OWNERREAD
            | TpmaNvExp::EXTERNAL_NV_ENCRYPTION
            | TpmaNvExp::EXTERNAL_NV_INTEGRITY
            | TpmaNvExp::EXTERNAL_NV_ANTIROLLBACK,
        auth_policy: max_policy,
        data_size: 128,
    };
    let tpmt_exp = TpmtNvPublic2::new(TpmuNvPublic2::ExternalNv(nv_pub_exp));
    assert_eq!(tpmt_exp.handle_type(), TpmHt::ExternalNv);
    let wrapped_exp = Tpm2bNvPublic2::from_struct(&tpmt_exp).unwrap();
    assert_eq!(wrapped_exp.get_size(), 83);
    assert_eq!(wrapped_exp.to_struct().unwrap(), tpmt_exp);

    let mut mbuf_exp = [0u8; Tpm2bNvPublic2::MAX_SIZE];
    let len_exp = wrapped_exp.marshal(&mut mbuf_exp);
    assert_eq!(len_exp, 2 + 83);
    let mut slice_exp = &mbuf_exp[..len_exp];
    let unmarshaled_exp = Tpm2bNvPublic2::unmarshal(&mut slice_exp).unwrap();
    assert!(slice_exp.is_empty());
    assert_eq!(unmarshaled_exp.0, tpmt_exp);

    // 4. TPM_HT_PERMANENT_NV variant round-trip
    let tpmt_perm = TpmtNvPublic2::new(TpmuNvPublic2::PermanentNv(nv_pub_legacy));
    assert_eq!(tpmt_perm.handle_type(), TpmHt::PermanentNv);
    let wrapped_perm = Tpm2bNvPublic2::from_struct(&tpmt_perm).unwrap();
    let mut mbuf_perm = [0u8; Tpm2bNvPublic2::MAX_SIZE];
    let len_perm = wrapped_perm.marshal(&mut mbuf_perm);
    let mut slice_perm = &mbuf_perm[..len_perm];
    let unmarshaled_perm = Tpm2bNvPublic2::unmarshal(&mut slice_perm).unwrap();
    assert!(slice_perm.is_empty());
    assert_eq!(unmarshaled_perm.0, tpmt_perm);

    // 5. Validate2bStruct rejects mismatched handle_type vs public_area
    let mismatched = Tpm2bNvPublic2::new(TpmtNvPublic2 {
        handle_type: TpmHt::ExternalNv,
        public_area: TpmuNvPublic2::NvIndex(nv_pub_legacy),
    });
    assert_eq!(
        mismatched.to_struct(),
        Err(tpm2::errors::UnmarshalError::SELECTOR)
    );

    // 6. Invalid handleType selectors (e.g. TpmHt::PCR = 0x00, TpmHt::Permanent = 0x40, unknown 0xFF)
    // must fail with UnmarshalError::SELECTOR
    for bad_ht in [0x00u8, 0x02, 0x40, 0x80, 0xFF] {
        let mut bad_buf = mbuf_legacy;
        bad_buf[2] = bad_ht;
        let mut s = &bad_buf[..len_legacy];
        assert_eq!(
            Tpm2bNvPublic2::unmarshal(&mut s),
            Err(tpm2::errors::UnmarshalError::SELECTOR)
        );
    }

    // 7. Invalid nvIndex handle in TpmsNvPublicExpAttr (e.g. 0x0100_0001 instead of 0x1100_xxxx)
    // must fail with UnmarshalError::VALUE
    let mut bad_exp_handle = mbuf_exp;
    bad_exp_handle[3..7].copy_from_slice(&0x0100_0001u32.to_be_bytes());
    let mut s = &bad_exp_handle[..len_exp];
    assert_eq!(
        Tpm2bNvPublic2::unmarshal(&mut s),
        Err(tpm2::errors::UnmarshalError::VALUE)
    );

    // 8. Reserved bits in TpmaNvExp (bit 35 = 1 << 35) must fail with UnmarshalError::RESERVED_BITS
    let mut bad_exp_attr = mbuf_exp;
    let reserved_attr: u64 = 1u64 << 35;
    bad_exp_attr[9..17].copy_from_slice(&reserved_attr.to_be_bytes());
    let mut s = &bad_exp_attr[..len_exp];
    assert_eq!(
        Tpm2bNvPublic2::unmarshal(&mut s),
        Err(tpm2::errors::UnmarshalError::RESERVED_BITS)
    );

    // 9. Oversized dataSize (> TPM2_MAX_NV_INDEX_SIZE) in TpmsNvPublicExpAttr fails with UnmarshalError::SIZE
    let mut bad_exp_datasize = mbuf_exp;
    let over_data_size: u16 = TPM2_MAX_NV_INDEX_SIZE + 1;
    bad_exp_datasize[len_exp - 2..len_exp].copy_from_slice(&over_data_size.to_be_bytes());
    let mut s = &bad_exp_datasize[..len_exp];
    assert_eq!(
        Tpm2bNvPublic2::unmarshal(&mut s),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );

    // 10. NVDefineSpace2 command and NVReadPublic2Rsp response round-trip and parameter error tagging
    let cmd = NVDefineSpace2 {
        auth: Tpm2bAuth::new(&[0x11, 0x22, 0x33, 0x44]).unwrap(),
        public_info: wrapped_exp,
    };
    let mut cmd_buf = [0u8; NVDefineSpace2::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);
    let mut cmd_slice = &cmd_buf[..cmd_len];
    let unmarshaled_cmd = NVDefineSpace2::unmarshal(&mut cmd_slice).unwrap();
    assert!(cmd_slice.is_empty());
    assert_eq!(unmarshaled_cmd, cmd);

    // Corrupt handleType in parameter 2 of NVDefineSpace2 -> UnmarshalError::SELECTOR.in_parameter(2)
    let mut bad_cmd_buf = cmd_buf;
    // auth is 2 + 4 = 6 bytes, public_info size is 2 bytes at 6..8, handleType is at index 8
    bad_cmd_buf[8] = 0xFF;
    let mut bad_cmd_slice = &bad_cmd_buf[..cmd_len];
    assert_eq!(
        NVDefineSpace2::unmarshal(&mut bad_cmd_slice),
        Err(tpm2::errors::UnmarshalError::SELECTOR.in_parameter(2))
    );

    let rsp = NVReadPublic2Rsp {
        nv_public: wrapped_exp,
        nv_name: Tpm2bName::new(&[0x00, 0x0B, 0xAA, 0xBB]).unwrap(),
    };
    let mut rsp_buf = [0u8; NVReadPublic2Rsp::MAX_SIZE];
    let rsp_len = rsp.marshal(&mut rsp_buf);
    let mut rsp_slice = &rsp_buf[..rsp_len];
    let unmarshaled_rsp = NVReadPublic2Rsp::unmarshal(&mut rsp_slice).unwrap();
    assert!(rsp_slice.is_empty());
    assert_eq!(unmarshaled_rsp, rsp);
}

macro_rules! impl_stress_test_tpm2b_simple {
    ($T:ty) => {
        let max_size = <$T>::CAP;
        let test_sizes = [0, 1, 2, max_size / 2, max_size];
        for &size in &test_sizes {
            if size > max_size {
                continue;
            }
            let bytes = vec![0u8; size];
            let struct_val = <$T>::new(&bytes).unwrap();
            let expected_marshaled_len = 2 + size;

            let mut mbuf = [0u8; <$T>::MAX_SIZE];
            let res = struct_val.marshal(&mut mbuf);
            assert_eq!(res, expected_marshaled_len);
            let mut slice = &mbuf[..res];
            let unmarshaled = <$T>::unmarshal(&mut slice).unwrap();
            assert_eq!(struct_val, unmarshaled);
        }
    };
}

#[test]
fn test_all_tpm2b_simple_marshalling_bounds() {
    impl_stress_test_tpm2b_simple! {Tpm2bName};
    impl_stress_test_tpm2b_simple! {Tpm2bContextData};
    impl_stress_test_tpm2b_simple! {Tpm2bData};
    impl_stress_test_tpm2b_simple! {Tpm2bDigest};
    impl_stress_test_tpm2b_simple! {Tpm2bEccParameter};
    impl_stress_test_tpm2b_simple! {Tpm2bEncryptedSecret};
    impl_stress_test_tpm2b_simple! {Tpm2bEvent};
    impl_stress_test_tpm2b_simple! {Tpm2bIdObject};
    impl_stress_test_tpm2b_simple! {Tpm2bIv};
    impl_stress_test_tpm2b_simple! {Tpm2bMaxBuffer};
    impl_stress_test_tpm2b_simple! {Tpm2bMaxNvBuffer};
    impl_stress_test_tpm2b_simple! {Tpm2bPrivate};
    impl_stress_test_tpm2b_simple! {Tpm2bPrivateKeyRsa};
    impl_stress_test_tpm2b_simple! {Tpm2bPublicKeyRsa};
    impl_stress_test_tpm2b_simple! {Tpm2bSensitiveData};
    impl_stress_test_tpm2b_simple! {Tpm2bSymKey};
    impl_stress_test_tpm2b_simple! {Tpm2bTimeout};
}

#[test]
fn test_unmarshal_invalid_public_type() {
    let mut buf = [0u8; 12];
    buf[0] = 0x00;
    buf[1] = 10; // size of TpmtPublic
    buf[2] = 0x00;
    buf[3] = 0x00; // type = 0 (invalid)
    buf[4] = 0x00;
    buf[5] = 0x0B; // name_alg = SHA256
    // rest are 0 (attrs = 0, auth_policy size = 0)

    let mut slice: &[u8] = &buf;
    let res = Tpm2bPublic::unmarshal(&mut slice);
    assert_eq!(res.unwrap_err(), tpm2::errors::UnmarshalError::TYPE);
}

#[test]
fn test_tpm2b_trailing_bytes_rejected() {
    // Empty TpmsEccPoint marshals to 4 bytes (x.size = 0, y.size = 0),
    // so an outer Tpm2bEccPoint size of 5 leaves 1 trailing byte inside the Tpm2b payload.
    let mut slice: &[u8] = &[0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF];
    assert_eq!(
        Tpm2bEccPoint::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError::SIZE)
    );
}

#[test]
fn test_option_tpm2b_sensitive() {
    // None <-> [0, 0]
    let none: Option<Tpm2bSensitive> = None;
    let mut buf = [0xFFu8; Option::<Tpm2bSensitive>::MAX_SIZE];
    let written = none.marshal(&mut buf);
    assert_eq!(written, 2);
    assert_eq!(&buf[..2], &[0, 0]);

    let mut slice: &[u8] = &[0, 0, 0xAA];
    let unmarshaled = Option::<Tpm2bSensitive>::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, None);
    assert_eq!(slice, &[0xAA]);

    // Some(...) roundtrip
    let some: Option<Tpm2bSensitive> = Some(Tpm2b(TpmtSensitive {
        auth_value: Tpm2bAuth::new(&[1, 2, 3, 4]).unwrap(),
        seed_value: Tpm2bDigest::new(&[]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::new(&[0xDE, 0xAD]).unwrap(),
        ),
    }));
    let written = some.marshal(&mut buf);
    let mut slice: &[u8] = &buf[..written];
    let unmarshaled = Option::<Tpm2bSensitive>::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, some);
    assert!(slice.is_empty());

    // Direct Tpm2bSensitive unmarshal rejects empty size
    let mut empty_slice: &[u8] = &[0, 0];
    assert!(Tpm2bSensitive::unmarshal(&mut empty_slice).is_err());
}

#[test]
fn test_tpm2b_private_key_rsa_spec_max_buffer_size() {
    assert_eq!(Tpm2bPrivateKeyRsa::CAP, 1280);
    assert_eq!(Tpm2bPrivateKeyRsa::CAP, TPM2_RSA_PRIVATE_SIZE);
    assert_eq!(Tpm2bPrivateKeyRsa::MAX_SIZE, 2 + 1280);

    // 1280 bytes should succeed for new, marshal, and unmarshal
    let valid_buf = [0xAAu8; 1280];
    let key = Tpm2bPrivateKeyRsa::new(&valid_buf).unwrap();
    assert_eq!(key.as_slice().len(), 1280);
    assert_eq!(key.as_slice(), &valid_buf[..]);

    let mut marshaled = [0u8; Tpm2bPrivateKeyRsa::MAX_SIZE];
    let len = key.marshal(&mut marshaled);
    assert_eq!(len, 2 + 1280);
    let mut slice = &marshaled[..len];
    let unmarshaled = Tpm2bPrivateKeyRsa::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, key);
    assert!(slice.is_empty());

    // Oversized buffers (e.g. 1281 and 1536) must fail with UnmarshalError::SIZE
    for oversized_len in [1281usize, 1400, 1536] {
        let oversized_buf = vec![0xBBu8; oversized_len];
        assert!(Tpm2bPrivateKeyRsa::new(&oversized_buf).is_none());

        let mut wire_bytes = Vec::with_capacity(2 + oversized_len);
        wire_bytes.extend_from_slice(&(oversized_len as u16).to_be_bytes());
        wire_bytes.extend_from_slice(&oversized_buf);
        let mut slice = &wire_bytes[..];
        assert_eq!(
            Tpm2bPrivateKeyRsa::unmarshal(&mut slice),
            Err(errors::UnmarshalError::SIZE)
        );
    }
}

#[test]
fn test_tpm2b_private_spec_max_buffer_size_rsa_4096() {
    let expected_max_private =
        Tpm2bDigest::MAX_SIZE + Tpm2bDigest::MAX_SIZE + Tpm2bSensitive::MAX_SIZE;
    assert_eq!(expected_max_private, 1550);
    assert_eq!(TPM2_MAX_PRIVATE_SIZE, expected_max_private);
    assert_eq!(Tpm2bPrivate::CAP, expected_max_private);
    assert_eq!(Tpm2bPrivate::MAX_SIZE, 2 + expected_max_private);

    // Construct a full 1550-byte _PRIVATE blob corresponding to a 4096-bit RSA CRT key:
    // integrityOuter (TPM2B_DIGEST: 66 bytes) + integrityInner (TPM2B_DIGEST: 66 bytes) +
    // sensitive (TPM2B_SENSITIVE: 1418 bytes).
    let outer_digest = Tpm2bDigest::new(&[0x11u8; Tpm2bDigest::CAP]).unwrap();
    let inner_digest = Tpm2bDigest::new(&[0x22u8; Tpm2bDigest::CAP]).unwrap();
    let rsa_sensitive_struct = TpmtSensitive {
        auth_value: Tpm2bAuth::new(&[0x33u8; Tpm2bAuth::CAP]).unwrap(),
        seed_value: Tpm2bDigest::new(&[0x44u8; Tpm2bDigest::CAP]).unwrap(),
        sensitive: TpmuSensitiveComposite::Rsa(
            Tpm2bPrivateKeyRsa::new(&[0x55u8; TPM2_RSA_PRIVATE_SIZE]).unwrap(),
        ),
    };
    let sensitive_2b: Tpm2bSensitive = Tpm2b(rsa_sensitive_struct);

    let mut private_blob = Vec::with_capacity(expected_max_private);
    let mut digest_buf = [0u8; Tpm2bDigest::MAX_SIZE];
    let len1 = outer_digest.marshal(&mut digest_buf);
    private_blob.extend_from_slice(&digest_buf[..len1]);
    let len2 = inner_digest.marshal(&mut digest_buf);
    private_blob.extend_from_slice(&digest_buf[..len2]);
    let mut sens_buf = [0u8; Tpm2bSensitive::MAX_SIZE];
    let len3 = sensitive_2b.marshal(&mut sens_buf);
    assert_eq!(len3 - 2, TpmtSensitive::MAX_SIZE);
    private_blob.extend_from_slice(&sens_buf[..len3]);

    assert_eq!(private_blob.len(), 1550);

    // Verify Tpm2bPrivate can hold, marshal, and unmarshal the full 1550-byte blob
    let tpm2b_priv = Tpm2bPrivate::new(&private_blob).unwrap();
    assert_eq!(tpm2b_priv.as_slice().len(), 1550);
    assert_eq!(tpm2b_priv.as_slice(), &private_blob[..]);

    let mut marshaled = [0u8; Tpm2bPrivate::MAX_SIZE];
    let marshaled_len = tpm2b_priv.marshal(&mut marshaled);
    assert_eq!(marshaled_len, 2 + 1550);

    let mut slice = &marshaled[..marshaled_len];
    let unmarshaled = Tpm2bPrivate::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, tpm2b_priv);
    assert!(slice.is_empty());

    // Oversized buffer (1551 bytes) must fail with UnmarshalError::SIZE
    let oversized_len = expected_max_private + 1;
    let oversized_buf = vec![0xFFu8; oversized_len];
    assert!(Tpm2bPrivate::new(&oversized_buf).is_none());

    let mut wire_bytes = Vec::with_capacity(2 + oversized_len);
    wire_bytes.extend_from_slice(&(oversized_len as u16).to_be_bytes());
    wire_bytes.extend_from_slice(&oversized_buf);
    let mut slice = &wire_bytes[..];
    assert_eq!(
        Tpm2bPrivate::unmarshal(&mut slice),
        Err(errors::UnmarshalError::SIZE)
    );
}

#[test]
fn test_tpm2b_encrypted_secret_spec_max_buffer_size() {
    // Per TPM 2.0 Spec Part 2 Section 11.4.2 & 11.4.3 (and C reference TpmTypes.h),
    // TPM2B_ENCRYPTED_SECRET has buffer size sizeof(TPMU_ENCRYPTED_SECRET),
    // which is the maximum of:
    // - sizeof(TPMS_ECC_POINT) = TpmsEccPoint::MAX_SIZE (260 bytes)
    // - MAX_RSA_KEY_BYTES = TPM2_MAX_RSA_KEY_BYTES (512 bytes)
    // - sizeof(TPM2B_DIGEST) = Tpm2bDigest::MAX_SIZE (66 bytes)
    let expected_max_secret = [
        TpmsEccPoint::MAX_SIZE,
        TPM2_MAX_RSA_KEY_BYTES as usize,
        Tpm2bDigest::MAX_SIZE,
    ]
    .into_iter()
    .max()
    .unwrap();
    assert_eq!(expected_max_secret, 512);
    assert_eq!(Tpm2bEncryptedSecret::CAP, expected_max_secret);
    assert_eq!(Tpm2bEncryptedSecret::MAX_BUFFER_SIZE, expected_max_secret);
    assert_eq!(
        TpmtPublicParms::MAX_ENCRYPTED_SECRET_BYTES,
        expected_max_secret
    );
    assert_eq!(Tpm2bEncryptedSecret::MAX_SIZE, 2 + expected_max_secret);

    // Verify Tpm2bEncryptedSecret can hold a full TpmsEccPoint (e.g. for ECC auth sessions or duplication)
    let ecc_point_data = vec![0x33u8; TpmsEccPoint::MAX_SIZE];
    let secret = Tpm2bEncryptedSecret::new(&ecc_point_data).unwrap();
    assert_eq!(secret.as_slice(), &ecc_point_data[..]);

    // Verify Tpm2bEncryptedSecret roundtrip up to full expected_max_secret bytes
    let full_data = vec![0x77u8; expected_max_secret];
    let secret = Tpm2bEncryptedSecret::new(&full_data).unwrap();
    let mut wire_buf = vec![0u8; 2 + expected_max_secret];
    let wire_len = secret.marshal((&mut wire_buf[..]).try_into().unwrap());
    assert_eq!(wire_len, 2 + expected_max_secret);

    let mut slice = &wire_buf[..];
    let unmarshaled = Tpm2bEncryptedSecret::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled.as_slice(), &full_data[..]);

    // Oversized buffer must be rejected
    let oversized = vec![0x88u8; expected_max_secret + 1];
    assert!(Tpm2bEncryptedSecret::new(&oversized).is_none());

    let mut bad_wire_buf = vec![0u8; 2 + expected_max_secret + 1];
    let oversized_len = (expected_max_secret + 1) as u16;
    bad_wire_buf[0..2].copy_from_slice(&oversized_len.to_be_bytes());
    let mut bad_slice = &bad_wire_buf[..];
    assert_eq!(
        Tpm2bEncryptedSecret::unmarshal(&mut bad_slice),
        Err(errors::UnmarshalError::SIZE)
    );
}

#[test]
fn test_tpms_id_object_and_tpm2b_id_object_encrypted_ciphertext() {
    // Ciphertext whose first 2 bytes are 0xFF, 0xFF (u16 = 65535 > 64).
    // If enc_identity were unmarshaled as plaintext Tpm2bDigest, this would fail with SIZE.
    let mut enc_ciphertext = [0xAAu8; Tpm2bDigest::MAX_SIZE];
    enc_ciphertext[0] = 0xFF;
    enc_ciphertext[1] = 0xFF;

    let hmac_bytes = [0x42u8; 32];
    let integrity_hmac = Tpm2bDigest::new(&hmac_bytes).unwrap();

    // 1. Test TpmsIdObject::new and enc_identity()
    let id_obj = TpmsIdObject::new(integrity_hmac, &enc_ciphertext[..34]).unwrap();
    assert_eq!(id_obj.integrity_hmac, integrity_hmac);
    assert_eq!(id_obj.enc_identity(), &enc_ciphertext[..34]);

    // 2. Test TpmsIdObject::marshal does NOT prepend an extra length prefix before enc_identity
    let mut marshaled_id_obj = [0u8; TpmsIdObject::MAX_SIZE];
    let marshaled_len = id_obj.marshal(&mut marshaled_id_obj);
    // Expected length: 2 (hmac size) + 32 (hmac bytes) + 34 (raw enc_identity bytes) = 68
    assert_eq!(marshaled_len, 2 + 32 + 34);
    assert_eq!(&marshaled_id_obj[34..68], &enc_ciphertext[..34]);

    // 3. Test TpmsIdObject::unmarshal round-trip with 0xFFFF leading ciphertext bytes
    let mut slice = &marshaled_id_obj[..marshaled_len];
    let unmarshaled_id_obj = TpmsIdObject::unmarshal(&mut slice).unwrap();
    assert!(slice.is_empty());
    assert_eq!(unmarshaled_id_obj, id_obj);
    assert_eq!(unmarshaled_id_obj.enc_identity(), &enc_ciphertext[..34]);

    // 4. Test Tpm2bIdObject::from_struct_in and to_struct round-trip
    let mut id_buf = [0u8; TpmsIdObject::MAX_SIZE];
    let tpm2b_id = Tpm2bIdObject::from_struct_in(&id_obj, &mut id_buf).unwrap();
    assert_eq!(tpm2b_id.as_slice().len(), marshaled_len);
    assert_eq!(tpm2b_id.as_slice(), &marshaled_id_obj[..marshaled_len]);

    let recovered_id_obj = tpm2b_id.to_struct().unwrap();
    assert_eq!(recovered_id_obj, id_obj);

    // 5. Test full max-sized TpmsIdObject (64-byte SHA-512 HMAC + 66-byte encrypted digest = 132 bytes)
    let max_hmac = Tpm2bDigest::new(&[0x55u8; 64]).unwrap();
    let max_id_obj = TpmsIdObject::new(max_hmac, &enc_ciphertext).unwrap();
    let mut max_buf = [0u8; TpmsIdObject::MAX_SIZE];
    let max_tpm2b_id = Tpm2bIdObject::from_struct_in(&max_id_obj, &mut max_buf).unwrap();
    assert_eq!(max_tpm2b_id.as_slice().len(), TpmsIdObject::MAX_SIZE);
    assert_eq!(max_tpm2b_id.to_struct().unwrap(), max_id_obj);

    // 6. Test oversized enc_identity (> 66 bytes) rejection
    let oversized_ciphertext = [0x99u8; Tpm2bDigest::MAX_SIZE + 1];
    assert_eq!(
        TpmsIdObject::new(integrity_hmac, &oversized_ciphertext),
        Err(errors::UnmarshalError::SIZE)
    );

    // 7. Test oversized enc_identity_len in Tpm2bIdObject::from_struct_in
    let mut bad_id_obj = id_obj;
    bad_id_obj.enc_identity_len = Tpm2bDigest::MAX_SIZE + 1;
    let mut bad_buf = [0u8; TpmsIdObject::MAX_SIZE];
    assert_eq!(
        Tpm2bIdObject::from_struct_in(&bad_id_obj, &mut bad_buf),
        Err(errors::UnmarshalError::SIZE)
    );

    // 8. Test PartialEq sensitivity to enc_identity_len
    let mut diff_len_id_obj = id_obj;
    diff_len_id_obj.enc_identity_len += 1;
    assert_ne!(id_obj, diff_len_id_obj);

    // Construct a buffer with valid 32-byte HMAC (34 bytes) + 67 bytes of enc_identity (total 101 bytes <= 132)
    let mut oversized_enc_buf = Vec::new();
    let mut hmac_buf = [0u8; Tpm2bDigest::MAX_SIZE];
    let hmac_len = integrity_hmac.marshal(&mut hmac_buf);
    oversized_enc_buf.extend_from_slice(&hmac_buf[..hmac_len]);
    oversized_enc_buf.extend_from_slice(&oversized_ciphertext);

    let mut slice = &oversized_enc_buf[..];
    assert_eq!(
        TpmsIdObject::unmarshal(&mut slice),
        Err(errors::UnmarshalError::SIZE)
    );

    // Tpm2bIdObject::new accepts raw buffer <= 132 bytes, but to_struct rejects oversized enc_identity
    let raw_2b = Tpm2bIdObject::new(&oversized_enc_buf).unwrap();
    assert_eq!(raw_2b.to_struct(), Err(errors::UnmarshalError::SIZE));
}
