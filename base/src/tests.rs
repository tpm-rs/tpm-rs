use super::*;
use core::mem::size_of;

// Unfortunately, I didn't see a way to generate a function name easily, see
// https://github.com/rust-lang/rust/issues/29599 for more details. So we just
// generate the test body here.
macro_rules! impl_test_tpm2b_simple {
    ($T:ty) => {
        const SIZE_OF_U16: usize = size_of::<u16>();
        const SIZE_OF_TYPE: usize = size_of::<$T>();
        const SIZE_OF_BUFFER: usize = SIZE_OF_TYPE - SIZE_OF_U16;

        /*
         * Generate arrays that are:
         *   - too small
         *   - smaller than buffer limit
         *   - same size as buffer limit
         *   - exceeding buffer limit
         */
        let mut too_small_size_buf: [u8; 1] = [0x00; 1];
        let mut smaller_size_buf: [u8; SIZE_OF_TYPE - 8] = [0xFF; SIZE_OF_TYPE - 8];
        let mut same_size_buf: [u8; SIZE_OF_TYPE] = [0xFF; SIZE_OF_TYPE];
        let mut bigger_size_buf: [u8; SIZE_OF_TYPE + 8] = [0xFF; SIZE_OF_TYPE + 8];

        let mut s = (smaller_size_buf.len() - SIZE_OF_U16) as u16;
        assert!(s.try_marshal(&mut smaller_size_buf).is_ok());

        s = (same_size_buf.len() - SIZE_OF_U16) as u16;
        assert!(s.try_marshal(&mut same_size_buf).is_ok());

        s = (bigger_size_buf.len() - SIZE_OF_U16) as u16;
        assert!(s.try_marshal(&mut bigger_size_buf).is_ok());

        // too small should fail
        let mut result: TpmRcResult<$T> =
            <$T>::try_unmarshal(&mut UnmarshalBuf::new(&too_small_size_buf));
        assert!(result.is_err());

        // bigger size should consume only the prefix
        result = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&bigger_size_buf));
        assert!(result.is_err());

        // small, should be good
        result = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&smaller_size_buf));
        assert!(result.is_ok());
        let mut digest = result.unwrap();
        assert_eq!(
            usize::from(digest.get_size()),
            smaller_size_buf.len() - SIZE_OF_U16
        );
        assert_eq!(digest.get_buffer(), &smaller_size_buf[SIZE_OF_U16..]);

        // same size should be good
        result = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&same_size_buf));
        assert!(result.is_ok());
        digest = result.unwrap();
        assert_eq!(
            usize::from(digest.get_size()),
            same_size_buf.len() - size_of::<u16>()
        );
        assert_eq!(digest.get_buffer(), &same_size_buf[size_of::<u16>()..]);

        let mut mres = digest.try_marshal(&mut too_small_size_buf);
        assert!(mres.is_err());

        mres = digest.try_marshal(&mut same_size_buf);
        assert!(mres.is_ok());
        assert_eq!(mres.unwrap(), digest.get_size() as usize + SIZE_OF_U16);
        let mut new_digest = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&same_size_buf)).unwrap();
        assert_eq!(digest, new_digest);

        mres = digest.try_marshal(&mut bigger_size_buf);
        assert!(mres.is_ok());
        assert_eq!(mres.unwrap(), digest.get_size() as usize + SIZE_OF_U16);
        new_digest =
            <$T>::try_unmarshal(&mut UnmarshalBuf::new(&bigger_size_buf[..SIZE_OF_TYPE])).unwrap();
        assert_eq!(digest, new_digest);
    };
}

#[test]
fn test_try_unmarshal_tpm2b_name() {
    impl_test_tpm2b_simple! {Tpm2bName};
}

#[test]
fn test_try_unmarshal_tpm2b_attest() {
    impl_test_tpm2b_simple! {Tpm2bAttest};
}

#[test]
fn test_try_unmarshal_tpm2b_context_data() {
    impl_test_tpm2b_simple! {Tpm2bContextData};
}

#[test]
fn test_try_unmarshal_tpm2b_context_sensitive() {
    impl_test_tpm2b_simple! {Tpm2bContextSensitive};
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
fn test_try_unmarshal_tpm2b_private_vendor_specific() {
    impl_test_tpm2b_simple! {Tpm2bPrivateVendorSpecific};
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
fn test_try_unmarshal_tpm2b_sym_key() {
    impl_test_tpm2b_simple! {Tpm2bSymKey};
}

#[test]
fn test_try_unmarshal_tpm2b_template() {
    impl_test_tpm2b_simple! {Tpm2bTemplate};
}

#[test]
fn test_impl_tpml_new() {
    let elements: Vec<TpmHandle> = (0..TPM2_MAX_CAP_HANDLES + 1)
        .map(|i| TpmHandle(i as u32))
        .collect();
    for x in 0..TPM2_MAX_CAP_HANDLES {
        let slice = &elements.as_slice()[..x];
        let list = TpmlHandle::new(slice).unwrap();
        assert_eq!(list.count(), x);
        assert_eq!(list.handle(), slice);
    }
    assert!(
        TpmlHandle::new(elements.as_slice()).is_err(),
        "Creating a TpmlHandle with more elements than capacity should fail."
    );
}

#[test]
fn test_impl_tpml_default_add() {
    let elements: Vec<TpmHandle> = (0..TPM2_MAX_CAP_HANDLES + 1)
        .map(|i| TpmHandle(i as u32))
        .collect();
    let mut list = TpmlHandle::default();
    for x in 0..TPM2_MAX_CAP_HANDLES {
        let slice = &elements.as_slice()[..x];
        assert_eq!(list.handle(), slice);

        list.add(elements.get(x).unwrap()).unwrap();
        assert_eq!(list.count(), x + 1);
    }
    assert!(
        TpmlHandle::new(elements.as_slice()).is_err(),
        "Creating a TpmlHandle with more elements than capacity should fail."
    );
}

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
    let mut marshal_buffer = [0u8; 48];
    let bytes = info.try_marshal(&mut marshal_buffer).unwrap();

    // Build the expected output manually.
    let mut expected = Vec::with_capacity(bytes);
    expected.extend_from_slice(&index_name.get_size().to_be_bytes());
    expected.extend_from_slice(&name_buffer);
    expected.extend_from_slice(&info.offset.to_be_bytes());
    expected.extend_from_slice(&nv_contents.get_size().to_be_bytes());
    expected.extend_from_slice(&nv_buffer);

    assert_eq!(expected.len(), bytes);
    assert_eq!(expected, marshal_buffer[..expected.len()]);

    let unmarshaled = TpmsNvCertifyInfo::try_unmarshal(&mut UnmarshalBuf::new(&marshal_buffer));
    assert_eq!(unmarshaled.unwrap(), info);
}

#[test]
fn test_marshal_enum_override() {
    let hmac = TpmsSchemeHmac {
        hash_alg: TpmiAlgHash::SHA256,
    };
    let scheme = TpmtKeyedHashScheme::Hmac(hmac);
    let mut buffer = [0u8; size_of::<TpmtKeyedHashScheme>()];
    assert!(scheme.try_marshal(&mut buffer).is_ok());
}

#[test]
fn test_marshal_tpmt_public() {
    let xor_sym_def_obj = TpmtSymDefObject::ExclusiveOr(TpmiAlgHash::SHA256, TpmsEmpty {});
    let mut buffer = [0u8; size_of::<TpmtSymDefObject>()];
    let mut marsh = xor_sym_def_obj.try_marshal(&mut buffer);
    // Because XOR does not populate TpmuSymMode, we have bytes left over.
    assert!(marsh.unwrap() < buffer.len());
    let rsa_scheme = TpmtRsaScheme::Ecdsa(TpmsSigSchemeEcdsa {
        hash_alg: TpmiAlgHash::SHA256,
    });

    let rsa_parms = TpmsRsaParms {
        symmetric: xor_sym_def_obj,
        scheme: rsa_scheme,
        key_bits: TpmiRsaKeyBits(74),
        exponent: 2,
    };

    let pubkey_buf = [9u8; 24];
    let pubkey = Tpm2bPublicKeyRsa::from_bytes(&pubkey_buf).unwrap();

    let example = TpmtPublic {
        name_alg: TpmiAlgHash::SHA256,
        object_attributes: TpmaObject::RESTRICTED | TpmaObject::SENSITIVE_DATA_ORIGIN,
        auth_policy: Tpm2bDigest::from_bytes(&[2, 2, 4, 4]).unwrap(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, pubkey),
    };

    // Test a round-trip marshaling and unmarshaling, confirm that we get the same output.
    let mut buffer = [0u8; 256];
    marsh = example.try_marshal(&mut buffer);
    assert!(marsh.is_ok());
    let expected: [u8; 54] = [
        0, 1, 0, 11, 0, 1, 0, 32, 0, 4, 2, 2, 4, 4, 0, 10, 0, 11, 0, 24, 0, 11, 0, 74, 0, 0, 0, 2,
        0, 24, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    ];
    //assert_eq!(expected.len(), marsh.unwrap());
    assert_eq!(buffer[..expected.len()], expected);
    let mut unmarsh = TpmtPublic::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
    let bytes_example = unmarsh.unwrap();
    assert_eq!(bytes_example.object_attributes, example.object_attributes);
    let mut remarsh_buffer = [1u8; 256];
    let remarsh = unmarsh.unwrap().try_marshal(&mut remarsh_buffer);
    assert_eq!(remarsh, marsh);
    assert_eq!(remarsh_buffer[..marsh.unwrap()], buffer[..marsh.unwrap()]);

    // Test invalid selector value.
    assert!(TpmAlgId::SHA256.try_marshal(&mut buffer).is_ok());
    unmarsh = TpmtPublic::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
    assert_eq!(unmarsh.err(), Some(TpmRcError::Selector));
}

#[test]
fn test_attributes_field() {
    let mut cc = TpmaCc::NV | TpmaCc::FLUSHED | TpmaCc::command_index(0x8);
    assert_eq!(cc.get_command_index(), 0x8);
    cc.set_command_index(0xA0);
    assert_eq!(cc.get_command_index(), 0xA0);

    // Set a field to a value that is wider than the field.
    cc.set_c_handles(0xFFFFFFFF);
    assert_eq!(cc.get_c_handles(), 0x7, "Only the field bits should be set");
    assert_eq!(cc.get_command_index(), 0xA0);
    assert!(cc.contains(TpmaCc::NV));
    assert!((cc & TpmaCc::FLUSHED).0 != 0);
}

#[test]
fn test_nv_index_range() {
    let lowest_ok = TpmHc::NVIndexFirst.get();
    assert!(TpmiRhNvIndex::try_from(lowest_ok - 1).is_err());
    assert!(TpmiRhNvIndex::try_from(lowest_ok).is_ok());
    assert!(TpmiRhNvIndex::try_from(lowest_ok + 432).is_ok());
    let highest_ok = TpmHc::NVIndexLast.get();
    assert!(TpmiRhNvIndex::try_from(highest_ok).is_ok());
    assert!(TpmiRhNvIndex::try_from(highest_ok + 1).is_err());
}

#[test]
fn test_2b_struct() {
    let creation_data = TpmsCreationData {
        pcr_select: TpmlPcrSelection::new(&[TpmsPcrSelection {
            hash: TpmiAlgHash::SHA256,
            sizeof_select: 2,
            pcr_select: [0xF, 0xF, 0x0, 0x0],
        }])
        .unwrap(),
        pcr_digest: Tpm2bDigest::from_bytes(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9])
            .unwrap(),
        locality: TpmaLocality(0xA),
        parent_name_alg: TpmAlgId::SHA384,
        parent_name: Tpm2bName::from_bytes(&[0xA, 0xB, 0xC, 0xD, 0xE, 0xF]).unwrap(),
        parent_qualified_name: Tpm2bName::default(),
        outside_info: Tpm2bData::from_bytes(&[0x1; 32]).unwrap(),
    };
    let creation_data_2b = Tpm2bCreationData::from_struct(&creation_data).unwrap();
    let out_creation_data = creation_data_2b.to_struct().unwrap();
    assert_eq!(creation_data, out_creation_data);
}
