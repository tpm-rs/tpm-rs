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
fn test_try_unmarshal_tpm2b_sym_key() {
    impl_test_tpm2b_simple! {Tpm2bSymKey};
}

#[test]
fn test_try_unmarshal_tpm2b_timeout() {
    impl_test_tpm2b_simple! {Tpm2bTimeout};
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
    assert_eq!(res.unwrap_err(), tpm2::errors::UnmarshalError);
}

#[test]
fn test_tpm2b_trailing_bytes_rejected() {
    // Empty TpmsEccPoint marshals to 4 bytes (x.size = 0, y.size = 0),
    // so an outer Tpm2bEccPoint size of 5 leaves 1 trailing byte inside the Tpm2b payload.
    let mut slice: &[u8] = &[0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF];
    assert_eq!(
        Tpm2bEccPoint::unmarshal(&mut slice),
        Err(tpm2::errors::UnmarshalError)
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
