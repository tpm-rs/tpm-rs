use tpm2::errors::UnmarshalError;
use tpm2::*;

#[test]
fn test_impl_tpml_new() {
    let elements: Vec<Handle> = (0..TpmlHandle::CAP + 1).map(|i| Handle(i as u32)).collect();
    for x in 0..=TpmlHandle::CAP {
        let slice = &elements.as_slice()[..x];
        let list = TpmlHandle::new(slice).unwrap();
        assert_eq!(list.as_slice().len(), x);
        assert_eq!(list.as_slice(), slice);
    }
    assert!(
        TpmlHandle::new(elements.as_slice()).is_none(),
        "Creating a TpmlHandle with more elements than capacity should fail."
    );
}

#[test]
fn test_tpml_traits() {
    let mut list1 = TpmlAlg::new(&[Alg::SHA256, Alg::SHA384, Alg::SHA512]).unwrap();
    let list2 = TpmlAlg::new(&[Alg::SHA256]).unwrap();
    assert_ne!(list1, list2);

    // Re-unmarshaling a smaller list over list1 leaves stale elements in the backing array,
    // but PartialEq and Debug must only inspect active elements.
    let mut buf = [0u8; TpmlAlg::MAX_SIZE];
    let len = list2.marshal(&mut buf);
    list1.unmarshal_ref(&buf[..len]).unwrap();

    assert_eq!(list1, list2);
    assert_eq!(list1.as_ref(), &[Alg::SHA256]);
    assert_eq!(
        format!("{:?}", list1),
        format!("Tpml({:?})", &[Alg::SHA256])
    );
}

#[test]
fn test_impl_tpml_default_add() {
    let elements: Vec<Handle> = (0..TpmlHandle::CAP + 1).map(|i| Handle(i as u32)).collect();
    let mut list = TpmlHandle::default();
    for x in 0..TpmlHandle::CAP {
        let slice = &elements.as_slice()[..x];
        assert_eq!(list.as_slice(), slice);

        list.add(elements.get(x).unwrap()).unwrap();
        assert_eq!(list.as_slice().len(), x + 1);
    }
    assert!(
        list.add(elements.get(TpmlHandle::CAP).unwrap()).is_err(),
        "Adding more elements than capacity should fail."
    );
}

#[test]
fn test_num_pcr_banks_matches_hash_count_and_enabled_features() {
    let expected_hash_count = cfg!(feature = "sha1") as usize
        + cfg!(feature = "sha256") as usize
        + cfg!(feature = "sha384") as usize
        + cfg!(feature = "sha512") as usize
        + cfg!(feature = "sm3_256") as usize
        + cfg!(feature = "sha3_256") as usize
        + cfg!(feature = "sha3_384") as usize
        + cfg!(feature = "sha3_512") as usize;
    assert_eq!(TpmtHa::HASH_COUNT, expected_hash_count);
    assert_eq!(TPM2_NUM_PCR_BANKS as usize, expected_hash_count);
}

#[test]
fn test_tpml_digest_values_count_bound_is_hash_count() {
    let max_count = TpmtHa::HASH_COUNT;
    let hash = TpmiAlgHash::DEFAULT_HASH;
    let digest_len = hash.digest_size();

    // Constructing with HASH_COUNT elements should succeed, HASH_COUNT + 1 should fail.
    let elem = TpmtHa::DEFAULT_HA;
    let elems = [elem; 16];
    assert!(TpmlDigestValues::from_slice(&elems[..max_count]).is_some());
    assert!(TpmlDigestValues::from_slice(&elems[..max_count + 1]).is_none());

    // Unmarshalling exactly HASH_COUNT elements should succeed.
    let mut valid_buf = [0u8; 2048];
    valid_buf[0..4].copy_from_slice(&(max_count as u32).to_be_bytes());
    let mut offset = 4;
    for _ in 0..max_count {
        valid_buf[offset..offset + 2].copy_from_slice(&Alg::from(hash).id().to_be_bytes());
        offset += 2 + digest_len;
    }
    let mut reader = &valid_buf[..offset];
    let parsed = TpmlDigestValues::unmarshal(&mut reader).unwrap();
    assert_eq!(parsed.count(), max_count);

    // Unmarshalling counts exceeding HASH_COUNT (including HASH_COUNT + 1 and 16) must fail with UnmarshalError::SIZE.
    for invalid_count in [max_count as u32 + 1, 16] {
        let mut invalid_buf = [0u8; 2048];
        invalid_buf[0..4].copy_from_slice(&invalid_count.to_be_bytes());
        let mut offset = 4;
        for _ in 0..invalid_count {
            invalid_buf[offset..offset + 2].copy_from_slice(&Alg::from(hash).id().to_be_bytes());
            offset += 2 + digest_len;
        }
        let mut reader = &invalid_buf[..offset];
        assert_eq!(
            TpmlDigestValues::unmarshal(&mut reader),
            Err(UnmarshalError::SIZE)
        );
    }
}

#[test]
fn test_tpml_pcr_selection_count_bound_is_hash_count() {
    let max_count = TpmtHa::HASH_COUNT;
    let hash = TpmiAlgHash::DEFAULT_HASH;

    // Constructing with HASH_COUNT elements should succeed, HASH_COUNT + 1 should fail.
    let elem = TpmsPcrSelection::new(hash, &[0u8; 3]).unwrap();
    let elems = [elem; 16];
    assert!(TpmlPcrSelection::from_slice(&elems[..max_count]).is_some());
    assert!(TpmlPcrSelection::from_slice(&elems[..max_count + 1]).is_none());

    // Unmarshalling exactly HASH_COUNT elements should succeed.
    let mut valid_buf = [0u8; 512];
    valid_buf[0..4].copy_from_slice(&(max_count as u32).to_be_bytes());
    let mut offset = 4;
    for _ in 0..max_count {
        valid_buf[offset..offset + 2].copy_from_slice(&Alg::from(hash).id().to_be_bytes());
        valid_buf[offset + 2] = 3;
        offset += 6;
    }
    let mut reader = &valid_buf[..offset];
    let parsed = TpmlPcrSelection::unmarshal(&mut reader).unwrap();
    assert_eq!(parsed.count(), max_count);

    // Unmarshalling counts exceeding HASH_COUNT (including HASH_COUNT + 1 and 16) must fail with UnmarshalError::SIZE.
    for invalid_count in [max_count as u32 + 1, 16] {
        let mut invalid_buf = [0u8; 512];
        invalid_buf[0..4].copy_from_slice(&invalid_count.to_be_bytes());
        let mut offset = 4;
        for _ in 0..invalid_count {
            invalid_buf[offset..offset + 2].copy_from_slice(&Alg::from(hash).id().to_be_bytes());
            invalid_buf[offset + 2] = 3;
            offset += 6;
        }
        let mut reader = &invalid_buf[..offset];
        assert_eq!(
            TpmlPcrSelection::unmarshal(&mut reader),
            Err(UnmarshalError::SIZE)
        );
    }
}

#[test]
fn test_tpml_vendor_property_count_overflow_returns_value() {
    let max_count = TPM2_MAX_VENDOR_PROPERTY;

    // Unmarshalling up to TPM2_MAX_VENDOR_PROPERTY elements should succeed.
    let mut valid_buf = [0u8; 32];
    valid_buf[0..4].copy_from_slice(&(max_count as u32).to_be_bytes());
    let mut offset = 4;
    for _ in 0..max_count {
        // Empty Tpm2bVendorProperty (size = 0)
        valid_buf[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes());
        offset += 2;
    }
    let mut reader = &valid_buf[..offset];
    let parsed = TpmlVendorProperty::unmarshal(&mut reader).unwrap();
    assert_eq!(parsed.count(), max_count);

    // Per TPM 2.0 Part 2 Table 126 and C TPM TPML_VENDOR_PROPERTY_Unmarshal,
    // count > MAX_VENDOR_PROPERTY must return TPM_RC_VALUE (UnmarshalError::VALUE), not TPM_RC_SIZE.
    for invalid_count in [max_count as u32 + 1, max_count as u32 + 10, u32::MAX] {
        let buf = invalid_count.to_be_bytes();
        let mut reader = &buf[..];
        assert_eq!(
            TpmlVendorProperty::unmarshal(&mut reader),
            Err(UnmarshalError::VALUE)
        );
        let mut target = TpmlVendorProperty::default();
        assert_eq!(target.unmarshal_ref(&buf), Err(UnmarshalError::VALUE));
    }
}
