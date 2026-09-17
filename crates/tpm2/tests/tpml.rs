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
