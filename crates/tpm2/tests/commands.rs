use tpm2::{
    Handle, UnmarshalMessage,
    commands::{Hash, PolicyOR},
    errors::{Position, TpmRc},
};

#[test]
fn test_command_parameter_error_has_position() {
    // TPM2_Hash parameters: data (empty), hashAlg = TPM_ALG_RSA (not a hash), hierarchy.
    let mut src: &[u8] = &[0x00, 0x00, 0x00, 0x01];
    let rc = Hash::unmarshal_with_handles([], &mut src).unwrap_err();
    assert_eq!(rc, TpmRc::HASH.with(Position::parameter(2)));
    // TPM_RC_HASH + TPM_RC_P + TPM_RC_2, as a TPM would return it.
    assert_eq!(rc.get(), 0x2C3);
}

#[test]
fn test_policy_or_requires_two_digests() {
    let session = Handle(0x0300_0000);

    // A pHashList with a single digest is rejected with TPM_RC_SIZE on parameter 1.
    let mut src: &[u8] = &[0, 0, 0, 1, 0, 2, 0xAA, 0xBB];
    let rc = PolicyOR::unmarshal_with_handles([session], &mut src).unwrap_err();
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(1)));

    // Two digests are accepted.
    let mut src: &[u8] = &[0, 0, 0, 2, 0, 2, 0xAA, 0xBB, 0, 2, 0xCC, 0xDD];
    let cmd = PolicyOR::unmarshal_with_handles([session], &mut src).unwrap();
    assert_eq!(cmd.policy_session, session);
    assert_eq!(cmd.p_hash_list.as_slice().len(), 2);
}
