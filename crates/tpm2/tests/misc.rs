use tpm2::{errors::UnmarshalError, *};

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
fn test_tpma_composite_structures_reject_reserved_bits() {
    // 1. TpmsAuthCommand with reserved TpmaSession bit (bit 3 = 0x08)
    let auth_cmd = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x08), // reserved bit
        hmac: Tpm2bAuth::default(),
    };
    let mut buf = [0u8; TpmsAuthCommand::MAX_SIZE];
    let len = auth_cmd.marshal(&mut buf);
    let mut slice = &buf[..len];
    assert_eq!(
        TpmsAuthCommand::unmarshal(&mut slice),
        Err(UnmarshalError::RESERVED_BITS)
    );

    // 2. TpmsNvPublic with reserved TpmaNv bit (bit 8 = 0x0000_0100)
    let nv_pub = TpmsNvPublic {
        nv_index: Handle(0x01000001),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv(0x0000_0100), // reserved bit 8
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    };
    let mut nv_buf = [0u8; TpmsNvPublic::MAX_SIZE];
    let nv_len = nv_pub.marshal(&mut nv_buf);
    let mut nv_slice = &nv_buf[..nv_len];
    assert_eq!(
        TpmsNvPublic::unmarshal(&mut nv_slice),
        Err(UnmarshalError::RESERVED_BITS)
    );

    // 3. TpmsAlgProperty with reserved TpmaAlgorithm bit (bit 4 = 0x0000_0010)
    let alg_prop = TpmsAlgProperty {
        alg: Alg::SHA256,
        alg_properties: TpmaAlgorithm(0x0000_0010), // reserved bit 4
    };
    let mut alg_buf = [0u8; TpmsAlgProperty::MAX_SIZE];
    let alg_len = alg_prop.marshal(&mut alg_buf);
    let mut alg_slice = &alg_buf[..alg_len];
    assert_eq!(
        TpmsAlgProperty::unmarshal(&mut alg_slice),
        Err(UnmarshalError::RESERVED_BITS)
    );

    // 4. Verify all standard TPMA_* bitfields and TpmaObject new flags exist and reject reserved bits
    assert_eq!(TpmaObject::FIRMWARE_LIMITED.bits(), 1 << 8);
    assert_eq!(TpmaObject::SVN_LIMITED.bits(), 1 << 9);
    assert_eq!(TpmaObject::RESERVED_BITS_MASK, 0xfff0_f009);
    assert_eq!(
        TpmaObject::unmarshal(&mut &0x0000_0008u32.to_be_bytes()[..]),
        Err(UnmarshalError::RESERVED_BITS)
    );
    assert_eq!(
        TpmaPermanent::unmarshal(&mut &0x0000_0008u32.to_be_bytes()[..]),
        Err(UnmarshalError::RESERVED_BITS)
    );
    assert_eq!(
        TpmaStartupClear::unmarshal(&mut &0x0000_0020u32.to_be_bytes()[..]),
        Err(UnmarshalError::RESERVED_BITS)
    );
    assert_eq!(
        TpmaMemory::unmarshal(&mut &0x0000_0008u32.to_be_bytes()[..]),
        Err(UnmarshalError::RESERVED_BITS)
    );
    assert_eq!(
        TpmaModes::unmarshal(&mut &0x0000_0010u32.to_be_bytes()[..]),
        Err(UnmarshalError::RESERVED_BITS)
    );
    assert_eq!(
        TpmaX509KeyUsage::unmarshal(&mut &0x0040_0000u32.to_be_bytes()[..]),
        Err(UnmarshalError::RESERVED_BITS)
    );
    assert_eq!(
        TpmaAct::unmarshal(&mut &0x0000_0004u32.to_be_bytes()[..]),
        Err(UnmarshalError::RESERVED_BITS)
    );
    assert_eq!(
        TpmaNvExp::unmarshal(&mut &0x0000_0008_0000_0000u64.to_be_bytes()[..]),
        Err(UnmarshalError::RESERVED_BITS)
    );
}
