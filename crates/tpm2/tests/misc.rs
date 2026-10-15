use tpm2::*;

#[test]
fn test_attributes_field() {
    let mut cc = TpmaCc::NV | TpmaCc::FLUSHED | TpmaCc::command_index(0x8);
    assert_eq!(cc.get_command_index(), 0x8);
    cc.set_command_index(0xA0);
    assert_eq!(cc.get_command_index(), 0xA0);

    // Set a field to a value that is wider than the field.
    cc.set_c_handles(0xFF);
    assert_eq!(cc.get_c_handles(), 0x7, "Only the field bits should be set");
    assert_eq!(cc.get_command_index(), 0xA0);
    assert!(cc.contains(TpmaCc::NV));
    assert!((cc & TpmaCc::FLUSHED).0 != 0);

    let nv = TpmaNv::from(TpmNt::Counter) | TpmaNv::OWNERWRITE;
    let mut nv_exp = TpmaNvExp::from(nv) | TpmaNvExp::EXTERNAL_NV_ENCRYPTION;
    assert_eq!(nv_exp.get_index_type(), Some(TpmNt::Counter));
    nv_exp.set_type(TpmNt::Extend);
    assert_eq!(nv_exp.get_index_type(), Some(TpmNt::Extend));
    assert!(nv_exp.contains(TpmaNvExp::OWNERWRITE | TpmaNvExp::EXTERNAL_NV_ENCRYPTION));
}
