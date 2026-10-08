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
}
