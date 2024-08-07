use super::*;

#[test]
fn test_format1() {
    let error = TpmRcError::AsymmetricFor(ErrorType::Parameter, ErrorPosition::Pos2);
    assert_eq!(error.get(), 0x2C1);

    let (on, pos) = error
        .format1_parameter()
        .expect("Should have format1 parameters");
    assert_eq!(on, ErrorType::Parameter);
    assert_eq!(pos, ErrorPosition::Pos2);
}

#[test]
fn test_warning() {
    let error = TpmRcError::Memory;
    assert!(error.is_warning());
}
