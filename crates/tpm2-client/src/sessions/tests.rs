use tpm2::Handle;

use super::*;

#[test]
fn test_password_auth_command() {
    let session = PasswordSession::new("hello").unwrap();
    let tpm_auth = session.auth_command();
    assert_eq!(tpm_auth.session_handle, Handle::RS_PW);
    assert_eq!(tpm_auth.hmac.as_slice().len(), 5);
    assert_eq!(tpm_auth.hmac.as_slice(), b"hello");
}
