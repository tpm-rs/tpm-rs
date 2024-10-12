use tpm2_rs_base::{Tpm2bSimple, TpmiShAuthSession};

use super::*;

#[test]
fn test_password_get_auth_command() {
    let session = PasswordSession::new("hello").unwrap();
    let tpm_auth = session.get_auth_command();
    assert_eq!(tpm_auth.session_handle, TpmiShAuthSession::RS_PW);
    assert_eq!(tpm_auth.hmac.get_size(), 5);
    assert_eq!(tpm_auth.hmac.get_buffer(), b"hello");
}
