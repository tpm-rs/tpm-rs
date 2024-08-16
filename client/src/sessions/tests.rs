use tpm2_rs_base::{Tpm2bAuth, Tpm2bSimple, TpmiShAuthSession};

use super::*;

#[test]
fn test_password_get_auth_command() {
    let auth = Tpm2bAuth::from_bytes("hello".as_bytes()).unwrap();
    let session = PasswordSession { auth };

    let tpm_auth = session.get_auth_command();
    assert_eq!(tpm_auth.session_handle, TpmiShAuthSession::RS_PW);
    assert_eq!(auth, tpm_auth.hmac);
}
