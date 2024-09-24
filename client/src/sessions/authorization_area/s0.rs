use crate::sessions::{AuthorizationArea, PasswordSession};

impl AuthorizationArea<PasswordSession, PasswordSession, PasswordSession> for () {
    fn decompose_ref(
        &self,
    ) -> (
        Option<&PasswordSession>,
        Option<&PasswordSession>,
        Option<&PasswordSession>,
    ) {
        (None, None, None)
    }
}
