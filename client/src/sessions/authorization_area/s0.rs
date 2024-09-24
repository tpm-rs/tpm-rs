use crate::sessions::{AuthorizationArea, PasswordSession};

impl AuthorizationArea<PasswordSession, PasswordSession, PasswordSession> for () {
    fn decompose(
        self,
    ) -> (
        Option<PasswordSession>,
        Option<PasswordSession>,
        Option<PasswordSession>,
    ) {
        (None, None, None)
    }

    fn decompose_ref(
        &self,
    ) -> (
        Option<&PasswordSession>,
        Option<&PasswordSession>,
        Option<&PasswordSession>,
    ) {
        (None, None, None)
    }

    fn decompose_mut(
        &mut self,
    ) -> (
        Option<&mut PasswordSession>,
        Option<&mut PasswordSession>,
        Option<&mut PasswordSession>,
    ) {
        (None, None, None)
    }
}
