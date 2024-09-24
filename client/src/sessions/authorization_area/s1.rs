use crate::sessions::{AuthorizationArea, AuthorizationArea1Plus, PasswordSession, Session};

impl<T: Session> AuthorizationArea<T, PasswordSession, PasswordSession> for T {
    fn decompose_ref(
        &self,
    ) -> (
        Option<&T>,
        Option<&PasswordSession>,
        Option<&PasswordSession>,
    ) {
        (Some(self), None, None)
    }
}
impl<T: Session> AuthorizationArea1Plus<T, PasswordSession, PasswordSession> for T {
    fn decompose_ref(&self) -> (&T, Option<&PasswordSession>, Option<&PasswordSession>) {
        (self, None, None)
    }
}
