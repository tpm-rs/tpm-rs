use super::{AuthorizationArea, AuthorizationArea1Plus};
use crate::sessions::{PasswordSession, Session};

impl<T: Session> AuthorizationArea<T, PasswordSession, PasswordSession> for T {
    fn decompose(self) -> (Option<T>, Option<PasswordSession>, Option<PasswordSession>) {
        (Some(self), None, None)
    }

    fn decompose_ref(
        &self,
    ) -> (
        Option<&T>,
        Option<&PasswordSession>,
        Option<&PasswordSession>,
    ) {
        (Some(self), None, None)
    }

    fn decompose_mut(
        &mut self,
    ) -> (
        Option<&mut T>,
        Option<&mut PasswordSession>,
        Option<&mut PasswordSession>,
    ) {
        (Some(self), None, None)
    }
}
impl<T: Session> AuthorizationArea1Plus<T, PasswordSession, PasswordSession> for T {
    fn decompose(self) -> (T, Option<PasswordSession>, Option<PasswordSession>) {
        (self, None, None)
    }

    fn decompose_ref(&self) -> (&T, Option<&PasswordSession>, Option<&PasswordSession>) {
        (self, None, None)
    }

    fn decompose_mut(
        &mut self,
    ) -> (
        &mut T,
        Option<&mut PasswordSession>,
        Option<&mut PasswordSession>,
    ) {
        (self, None, None)
    }
}
