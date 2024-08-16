use super::{AuthorizationArea, AuthorizationArea1Plus, AuthorizationArea2Plus};
use crate::sessions::{PasswordSession, Session};

impl<T: Session, U: Session> AuthorizationArea<T, U, PasswordSession> for (T, U) {
    fn decompose(self) -> (Option<T>, Option<U>, Option<PasswordSession>) {
        (Some(self.0), Some(self.1), None)
    }

    fn decompose_ref(&self) -> (Option<&T>, Option<&U>, Option<&PasswordSession>) {
        (Some(&self.0), Some(&self.1), None)
    }

    fn decompose_mut(&mut self) -> (Option<&mut T>, Option<&mut U>, Option<&mut PasswordSession>) {
        (Some(&mut self.0), Some(&mut self.1), None)
    }
}

impl<T: Session, U: Session> AuthorizationArea1Plus<T, U, PasswordSession> for (T, U) {
    fn decompose(self) -> (T, Option<U>, Option<PasswordSession>) {
        (self.0, Some(self.1), None)
    }

    fn decompose_ref(&self) -> (&T, Option<&U>, Option<&PasswordSession>) {
        (&self.0, Some(&self.1), None)
    }

    fn decompose_mut(&mut self) -> (&mut T, Option<&mut U>, Option<&mut PasswordSession>) {
        (&mut self.0, Some(&mut self.1), None)
    }
}

impl<T: Session, U: Session> AuthorizationArea2Plus<T, U, PasswordSession> for (T, U) {
    fn decompose(self) -> (T, U, Option<PasswordSession>) {
        (self.0, self.1, None)
    }
    fn decompose_ref(&self) -> (&T, &U, Option<&PasswordSession>) {
        (&self.0, &self.1, None)
    }
    fn decompose_mut(&mut self) -> (&mut T, &mut U, Option<&mut PasswordSession>) {
        (&mut self.0, &mut self.1, None)
    }
}
