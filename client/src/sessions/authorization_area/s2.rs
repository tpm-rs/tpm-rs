use crate::sessions::{
    AuthorizationArea, AuthorizationArea1Plus, AuthorizationArea2Plus, PasswordSession, Session,
};

impl<T: Session, U: Session> AuthorizationArea<T, U, PasswordSession> for (T, U) {
    fn decompose_ref(&self) -> (Option<&T>, Option<&U>, Option<&PasswordSession>) {
        (Some(&self.0), Some(&self.1), None)
    }
}

impl<T: Session, U: Session> AuthorizationArea1Plus<T, U, PasswordSession> for (T, U) {
    fn decompose_ref(&self) -> (&T, Option<&U>, Option<&PasswordSession>) {
        (&self.0, Some(&self.1), None)
    }
}

impl<T: Session, U: Session> AuthorizationArea2Plus<T, U, PasswordSession> for (T, U) {
    fn decompose_ref(&self) -> (&T, &U, Option<&PasswordSession>) {
        (&self.0, &self.1, None)
    }
}
