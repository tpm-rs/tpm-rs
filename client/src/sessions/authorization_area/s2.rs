use crate::sessions::{
    AuthorizationArea, AuthorizationArea1Plus, AuthorizationArea2Plus, NotSession, Session,
};

impl<T: Session, U: Session> AuthorizationArea<T, U, NotSession> for (T, U) {
    fn decompose_ref(&self) -> (Option<&T>, Option<&U>, Option<&NotSession>) {
        (Some(&self.0), Some(&self.1), None)
    }
}

impl<T: Session, U: Session> AuthorizationArea1Plus<T, U, NotSession> for (T, U) {
    fn decompose_ref(&self) -> (&T, Option<&U>, Option<&NotSession>) {
        (&self.0, Some(&self.1), None)
    }
}

impl<T: Session, U: Session> AuthorizationArea2Plus<T, U, NotSession> for (T, U) {
    fn decompose_ref(&self) -> (&T, &U, Option<&NotSession>) {
        (&self.0, &self.1, None)
    }
}
