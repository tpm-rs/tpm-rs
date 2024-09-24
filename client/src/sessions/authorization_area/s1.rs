use crate::sessions::{AuthorizationArea, AuthorizationArea1Plus, NotSession, Session};

impl<T: Session> AuthorizationArea<T, NotSession, NotSession> for T {
    fn decompose_ref(&self) -> (Option<&T>, Option<&NotSession>, Option<&NotSession>) {
        (Some(self), None, None)
    }
}
impl<T: Session> AuthorizationArea1Plus<T, NotSession, NotSession> for T {
    fn decompose_ref(&self) -> (&T, Option<&NotSession>, Option<&NotSession>) {
        (self, None, None)
    }
}
