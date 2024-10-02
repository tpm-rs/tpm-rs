use crate::sessions::{AuthorizationArea, AuthorizationArea1Plus, AuthorizationArea2Plus, Session};

impl<T: Session, U: Session, V: Session> AuthorizationArea<T, U, V> for (T, U, V) {
    fn decompose_ref(&self) -> (Option<&T>, Option<&U>, Option<&V>) {
        (Some(&self.0), Some(&self.1), Some(&self.2))
    }
}
impl<T: Session, U: Session, V: Session> AuthorizationArea1Plus<T, U, V> for (T, U, V) {
    fn decompose_ref(&self) -> (&T, Option<&U>, Option<&V>) {
        (&self.0, Some(&self.1), Some(&self.2))
    }
}
impl<T: Session, U: Session, V: Session> AuthorizationArea2Plus<T, U, V> for (T, U, V) {
    fn decompose_ref(&self) -> (&T, &U, Option<&V>) {
        (&self.0, &self.1, Some(&self.2))
    }
}
