use crate::sessions::{AuthorizationArea, AuthorizationArea1Plus, AuthorizationArea2Plus, Session};

impl<T: Session, U: Session, V: Session> AuthorizationArea<T, U, V> for (T, U, V) {
    fn decompose(self) -> (Option<T>, Option<U>, Option<V>) {
        (Some(self.0), Some(self.1), Some(self.2))
    }
    fn decompose_ref(&self) -> (Option<&T>, Option<&U>, Option<&V>) {
        (Some(&self.0), Some(&self.1), Some(&self.2))
    }
    fn decompose_mut(&mut self) -> (Option<&mut T>, Option<&mut U>, Option<&mut V>) {
        (Some(&mut self.0), Some(&mut self.1), Some(&mut self.2))
    }
}
impl<T: Session, U: Session, V: Session> AuthorizationArea1Plus<T, U, V> for (T, U, V) {
    fn decompose(self) -> (T, Option<U>, Option<V>) {
        (self.0, Some(self.1), Some(self.2))
    }
    fn decompose_ref(&self) -> (&T, Option<&U>, Option<&V>) {
        (&self.0, Some(&self.1), Some(&self.2))
    }
    fn decompose_mut(&mut self) -> (&mut T, Option<&mut U>, Option<&mut V>) {
        (&mut self.0, Some(&mut self.1), Some(&mut self.2))
    }
}
impl<T: Session, U: Session, V: Session> AuthorizationArea2Plus<T, U, V> for (T, U, V) {
    fn decompose(self) -> (T, U, Option<V>) {
        (self.0, self.1, Some(self.2))
    }

    fn decompose_ref(&self) -> (&T, &U, Option<&V>) {
        (&self.0, &self.1, Some(&self.2))
    }

    fn decompose_mut(&mut self) -> (&mut T, &mut U, Option<&mut V>) {
        (&mut self.0, &mut self.1, Some(&mut self.2))
    }
}
