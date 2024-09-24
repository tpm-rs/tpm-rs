mod s0;
mod s1;
mod s2;
mod s3;

use crate::sessions::Session;

/// A trait for authorization area with (possibly zero) unkown number of sessions.
/// Check top level module documentation.
pub trait AuthorizationArea<T: Session, U: Session, V: Session> {
    fn decompose(self) -> (Option<T>, Option<U>, Option<V>);
    fn decompose_ref(&self) -> (Option<&T>, Option<&U>, Option<&V>);
    fn decompose_mut(&mut self) -> (Option<&mut T>, Option<&mut U>, Option<&mut V>);
    fn is_empty(&self) -> bool {
        self.decompose_ref().0.is_none()
    }
}

/// Authorization area with 1+ sessions
pub trait AuthorizationArea1Plus<T: Session, U: Session, V: Session>:
    AuthorizationArea<T, U, V>
{
    fn decompose(self) -> (T, Option<U>, Option<V>);
    fn decompose_ref(&self) -> (&T, Option<&U>, Option<&V>);
    fn decompose_mut(&mut self) -> (&mut T, Option<&mut U>, Option<&mut V>);
}

/// Authorization area with 2+ sessions
pub trait AuthorizationArea2Plus<T: Session, U: Session, V: Session>:
    AuthorizationArea1Plus<T, U, V>
{
    fn decompose(self) -> (T, U, Option<V>);
    fn decompose_ref(&self) -> (&T, &U, Option<&V>);
    fn decompose_mut(&mut self) -> (&mut T, &mut U, Option<&mut V>);
}
