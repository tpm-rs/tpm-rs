use crate::sessions::{AuthorizationArea, NoSession};

impl AuthorizationArea<NoSession, NoSession, NoSession> for () {
    fn decompose_ref(&self) -> (Option<&NoSession>, Option<&NoSession>, Option<&NoSession>) {
        (None, None, None)
    }
}
