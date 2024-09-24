use crate::sessions::{AuthorizationArea, NotSession};

impl AuthorizationArea<NotSession, NotSession, NotSession> for () {
    fn decompose_ref(
        &self,
    ) -> (
        Option<&NotSession>,
        Option<&NotSession>,
        Option<&NotSession>,
    ) {
        (None, None, None)
    }
}
