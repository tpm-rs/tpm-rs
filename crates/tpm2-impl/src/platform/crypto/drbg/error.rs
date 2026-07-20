use crate::ServerError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DrbgError;

impl From<DrbgError> for ServerError {
    fn from(_: DrbgError) -> Self {
        Self::DrbgError
    }
}
