use crate::ServerError;

#[derive(Debug)]
pub struct DrbgError;

impl From<DrbgError> for ServerError {
    fn from(_: DrbgError) -> Self {
        Self::DrbgError
    }
}