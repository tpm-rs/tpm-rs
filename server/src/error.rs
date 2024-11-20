use core::{
    error::Error,
    fmt::{Debug, Display},
};

#[derive(Debug)]
pub enum ServerError {
    DrbgError,
}

impl Display for ServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServerError::DrbgError => write!(f, "Drbg operation failed"),
        }
    }
}

impl Error for ServerError {}
