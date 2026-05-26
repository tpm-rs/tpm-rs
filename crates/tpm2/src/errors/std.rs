//! Implement std-only traits and conversions
extern crate std;

use crate::errors::TssError;

impl From<TssError> for std::io::Error {
    fn from(value: TssError) -> Self {
        std::io::Error::other(value)
    }
}
