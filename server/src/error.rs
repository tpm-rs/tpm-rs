use core::{
    error::Error,
    fmt::{Debug, Display},
};

use crate::platform::{crypto::Drbg, TpmContextDeps};

pub enum ServerError<Deps: TpmContextDeps> {
    Drbg(<Deps::Drbg as Drbg>::Error),
}

impl<Deps: TpmContextDeps> Debug for ServerError<Deps> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Drbg(arg0) => f.debug_tuple("Drbg").field(arg0).finish(),
        }
    }
}

impl<Deps: TpmContextDeps> Display for ServerError<Deps> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

impl<Deps: TpmContextDeps> Error for ServerError<Deps> {}
