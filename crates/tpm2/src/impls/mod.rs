macro_rules! impl_unmarshal_ref {
    () => {
        #[inline(always)]
        fn unmarshal_ref(&mut self, mut src: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
            *self = Unmarshal::unmarshal(&mut src)?;
            Ok(src)
        }
    };
}

mod alg;
mod commands;
mod enums;
mod newtypes;
