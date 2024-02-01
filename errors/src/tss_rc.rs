use core::num::NonZeroU32;

/// Generate a typed error and result for a specifc TSS client layer.
macro_rules! generate_tss_layer_error {
    ($error_name:ident, $result_name:ident, $layer_value:literal) => {
        /// Represents success or client side error.
        pub type $result_name<T> = Result<T, $error_name>;

        /// Represents a TSS client side error.
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        pub struct $error_name(NonZeroU32);

        // Allow constant to have enum-style case.
        #[allow(non_upper_case_globals)]
        impl $error_name {
            /// Non-specific failure (`TSS_E_FAIL`).
            pub const GeneralFailure: Self = Self::new(2);
            /// One or more parameter is bad (`TSS_E_BAD_PARAMETER`).
            pub const BadParameter: Self = Self::new(3);
            ///An internal SW error has been detected (`TSS_E_INTERNAL_ERROR`).
            pub const InternalError: Self = Self::new(4);
            /// Ran out of memory (`TSS_E_OUTOFMEMORY`).
            pub const OutOfMemory: Self = Self::new(5);
            /// Not implemented (`TSS_E_NOTIMPL`).
            pub const NotImplemented: Self = Self::new(6);
            /// Key could not be registered because UUID has already registered
            /// (`TSS_E_KEY_ALREADY_REGISTERED`).
            pub const KeyAlredyRegistered: Self = Self::new(8);
            /// TPM returns with success but TSP/TCS notice that something is wrong
            /// (`TSS_E_TPM_UNEXPECTED`).
            pub const TpmUnexpected: Self = Self::new(16);
            /// A communications error with the TPM has been detected (`TSS_E_COMM_FAILURE`).
            pub const CommFailure: Self = Self::new(17);
            /// The operation has timed out (`TSS_E_TIMEOUT`).
            pub const Timeout: Self = Self::new(18);
            /// The TPM does not support the requested feature (`TSS_E_TPM_UNSUPPORTED_FEATURE`).
            pub const Unsupported: Self = Self::new(20);
            /// The action was canceled (`TSS_E_CANCELED`).
            pub const Canceled: Self = Self::new(22);

            /// Creates a new error for this layer from a common return code value.
            const fn new(value: u32) -> Self {
                match NonZeroU32::new(value | ($layer_value << 12)) {
                    Some(val) => Self(val),
                    None => unreachable!(),
                }
            }
        }

        impl From<$error_name> for super::TpmError {
            fn from(val: $error_name) -> Self {
                super::TpmError(val.0)
            }
        }
    };
}

generate_tss_layer_error!(TssTddlError, TssTddlResult, 0x1);
generate_tss_layer_error!(TssTcsError, TssTcsResult, 0x2);
generate_tss_layer_error!(TssTspError, TssTspResult, 0x3);
