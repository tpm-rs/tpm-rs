//! Raw `bindgen` bindings to BoringSSL's internal FIPS module interface
//! (`crypto/fipsmodule/bcm_interface.h`).

#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    clippy::all,
    clippy::pedantic
)]

include!(concat!(env!("OUT_DIR"), "/bcm_bindings.rs"));
#[cfg(feature = "non-fips")]
include!(concat!(env!("OUT_DIR"), "/curve25519_bindings.rs"));

use core::{
    mem::size_of,
    ops::Deref,
    ptr::{self, NonNull},
};

use tpm2::crypto::CryptoError;

use crate::bssl_sys;

/// Converts a `bcm_status_t` return code into a [`Result`].
#[inline]
pub(crate) const fn check_status(status: bssl_bcm_status) -> Result<(), CryptoError> {
    if status == bssl_bcm_status_t_failure {
        Err(CryptoError::Internal)
    } else {
        Ok(())
    }
}

/// Heap-allocated BCM structure backed by `bssl_sys::OPENSSL_malloc` and
/// `bssl_sys::OPENSSL_free` (with `OPENSSL_cleanse` on drop), avoiding large
/// stack frames without requiring `alloc`.
pub(crate) struct BsslBox<T> {
    ptr: NonNull<T>,
}

impl<T> BsslBox<T> {
    /// Allocates uninitialized memory for `T` on the BoringSSL heap and runs
    /// `init(ptr)`. Frees and cleanses the allocation if `init` returns
    /// `Ok(false)` or `Err(_)`.
    pub(crate) fn try_init(
        init: impl FnOnce(*mut T) -> Result<bool, CryptoError>,
    ) -> Result<Option<Self>, CryptoError> {
        let size = size_of::<T>();
        let raw = unsafe { bssl_sys::OPENSSL_malloc(size) }.cast::<T>();
        let Some(ptr) = NonNull::new(raw) else {
            return Err(CryptoError::Internal);
        };
        match init(ptr.as_ptr()) {
            Ok(true) => Ok(Some(Self { ptr })),
            Ok(false) => {
                unsafe {
                    bssl_sys::OPENSSL_cleanse(ptr.as_ptr().cast(), size);
                    bssl_sys::OPENSSL_free(ptr.as_ptr().cast());
                }
                Ok(None)
            }
            Err(e) => {
                unsafe {
                    bssl_sys::OPENSSL_cleanse(ptr.as_ptr().cast(), size);
                    bssl_sys::OPENSSL_free(ptr.as_ptr().cast());
                }
                Err(e)
            }
        }
    }

    #[inline]
    pub(crate) const fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }
}

impl<T: Copy> Clone for BsslBox<T> {
    fn clone(&self) -> Self {
        let size = size_of::<T>();
        let raw = unsafe { bssl_sys::OPENSSL_malloc(size) }.cast::<T>();
        let ptr = NonNull::new(raw).expect("OPENSSL_malloc failed in BsslBox::clone");
        unsafe {
            ptr::copy_nonoverlapping(self.ptr.as_ptr(), ptr.as_ptr(), 1);
        }
        Self { ptr }
    }
}

impl<T> Deref for BsslBox<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> Drop for BsslBox<T> {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::OPENSSL_cleanse(self.ptr.as_ptr().cast(), size_of::<T>());
            bssl_sys::OPENSSL_free(self.ptr.as_ptr().cast());
        }
    }
}
