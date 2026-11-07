//! Helpers shared by the BoringSSL key types.

use core::{
    ffi::c_int,
    mem::{MaybeUninit, size_of},
    ops::Deref,
    ptr::{self, NonNull},
};

use tpm2::crypto::CryptoError;

use crate::bssl_sys;

/// Returns the `N` bytes `marshal` writes to a `CBB`, e.g. via
/// `MLKEM768_marshal_public_key`.
pub(crate) fn marshal<const N: usize>(
    marshal: impl FnOnce(*mut bssl_sys::CBB) -> c_int,
) -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    let mut cbb = MaybeUninit::<bssl_sys::CBB>::uninit();
    unsafe {
        if bssl_sys::CBB_init_fixed(cbb.as_mut_ptr(), out.as_mut_ptr(), N) != 1 {
            return Err(CryptoError::Internal);
        }
        let ok = marshal(cbb.as_mut_ptr()) == 1 && bssl_sys::CBB_len(cbb.as_ptr()) == N;
        bssl_sys::CBB_cleanup(cbb.as_mut_ptr());
        if !ok {
            return Err(CryptoError::Internal);
        }
    }
    Ok(out)
}

/// Returns whether `parse` (e.g. `MLKEM768_parse_public_key`) succeeds on a
/// `CBS` over `bytes`, consuming all of them.
pub(crate) fn parse(bytes: &[u8], parse: impl FnOnce(*mut bssl_sys::CBS) -> c_int) -> bool {
    let mut cbs = bssl_sys::CBS {
        data: bytes.as_ptr(),
        len: bytes.len(),
    };
    parse(&raw mut cbs) == 1 && cbs.len == 0
}

/// Heap-allocated BoringSSL structure backed by `OPENSSL_malloc` and
/// `OPENSSL_free` (with `OPENSSL_cleanse` on drop), avoiding large stack frames
/// without requiring `alloc`.
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
        let raw = unsafe { bssl_sys::OPENSSL_malloc(size_of::<T>()) }.cast::<T>();
        let Some(ptr) = NonNull::new(raw) else {
            return Err(CryptoError::Internal);
        };
        // Constructed before `init` runs, so `Drop` cleans up on failure.
        let this = Self { ptr };
        match init(ptr.as_ptr()) {
            Ok(true) => Ok(Some(this)),
            Ok(false) => Ok(None),
            Err(e) => Err(e),
        }
    }

    #[inline]
    pub(crate) const fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }
}

impl<T: Copy> Clone for BsslBox<T> {
    fn clone(&self) -> Self {
        let raw = unsafe { bssl_sys::OPENSSL_malloc(size_of::<T>()) }.cast::<T>();
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
