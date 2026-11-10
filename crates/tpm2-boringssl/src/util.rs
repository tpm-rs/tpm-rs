//! Helpers shared by the BoringSSL key types.

use core::{
    ffi::c_int,
    mem::{MaybeUninit, size_of},
    ops::Deref,
    ptr::{self, NonNull},
};

use tpm2::crypto::CryptoError;

use crate::bssl_sys;

/// Converts the result of a BoringSSL function returning one on success.
pub(crate) fn check(ret: c_int) -> Result<(), CryptoError> {
    if ret == 1 {
        Ok(())
    } else {
        Err(CryptoError::Internal)
    }
}

/// A BoringSSL object type, with its destructor.
pub(crate) trait Free {
    unsafe fn free(ptr: *mut Self);
}

/// A reference-counted BoringSSL object type.
pub(crate) trait UpRef: Free {
    unsafe fn up_ref(ptr: *mut Self);
}

macro_rules! impl_free {
    ($($ty:ident => $free:ident $(, $up_ref:ident)?;)*) => {$(
        impl Free for bssl_sys::$ty {
            unsafe fn free(ptr: *mut Self) {
                unsafe { bssl_sys::$free(ptr) }
            }
        }
        $(impl UpRef for bssl_sys::$ty {
            unsafe fn up_ref(ptr: *mut Self) {
                unsafe { bssl_sys::$up_ref(ptr) };
            }
        })?
    )*};
}

impl_free! {
    BIGNUM => BN_clear_free;
    BN_CTX => BN_CTX_free;
    CMAC_CTX => CMAC_CTX_free;
    CTR_DRBG_STATE => CTR_DRBG_free;
    EC_KEY => EC_KEY_free, EC_KEY_up_ref;
    EC_POINT => EC_POINT_free;
    EVP_PKEY => EVP_PKEY_free;
    EVP_PKEY_CTX => EVP_PKEY_CTX_free;
    HMAC_CTX => HMAC_CTX_free;
    RSA => RSA_free, RSA_up_ref;
}

/// An owned BoringSSL object: freed on drop, and (if reference-counted)
/// cloned by taking another reference.
pub(crate) struct Owned<T: Free>(NonNull<T>);

// SAFETY: None of these objects have thread affinity. They're only mutated
// while uniquely owned or through `&mut`, and the BoringSSL functions used on
// shared objects (e.g. `RSA` and `EC_KEY` operations) are thread-safe.
unsafe impl<T: Free> Send for Owned<T> {}
unsafe impl<T: Free> Sync for Owned<T> {}

impl<T: Free> Owned<T> {
    /// Takes ownership of the result of a BoringSSL constructor, or returns
    /// `None` if it's NULL.
    pub(crate) fn from_ptr(ptr: *mut T) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    /// Like [`Owned::from_ptr`], but treats NULL as an internal error.
    pub(crate) fn new(ptr: *mut T) -> Result<Self, CryptoError> {
        Self::from_ptr(ptr).ok_or(CryptoError::Internal)
    }

    #[inline]
    pub(crate) const fn as_ptr(&self) -> *mut T {
        self.0.as_ptr()
    }
}

impl<T: Free> Drop for Owned<T> {
    fn drop(&mut self) {
        unsafe { T::free(self.as_ptr()) }
    }
}

impl<T: UpRef> Clone for Owned<T> {
    fn clone(&self) -> Self {
        unsafe { T::up_ref(self.as_ptr()) };
        Self(self.0)
    }
}

/// A BoringSSL `BIGNUM`, cleared on drop.
pub(crate) type Bn = Owned<bssl_sys::BIGNUM>;

impl Bn {
    pub(crate) fn zero() -> Result<Self, CryptoError> {
        Self::new(unsafe { bssl_sys::BN_new() })
    }

    pub(crate) fn from_be(bytes: &[u8]) -> Result<Self, CryptoError> {
        Self::new(unsafe { bssl_sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), ptr::null_mut()) })
    }

    pub(crate) fn from_u32(val: u32) -> Result<Self, CryptoError> {
        let bn = Self::zero()?;
        // `BN_ULONG` is `u32` or `u64`, depending on the target.
        check(unsafe { bssl_sys::BN_set_word(bn.as_ptr(), val.into()) })?;
        Ok(bn)
    }

    pub(crate) fn to_be_padded(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        check(unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), out.len(), self.as_ptr()) })
    }
}

/// Returns a new `BN_CTX`. Despite `bn.h`, most `BN_*` functions don't accept
/// a NULL `BN_CTX` (the `EC_*` functions ignore it, so they get NULL).
pub(crate) fn bn_ctx() -> Result<Owned<bssl_sys::BN_CTX>, CryptoError> {
    Owned::new(unsafe { bssl_sys::BN_CTX_new() })
}

/// A secret value, wiped with `OPENSSL_cleanse` on drop.
#[derive(Clone)]
pub(crate) struct Secret<T: Copy>(pub(crate) T);

impl<T: Copy> Drop for Secret<T> {
    fn drop(&mut self) {
        unsafe { bssl_sys::OPENSSL_cleanse((&raw mut self.0).cast(), size_of::<T>()) };
    }
}

/// Returns the `N` bytes `marshal` writes to a `CBB`, e.g. via
/// `MLKEM768_marshal_public_key`.
pub(crate) fn marshal<const N: usize>(
    marshal: impl FnOnce(*mut bssl_sys::CBB) -> c_int,
) -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    let mut cbb = MaybeUninit::<bssl_sys::CBB>::uninit();
    unsafe {
        check(bssl_sys::CBB_init_fixed(
            cbb.as_mut_ptr(),
            out.as_mut_ptr(),
            N,
        ))?;
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

// SAFETY: `BsslBox<T>` uniquely owns its `T`, like `Box<T>`.
unsafe impl<T: Send> Send for BsslBox<T> {}
unsafe impl<T: Sync> Sync for BsslBox<T> {}

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
