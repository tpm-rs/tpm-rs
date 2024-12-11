//! Funtions here are not part of any standards, but we need them for practical reasons.
use crypto_bigint::U896;
use digest::generic_array::{ArrayLength, GenericArray};

/// # Invariant
/// The invariant that should hold here is that array must have length less than
/// or equal to 112 bytes. If it does not, this function will crashs.
///
/// At the time being the largest number we fit has 888 bits so it should fit.
///
/// # Justification
/// The reason we need this function is when converting `V` or `C` into a number
/// we will have to deal with buffer of less than 896 bits. Sadly [crypto_bigint] does
/// not pad on its own, so we need to do th padding outselves.
pub fn slice_to_u896(data: &[u8]) -> U896 {
    let mut buffer = [0; 112];
    buffer[112 - data.len()..].copy_from_slice(data);
    U896::from_be_slice(&buffer)
}

/// # Invariant
/// The main invariant is that `N` must be greater than or equal to `M`.
/// This invariant should hold because the input is always the array behind [U896]
/// and the output has `M` of at most 888 bits.
///
/// # Justification
/// we do not have `U888` or `U440` arrays. so we just use [U896] and do arithmetic
/// mod `2^seedlen`. The most significant `N-M` bits are gauranteed to be zeros, so we
/// remove them.
pub fn truncate_from_start<N, M>(input: &GenericArray<u8, N>) -> GenericArray<u8, M>
where
    N: ArrayLength<u8>,
    M: ArrayLength<u8>,
{
    let mut truncated = GenericArray::default();
    let len = M::to_usize();
    for i in 0..len {
        truncated[i] = input[i + (N::to_usize() - M::to_usize())];
    }
    truncated
}
