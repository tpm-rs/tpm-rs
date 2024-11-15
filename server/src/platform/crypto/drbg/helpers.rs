use super::Drbg;

/// Implement `fill_bytes` via `next_u64` and `next_u32`, little-endian order.
///
/// The fastest way to fill a slice is usually to work as long as possible with
/// integers. That is why this method mostly uses `next_u64`, and only when
/// there are 4 or less bytes remaining at the end of the slice it uses
/// `next_u32` once.
pub fn fill_bytes_via_next<R: Drbg>(
    rng: &mut R,
    mut additional_input: &[u8],
    mut dest: &mut [u8],
) -> Result<(), R::Error> {
    while dest.len() >= 8 {
        let (left, right) = dest.split_at_mut(8);
        dest = right;
        let chunk: [u8; 8] = rng.next_u64(additional_input)?.to_le_bytes();
        additional_input = &[];
        left.copy_from_slice(&chunk);
    }
    let n = dest.len();
    if n > 4 {
        let chunk: [u8; 8] = rng.next_u64(additional_input)?.to_le_bytes();
        dest.copy_from_slice(&chunk[..n]);
    } else if n > 0 {
        let chunk: [u8; 4] = rng.next_u32(additional_input)?.to_le_bytes();
        dest.copy_from_slice(&chunk[..n]);
    }
    Ok(())
}

/// Implement `next_u32` via `fill_bytes`, little-endian order.
pub fn next_u32_via_fill<R: Drbg>(rng: &mut R, additional_input: &[u8]) -> Result<u32, R::Error> {
    let mut buf = [0; 4];
    rng.fill_bytes(additional_input, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Implement `next_u64` via `fill_bytes`, little-endian order.
pub fn next_u64_via_fill<R: Drbg>(rng: &mut R, additional_input: &[u8]) -> Result<u64, R::Error> {
    let mut buf = [0; 8];
    rng.fill_bytes(additional_input, &mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Implement `next_u64` via `next_u32`, little-endian order.
pub fn next_u64_via_u32<R: Drbg>(rng: &mut R, additional_input: &[u8]) -> Result<u64, R::Error> {
    // Use LE; we explicitly generate one value before the next.
    let x = u64::from(rng.next_u32(additional_input)?);
    let y = u64::from(rng.next_u32(&[])?);
    Ok((y << 32) | x)
}
