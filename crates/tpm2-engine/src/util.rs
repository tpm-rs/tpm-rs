pub(crate) fn strip_trailing_zeros(slice: &[u8]) -> &[u8] {
    let mut len = slice.len();
    while len > 0 && slice[len - 1] == 0 {
        len -= 1;
    }
    &slice[..len]
}

/// Compares two byte slices for equality in a way that attempts to avoid timing side-channels.
///
/// ## Limitations and Security Warning
///
/// While this function avoids high-level logical branching on slice mismatch, **it does not
/// guarantee absolute constant-time execution** across all compilers and CPU architectures:
///
/// 1. **Compiler Optimization Risk**: The compiler (LLVM) is unaware of constant-time constraints
///    and may optimize this loop (e.g., short-circuiting or vectorizing) in a way that introduces
///    timing variations.
/// 2. **Hardware Operand-Dependent Timing**: On some modern processors (e.g., Intel Ice Lake+,
///    ARM), basic ALU instructions may execute faster or slower depending on their input values
///    (such as zero). Absolute constant-time execution on these cores requires enabling hardware-level
///    modes (like Intel's DOITM or ARM's DIT).
/// 3. **Length Disclosure**: If the two slices have different lengths, this function returns
///    `false` immediately. It is only suitable for comparing buffers where lengths are already
///    public or identical (e.g., comparing cryptographic hash digests).
///
/// For cryptographically secure comparisons, consider using dedicated constant-time libraries.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
