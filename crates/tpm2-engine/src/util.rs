pub(crate) fn strip_trailing_zeros(slice: &[u8]) -> &[u8] {
    let mut len = slice.len();
    while len > 0 && slice[len - 1] == 0 {
        len -= 1;
    }
    &slice[..len]
}

/// The authValue of a new object as the TCG reference keeps it (`AdjustAuthSize()`, called by
/// `TPM2_Create`, `TPM2_CreatePrimary`, `TPM2_CreateLoaded`): without its trailing zeros,
/// zero-padded to the digest size of the object's `nameAlg` (`sizeof(TPMU_HA)` for none). The
/// callers have checked that the value without its trailing zeros fits that size. An authValue is
/// compared and used without its trailing zeros, so the padding changes no authorization; it is the
/// object's authValue in its private area and in its saved context.
pub(crate) fn adjust_auth_size(
    auth: &[u8],
    name_alg: Option<tpm2::TpmiAlgHash>,
) -> crate::owned::OwnedAuth {
    let size = name_alg.map_or(tpm2::TpmiAlgHash::MAX_DIGEST_BYTES, |alg| alg.digest_size());
    let auth = strip_trailing_zeros(auth);
    let mut padded = [0u8; crate::owned::OwnedAuth::CAP];
    let len = core::cmp::max(size, auth.len()).min(padded.len());
    padded[..auth.len().min(len)].copy_from_slice(&auth[..auth.len().min(len)]);
    crate::owned::OwnedAuth::new(&padded[..len]).unwrap_or_default()
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
