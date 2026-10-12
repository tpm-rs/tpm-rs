use tpm2::errors::Position;
use tpm2::{Handle, Tpm2bName, TpmCc, TpmSu};

use crate::owned::OwnedName;

/// `TPM_RH_UNASSIGNED` (TPM 2.0 Part 2, Section 7.4, Table 30).
///
/// Not provided by [`tpm2::Handle`]; use this instead of exp's `Handle::RH_UNASSIGNED`.
pub(crate) const RH_UNASSIGNED: Handle = Handle(0x4000_0008);

/// `TPM_RH_AUTH_00`, the first vendor authorization handle (`VENDOR_PERMANENT`)
/// (TPM 2.0 Part 2, Section 7.4, Table 30).
///
/// Not provided by [`tpm2::Handle`]; use this instead of exp's `Handle::RH_AUTH_00`.
pub(crate) const RH_AUTH_00: Handle = Handle(0x4000_0010);

/// Returns the [`Position`] of the session at 0-based `index` in the authorization area.
///
/// Indices past the 7 encodable session positions saturate to session 7.
///
/// PORTING: replaces exp's `Position::session((index + 1) as u8)`.
pub(crate) const fn session_position(index: usize) -> Position {
    let n = if index < 7 { index + 1 } else { 7 };
    Position::session(n as u8)
}

/// Returns the [`Position`] of the handle at 0-based `index` in the handle area.
///
/// Indices past the 7 encodable handle positions saturate to handle 7.
///
/// PORTING: replaces exp's `Position::handle((index + 1) as u8)`.
pub(crate) const fn handle_position(index: usize) -> Position {
    let n = if index < 7 { index + 1 } else { 7 };
    Position::handle(n as u8)
}

/// Returns the raw `TPM_SU` value of `su`, as stored in
/// `GlobalState::orderly_state`.
///
/// PORTING: replaces exp's `cmd.shutdown_type as u16` (the new [`TpmSu`]
/// has no `From<TpmSu> for u16`).
pub(crate) const fn tpm_su_value(su: TpmSu) -> u16 {
    su as u16
}

/// Returns the `commandIndex` field (the low 16 bits) of `cc` (TPM 2.0 Part 2, Section 8.9).
///
/// PORTING: replaces exp's `cc.code() as u16`.
pub(crate) const fn command_index(cc: TpmCc) -> u16 {
    cc.code() as u16
}

pub(crate) fn strip_trailing_zeros(slice: &[u8]) -> &[u8] {
    let mut len = slice.len();
    while len > 0 && slice[len - 1] == 0 {
        len -= 1;
    }
    &slice[..len]
}

/// Returns the value a session bound to an entity records to identify it
/// (`SessionComputeBoundEntity` in the reference implementation): the entity's Name,
/// zero-padded to the size of a `TPMU_NAME`, with the entity's authValue (without trailing
/// zeros) XORed into its last bytes.
///
/// Returns `None` if `name` or `auth` is longer than a `TPMU_NAME`.
pub(crate) fn bound_entity(name: &[u8], auth: &[u8]) -> Option<OwnedName> {
    let mut buf = [0u8; Tpm2bName::CAP];
    buf.get_mut(..name.len())?.copy_from_slice(name);
    let auth = strip_trailing_zeros(auth);
    let start = buf.len().checked_sub(auth.len())?;
    for (b, a) in buf[start..].iter_mut().zip(auth) {
        *b ^= a;
    }
    OwnedName::from_bytes(&buf).ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_are_one_based_and_saturate() {
        assert_eq!(session_position(0), Position::session(1));
        assert_eq!(session_position(6), Position::session(7));
        assert_eq!(session_position(100), Position::session(7));
        assert_eq!(handle_position(0), Position::handle(1));
        assert_eq!(handle_position(2), Position::handle(3));
        assert_eq!(handle_position(usize::MAX), Position::handle(7));
    }

    #[test]
    fn raw_values() {
        assert_eq!(tpm_su_value(TpmSu::Clear), 0x0000);
        assert_eq!(tpm_su_value(TpmSu::State), 0x0001);
        assert_eq!(command_index(TpmCc::Startup), 0x0144);
        assert_eq!(command_index(TpmCc::GetRandom), 0x017B);
    }

    #[test]
    fn byte_helpers() {
        assert_eq!(strip_trailing_zeros(&[1, 0, 2, 0, 0]), &[1, 0, 2]);
        assert!(strip_trailing_zeros(&[0, 0]).is_empty());
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn bound_entity_pads_name_and_xors_auth() {
        // A SHA-512 Name (2-byte nameAlg + 64-byte digest) fills the whole buffer.
        let bound = bound_entity(&[0x11; 66], &[0xFF, 0x00]).unwrap();
        let bound = bound.get_buffer();
        assert_eq!(bound.len(), 66);
        assert_eq!(bound[..65], [0x11; 65]);
        assert_eq!(bound[65], 0x11 ^ 0xFF);

        // Shorter Names are zero-padded before the authValue is XORed in.
        let bound = bound_entity(&[0xAA; 34], &[0x01, 0x02]).unwrap();
        let bound = bound.get_buffer();
        assert_eq!(bound.len(), 66);
        assert_eq!(bound[..34], [0xAA; 34]);
        assert_eq!(bound[34..64], [0; 30]);
        assert_eq!(bound[64..], [0x01, 0x02]);

        assert!(bound_entity(&[0; 67], &[]).is_none());
    }
}
