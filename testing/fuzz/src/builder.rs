//! Operand resolution, fix-ups and the command builder.
//!
//! A [`Cmd`] becomes bytes in three steps: its handles are resolved against
//! the value pool and the live sessions ([`resolve_handles`]), its parameter
//! segments are resolved and concatenated ([`resolve_params`], with TPM2B
//! size fix-ups), and the parts are assembled into a command buffer
//! ([`assemble`], with the `commandSize` and `authorizationSize` fix-ups).
//! The authorization area comes from the session engine, which needs the
//! resolved handles and parameters first, so the steps are separate.

use crate::model::{Cmd, Fixups, Segment, TPM_ST_SESSIONS};
use crate::pool::ValuePool;

/// Resolves the handle area of `cmd` (see
/// [`ValuePool::resolve_handle`]); `sessions` are the live session handles,
/// oldest first.
pub fn resolve_handles(cmd: &Cmd, pool: &ValuePool, sessions: &[u32]) -> Vec<u32> {
    cmd.handles
        .iter()
        .map(|&op| pool.resolve_handle(op, sessions))
        .collect()
}

/// Resolves and concatenates the parameter segments of `cmd`.
pub fn resolve_params(cmd: &Cmd, pool: &ValuePool) -> Vec<u8> {
    let mut out = Vec::new();
    resolve_segments(&cmd.params, pool, &cmd.fixups, &mut out);
    out
}

/// Appends the bytes of `segments` to `out`.
fn resolve_segments(segments: &[Segment], pool: &ValuePool, fixups: &Fixups, out: &mut Vec<u8>) {
    for segment in segments {
        match segment {
            Segment::Bytes(bytes) => out.extend_from_slice(bytes),
            Segment::Value(r) => out.extend_from_slice(&pool.resolve_value(*r)),
            Segment::Mutated(r, m) => {
                let mut value = pool.resolve_value(*r);
                m.apply(&mut value);
                out.extend_from_slice(&value);
            }
            Segment::Sized(children) => {
                let at = out.len();
                out.extend_from_slice(&[0, 0]);
                resolve_segments(children, pool, fixups, out);
                let len = (out.len() - at - 2) as u16;
                let size = len.wrapping_add_signed(fixups.tpm2b_delta.unwrap_or(0));
                out[at..at + 2].copy_from_slice(&size.to_be_bytes());
            }
        }
    }
}

/// Assembles a command buffer: `tag`, `commandSize`, `code`, `handles`, the
/// authorization area (`authorizationSize` and `auth_area`) if `auth_area` is
/// given, then `params`. The sizes are computed unless `fixups` overrides
/// them.
pub fn assemble(
    tag: u16,
    code: u32,
    handles: &[u32],
    auth_area: Option<&[u8]>,
    params: &[u8],
    fixups: &Fixups,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + 4 * handles.len() + params.len());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&code.to_be_bytes());
    for h in handles {
        out.extend_from_slice(&h.to_be_bytes());
    }
    if let Some(auth) = auth_area {
        let size = fixups.auth_size.unwrap_or(auth.len() as u32);
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(auth);
    }
    out.extend_from_slice(params);
    let size = fixups.command_size.unwrap_or(out.len() as u32);
    out[2..6].copy_from_slice(&size.to_be_bytes());
    out
}

/// Whether a command buffer of `cmd` has an authorization area: when it has
/// sessions or its tag is `TPM_ST_SESSIONS` (then possibly empty).
pub fn has_auth_area(cmd: &Cmd) -> bool {
    !cmd.sessions.is_empty() || cmd.tag.value(false) == TPM_ST_SESSIONS
}

/// Builds the command buffer of `cmd` with a given authorization area
/// (`auth_area` is used only if [`has_auth_area`]; `None` means an empty
/// one). Convenient for tools that resolve commands without a session engine.
pub fn build(cmd: &Cmd, pool: &ValuePool, sessions: &[u32], auth_area: Option<&[u8]>) -> Vec<u8> {
    let handles = resolve_handles(cmd, pool, sessions);
    let params = resolve_params(cmd, pool);
    let auth = has_auth_area(cmd).then(|| auth_area.unwrap_or(&[]));
    assemble(
        cmd.tag.value(!cmd.sessions.is_empty()),
        cmd.code,
        &handles,
        auth,
        &params,
        &cmd.fixups,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldKind, HandleOperand, Mutation, TagSel, ValueRef};

    #[test]
    fn builds_a_plain_command() {
        let mut cmd = Cmd::new(0x17B);
        cmd.params = vec![Segment::Bytes(vec![0, 16])];
        let pool = ValuePool::default();
        assert_eq!(
            build(&cmd, &pool, &[], None),
            [0x80, 1, 0, 0, 0, 12, 0, 0, 1, 0x7B, 0, 16]
        );
    }

    #[test]
    fn computes_sizes_and_honors_overrides() {
        let mut cmd = Cmd::new(0x131);
        cmd.handles = vec![HandleOperand::Raw(0x4000_0001)];
        cmd.params = vec![Segment::Sized(vec![
            Segment::Bytes(vec![1, 2]),
            Segment::Sized(vec![Segment::Bytes(vec![3])]),
        ])];
        let pool = ValuePool::default();
        let auth = [0x40, 0, 0, 9, 0, 0, 1, 0, 0];
        let built = build(&cmd, &pool, &[], Some(&auth));
        // No sessions in the model, so no auth area and NO_SESSIONS.
        assert_eq!(
            built,
            [
                0x80, 1, 0, 0, 0, 21, 0, 0, 1, 0x31, 0x40, 0, 0, 1, 0, 5, 1, 2, 0, 1, 3
            ]
        );
        cmd.tag = TagSel::Sessions;
        cmd.fixups = Fixups {
            command_size: Some(0xABCD),
            auth_size: Some(1),
            tpm2b_delta: Some(-1),
        };
        let built = build(&cmd, &pool, &[], Some(&auth));
        assert_eq!(&built[..6], [0x80, 2, 0, 0, 0xAB, 0xCD]);
        assert_eq!(&built[14..18], [0, 0, 0, 1]);
        assert_eq!(&built[18..27], auth);
        assert_eq!(&built[27..], [0, 4, 1, 2, 0, 0, 3]);
    }

    #[test]
    fn splices_and_mutates_values() {
        let mut cmd = Cmd::new(0x173);
        let r = ValueRef {
            kind: FieldKind::Name,
            back: 0,
        };
        cmd.params = vec![
            Segment::Value(r),
            Segment::Mutated(r, Mutation::Extend(vec![9])),
        ];
        let pool = ValuePool::default();
        assert_eq!(resolve_params(&cmd, &pool), [0, 0, 0, 0, 9]);
    }
}
