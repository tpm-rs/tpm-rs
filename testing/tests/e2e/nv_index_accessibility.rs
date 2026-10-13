//! Accessibility of NV indices in disabled hierarchies and in non-NV handle positions.

use crate::_common::{
    define_nv_with_policy_unwrap as define, exec_with_empty_passwords as pw,
    start_session_active as start_session, *,
};
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::create_simulator;

/// An NV index handle in a TPMI_DH_OBJECT position is rejected at unmarshal with TPM_RC_VALUE
///
/// The NV accessibility check only applies to positions that can hold an NV Index; a
/// `TPMI_DH_OBJECT` position rejects an NV Index handle at unmarshaling (`TPM_RC_VALUE`).
#[test]
fn nv_handle_in_object_slot_rejected() {
    let mut sim = create_simulator!();
    let cmd = ObjectChangeAuth {
        object_handle: Handle(0x0150_0605),
        parent_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::default(),
    };
    assert_eq!(
        pw(&mut sim, &cmd, 1).unwrap_err(),
        TpmRc::VALUE.with(Position::handle(1)).get()
    );
}

/// PolicyNV on an index of a disabled owner hierarchy is TPM_RC_HANDLE + RC_H1
#[test]
fn policy_nv_on_hidden_index() {
    let mut sim = create_simulator!();
    let index = 0x0150_0603;
    define(&mut sim, index, OWNER_RW | TpmaNv::AUTHREAD, 8, &[]);
    owner_write(&mut sim, index, 0, &[0; 8]).unwrap();
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let session = start_session(&mut sim, TpmSe::Policy);
    let cmd = PolicyNV {
        auth_handle: Handle(index),
        nv_index: Handle(index),
        policy_session: session.session_handle,
        operand_b: Tpm2bOperand::from_bytes(&[0]).unwrap(),
        offset: 0,
        operation: TpmEo::Eq,
    };
    assert_eq!(
        pw(&mut sim, &cmd, 1).unwrap_err(),
        TpmRc::HANDLE.with(Position::handle(1)).get()
    );
}

/// NV_ReadPublic of a missing index or an index of a disabled owner hierarchy is TPM_RC_HANDLE + RC_H1
#[test]
fn read_public_missing_or_hidden_index() {
    let mut sim = create_simulator!();
    let missing = sim
        .execute(NVReadPublic {
            nv_index: Handle(0x0150_0600),
        })
        .unwrap_err();
    assert_eq!(missing.get(), TpmRc::HANDLE.with(Position::handle(1)).get());

    let index = 0x0150_0601;
    define(&mut sim, index, OWNER_RW, 8, &[]);
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let hidden = sim
        .execute(NVReadPublic {
            nv_index: Handle(index),
        })
        .unwrap_err();
    assert_eq!(hidden.get(), TpmRc::HANDLE.with(Position::handle(1)).get());
}

/// StartAuthSession bound to an undefined NV index is TPM_RC_HANDLE + RC_H2
#[test]
fn start_auth_session_bind_missing_index() {
    let mut sim = create_simulator!();
    let rc = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle(0x0150_0604),
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::HANDLE.with(Position::handle(2)).get());
}
