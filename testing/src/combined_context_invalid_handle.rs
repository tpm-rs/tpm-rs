use crate::test_utils::*;
use tpm2::commands::*;
use tpm2::*;
use tpm2_simulator::create_simulator;

#[test]
fn test_context_save_invalid_handle() {
    let mut sim = create_simulator!();

    let save_cmd = ContextSave::default();
    let save_handles = ContextSaveHandles {
        save_handle: Handle(0x40000001), // TPM_RH_OWNER
    };
    let res = execute_with_password_sessions(&mut sim, &save_cmd, save_handles, 0, &[]);
    assert!(res.is_err(), "Context save on permanent handle should fail");
}
