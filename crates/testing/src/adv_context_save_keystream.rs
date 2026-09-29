use crate::test_utils::*;
use tpm2::Unmarshal;
use tpm2::commands::*;
use tpm2::*;
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_context_save_load_qualified_name() {
    let mut sim = create_simulator!();
    let (in_sensitive, in_public) = create_test_keys();
    let cmd = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let handles = CreateLoadedHandles {
        parent_handle: tpm2::Handle(0x40000001), // TPM_RH_OWNER
    };

    let (_, resp_handles) =
        execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();
    let created_handle = resp_handles.object_handle;

    let read_public_cmd = ReadPublic {};
    let read_public_handles = ReadPublicHandles {
        object_handle: created_handle,
    };
    let (read_pub_resp1, _) =
        execute_with_password_sessions(&mut sim, &read_public_cmd, read_public_handles, 0, &[])
            .unwrap();
    let qn1 = read_pub_resp1.qualified_name.get_buffer().to_vec();

    // ContextSave
    let save_cmd = ContextSave {};
    let save_handles = ContextSaveHandles {
        save_handle: created_handle,
    };
    let (save_resp, _) =
        execute_with_password_sessions(&mut sim, &save_cmd, save_handles, 0, &[]).unwrap();

    flush_context(&mut sim, created_handle).unwrap();

    // ContextLoad
    let load_cmd = ContextLoad {
        context: save_resp.context,
    };
    let (_, load_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, (), 0, &[]).unwrap();
    let loaded_handle = load_handles.loaded_handle;

    // ReadPublic again to check qualified_name
    let read_public_handles2 = ReadPublicHandles {
        object_handle: loaded_handle,
    };
    let (read_pub_resp2, _) =
        execute_with_password_sessions(&mut sim, &read_public_cmd, read_public_handles2, 0, &[])
            .unwrap();
    let qn2 = read_pub_resp2.qualified_name.get_buffer().to_vec();

    assert_eq!(
        qn1, qn2,
        "Qualified name was lost across ContextSave/ContextLoad!"
    );
}

#[test]
fn test_context_save_eviction_spec() {
    let mut sim = create_simulator!();
    let (in_sensitive, in_public) = create_test_keys();
    let cmd = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let handles = CreateLoadedHandles {
        parent_handle: tpm2::Handle(0x40000001),
    };
    let (_, resp_handles) =
        execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();
    let created_handle = resp_handles.object_handle;

    let save_cmd = ContextSave {};
    let save_handles = ContextSaveHandles {
        save_handle: created_handle,
    };
    // Save once
    let _ = execute_with_password_sessions(&mut sim, &save_cmd, save_handles, 0, &[]).unwrap();

    // Verify object still exists by reading public
    let read_public_cmd = ReadPublic {};
    let read_public_handles = ReadPublicHandles {
        object_handle: created_handle,
    };
    let read_res =
        execute_with_password_sessions(&mut sim, &read_public_cmd, read_public_handles, 0, &[]);
    assert!(
        read_res.is_ok(),
        "ContextSave incorrectly evicted the object!"
    );
}

#[test]
fn test_context_keystream_reuse() {
    let mut sim = create_simulator!();
    let (in_sensitive, in_public) = create_test_keys();
    let cmd = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let handles = CreateLoadedHandles {
        parent_handle: tpm2::Handle(0x40000001),
    };
    let (_, resp_handles) =
        execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();
    let created_handle = resp_handles.object_handle;

    let save_cmd = ContextSave {};
    let save_handles = ContextSaveHandles {
        save_handle: created_handle,
    };

    let (save_resp1, _) =
        execute_with_password_sessions(&mut sim, &save_cmd, save_handles, 0, &[]).unwrap();
    let (save_resp2, _) =
        execute_with_password_sessions(&mut sim, &save_cmd, save_handles, 0, &[]).unwrap();

    let ctx1 = save_resp1.context;
    let ctx2 = save_resp2.context;

    assert_eq!(ctx1.saved_handle, ctx2.saved_handle);
    assert_ne!(ctx1.sequence, ctx2.sequence, "Sequence should increment!");

    // The encrypted part must be different, avoiding keystream reuse

    let mut u1 = ctx1.context_blob.get_buffer();
    let tpms_ctx1 = TpmsContextData::unmarshal(&mut u1).unwrap();
    let mut u2 = ctx2.context_blob.get_buffer();
    let tpms_ctx2 = TpmsContextData::unmarshal(&mut u2).unwrap();
    assert_ne!(
        tpms_ctx1.encrypted.get_buffer(),
        tpms_ctx2.encrypted.get_buffer(),
        "ContextSave encrypted payload is identical! Keystream/IV reuse detected!"
    );
}

#[test]
fn test_context_incomplete_mac() {
    let mut sim = create_simulator!();
    let (in_sensitive, in_public) = create_test_keys();
    let cmd = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let handles = CreateLoadedHandles {
        parent_handle: tpm2::Handle(0x40000001),
    };
    let (_, resp_handles) =
        execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();
    let created_handle = resp_handles.object_handle;

    let save_cmd = ContextSave {};
    let save_handles = ContextSaveHandles {
        save_handle: created_handle,
    };
    let (save_resp, _) =
        execute_with_password_sessions(&mut sim, &save_cmd, save_handles, 0, &[]).unwrap();

    flush_context(&mut sim, created_handle).unwrap();

    // 1. Mutate sequence
    let mut mutated_seq = save_resp.context;
    mutated_seq.sequence = mutated_seq.sequence.wrapping_add(1);
    let load_cmd = ContextLoad {
        context: mutated_seq,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, (), 0, &[]);
    assert!(res.is_err(), "MAC check failed to catch mutated sequence!");

    // 2. Mutate saved_handle
    let mut mutated_handle = save_resp.context;
    mutated_handle.saved_handle.0 ^= 1;
    let load_cmd = ContextLoad {
        context: mutated_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, (), 0, &[]);
    assert!(
        res.is_err(),
        "MAC check failed to catch mutated saved_handle!"
    );

    // 3. Mutate hierarchy
    let mut mutated_hierarchy = save_resp.context;
    mutated_hierarchy.hierarchy.0 ^= 1;
    let load_cmd = ContextLoad {
        context: mutated_hierarchy,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, (), 0, &[]);
    assert!(res.is_err(), "MAC check failed to catch mutated hierarchy!");
}
