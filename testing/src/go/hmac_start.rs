#![forbid(unsafe_code)]

use crate::test_utils::{
    execute_with_hmac_sessions, execute_with_password_sessions, flush_context, start_auth_session,
};
use rand::{RngCore, thread_rng};
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, HmacStart, HmacStartHandles, SequenceComplete,
    SequenceCompleteHandles, SequenceUpdate, SequenceUpdateHandles,
};
use tpm2::{Handle, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, TpmaObject, TpmaSession, TpmiAlgHash, TpmiAlgSymMode,
    TpmsSensitiveCreate, TpmtKeyedHashScheme, TpmtPublic, TpmtSymDefObject,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn run_hmac_start(
    sim: &mut Simulator<'_>,
    data: &[u8],
    password: &[u8],
    hierarchy: Handle,
    use_session: bool,
) -> Vec<u8> {
    let max_input_buffer = 1024;
    let auth_bytes = password;

    let mut session = if use_session {
        let sym_def = Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)));
        let mut s = start_auth_session(
            sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            sym_def,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        s.attributes.insert(TpmaSession::DECRYPT);
        s.attributes.insert(TpmaSession::ENCRYPT);
        s.attributes.insert(TpmaSession::CONTINUE_SESSION);
        Some(s)
    } else {
        None
    };

    let hmac_scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(hmac_scheme, Tpm2bDigest::default()),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: hierarchy,
    };

    let (create_rsp, create_rsp_handles) = if let Some(ref mut sess) = session {
        execute_with_hmac_sessions(
            sim,
            &create_cmd,
            create_handles,
            &[],
            core::slice::from_mut(sess),
            &[&[]],
        )
        .unwrap()
    } else {
        execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[]).unwrap()
    };

    let object_handle = create_rsp_handles.object_handle;
    let name = create_rsp.name;

    if let Some(ref mut sess) = session {
        sess.attributes.remove(TpmaSession::DECRYPT);
        sess.attributes.remove(TpmaSession::ENCRYPT);
    }

    let start_cmd = HmacStart {
        auth: Tpm2bAuth::from_bytes(auth_bytes).unwrap(),
        hash_alg: None,
    };
    let start_handles = HmacStartHandles {
        handle: object_handle,
    };

    let (_, start_resp_handles) = if let Some(ref mut sess) = session {
        execute_with_hmac_sessions(
            sim,
            &start_cmd,
            start_handles,
            &[name.get_buffer()],
            core::slice::from_mut(sess),
            &[&[]],
        )
        .unwrap()
    } else {
        execute_with_password_sessions(sim, &start_cmd, start_handles, 1, &[]).unwrap()
    };

    let sequence_handle = start_resp_handles.sequence_handle;

    let mut remaining_data = data;
    while remaining_data.len() > max_input_buffer {
        let chunk = &remaining_data[..max_input_buffer];
        let cmd_update = SequenceUpdate {
            buffer: tpm2::Tpm2bMaxBuffer::from_bytes(chunk).unwrap(),
        };
        let cmd_handles = SequenceUpdateHandles { sequence_handle };
        let _ = execute_with_password_sessions(sim, &cmd_update, cmd_handles, 1, auth_bytes)
            .expect("SequenceUpdate failed");
        remaining_data = &remaining_data[max_input_buffer..];
    }

    let cmd_complete = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(remaining_data).unwrap(),
        hierarchy,
    };
    let cmd_handles = SequenceCompleteHandles { sequence_handle };
    let (resp_complete, _) =
        execute_with_password_sessions(sim, &cmd_complete, cmd_handles, 1, auth_bytes)
            .expect("SequenceComplete failed");

    flush_context(sim, object_handle).unwrap();

    if let Some(sess) = session {
        flush_context(sim, sess.session_handle).unwrap();
    }

    resp_complete.result.as_ref().to_vec()
}

// Original Go test: hmac_start_test.go - TestHmacStart
#[test]
fn test_hmac_start() {
    let mut sim = create_simulator!();
    let buffer_sizes = [512, 1024, 2048, 4096];
    let hierarchies = [Handle::RH_NULL, Handle::RH_OWNER, Handle::RH_ENDORSEMENT];

    let mut password = [0u8; 8];
    thread_rng().fill_bytes(&mut password);

    for &size in &buffer_sizes {
        let mut data = vec![0u8; size];
        thread_rng().fill_bytes(&mut data);
        for &hierarchy in &hierarchies {
            let hmac1 = run_hmac_start(&mut sim, &data, &password, hierarchy, true);
            let hmac2 = run_hmac_start(&mut sim, &data, &password, hierarchy, true);
            assert_eq!(hmac1, hmac2, "HMAC outputs must be identical");
        }
    }
}

// Original Go test: hmac_start_test.go - TestHmacStartNoKeyAuth
#[test]
fn test_hmac_start_no_key_auth() {
    let mut sim = create_simulator!();
    let hierarchies = [Handle::RH_NULL, Handle::RH_OWNER, Handle::RH_ENDORSEMENT];

    let mut password = [0u8; 8];
    thread_rng().fill_bytes(&mut password);

    let mut data = vec![0u8; 1024];
    thread_rng().fill_bytes(&mut data);

    for &hierarchy in &hierarchies {
        let hmac1 = run_hmac_start(&mut sim, &data, &password, hierarchy, false);
        let hmac2 = run_hmac_start(&mut sim, &data, &password, hierarchy, false);
        assert_eq!(hmac1, hmac2, "HMAC outputs must be identical");
    }
}

// Original Go test: hmac_start_test.go - TestHmacStart/Same key multiple sequences
#[test]
fn test_hmac_start_same_key_multiple_sequences() {
    let mut sim = create_simulator!();

    let sym_def = Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)));
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        sym_def,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);
    session.attributes.insert(TpmaSession::ENCRYPT);
    session.attributes.insert(TpmaSession::CONTINUE_SESSION);

    let hmac_scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(hmac_scheme, Tpm2bDigest::default()),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_NULL,
    };

    let (create_rsp, create_rsp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        core::slice::from_mut(&mut session),
        &[&[]],
    )
    .unwrap();

    let object_handle = create_rsp_handles.object_handle;
    let name = create_rsp.name;

    session.attributes.remove(TpmaSession::DECRYPT);
    session.attributes.remove(TpmaSession::ENCRYPT);

    let start_cmd = HmacStart {
        auth: Tpm2bAuth::from_bytes(b"password").unwrap(),
        hash_alg: None,
    };
    let start_handles = HmacStartHandles {
        handle: object_handle,
    };

    let (_, start_resp_handles1) = execute_with_hmac_sessions(
        &mut sim,
        &start_cmd,
        start_handles,
        &[name.get_buffer()],
        core::slice::from_mut(&mut session),
        &[&[]],
    )
    .unwrap();

    let (_, start_resp_handles2) = execute_with_hmac_sessions(
        &mut sim,
        &start_cmd,
        start_handles,
        &[name.get_buffer()],
        core::slice::from_mut(&mut session),
        &[&[]],
    )
    .unwrap();

    let h1 = start_resp_handles1.sequence_handle;
    let h2 = start_resp_handles2.sequence_handle;
    assert_ne!(h1.0, h2.0, "Sequence handles must be unique");

    let cmd_complete1 = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let cmd_handles1 = SequenceCompleteHandles {
        sequence_handle: h1,
    };
    let _ = execute_with_password_sessions(&mut sim, &cmd_complete1, cmd_handles1, 1, b"password")
        .expect("SequenceComplete 1 failed");

    let cmd_complete2 = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let cmd_handles2 = SequenceCompleteHandles {
        sequence_handle: h2,
    };
    let _ = execute_with_password_sessions(&mut sim, &cmd_complete2, cmd_handles2, 1, b"password")
        .expect("SequenceComplete 2 failed");

    flush_context(&mut sim, object_handle).unwrap();
    flush_context(&mut sim, session.session_handle).unwrap();
}
