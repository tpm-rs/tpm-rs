//! TPM2_CreatePrimary validation: hierarchy handle, hierarchy auth, session handles, key sizes and
//! object memory.

use crate::_common::{Connection, NO_STREAM, PlatformConnection};
use crate::_common::{
    create, default_ecc_public, ecc_sign_template, execute_with_password_sessions, flush_context,
    load, load_external, marshal_to_slice, owner_srk, rc0, rsa_public_bits, sealed_template,
    set_hierarchy_enabled, try_create_primary_in,
};
use tpm2::commands::CreatePrimary;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bPrivate, TpmaObject, TpmiAlgHash,
};
use tpm2_simulator::{SimulatorPlatformSignal, create_simulator};

/// CreatePrimary with a transient handle as primaryHandle fails with TPM_RC_VALUE.
#[test]
fn non_hierarchy_handle_rejected() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(default_ecc_public());
    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    // Use an invalid handle for primary (e.g. transient handle 0x80000000)
    let cmd = CreatePrimary {
        primary_handle: Handle(0x80000000),
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let err = match execute_with_password_sessions(&mut sim, &cmd, 0, &[]) {
        Ok(_) => panic!("expected CreatePrimary to fail"),
        Err(e) => e,
    };
    assert_eq!(err, TpmRc::VALUE.with(Position::handle(1)).get());
}

/// CreatePrimary authorized by an unloaded non-password session handle fails with TPM_RC_REFERENCE_S0.
#[test]
fn non_password_session_handle_rejected() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(default_ecc_public());
    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    // Use a session handle other than password session (e.g. 0x03000000)
    // We expect the command to fail with value_for(Position::session(1)) -> 0x1C7
    let bad_session = tpm2::TpmsAuthCommand {
        session_handle: Handle(0x03000000),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: tpm2::TpmaSession(0),
        hmac: tpm2::Tpm2bDigest::default(),
    };

    let mut buf = [0u8; 1024];
    let mut session_buf = [0u8; 1024];
    let cmd_len = marshal_to_slice(&cmd, &mut buf);
    let session_len = marshal_to_slice(&bad_session, &mut session_buf);

    let mut req_buf = Vec::new();
    // write header: tag=0x8002, size=0, cc=CreatePrimary(0x131)
    req_buf.extend_from_slice(&0x8002_u16.to_be_bytes());
    req_buf.extend_from_slice(&0_u32.to_be_bytes()); // placeholder for size
    req_buf.extend_from_slice(&0x00000131_u32.to_be_bytes());

    // write handles
    req_buf.extend_from_slice(&cmd.primary_handle.0.to_be_bytes());

    // write auth area size
    req_buf.extend_from_slice(&(session_len as u32).to_be_bytes());
    req_buf.extend_from_slice(&session_buf[..session_len]);

    // write parameters
    req_buf.extend_from_slice(&buf[..cmd_len]);

    // update size in header
    let total_size = req_buf.len() as u32;
    req_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    let mut resp_buf = [0u8; 4096];
    sim.transact(&req_buf, &mut resp_buf).unwrap();
    let response_code = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());

    // C RetrieveSessionData: an unloaded session handle returns
    // TPM_RC_REFERENCE_S0 (0x918).
    assert_eq!(response_code, 0x918);
}

/// After changing owner auth, CreatePrimary with empty or wrong auth fails with TPM_RC_BAD_AUTH and succeeds with the right one.
#[test]
fn owner_auth_enforced() {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(default_ecc_public());
    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    // 1. Change Owner Auth to "ownerpass"
    let hca_cmd = tpm2::commands::HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(b"ownerpass").unwrap(),
    };
    execute_with_password_sessions(&mut sim, &hca_cmd, 1, &[])
        .expect("Failed to change hierarchy auth");

    // 2. Try CreatePrimary with NO auth (empty password).
    let res_no_auth = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert_eq!(
        res_no_auth.err(),
        Some(TpmRc::BAD_AUTH.with(Position::session(1)).get())
    );

    // 3. Try CreatePrimary with WRONG auth.
    let res_wrong_auth = execute_with_password_sessions(&mut sim, &cmd, 1, b"wrongpass");
    assert_eq!(
        res_wrong_auth.err(),
        Some(TpmRc::BAD_AUTH.with(Position::session(1)).get())
    );

    // 4. Try CreatePrimary with CORRECT auth.
    let resp = execute_with_password_sessions(&mut sim, &cmd, 1, b"ownerpass");
    assert!(
        resp.is_ok(),
        "Expected success with correct password, got: {:?}",
        resp.err()
    );
}

/// CreatePrimary of a 512-bit RSA key fails with TPM_RC_VALUE.
#[test]
fn rsa_512_bits_rejected() {
    let mut sim = create_simulator!();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    // Request a 512-bit RSA key, which is unsupported.
    let in_public = tpm2::Tpm2b(rsa_public_bits(512));

    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    // RH_OWNER needs authorization: with no session C returns AUTH_MISSING
    // before parameters are checked (SessionProcess.c:1650).
    let err = match execute_with_password_sessions(&mut sim, &cmd, 1, &[]) {
        Ok(_) => panic!("Expected error for 512-bit RSA key"),
        Err(e) => e,
    };
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(2)).get());
}

/// CreatePrimary needs no NV; with all transient slots full, OBJECT_MEMORY precedes template/inPrivate/hierarchy errors.
#[test]
fn works_without_nv_and_object_memory_checked_first() {
    let mut sim = create_simulator!();
    // CreatePrimary does not need NV.
    sim.signal_platform(SimulatorPlatformSignal::NvOff, NO_STREAM)
        .unwrap();
    let (h, _) = try_create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_sign_template(
            TpmiAlgHash::Sha256,
            TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
        ),
        &[],
    )
    .expect("CreatePrimary with NV unavailable");
    sim.signal_platform(SimulatorPlatformSignal::NvOn, NO_STREAM)
        .unwrap();
    flush_context(&mut sim, h).unwrap();

    // Fill every transient slot.
    let srk = owner_srk(&mut sim);
    let sealed = create(
        &mut sim,
        srk,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        b"x",
    )
    .unwrap();
    let mut loaded = vec![srk];
    loop {
        match load(&mut sim, srk, sealed.out_private, sealed.out_public) {
            Ok(h) => loaded.push(h),
            Err(rc) => {
                assert_eq!(rc, rc0(TpmRc::OBJECT_MEMORY));
                break;
            }
        }
        assert!(loaded.len() < 64, "no object memory limit reached");
    }

    // With no free slot, OBJECT_MEMORY precedes template, inPrivate and hierarchy errors.
    let mut bad = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::FIXED_TPM);
    bad.object_attributes.remove(TpmaObject::FIXED_PARENT);
    assert_eq!(
        try_create_primary_in(&mut sim, Handle::RH_OWNER, bad, &[]).unwrap_err(),
        rc0(TpmRc::OBJECT_MEMORY)
    );
    assert_eq!(
        load(&mut sim, srk, Tpm2bPrivate::default(), sealed.out_public).unwrap_err(),
        rc0(TpmRc::OBJECT_MEMORY)
    );
    set_hierarchy_enabled(&mut sim, Handle::RH_ENDORSEMENT, false);
    let mut public = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    public.parms_and_id =
        PublicParmsAndId::KeyedHash(None, Tpm2bDigest::from_bytes(&[3u8; 32]).unwrap());
    assert_eq!(
        load_external(&mut sim, public, None, Handle::RH_ENDORSEMENT).unwrap_err(),
        rc0(TpmRc::OBJECT_MEMORY)
    );
}
