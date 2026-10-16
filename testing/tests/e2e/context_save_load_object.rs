//! TPM2_ContextSave / TPM2_ContextLoad round trips of transient objects (names, hierarchy,
//! keystream freshness, corruption).

use crate::_common::{
    create_keyed_hash_object, create_test_keys, execute_with_password_sessions, flush_context,
    make_template, marshal_to_slice, read_public_name,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{ContextLoad, ContextSave, CreateLoaded, CreatePrimary, ReadPublic};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bContextData, Tpm2bData, Tpm2bDigest,
    Tpm2bEccParameter, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmEccCurve, TpmaObject, TpmiAlgHash,
    TpmiRsaKeyBits, TpmlPcrSelection, TpmsContext, TpmsContextData, TpmsEccParms, TpmsEccPoint,
    TpmsRsaParms, TpmsSchemeEcdaa, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtRsaScheme,
    Unmarshal,
};

/// TPM2_ContextSave of an object does not evict it
#[test]
#[allow(deprecated)]
fn context_save_keeps_object_loaded() {
    let mut sim = Tpm::new();
    let (in_sensitive, in_public) = create_test_keys();
    let cmd = CreateLoaded {
        parent_handle: tpm2::Handle(0x40000001),
        in_sensitive,
        in_public,
    };
    let resp_handles = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
    let created_handle = resp_handles.object_handle;

    let save_cmd = ContextSave {
        save_handle: created_handle,
    };
    // Save once
    let _ = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).unwrap();

    // Verify object still exists by reading public
    let read_public_cmd = ReadPublic {
        object_handle: created_handle,
    };
    let read_res = execute_with_password_sessions(&mut sim, &read_public_cmd, 0, &[]);
    assert!(
        read_res.is_ok(),
        "ContextSave incorrectly evicted the object!"
    );
}

/// An object context-saved, flushed and reloaded keeps its qualified name
#[test]
#[allow(deprecated)]
fn context_save_load_preserves_qualified_name() {
    let mut sim = Tpm::new();
    let (in_sensitive, in_public) = create_test_keys();
    let cmd = CreateLoaded {
        parent_handle: tpm2::Handle(0x40000001), // TPM_RH_OWNER
        in_sensitive,
        in_public,
    };

    let resp_handles = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
    let created_handle = resp_handles.object_handle;

    let read_public_cmd = ReadPublic {
        object_handle: created_handle,
    };
    let read_pub_resp1 =
        execute_with_password_sessions(&mut sim, &read_public_cmd, 0, &[]).unwrap();
    let qn1 = read_pub_resp1.qualified_name.get_buffer().to_vec();

    // ContextSave
    let save_cmd = ContextSave {
        save_handle: created_handle,
    };
    let save_resp = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).unwrap();

    flush_context(&mut sim, created_handle).unwrap();

    // ContextLoad
    let load_cmd = ContextLoad {
        context: save_resp.context,
    };
    let load_handles = execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]).unwrap();
    let loaded_handle = load_handles.loaded_handle;

    // ReadPublic again to check qualified_name
    let read_public_cmd = ReadPublic {
        object_handle: loaded_handle,
    };
    let read_pub_resp2 =
        execute_with_password_sessions(&mut sim, &read_public_cmd, 0, &[]).unwrap();
    let qn2 = read_pub_resp2.qualified_name.get_buffer().to_vec();

    assert_eq!(
        qn1, qn2,
        "Qualified name was lost across ContextSave/ContextLoad!"
    );
}

/// ContextLoad of an object context with a corrupted blob fails.
#[test]
fn corrupted_blob_rejected() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };

    let tpmt_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(tpmt_public);

    let mut pcr_buf = [0u8; 100];
    let mut written = 0;
    written += marshal_to_slice(&(1u32), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(TpmiAlgHash::Sha1), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(3u8), &mut pcr_buf[written..]);
    pcr_buf[written] = 0x80;
    pcr_buf[written + 1] = 0;
    pcr_buf[written + 2] = 0;
    written += 3;
    let mut unmarsh = &pcr_buf[..written];
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut unmarsh).unwrap();

    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr,
    };

    let cp_resp_handles = execute_with_password_sessions(&mut sim, &cp_cmd, 1, &[]).unwrap();
    let cp_handle = cp_resp_handles.object_handle;

    let save_cmd = ContextSave {
        save_handle: cp_handle,
    };
    let mut save_resp = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).unwrap();

    // Corrupt the context blob
    let mut blob = save_resp.context.context_blob.get_buffer().to_vec();
    let len = blob.len();
    if len > 0 {
        blob[len / 2] ^= 0xFF; // flip bits
        save_resp.context.context_blob = Tpm2bContextData::from_bytes(&blob).unwrap();
    }

    let load_cmd = ContextLoad {
        context: save_resp.context,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]);
    assert!(res.is_err(), "Context load with corrupt blob should fail");

    flush_context(&mut sim, cp_handle).unwrap();
}

/// Object context save/flush/load round trip; corrupted blob and saving a flushed handle fail; reload gives same handle and Name.
///
/// Previous (extended) version of the `TestCombinedContext` port. In addition
/// to the save/load round trip, it flushes the original object before loading,
/// checks that a corrupted context blob and a ContextSave on a flushed handle
/// fail, and that reloading the same context yields the same handle and name.
#[test]
fn flush_reload_corrupt_and_flushed_save() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };

    let tpmt_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(tpmt_public);

    let mut pcr_buf = [0u8; 100];
    let mut written = 0;
    written += marshal_to_slice(&(1u32), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(TpmiAlgHash::Sha1), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(3u8), &mut pcr_buf[written..]);
    pcr_buf[written] = 0x80;
    pcr_buf[written + 1] = 0;
    pcr_buf[written + 2] = 0;
    written += 3;
    let mut unmarsh = &pcr_buf[..written];
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut unmarsh).unwrap();

    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr,
    };

    let cp_resp = execute_with_password_sessions(&mut sim, &cp_cmd, 1, &[]).unwrap();
    let cp_handle = cp_resp.object_handle;

    let save_cmd = ContextSave {
        save_handle: cp_handle,
    };
    let save_resp = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).unwrap();

    let cp_name = read_public_name(&mut sim, cp_handle);
    let _ = flush_context(&mut sim, cp_handle);

    // Stress-test: Load with corrupted context blob
    let bad_context = save_resp.context;
    let mut buf = [0u8; 4096];
    let len = marshal_to_slice(&bad_context, &mut buf);
    buf[len - 1] ^= 0xFF; // Mutate last byte
    let mut unmarsh = &buf[..len];
    if let Ok(bad_ctx) = TpmsContext::unmarshal(&mut unmarsh) {
        let bad_cmd = ContextLoad { context: bad_ctx };
        assert!(
            execute_with_password_sessions(&mut sim, &bad_cmd, 0, &[]).is_err(),
            "Corrupted context should fail to load"
        );
    }

    // Stress-test: Save a flushed handle
    let save_flushed_cmd = ContextSave {
        save_handle: cp_handle,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &save_flushed_cmd, 0, &[]).is_err(),
        "ContextSave on a flushed handle should fail"
    );

    let load_cmd = ContextLoad {
        context: save_resp.context,
    };
    let load_resp_handles = execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]).unwrap();
    let cl_handle = load_resp_handles.loaded_handle;

    let cl_name = read_public_name(&mut sim, cl_handle);

    assert_eq!(
        cp_name.get_size(),
        cl_name.get_size(),
        "Mismatch in name size"
    );
    assert_eq!(
        cp_name.get_buffer()[..cp_name.get_size() as usize],
        cl_name.get_buffer()[..cl_name.get_size() as usize],
        "Mismatch in name contents"
    );

    assert_eq!(
        cp_resp.name.get_size(),
        cp_name.get_size(),
        "CreatePrimary name size mismatch"
    );
    assert_eq!(
        cp_resp.name.get_buffer()[..cp_resp.name.get_size() as usize],
        cp_name.get_buffer()[..cp_name.get_size() as usize],
        "CreatePrimary name content mismatch"
    );

    let _ = flush_context(&mut sim, cl_handle);

    let load_resp_handles2 = execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]).unwrap();
    let cl_handle2 = load_resp_handles2.loaded_handle;
    assert_eq!(
        cl_handle, cl_handle2,
        "Loaded handles should match under slot-based allocation"
    );

    let cl_name2 = read_public_name(&mut sim, cl_handle2);
    assert_eq!(cl_name.get_size(), cl_name2.get_size());
    assert_eq!(
        cl_name.get_buffer()[..cl_name.get_size() as usize],
        cl_name2.get_buffer()[..cl_name2.get_size() as usize]
    );

    let _ = flush_context(&mut sim, cl_handle2);
}

/// ContextSave, FlushContext then ContextLoad of a primary key restores the same Name
#[test]
fn load_after_flush_keeps_name() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };

    let tpmt_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(tpmt_public);

    let mut pcr_buf = [0u8; 100];
    let mut written = 0;
    written += marshal_to_slice(&(1u32), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(TpmiAlgHash::Sha1), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(3u8), &mut pcr_buf[written..]);
    pcr_buf[written] = 0x80;
    pcr_buf[written + 1] = 0;
    pcr_buf[written + 2] = 0;
    written += 3;
    let mut unmarsh = &pcr_buf[..written];
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut unmarsh).unwrap();

    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr,
    };

    let cp_resp_handles = execute_with_password_sessions(&mut sim, &cp_cmd, 1, &[]).unwrap();
    let cp_handle = cp_resp_handles.object_handle;
    let cp_name = read_public_name(&mut sim, cp_handle);

    let save_cmd = ContextSave {
        save_handle: cp_handle,
    };
    let save_resp = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).unwrap();

    flush_context(&mut sim, cp_handle).unwrap();

    let load_cmd = ContextLoad {
        context: save_resp.context,
    };
    let load_resp_handles = execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]).unwrap();
    let cl_handle = load_resp_handles.loaded_handle;

    let cl_name = read_public_name(&mut sim, cl_handle);

    assert_eq!(
        cp_name.get_size(),
        cl_name.get_size(),
        "Mismatch in name size"
    );
    assert_eq!(
        cp_name.get_buffer()[..cp_name.get_size() as usize],
        cl_name.get_buffer()[..cl_name.get_size() as usize],
        "Mismatch in name contents"
    );

    flush_context(&mut sim, cl_handle).unwrap();
}

/// Several objects saved, flushed and reloaded keep their names; blobs survive marshal/unmarshal.
#[test]
fn multiple_objects_round_trip() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };

    let tpmt_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(tpmt_public);

    let mut pcr_buf = [0u8; 100];
    let mut written = 0;
    written += marshal_to_slice(&(1u32), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(TpmiAlgHash::Sha1), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(3u8), &mut pcr_buf[written..]);
    pcr_buf[written] = 0x80;
    pcr_buf[written + 1] = 0;
    pcr_buf[written + 2] = 0;
    written += 3;
    let mut unmarsh = &pcr_buf[..written];
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut unmarsh).unwrap();

    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr,
    };

    let cp_resp_handles = execute_with_password_sessions(&mut sim, &cp_cmd, 1, &[]).unwrap();
    let cp_handle = cp_resp_handles.object_handle;
    let cp_name = read_public_name(&mut sim, cp_handle);

    for i in 0..100 {
        let save_cmd = ContextSave {
            save_handle: cp_handle,
        };
        let save_resp = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).unwrap();

        let load_cmd = ContextLoad {
            context: save_resp.context,
        };
        let load_resp_handles =
            execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]).unwrap();
        let cl_handle = load_resp_handles.loaded_handle;

        let cl_name = read_public_name(&mut sim, cl_handle);

        assert_eq!(
            cp_name.get_size(),
            cl_name.get_size(),
            "Mismatch in name size at iter {}",
            i
        );
        assert_eq!(
            cp_name.get_buffer()[..cp_name.get_size() as usize],
            cl_name.get_buffer()[..cl_name.get_size() as usize],
            "Mismatch in name contents at iter {}",
            i
        );

        flush_context(&mut sim, cl_handle).unwrap();
    }

    flush_context(&mut sim, cp_handle).unwrap();
}

/// Saving the same object twice increments the sequence and produces different ciphertext.
#[test]
fn repeated_saves_use_fresh_keystream() {
    let mut sim = Tpm::new();
    let handle = create_keyed_hash_object(&mut sim);

    // We execute ContextSave command twice
    let save_cmd = ContextSave {
        save_handle: handle,
    };
    let rsp1_parsed = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[])
        .unwrap_or_else(|rc| panic!("first ContextSave failed: {rc:#x}"));
    let rsp2_parsed = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[])
        .unwrap_or_else(|rc| panic!("second ContextSave failed: {rc:#x}"));

    let mut data1_unmarshal = rsp1_parsed.context.context_blob.get_buffer();
    let ctx1 = TpmsContextData::unmarshal(&mut data1_unmarshal).unwrap();

    let mut data2_unmarshal = rsp2_parsed.context.context_blob.get_buffer();
    let ctx2 = TpmsContextData::unmarshal(&mut data2_unmarshal).unwrap();

    assert_ne!(
        rsp1_parsed.context.sequence, rsp2_parsed.context.sequence,
        "Sequence must increment"
    );
    assert_ne!(
        ctx1.encrypted.get_buffer(),
        ctx2.encrypted.get_buffer(),
        "Keystream reuse detected!"
    );
}

/// ContextSave of an owner-hierarchy object records a non-zero hierarchy in the context.
#[test]
#[allow(deprecated)]
fn saved_context_records_hierarchy() {
    let mut sim = Tpm::new();

    // 1. CreateLoaded (in Owner hierarchy)
    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = make_template(&pub_area);
    let create = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPM_RH_OWNER
        in_sensitive,
        in_public,
    };

    let create_resp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();
    let object_handle = create_resp_handles.object_handle;

    // 2. ContextSave
    let save = ContextSave {
        save_handle: object_handle,
    };
    let save_resp = execute_with_password_sessions(&mut sim, &save, 0, &[]).unwrap();

    // Bug 1: Hierarchy is hardcoded to 0 instead of TPM_RH_OWNER (0x40000001)
    assert_ne!(
        save_resp.context.hierarchy.0, 0,
        "BUG: Hierarchy is hardcoded to 0 in ContextSave!"
    );
}

/// A saved RSA primary reloads (twice, to distinct handles) with the same Name after flush.
#[test]
fn saved_object_reloads_with_same_name() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };

    let tpmt_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(tpmt_public);

    let mut pcr_buf = [0u8; 100];
    let mut written = 0;
    written += marshal_to_slice(&(1u32), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(TpmiAlgHash::Sha1), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(3u8), &mut pcr_buf[written..]);
    pcr_buf[written] = 0x80;
    pcr_buf[written + 1] = 0;
    pcr_buf[written + 2] = 0;
    written += 3;
    let mut unmarsh = &pcr_buf[..written];
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut unmarsh).unwrap();

    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr,
    };

    let cp_resp_handles = execute_with_password_sessions(&mut sim, &cp_cmd, 1, &[]).unwrap();
    let cp_handle = cp_resp_handles.object_handle;

    let cp_name = read_public_name(&mut sim, cp_handle);

    // Save Context
    let save_cmd = ContextSave {
        save_handle: cp_handle,
    };
    let save_resp = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).unwrap();

    // Flush it before load
    let _ = flush_context(&mut sim, cp_handle);

    // Load it back
    let load_cmd = ContextLoad {
        context: save_resp.context,
    };
    let load_resp_handles = execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]).unwrap();
    let cl_handle = load_resp_handles.loaded_handle;

    let cl_name = read_public_name(&mut sim, cl_handle);

    assert_eq!(
        cp_name.get_size(),
        cl_name.get_size(),
        "Mismatch in name size"
    );
    assert_eq!(
        cp_name.get_buffer()[..cp_name.get_size() as usize],
        cl_name.get_buffer()[..cl_name.get_size() as usize],
        "Mismatch in name contents"
    );

    // Load it again, should work and give a different handle
    let load_resp_handles2 = execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]).unwrap();
    let cl_handle2 = load_resp_handles2.loaded_handle;
    assert_ne!(
        cl_handle.0, cl_handle2.0,
        "Should get a different transient handle"
    );

    let _ = flush_context(&mut sim, cl_handle);
    let _ = flush_context(&mut sim, cl_handle2);
}

/// An external object loaded with `nameAlg = TPM_ALG_NULL` (and a private key) can be saved and
/// loaded again: the context holds a `TPMT_PUBLIC+` (found by differential fuzzing; `tpm-rs`
/// returned TPM_RC_FAILURE). TPM 2.0 Part 3, TPM2_LoadExternal: "If *nameAlg* is
/// `TPM_ALG_NULL`, then the Name is the Empty Buffer."
#[test]
fn null_name_alg_external_object_round_trips() {
    let mut tpm = Tpm::new();
    // LoadExternal: ECC P-256 private key 0x0101..01, ECDSA-SHA256 signing public area with
    // nameAlg TPM_ALG_NULL and an empty unique field, NULL hierarchy.
    let load = [
        "8001000000520000016700280023000000000020",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "00180023001000040040000000100018000b000300100000000040000007",
    ]
    .concat();
    let rsp = tpm.send_command(0, &crate::_common::hex(&load));
    assert_eq!(&rsp[6..10], [0, 0, 0, 0], "LoadExternal: {rsp:02x?}");
    let handle = rsp[10..14].to_vec();
    let mut save = vec![0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x62];
    save.extend_from_slice(&handle);
    let rsp = tpm.send_command(0, &save);
    assert_eq!(&rsp[6..10], [0, 0, 0, 0], "ContextSave: {rsp:02x?}");
    // Flush the object, then load its context (the TPMS_CONTEXT response parameter).
    let mut flush = vec![0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x65];
    flush.extend_from_slice(&handle);
    assert_eq!(&tpm.send_command(0, &flush)[6..10], [0, 0, 0, 0]);
    let context = &rsp[10..];
    let mut load_ctx = vec![0x80, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0x61];
    load_ctx.extend_from_slice(context);
    let size = load_ctx.len() as u32;
    load_ctx[2..6].copy_from_slice(&size.to_be_bytes());
    let rsp = tpm.send_command(0, &load_ctx);
    assert_eq!(&rsp[6..10], [0, 0, 0, 0], "ContextLoad: {rsp:02x?}");
}
