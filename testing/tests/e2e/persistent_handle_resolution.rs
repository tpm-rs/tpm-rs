//! Using persistent objects by handle: names in HMACs, valid handle ranges and resolution in
//! commands.

use crate::_common::{
    build_raw_cmd as build_cmd, create_storage_primary_in as create_primary,
    execute_tpm_command_mapping_parse_errors as execute_tpm_command, hex_checked as hex,
    mssim_rc_of as rc_of, read_public_rc as read_public, send_with_sessions as send, *,
};
use testing::tpm::Tpm;
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

/// HMAC authorization of a persistent object uses the object's Name (not its handle) in cpHash
///
/// Case 3: Persistent Object Name Lookup Verification: the cpHash of a command
/// authorizing a persistent object uses the object's real Name, not its handle.
#[test]
fn persistent_object_uses_real_name() {
    let mut sim = Tpm::new();

    let key_auth = [0x11, 0x22];
    let persistent_handle = Handle(0x81000001);

    // 1. Create a signing key with a non-empty authValue
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(&key_auth).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp =
        execute_with_password_sessions(&mut sim, &create, 1, &[]).expect("CreatePrimary failed");
    let key_handle = create_rsp.object_handle;

    // 2. Persist the key to persistent_handle using EvictControl
    execute_with_password_sessions(
        &mut sim,
        &EvictControl {
            auth: Handle::RH_OWNER,
            object_handle: key_handle,
            persistent_handle,
        },
        1,
        &[],
    )
    .expect("EvictControl failed");

    // 3. Flush the transient key so it's only accessible via persistent_handle
    flush_context(&mut sim, key_handle).unwrap();
    let real_name = read_public_name(&mut sim, persistent_handle)
        .get_buffer()
        .to_vec();

    // 4. Authorize Certify of the persistent key with an HMAC session.
    let mut session = start_hmac_session(&mut sim);
    let params = marshal_to_vec(&Certify {
        object_handle: persistent_handle,
        sign_handle: Handle::RH_NULL,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    });
    let handles = [persistent_handle, Handle::RH_NULL];
    let null_name = Handle::RH_NULL.0.to_be_bytes();

    // An HMAC computed over the cpHash with the key's real Name must succeed.
    let real_cp = cp_hash(TpmCc::Certify, &[&real_name, &null_name], &params);
    let real_auth = hmac_auth(&session, &real_cp, 0x01, &key_auth);
    let res_real = send(
        &mut sim,
        TpmCc::Certify,
        &handles,
        // signHandle (TPM_RH_NULL) has the USER auth role, so C needs a second session
        // (SessionProcess.c:1641-1651, otherwise TPM_RC_AUTH_MISSING).
        &[real_auth, pw_continue()],
        &params,
    );
    assert!(
        res_real.is_ok(),
        "Expected authentication to succeed using correct real name, got error: {:?}",
        res_real.as_ref().err()
    );
    let (_, resp_auths) = res_real.unwrap();
    session.nonce_tpm =
        Tpm2bNonce::from_bytes(leak_bytes(resp_auths[0].nonce.get_buffer())).unwrap();

    // An HMAC computed with the handle bytes as the Name must fail.
    let wrong_cp = cp_hash(
        TpmCc::Certify,
        &[&persistent_handle.0.to_be_bytes(), &null_name],
        &params,
    );
    let wrong_auth = hmac_auth(&session, &wrong_cp, 0x01, &key_auth);
    let res_wrong = send(
        &mut sim,
        TpmCc::Certify,
        &handles,
        &[wrong_auth, pw_continue()],
        &params,
    );
    assert_eq!(
        res_wrong.err(),
        Some(TpmRc::AUTH_FAIL.with(Position::session(1)).get()),
        "Expected authentication to fail with TPM_RC_AUTH_FAIL because wrong-name-based HMAC was used!"
    );
}

/// Platform persistent handles above 0x8180FFFF are valid handles.
///
/// Platform persistent handles above `0x8180_FFFF` are valid.
#[test]
fn platform_range_above_8180ffff_valid() {
    let mut sim = Tpm::new();
    let key = create_primary(&mut sim, Handle::RH_PLATFORM);
    evict(&mut sim, Handle::RH_PLATFORM, key, 0x8181_0000);
    assert_eq!(read_public(&mut sim, 0x8181_0000), 0);
    let s = {
        let cmd = build_pw_cmd(CC_SIGN, &[0x8181_0000], 1, &[]);
        rc_of(&mut sim, &cmd)
    };
    assert_ne!(s, rc_h(TpmRc::VALUE, 1));
}

// 4. Testing persistent handle resolution under different commands (read_public, hmac_start, certify).
/// A persistent key resolves correctly in ReadPublic, Certify (signHandle) and HMAC_Start.
#[test]
fn read_public_certify_and_hmac_start() {
    let mut sim = Tpm::new();

    let persistent_key_handle = Handle(0x81000002);

    // Create an RSA signing key with authValue [0x11, 0x22]
    let rsa_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let (transient_key_handle, name) =
        create_primary_with_auth_and_data(&mut sim, rsa_public, &[0x11, 0x22], b"");

    // Evict key to persistent handle and flush the transient key
    evict_owner(&mut sim, transient_key_handle, persistent_key_handle);

    // A. Verify ReadPublic resolves persistent key
    let read_resp = execute_tpm_command(
        &mut sim,
        &ReadPublic {
            object_handle: persistent_key_handle,
        },
        &[],
    )
    .unwrap();
    assert_eq!(read_resp.name, name);

    // B. Verify Certify resolves persistent key as sign_handle
    let certified_handle = make_keyed_hash_key(&mut sim, b"cert_key_bytes");

    let certify_cmd = Certify {
        object_handle: certified_handle,
        sign_handle: persistent_key_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Use password auth for both the certified key (empty auth) and the persistent key (password [0x11, 0x22])
    let certify_resp = execute_tpm_command(
        &mut sim,
        &certify_cmd,
        &[pw_with(b""), pw_with(&[0x11, 0x22])],
    )
    .unwrap();
    assert!(matches!(
        certify_resp.signature,
        Some(TpmtSignature::Rsassa(..))
    ));

    // C. Verify HmacStart resolves persistent key as key handle
    // Evict an HMAC key to a persistent handle
    let hmac_key_bytes: &'static [u8] = b"pers_hmac_bytes";
    let transient_hmac_handle = make_keyed_hash_key(&mut sim, hmac_key_bytes);
    let persistent_hmac_handle = Handle(0x81000003);
    evict_owner(&mut sim, transient_hmac_handle, persistent_hmac_handle);

    let hmac_start_cmd = HMACStart {
        handle: persistent_hmac_handle,
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_start_resp = execute_tpm_command(&mut sim, &hmac_start_cmd, &[pw()]).unwrap();
    let seq_handle = hmac_start_resp.sequence_handle;

    // Perform update and complete on the hmac sequence
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
    };
    execute_tpm_command(&mut sim, &update_cmd, &[pw()]).unwrap();

    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command(&mut sim, &complete_cmd, &[pw()]).unwrap();

    // Verify correct HMAC computed from persistent key
    assert_eq!(
        complete_resp.result.get_buffer(),
        expected_hmac(hmac_key_bytes, b"hello")
    );
}

/// Using a persistent object needs a free object slot (OBJECT_MEMORY) and its hierarchy is derived from the handle range.
///
/// A persistent object needs a free object slot (`TPM_RC_OBJECT_MEMORY`), and the hierarchy of a
/// persistent handle is checked by its handle range.
#[test]
fn requires_free_object_slot() {
    let mut sim = Tpm::new();
    let key = create_primary(&mut sim, Handle::RH_OWNER);
    evict(&mut sim, Handle::RH_OWNER, key, 0x8100_0003);
    // Fill every object slot.
    let mut loaded = vec![key];
    loop {
        let cmd = CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: Tpm2b(ecc_storage_template()),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        match execute_with_password_sessions(&mut sim, &cmd, 1, &[]) {
            Ok(h) => loaded.push(h.object_handle),
            Err(rc) => {
                assert_eq!(rc, TpmRc::OBJECT_MEMORY.get());
                break;
            }
        }
        assert!(loaded.len() <= 64, "object memory never exhausted");
    }
    assert_eq!(
        read_public(&mut sim, 0x8100_0003),
        TpmRc::OBJECT_MEMORY.get()
    );
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        0x165,
        &[],
        None,
        &loaded.pop().unwrap().0.to_be_bytes(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), 0);
    assert_eq!(read_public(&mut sim, 0x8100_0003), 0);
    for h in loaded {
        let cmd = build_cmd(ST_NO_SESSIONS, 0x165, &[], None, &h.0.to_be_bytes());
        assert_eq!(rc_of(&mut sim, &cmd), 0);
    }

    // A platform persistent handle while phEnable is clear: TPM_RC_HANDLE + RC_H1.
    let pkey = create_primary(&mut sim, Handle::RH_PLATFORM);
    evict(&mut sim, Handle::RH_PLATFORM, pkey, 0x8180_0001);
    assert_eq!(read_public(&mut sim, 0x8180_0001), 0);
    let mut params = Handle::RH_PLATFORM.0.to_be_bytes().to_vec();
    params.push(0);
    let cmd = build_pw_cmd(CC_HIERARCHY_CONTROL, &[Handle::RH_PLATFORM.0], 1, &params);
    assert_eq!(rc_of(&mut sim, &cmd), 0);
    assert_eq!(read_public(&mut sim, 0x8180_0001), rc_h(TpmRc::HANDLE, 1));
}

/// Undefined persistent handles and those of a disabled hierarchy fail with TPM_RC_HANDLE + Hx.
///
/// Undefined persistent handles and persistent handles of a disabled hierarchy are
/// `TPM_RC_HANDLE + RC_Hx` (not `TPM_RC_REFERENCE_Hx` / `TPM_RC_HIERARCHY`).
#[test]
fn undefined_or_disabled_returns_handle() {
    let mut sim = Tpm::new();
    let cmd = build_pw_cmd(CC_SIGN, &[0x8100_0099], 1, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 1));
    let cmd = build_pw_cmd(CC_EVICT_CONTROL, &[Handle::RH_OWNER.0, 0x8100_0099], 1, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 2));

    let key = create_primary(&mut sim, Handle::RH_OWNER);
    evict(&mut sim, Handle::RH_OWNER, key, 0x8100_0001);
    assert_eq!(read_public(&mut sim, 0x8100_0001), 0);
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let cmd = build_pw_cmd(CC_SIGN, &[0x8100_0001], 1, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 1));
    assert_eq!(read_public(&mut sim, 0x8100_0001), rc_h(TpmRc::HANDLE, 1));
}

/// Unseal of an undefined persistent handle fails with TPM_RC_HANDLE + H1 (not REFERENCE_H0).
///
/// Verifies that TPM2_Unseal resolves persistent objects per TPM (2 as u16) specification requirements,
/// querying persistent storage rather than failing immediately during transient-only searches.
#[test]
fn unseal_undefined_persistent_handle() {
    let mut sim = Tpm::new();

    let unseal_req = hex(concat!(
        "8002",     // tag: SESSIONS
        "0000001b", // size: 27 bytes
        "0000015e", // command code: TPM_CC_Unseal (0x015E)
        "81000001", // itemHandle: persistent handle
        "00000009", // authSize: 9 bytes
        "40000009", // sessionHandle: RS_PW
        "0000",     // nonce
        "01",       // sessionAttributes: continueSession
        "0000",     // hmac
    ));
    let rc = raw_rc(&mut sim, &unseal_req);
    // C `ObjectLoadEvict()` (Object.c): an undefined persistent handle is TPM_RC_HANDLE + RC_H1;
    // only unloaded transient handles give TPM_RC_REFERENCE_H0.
    assert_eq!(
        rc,
        TpmRc::HANDLE.with(Position::handle(1)).get(),
        "Expected TPM_RC_HANDLE + RC_H1 when Unseal references an undefined persistent object"
    );
}
