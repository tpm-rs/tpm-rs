//! TPM2_NV_Certify: handle and authorization checks, written state, locks and certified ranges.

use crate::_common::{
    create_signing_key_handle as create_signing_key, define_nv_with_policy_unwrap as define,
    handle_name_of as handle_name, start_session_active as start_session, *,
};
use testing::tpm::Tpm;
use tpm2::commands::{CreatePrimary, NVCertify, NVDefineSpace, NVReadLock, NVReadPublic, NVWrite};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

/// After NV_ReadLock of a READ_STCLEAR index, NV_Certify fails with TPM_RC_NV_LOCKED
#[test]
fn certify_after_read_lock_rejected() {
    let mut sim = Tpm::new();
    let nv_index_val = 0x01500033;
    // READ_STCLEAR allows the index to be read-locked with TPM2_NV_ReadLock.
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::READ_STCLEAR,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 64]).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap();

    // Normal certify -> success
    let certify_cmd = NVCertify {
        sign_handle: Handle(0x40000007), // TPM_RH_NULL
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 0,
    };
    nv_certify_pw(&mut sim, &certify_cmd, &[], &[]).unwrap();

    // Set TPMA_NV_READLOCKED through the TPM interface.
    execute_with_password_sessions(
        &mut sim,
        &NVReadLock {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(nv_index_val),
        },
        1,
        &[],
    )
    .unwrap();

    // Try certifying again -> should fail with NvLocked (0x14F)
    let res = nv_certify_pw(&mut sim, &certify_cmd, &[], &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_LOCKED.get()),
        Ok(_) => panic!("Expected NvLocked error, but certify succeeded on READLOCKED index"),
    }
}

/// NV_Certify reports unloaded signHandle first, rejects non-NV-auth authHandle (TPM_RC_VALUE + RC_H2), resolves key before NV
#[test]
fn handle_validation_order() {
    let mut sim = Tpm::new();
    // Unloaded signHandle and undefined nvIndex: handle 1 is reported first.
    assert_eq!(
        nv_certify(
            &mut sim,
            Handle(0x8000_000E),
            Handle::RH_OWNER,
            Handle(0x0150_0800),
            None,
            0,
            0,
            2
        )
        .unwrap_err(),
        TpmRc::REFERENCE_H0.get()
    );

    // authHandle must be a TPMI_RH_NV_AUTH.
    let index = 0x0150_0801;
    define(&mut sim, index, OWNER_RW, 8, &[]);
    assert_eq!(
        nv_certify(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_ENDORSEMENT,
            Handle(index),
            None,
            0,
            0,
            2
        )
        .unwrap_err(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );

    // A valid index but an unloaded signing key: the key is resolved before NV checks.
    assert_eq!(
        nv_certify(
            &mut sim,
            Handle(0x8000_000E),
            Handle::RH_OWNER,
            Handle(index),
            None,
            4,
            0,
            2
        )
        .unwrap_err(),
        TpmRc::REFERENCE_H0.get()
    );
}

/// NV_Write out of bounds fails with TPM_RC_SIZE, NV_Certify of a sub-range succeeds and out-of-range fails with TPM_RC_NV_RANGE
#[test]
fn nv_certify_rejects_out_of_range_reads() {
    let mut sim = Tpm::new();

    // Setup signer primary template (RSA, SHA256, restricted, sign/encrypt)
    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::RESTRICTED,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_signer_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let signer_rsp_handles =
        execute_with_password_sessions(&mut sim, &create_signer_cmd, 1, &[]).unwrap();
    let signer_handle = signer_rsp_handles.object_handle;

    // Define NV Space (size 4)
    let nv_index_val = 0x0180000F;
    let mut attributes = TpmaNv::OWNERWRITE
        | TpmaNv::OWNERREAD
        | TpmaNv::AUTHWRITE
        | TpmaNv::AUTHREAD
        | TpmaNv::NO_DA;
    attributes.set_type(TpmNt::Ordinary);

    let nv_public_struct = TpmsNvPublic {
        nv_index: Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 4,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);

    let nv_define_cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &nv_define_cmd, 1, &[]).unwrap();

    // Write to NV Space
    let data_to_write = &[0x01, 0x02, 0x03, 0x04];
    let nv_write_cmd = NVWrite {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(data_to_write).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &nv_write_cmd, 1, &[]).unwrap();

    // 1. Write out of bounds should fail (TPM_RC_SIZE = 0x095)
    let nv_write_bad = NVWrite {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0x05]).unwrap(),
        offset: 4, // offset 4 is out of bounds for size 4 space (range 0..3)
    };
    let res_write_bad = execute_with_password_sessions(&mut sim, &nv_write_bad, 1, &[]);
    assert_eq!(res_write_bad.err(), Some(0x146));

    // 2. Call NVCertify with correct offset and size (offset 1, size 2)
    let nv_certify_cmd = NVCertify {
        sign_handle: signer_handle,
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        qualifying_data: Tpm2bData::from_bytes(b"nonce").unwrap(),
        in_scheme: None,
        size: 2,
        offset: 1,
    };
    let mut resp_buffer = [0u8; 4096];
    let nv_certify_rsp =
        execute_nv_certify(&mut sim, &nv_certify_cmd, 2, &[], &mut resp_buffer).unwrap();

    let certify_info = nv_certify_rsp.certify_info.0;
    if let TpmuAttest::Nv(nv_cert_info) = certify_info.attested {
        assert_eq!(nv_cert_info.offset, 1);
        assert_eq!(nv_cert_info.nv_contents.get_buffer(), &[0x02, 0x03]);
    } else {
        panic!("Expected NV certify info");
    }

    // 3. Call NVCertify with size out of bounds should fail (TPM_RC_NV_RANGE = 0x146)
    let nv_certify_bad = NVCertify {
        sign_handle: signer_handle,
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        size: 3,
        offset: 2, // 2 + 3 = 5 > 4 (data_size)
        ..nv_certify_cmd
    };
    let res_certify_bad = execute_with_password_sessions_status(&mut sim, &nv_certify_bad, 2, &[]);
    assert_eq!(res_certify_bad.err(), Some(0x146));

    // Flush key
    flush_context(&mut sim, signer_handle).unwrap();
}

/// NV_Certify with offset+size wrapping u16 is rejected (no overflow)
#[test]
fn offset_overflow_rejected() {
    let mut sim = Tpm::new();
    let nv_index_val = 0x01500004;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 64]).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap();

    // 4. Wrapping overflow certify: offset = 65530, size = 10 -> offset + size = 65540 -> wraps to 4.
    let certify_cmd_overflow = NVCertify {
        sign_handle: Handle(0x40000007),
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 65530,
    };

    // This is expected to return TpmRc::SIZE. Instead, it currently panics (in debug) or wraps (in release).
    let res = nv_certify_pw(&mut sim, &certify_cmd_overflow, &[], &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_RANGE.get()),
        Ok(_) => {
            panic!("SECURITY BUG: nv_certify overflow allowed reading out-of-bounds/metadata area!")
        }
    }
}

/// NV_Certify at the end boundary succeeds; one byte past it is TPM_RC_NV_RANGE
#[test]
fn offset_plus_size_boundaries() {
    let mut sim = Tpm::new();
    let nv_index_val = 0x01500003;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 64]).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap();

    // Certify command definition
    let certify_cmd = NVCertify {
        sign_handle: Handle(0x40000007), // TPM_RH_NULL
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 0,
    };

    // 1. Normal certify (offset = 0, size = 10)
    nv_certify_pw(&mut sim, &certify_cmd, &[], &[]).unwrap();

    // 2. Normal certify at boundary (offset = 54, size = 10)
    let certify_cmd_boundary = NVCertify {
        sign_handle: Handle(0x40000007), // TPM_RH_NULL
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 54,
    };
    nv_certify_pw(&mut sim, &certify_cmd_boundary, &[], &[]).unwrap();

    // 3. Out of bounds certify (offset = 55, size = 10)
    let certify_cmd_oob = NVCertify {
        sign_handle: Handle(0x40000007), // TPM_RH_NULL
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 55,
    };
    let res = nv_certify_pw(&mut sim, &certify_cmd_oob, &[], &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_RANGE.get()),
        Ok(_) => panic!("Expected Size error, but command succeeded"),
    }
}

/// A POLICYREAD-only index can be certified with a satisfied policy session
///
/// An index readable only with its authPolicy (`TPMA_NV_POLICYREAD`) can be certified with a
/// satisfied policy session.
#[test]
fn policyread_index_certified_with_policy_session() {
    let mut sim = Tpm::new();
    let index = 0x0150_0102;
    define(
        &mut sim,
        index,
        TpmaNv::POLICYREAD | TpmaNv::OWNERWRITE,
        8,
        &EMPTY_POLICY,
    );
    owner_write(&mut sim, index, 0, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    let name = nv_index_name(&mut sim, index);

    // C requires a session for every authorization handle, including a TPM_RH_NULL
    // signHandle: an (empty-auth) HMAC session for it, the policy session for the index.
    let hmac = start_session(&mut sim, TpmSe::HMAC);
    let policy = start_session(&mut sim, TpmSe::Policy);
    let mut sessions = [hmac, policy];
    let cmd = NVCertify {
        sign_handle: Handle::RH_NULL,
        auth_handle: Handle(index),
        nv_index: Handle(index),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 4,
        offset: 0,
    };
    let null_name = handle_name(Handle::RH_NULL);
    execute_with_hmac_sessions_status(
        &mut sim,
        &cmd,
        &[&null_name, &name, &name],
        &mut sessions,
        &[&[], &[]],
    )
    .expect("NV_Certify with a POLICYREAD policy session failed");
}

/// NV_Certify enforces AUTHREAD/PPREAD/OWNERREAD attributes (NV_AUTHORIZATION / AUTH_UNAVAILABLE)
#[test]
fn read_role_attributes_enforced() {
    let mut sim = Tpm::new();
    let nv_index_val = 0x01500034;

    // 1. Index defined with OWNERWRITE | OWNERREAD only (no AUTHREAD, no PPREAD)
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::from_bytes(b"nvpass").unwrap(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 64]).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap();

    let certify_cmd = NVCertify {
        sign_handle: Handle(0x40000007),
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 0,
    };

    // Try certifying with AUTHREAD (using nv_index_val auth handle) -> should fail with NvAuthorization (0x14B)
    let res_auth = nv_certify_pw(&mut sim, &certify_cmd, &[], b"nvpass");
    match res_auth {
        // AUTHREAD is clear: the authValue is unavailable (C IsAuthValueAvailable).
        Err(err) => assert_eq!(err, TpmRc::AUTH_UNAVAILABLE.get()),
        Ok(_) => panic!("Expected NvAuthorization error for AUTHREAD, but certify succeeded"),
    }

    // Try certifying with PPREAD (using RHPlatform auth handle) -> should fail with NvAuthorization (0x14B)
    let res_pp = nv_certify_pw(
        &mut sim,
        &NVCertify {
            auth_handle: Handle::RH_PLATFORM,
            ..certify_cmd
        },
        &[],
        &[],
    );
    match res_pp {
        Err(err) => assert_eq!(err, TpmRc::NV_AUTHORIZATION.get()),
        Ok(_) => panic!("Expected NvAuthorization error for PPREAD, but certify succeeded"),
    }

    // Try certifying with OWNERREAD (using RHOwner auth handle) -> success
    nv_certify_pw(
        &mut sim,
        &NVCertify {
            auth_handle: Handle::RH_OWNER,
            ..certify_cmd
        },
        &[],
        &[],
    )
    .unwrap();

    // 2. Define another index with OWNERWRITE | AUTHREAD only (no OWNERREAD)
    let nv_index_val_2 = 0x01500035;
    let nv_public_struct_2 = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val_2),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info_2 = tpm2::Tpm2b(nv_public_struct_2);
    let cmd_2 = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::from_bytes(b"nvpass2").unwrap(),
        public_info: public_info_2,
    };
    execute_with_password_sessions(&mut sim, &cmd_2, 1, &[]).unwrap();

    let write_cmd_2 = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val_2),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 64]).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd_2, 1, &[]).unwrap();

    // Try certifying with OWNERREAD (using RHOwner auth handle) -> should fail with NvAuthorization (0x14B)
    let res_owner_2 = nv_certify_pw(
        &mut sim,
        &NVCertify {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(nv_index_val_2),
            ..certify_cmd
        },
        &[],
        &[],
    );
    match res_owner_2 {
        Err(err) => assert_eq!(err, TpmRc::NV_AUTHORIZATION.get()),
        Ok(_) => panic!("Expected NvAuthorization error for OWNERREAD, but certify succeeded"),
    }

    // Try certifying with AUTHREAD (using nv_index_val_2 auth handle) -> success
    nv_certify_pw(
        &mut sim,
        &NVCertify {
            auth_handle: Handle(nv_index_val_2),
            nv_index: Handle(nv_index_val_2),
            ..certify_cmd
        },
        &[],
        b"nvpass2",
    )
    .unwrap();
}

/// NV_Certify validates the signing scheme (TPM_RC_SCHEME + RC_P2) before NV access checks such as NV_UNINITIALIZED
///
/// The signing scheme is validated (`TPM_RC_SCHEME + RC_P2`) before any NV access check, so an
/// unwritten index does not mask it with `TPM_RC_NV_UNINITIALIZED`.
#[test]
fn scheme_checked_before_nv_access() {
    let mut sim = Tpm::new();
    let index = 0x0150_0101;
    define(&mut sim, index, OWNER_RW, 16, &[]);
    let key = create_signing_key(&mut sim);
    // The key's scheme is ECDSA/SHA-256; asking for ECDSA/SHA-384 is a scheme error.
    let rc = nv_certify(
        &mut sim,
        key,
        Handle::RH_OWNER,
        Handle(index),
        Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha384)),
        4,
        0,
        2,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::SCHEME.with(Position::parameter(2)).get());
}

/// NV_Certify size > MAX_NV_BUFFER_SIZE is TPM_RC_VALUE + RC_P3, checked after the range check
///
/// `size > MAX_NV_BUFFER_SIZE` is `TPM_RC_VALUE + RC_P3` (checked after the range check).
#[test]
fn size_above_max_nv_buffer_rejected() {
    let mut sim = Tpm::new();
    let index = 0x0150_0103;
    define(&mut sim, index, OWNER_RW, 1100, &[]);
    owner_write(&mut sim, index, 0, &[0x11; 1024]).unwrap();
    let rc = nv_certify(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_OWNER,
        Handle(index),
        None,
        1025,
        0,
        2,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(3)).get());
    // The range check comes first.
    let rc = nv_certify(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_OWNER,
        Handle(index),
        None,
        1025,
        100,
        2,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::NV_RANGE.get());
}

// 3. Validate that certifying an unwritten NV index fails with TPM_RC_NV_UNINITIALIZED.
/// NV_Certify of an unwritten index fails with TPM_RC_NV_UNINITIALIZED.
#[test]
fn unwritten_index_rejected() {
    let mut sim = Tpm::new();

    let nv_index = Handle(0x01000005);
    define_nv_space(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_index,
        platform_attrs(TpmNt::Ordinary, TpmaNv::empty()),
        16,
    )
    .expect("Failed to define Ordinary NV space");

    // Certify the NV index (unwritten)
    let res = execute_with_password_sessions(
        &mut sim,
        &NVCertify {
            sign_handle: Handle::RH_NULL,
            auth_handle: nv_index,
            nv_index,
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
            size: 16,
            offset: 0,
        },
        // One session per authorization handle, incl. the TPM_RH_NULL signHandle.
        2,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::NV_UNINITIALIZED.get()));
}

/// NV_Certify of an unwritten index is TPM_RC_NV_UNINITIALIZED; succeeds after the first write
#[test]
fn unwritten_index_rejected_until_first_write() {
    let mut sim = Tpm::new();
    let nv_index_val = 0x01500050;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 16,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    // 1. Try certifying before writing -> must fail with NvUninitialized (0x14A)
    let certify_cmd = NVCertify {
        sign_handle: Handle(0x40000007),
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 0,
        offset: 0,
    };
    let err_cert = nv_certify_pw(&mut sim, &certify_cmd, &[], &[]).unwrap_err();
    assert_eq!(err_cert, TpmRc::NV_UNINITIALIZED.get());

    // 2. Write data -> should set WRITTEN
    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0x55; 8]).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap();

    // 3. Certify after writing -> should succeed
    nv_certify_pw(&mut sim, &certify_cmd, &[], &[]).unwrap();
}

/// NV_Certify with size=0, offset=0 returns a TPM_ST_ATTEST_NV_DIGEST attestation (digest of whole index; empty when unsigned)
///
/// `size == 0 && offset == 0` produces a `TPM_ST_ATTEST_NV_DIGEST` attestation whose digest is
/// H_schemeHash(whole index data); an unsigned one has an empty digest.
#[test]
fn whole_index_produces_nv_digest_attestation() {
    let mut sim = Tpm::new();
    let index = 0x0150_0100;
    define(&mut sim, index, OWNER_RW, 16, &[]);
    let data = [0x5au8; 16];
    owner_write(&mut sim, index, 0, &data).unwrap();
    let name = nv_index_name(&mut sim, index);

    // Signed with an ECDSA/SHA-256 key.
    let key = create_signing_key(&mut sim);
    let attest = nv_certify(
        &mut sim,
        key,
        Handle::RH_OWNER,
        Handle(index),
        None,
        0,
        0,
        2,
    )
    .expect("NV_Certify failed");
    match attest.attested {
        TpmuAttest::NvDigest(info) => {
            assert_eq!(info.index_name.get_buffer(), name.as_slice());
            assert_eq!(info.nv_digest.get_buffer(), sha256(&[&data]).as_slice());
        }
        other => panic!("expected TPM_ST_ATTEST_NV_DIGEST, got {other:?}"),
    }

    // Unsigned (TPM_RH_NULL): the scheme hash is TPM_ALG_NULL, so the digest is empty.
    let attest = nv_certify(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_OWNER,
        Handle(index),
        None,
        0,
        0,
        2,
    )
    .expect("NV_Certify failed");
    match attest.attested {
        TpmuAttest::NvDigest(info) => assert!(info.nv_digest.get_buffer().is_empty()),
        other => panic!("expected TPM_ST_ATTEST_NV_DIGEST, got {other:?}"),
    }
}

// 4. Validate that writing data successfully sets the WRITTEN attribute and subsequent certifies succeed.
/// Writing sets TPMA_NV_WRITTEN and NV_Certify then succeeds with the written data in the attestation.
#[test]
fn written_index_certifies_data() {
    let mut sim = Tpm::new();

    let nv_index = Handle(0x01000006);
    define_nv_space(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_index,
        platform_attrs(TpmNt::Ordinary, TpmaNv::empty()),
        16,
    )
    .expect("Failed to define Ordinary NV space");

    // Check that WRITTEN is NOT set originally
    let initial_pub = execute_with_password_sessions(&mut sim, &NVReadPublic { nv_index }, 0, &[])
        .expect("Failed to read public info of unwritten index");
    assert!(!initial_pub.nv_public.0.attributes.contains(TpmaNv::WRITTEN));

    // Write data to the NV index
    nv_write(&mut sim, nv_index, &[0xaau8; 16]).expect("Failed to write data to NV index");

    // Check that WRITTEN is now set
    let after_pub = execute_with_password_sessions(&mut sim, &NVReadPublic { nv_index }, 0, &[])
        .expect("Failed to read public info of written index");
    assert!(after_pub.nv_public.0.attributes.contains(TpmaNv::WRITTEN));

    // Certify the NV index should now succeed
    let certify_resp = execute_with_password_sessions(
        &mut sim,
        &NVCertify {
            sign_handle: Handle::RH_NULL,
            auth_handle: nv_index,
            nv_index,
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
            size: 16,
            offset: 0,
        },
        // One session per authorization handle, incl. the TPM_RH_NULL signHandle.
        2,
        &[],
    )
    .expect("NV Certify failed after writing data");

    // Verify certified info contains our data
    let attest = certify_resp.certify_info.0;
    if let tpm2::TpmuAttest::Nv(ref nv_cert_info) = attest.attested {
        assert_eq!(nv_cert_info.offset, 0);
        assert_eq!(nv_cert_info.nv_contents.get_size(), 16);
        assert_eq!(nv_cert_info.nv_contents.get_buffer(), &[0xaau8; 16]);
    } else {
        panic!("Expected Nv attest type");
    }
}
