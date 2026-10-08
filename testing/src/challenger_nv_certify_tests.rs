#![forbid(unsafe_code)]
use crate::test_utils::marshal_to_slice;
use tpm2::errors::TpmRc;

use crate::test_utils::{execute_with_password_sessions, execute_with_password_sessions_status};
use tpm2::Handle;
use tpm2::TpmiAlgHash;
use tpm2::Unmarshal;
use tpm2::commands::{
    CertifyCreation, CertifyCreationHandles, CreatePrimary, CreatePrimaryHandles, NVCertify,
    NVCertifyHandles, NVDefineSpace, NVDefineSpaceHandles, NVWrite, NVWriteHandles,
};
use tpm2::{
    Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bMaxNvBuffer, Tpm2bNvPublic, Tpm2bSensitiveData, TpmaNv,
    TpmsNvPublic, TpmsSensitiveCreate, TpmtTkCreation,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_nv_write_boundaries() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500001;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    // 1. Normal write (offset = 0, size = 10)
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 10]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]).unwrap();

    // 2. Normal write at boundary (offset = 54, size = 10)
    let write_cmd_boundary = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xBB; 10]).unwrap(),
        offset: 54,
    };
    execute_with_password_sessions(&mut sim, &write_cmd_boundary, write_handles, 1, &[]).unwrap();

    // 3. Out of bounds write (offset = 55, size = 10)
    let write_cmd_oob = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xCC; 10]).unwrap(),
        offset: 55,
    };
    let res = execute_with_password_sessions(&mut sim, &write_cmd_oob, write_handles, 1, &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_RANGE.get()),
        Ok(_) => panic!("Expected Size error, but command succeeded"),
    }
}

#[test]
fn test_nv_write_overflow() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500002;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    // 4. Wrapping overflow write: offset = 65530, size = 10 -> offset + size = 65540 -> wraps to 4.
    let write_cmd_overflow = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xDD; 10]).unwrap(),
        offset: 65530,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };

    // This is expected to return TpmRc::SIZE. Instead, it currently panics (in debug) or wraps (in release).
    let res = execute_with_password_sessions(&mut sim, &write_cmd_overflow, write_handles, 1, &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_RANGE.get()),
        Ok(_) => panic!(
            "SECURITY BUG: nv_write overflow allowed writing to out-of-bounds offset (underflow/metadata overwrite)!"
        ),
    }
}

#[test]
fn test_nv_certify_boundaries() {
    let mut sim = create_simulator!();
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
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 64]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]).unwrap();

    // Certify command definition
    let certify_cmd = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 0,
    };
    let certify_handles = NVCertifyHandles {
        sign_handle: Handle(0x40000007), // TPM_RH_NULL
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };

    // 1. Normal certify (offset = 0, size = 10)
    execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 1, &[]).unwrap();

    // 2. Normal certify at boundary (offset = 54, size = 10)
    let certify_cmd_boundary = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 54,
    };
    execute_with_password_sessions_status(&mut sim, &certify_cmd_boundary, certify_handles, 1, &[])
        .unwrap();

    // 3. Out of bounds certify (offset = 55, size = 10)
    let certify_cmd_oob = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 55,
    };
    let res =
        execute_with_password_sessions_status(&mut sim, &certify_cmd_oob, certify_handles, 1, &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_RANGE.get()),
        Ok(_) => panic!("Expected Size error, but command succeeded"),
    }
}

#[test]
fn test_nv_certify_overflow() {
    let mut sim = create_simulator!();
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
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 64]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]).unwrap();

    // 4. Wrapping overflow certify: offset = 65530, size = 10 -> offset + size = 65540 -> wraps to 4.
    let certify_cmd_overflow = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 65530,
    };
    let certify_handles = NVCertifyHandles {
        sign_handle: Handle(0x40000007),
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };

    // This is expected to return TpmRc::SIZE. Instead, it currently panics (in debug) or wraps (in release).
    let res = execute_with_password_sessions_status(
        &mut sim,
        &certify_cmd_overflow,
        certify_handles,
        1,
        &[],
    );
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_RANGE.get()),
        Ok(_) => {
            panic!("SECURITY BUG: nv_certify overflow allowed reading out-of-bounds/metadata area!")
        }
    }
}

#[test]
fn test_certify_creation_validation() {
    let mut sim = create_simulator!();

    // Create an object (transient key) to certify
    let rsa_parms = tpm2::TpmsRsaParms {
        symmetric: None,
        scheme: Some(tpm2::TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: tpm2::TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pubkey = tpm2::Tpm2bPublicKeyRsa::default();
    let tpmt_public = tpm2::TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::from_bits_retain(0x00040072),
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Rsa(rsa_parms, pubkey),
    };
    let in_public = tpm2::Tpm2b(tpmt_public);

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (resp, resp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();
    let object_handle = resp_handles.object_handle;

    // Normal ticket that we received
    let ticket = resp.creation_ticket;
    let creation_hash = resp.creation_hash;

    let cert_handles = CertifyCreationHandles {
        sign_handle: Handle(0x40000007), // TPM_RH_NULL
        object_handle,
    };

    // 2. Verify mismatching ticket hierarchy (should fail with Ticket error)
    let bad_hier_ticket = TpmtTkCreation::Creation(Handle::RH_PLATFORM, *ticket.digest());
    let cert_cmd_hier = CertifyCreation {
        qualifying_data: Tpm2bData::default(),
        creation_hash,
        in_scheme: None,
        creation_ticket: bad_hier_ticket,
    };
    let res = execute_with_password_sessions_status(&mut sim, &cert_cmd_hier, cert_handles, 0, &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::TICKET.get()),
        Ok(_) => panic!("Expected Ticket error, but command succeeded"),
    }

    // 3. Verify mismatching ticket digest / cryptographically invalid ticket
    // Let's modify the ticket digest to an invalid value (e.g. non-zeroes)
    let bad_digest_ticket = TpmtTkCreation::Creation(
        ticket.hierarchy(),
        Tpm2bDigest::from_bytes(&[0xAA; 32]).unwrap(),
    );
    let cert_cmd_digest = CertifyCreation {
        qualifying_data: Tpm2bData::default(),
        creation_hash,
        in_scheme: None,
        creation_ticket: bad_digest_ticket,
    };
    let res_digest =
        execute_with_password_sessions_status(&mut sim, &cert_cmd_digest, cert_handles, 0, &[]);

    // We expect this to fail with Ticket error (since the digest is wrong).
    let err_digest = match res_digest {
        Err(err) => err,
        Ok(_) => panic!(
            "SECURITY BUG: CertifyCreation accepted a ticket with a mismatching/fabricated digest!"
        ),
    };
    assert_eq!(err_digest, TpmRc::TICKET.get());
}

#[test]
fn test_unsupported_command_codes() {
    let mut sim = create_simulator!();

    // Pick multiple other unimplemented command codes and check they return TPM_RC_COMMAND_CODE (0x143)
    let unimplemented_codes: [u32; 3] = [
        0x0000012D, // TPM_CC_PPCommands
        0x0000012F, // TPM_CC_FieldUpgradeStart
        0x00000141, // TPM_CC_FieldUpgradeData
    ];

    for &code in &unimplemented_codes {
        // Construct raw request buffer for each code
        let mut req = Vec::new();
        // tag: NoSessions (0x8001)
        req.extend_from_slice(&0x8001u16.to_be_bytes());
        // size: 10 bytes
        req.extend_from_slice(&10u32.to_be_bytes());
        // command code
        req.extend_from_slice(&code.to_be_bytes());

        let mut resp = [0u8; 1024];
        let resp_bytes = sim.transact(&req, &mut resp).unwrap();
        assert_eq!(resp_bytes.len(), 10);

        let mut unmarsh: &'static [u8] = crate::test_utils::leak_bytes(resp_bytes);
        let header = crate::test_utils::RespHeader::unmarshal(&mut unmarsh).unwrap();
        assert_eq!(
            header.rc, 0x143,
            "Expected TPM_RC_COMMAND_CODE (0x143) for command 0x{:X}, got 0x{:X}",
            code, header.rc
        );
    }
}

#[test]
fn test_nv_password_auth_write_read() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500005;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::AUTHWRITE
            | TpmaNv::AUTHREAD
            | TpmaNv::OWNERWRITE
            | TpmaNv::OWNERREAD
            | TpmaNv::NO_DA,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::from_bytes(b"nvpassword").unwrap(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    // 1. Try writing with NV Index auth but incorrect password
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 10]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
    };
    let res = execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, b"wrongpass");
    match res {
        Err(err) => assert_eq!(err, 0x9A2), // BadAuth for session 1
        Ok(_) => panic!("Expected BadAuth error, but command succeeded"),
    }

    // 2. Try writing with NV Index auth and correct password
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, b"nvpassword").unwrap();

    // 3. Try certifying with NV Index auth but incorrect password
    let certify_cmd = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 0,
    };
    let certify_handles = NVCertifyHandles {
        sign_handle: Handle(0x40000007), // TPM_RH_NULL
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
    };
    let res_cert = execute_with_password_sessions_status(
        &mut sim,
        &certify_cmd,
        certify_handles,
        1,
        b"wrongpass",
    );
    match res_cert {
        Err(err) => assert_eq!(err, 0x9A2), // BadAuth for session 1
        Ok(_) => panic!("Expected BadAuth error, but command succeeded"),
    }

    // 4. Try certifying with NV Index auth and correct password
    execute_with_password_sessions_status(
        &mut sim,
        &certify_cmd,
        certify_handles,
        1,
        b"nvpassword",
    )
    .unwrap();
}

#[test]
fn test_nv_write_writelocked() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500030;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    // Normal write -> success
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 10]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]).unwrap();

    // Modify TOC in storage to add WRITELOCKED
    use tpm2_impl::storage::NvStorage;
    use tpm2_impl::storage::manager::{RESERVED_SIZE, TOC_SIZE};
    use tpm2_impl::storage::types::ItemMetadata;
    let mut toc_bytes = [0u8; TOC_SIZE];
    sim.context
        .platform
        .storage
        .read_nv(RESERVED_SIZE, &mut toc_bytes)
        .unwrap();
    let mut item_offset = RESERVED_SIZE + TOC_SIZE;
    let mut found = false;
    for i in 0..64 {
        let offset = i * ItemMetadata::SIZE;
        let mut item = ItemMetadata::from_bytes(&toc_bytes[offset..offset + ItemMetadata::SIZE]);
        if item.in_use == 0 {
            break;
        }
        if item.handle == nv_index_val {
            item.attributes |= TpmaNv::WRITELOCKED.bits();
            toc_bytes[offset..offset + ItemMetadata::SIZE].copy_from_slice(&item.to_bytes());
            found = true;
            break;
        }
        item_offset += item.data_size as usize;
    }
    assert!(found);
    sim.context
        .platform
        .storage
        .write_nv(RESERVED_SIZE, &toc_bytes)
        .unwrap();

    // Modify the index data payload attributes
    let mut payload = [0u8; 128];
    sim.context
        .platform
        .storage
        .read_nv(item_offset, &mut payload)
        .unwrap();
    let mut unmarshal_buf = &payload[..];
    let nv_auth = Tpm2bAuth::unmarshal(&mut unmarshal_buf).unwrap();
    let mut public_info = Tpm2bNvPublic::unmarshal(&mut unmarshal_buf).unwrap();
    let mut public_struct = public_info.0;
    public_struct.attributes.0 |= TpmaNv::WRITELOCKED.bits();
    public_info = tpm2::Tpm2b(public_struct);

    let mut write_buf = [0u8; 128];
    let mut offset = 0;
    offset += marshal_to_slice(&(nv_auth), &mut write_buf[offset..]);
    offset += marshal_to_slice(&(public_info), &mut write_buf[offset..]);
    sim.context
        .platform
        .storage
        .write_nv(item_offset, &write_buf[..offset])
        .unwrap();

    // Try writing again -> should fail with NvLocked (0x14F)
    let res = execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_LOCKED.get()),
        Ok(_) => panic!("Expected NvLocked error, but write succeeded on WRITELOCKED index"),
    }
}

#[test]
fn test_nv_write_role_authorization() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500031;

    // 1. Index defined with OWNERWRITE | OWNERREAD only (no AUTHWRITE, no PPWRITE)
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::from_bytes(b"nvpass").unwrap(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 10]).unwrap(),
        offset: 0,
    };

    // Try writing with AUTHWRITE (using nv_index_val auth handle) -> should fail with NvAuthorization (0x14B)
    let write_handles_auth = NVWriteHandles {
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
    };
    let res_auth =
        execute_with_password_sessions(&mut sim, &write_cmd, write_handles_auth, 1, b"nvpass");
    match res_auth {
        Err(err) => assert_eq!(err, TpmRc::NV_AUTHORIZATION.get()),
        Ok(_) => panic!("Expected NvAuthorization error for AUTHWRITE, but write succeeded"),
    }

    // Try writing with PPWRITE (using RHPlatform auth handle) -> should fail with NvAuthorization (0x14B)
    let write_handles_pp = NVWriteHandles {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: Handle(nv_index_val),
    };
    let res_pp = execute_with_password_sessions(&mut sim, &write_cmd, write_handles_pp, 1, &[]);
    match res_pp {
        Err(err) => assert_eq!(err, TpmRc::NV_AUTHORIZATION.get()),
        Ok(_) => panic!("Expected NvAuthorization error for PPWRITE, but write succeeded"),
    }

    // Try writing with OWNERWRITE (using RHOwner auth handle) -> success
    let write_handles_owner = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles_owner, 1, &[]).unwrap();

    // 2. Define another index with AUTHWRITE | OWNERREAD only (no OWNERWRITE)
    let nv_index_val_2 = 0x01500032;
    let nv_public_struct_2 = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val_2),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::AUTHWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info_2 = tpm2::Tpm2b(nv_public_struct_2);
    let cmd_2 = NVDefineSpace {
        auth: Tpm2bAuth::from_bytes(b"nvpass2").unwrap(),
        public_info: public_info_2,
    };
    execute_with_password_sessions(&mut sim, &cmd_2, handles, 1, &[]).unwrap();

    let write_cmd_2 = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xBB; 10]).unwrap(),
        offset: 0,
    };

    // Try writing with OWNERWRITE (using RHOwner auth handle) -> should fail with NvAuthorization (0x14B)
    let write_handles_owner_2 = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val_2),
    };
    let res_owner_2 =
        execute_with_password_sessions(&mut sim, &write_cmd_2, write_handles_owner_2, 1, &[]);
    match res_owner_2 {
        Err(err) => assert_eq!(err, TpmRc::NV_AUTHORIZATION.get()),
        Ok(_) => panic!("Expected NvAuthorization error for OWNERWRITE, but write succeeded"),
    }

    // Try writing with AUTHWRITE (using nv_index_val_2 auth handle) -> success
    let write_handles_auth_2 = NVWriteHandles {
        auth_handle: Handle(nv_index_val_2),
        nv_index: Handle(nv_index_val_2),
    };
    execute_with_password_sessions(&mut sim, &write_cmd_2, write_handles_auth_2, 1, b"nvpass2")
        .unwrap();
}

#[test]
fn test_nv_certify_readlocked() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500033;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 64]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]).unwrap();

    // Normal certify -> success
    let certify_cmd = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 0,
    };
    let certify_handles = NVCertifyHandles {
        sign_handle: Handle(0x40000007), // TPM_RH_NULL
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 1, &[]).unwrap();

    // Modify TOC in storage to add READLOCKED
    use tpm2_impl::storage::NvStorage;
    use tpm2_impl::storage::manager::{RESERVED_SIZE, TOC_SIZE};
    use tpm2_impl::storage::types::ItemMetadata;
    let mut toc_bytes = [0u8; TOC_SIZE];
    sim.context
        .platform
        .storage
        .read_nv(RESERVED_SIZE, &mut toc_bytes)
        .unwrap();
    let mut item_offset = RESERVED_SIZE + TOC_SIZE;
    let mut found = false;
    for i in 0..64 {
        let offset = i * ItemMetadata::SIZE;
        let mut item = ItemMetadata::from_bytes(&toc_bytes[offset..offset + ItemMetadata::SIZE]);
        if item.in_use == 0 {
            break;
        }
        if item.handle == nv_index_val {
            item.attributes |= TpmaNv::READLOCKED.bits();
            toc_bytes[offset..offset + ItemMetadata::SIZE].copy_from_slice(&item.to_bytes());
            found = true;
            break;
        }
        item_offset += item.data_size as usize;
    }
    assert!(found);
    sim.context
        .platform
        .storage
        .write_nv(RESERVED_SIZE, &toc_bytes)
        .unwrap();

    // Modify the index data payload attributes
    let mut payload = [0u8; 128];
    sim.context
        .platform
        .storage
        .read_nv(item_offset, &mut payload)
        .unwrap();
    let mut unmarshal_buf = &payload[..];
    let nv_auth = Tpm2bAuth::unmarshal(&mut unmarshal_buf).unwrap();
    let mut public_info = Tpm2bNvPublic::unmarshal(&mut unmarshal_buf).unwrap();
    let mut public_struct = public_info.0;
    public_struct.attributes.0 |= TpmaNv::READLOCKED.bits();
    public_info = tpm2::Tpm2b(public_struct);

    let mut write_buf = [0u8; 128];
    let mut offset = 0;
    offset += marshal_to_slice(&(nv_auth), &mut write_buf[offset..]);
    offset += marshal_to_slice(&(public_info), &mut write_buf[offset..]);
    sim.context
        .platform
        .storage
        .write_nv(item_offset, &write_buf[..offset])
        .unwrap();

    // Try certifying again -> should fail with NvLocked (0x14F)
    let res =
        execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 1, &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_LOCKED.get()),
        Ok(_) => panic!("Expected NvLocked error, but certify succeeded on READLOCKED index"),
    }
}

#[test]
fn test_nv_certify_role_authorization() {
    let mut sim = create_simulator!();
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
        auth: Tpm2bAuth::from_bytes(b"nvpass").unwrap(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 64]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]).unwrap();

    let certify_cmd = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 10,
        offset: 0,
    };

    // Try certifying with AUTHREAD (using nv_index_val auth handle) -> should fail with NvAuthorization (0x14B)
    let certify_handles_auth = NVCertifyHandles {
        sign_handle: Handle(0x40000007),
        auth_handle: Handle(nv_index_val),
        nv_index: Handle(nv_index_val),
    };
    let res_auth = execute_with_password_sessions_status(
        &mut sim,
        &certify_cmd,
        certify_handles_auth,
        1,
        b"nvpass",
    );
    match res_auth {
        Err(err) => assert_eq!(err, TpmRc::NV_AUTHORIZATION.get()),
        Ok(_) => panic!("Expected NvAuthorization error for AUTHREAD, but certify succeeded"),
    }

    // Try certifying with PPREAD (using RHPlatform auth handle) -> should fail with NvAuthorization (0x14B)
    let certify_handles_pp = NVCertifyHandles {
        sign_handle: Handle(0x40000007),
        auth_handle: Handle::RH_PLATFORM,
        nv_index: Handle(nv_index_val),
    };
    let res_pp =
        execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles_pp, 1, &[]);
    match res_pp {
        Err(err) => assert_eq!(err, TpmRc::NV_AUTHORIZATION.get()),
        Ok(_) => panic!("Expected NvAuthorization error for PPREAD, but certify succeeded"),
    }

    // Try certifying with OWNERREAD (using RHOwner auth handle) -> success
    let certify_handles_owner = NVCertifyHandles {
        sign_handle: Handle(0x40000007),
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles_owner, 1, &[])
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
        auth: Tpm2bAuth::from_bytes(b"nvpass2").unwrap(),
        public_info: public_info_2,
    };
    execute_with_password_sessions(&mut sim, &cmd_2, handles, 1, &[]).unwrap();

    let write_cmd_2 = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 64]).unwrap(),
        offset: 0,
    };
    let write_handles_2 = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val_2),
    };
    execute_with_password_sessions(&mut sim, &write_cmd_2, write_handles_2, 1, &[]).unwrap();

    // Try certifying with OWNERREAD (using RHOwner auth handle) -> should fail with NvAuthorization (0x14B)
    let certify_handles_owner_2 = NVCertifyHandles {
        sign_handle: Handle(0x40000007),
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val_2),
    };
    let res_owner_2 = execute_with_password_sessions_status(
        &mut sim,
        &certify_cmd,
        certify_handles_owner_2,
        1,
        &[],
    );
    match res_owner_2 {
        Err(err) => assert_eq!(err, TpmRc::NV_AUTHORIZATION.get()),
        Ok(_) => panic!("Expected NvAuthorization error for OWNERREAD, but certify succeeded"),
    }

    // Try certifying with AUTHREAD (using nv_index_val_2 auth handle) -> success
    let certify_handles_auth_2 = NVCertifyHandles {
        sign_handle: Handle(0x40000007),
        auth_handle: Handle(nv_index_val_2),
        nv_index: Handle(nv_index_val_2),
    };
    execute_with_password_sessions_status(
        &mut sim,
        &certify_cmd,
        certify_handles_auth_2,
        1,
        b"nvpass2",
    )
    .unwrap();
}

#[test]
fn test_nv_written_validation() {
    let mut sim = create_simulator!();
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
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    // 1. Try certifying before writing -> must fail with NvUninitialized (0x14A)
    let certify_cmd = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 0,
        offset: 0,
    };
    let certify_handles = NVCertifyHandles {
        sign_handle: Handle(0x40000007),
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    let err_cert =
        execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 1, &[])
            .unwrap_err();
    assert_eq!(err_cert, TpmRc::NV_UNINITIALIZED.get());

    // 2. Write data -> should set WRITTEN
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0x55; 8]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };
    execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[]).unwrap();

    // 3. Certify after writing -> should succeed
    execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 1, &[]).unwrap();
}

#[test]
fn test_nv_write_invalid_types() {
    let mut sim = create_simulator!();

    // Test Counter index
    {
        let nv_index_val = 0x01500051;
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::Counter);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(nv_index_val),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 8,
        };
        let cmd = NVDefineSpace {
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

        let write_cmd = NVWrite {
            data: Tpm2bMaxNvBuffer::from_bytes(&[0x11; 8]).unwrap(),
            offset: 0,
        };
        let write_handles = NVWriteHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(nv_index_val),
        };
        let err = execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[])
            .unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.get());
    }

    // Test Bits index
    {
        let nv_index_val = 0x01500052;
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::Bits);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(nv_index_val),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 8,
        };
        let cmd = NVDefineSpace {
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

        let write_cmd = NVWrite {
            data: Tpm2bMaxNvBuffer::from_bytes(&[0x11; 8]).unwrap(),
            offset: 0,
        };
        let write_handles = NVWriteHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(nv_index_val),
        };
        let err = execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[])
            .unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.get());
    }

    // Test Extend index
    {
        let nv_index_val = 0x01500053;
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::Extend);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(nv_index_val),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 32,
        };
        let cmd = NVDefineSpace {
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        let handles = NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        };
        execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

        let write_cmd = NVWrite {
            data: Tpm2bMaxNvBuffer::from_bytes(&[0x11; 32]).unwrap(),
            offset: 0,
        };
        let write_handles = NVWriteHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(nv_index_val),
        };
        let err = execute_with_password_sessions(&mut sim, &write_cmd, write_handles, 1, &[])
            .unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.get());
    }
}

#[test]
fn test_nv_write_writeall() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500054;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::WRITEALL,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 16,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
    };

    // 1. Partial write (size = 8 != 16) -> must fail with NvRange (0x146)
    let write_cmd_partial = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 8]).unwrap(),
        offset: 0,
    };
    let err = execute_with_password_sessions(&mut sim, &write_cmd_partial, write_handles, 1, &[])
        .unwrap_err();
    assert_eq!(err, TpmRc::NV_RANGE.get());

    // 2. Full write (size = 16) -> success
    let write_cmd_full = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 16]).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd_full, write_handles, 1, &[]).unwrap();
}
