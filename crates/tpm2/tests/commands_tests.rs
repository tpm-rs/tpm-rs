// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc, UnmarshalError};
use tpm2::*;

// --- From commands/mod.rs ---

#[test]
fn test_command_handles_validate_tpmi_interface_types() {
    let transient = 0x8000_0001u32.to_be_bytes();
    let persistent = 0x8100_0001u32.to_be_bytes();
    let rh_null = Handle::RH_NULL.0.to_be_bytes();
    let rh_platform = Handle::RH_PLATFORM.0.to_be_bytes();
    let rh_owner = Handle::RH_OWNER.0.to_be_bytes();
    let rh_lockout = Handle::RH_LOCKOUT.0.to_be_bytes();
    let policy_sess = 0x0300_0001u32.to_be_bytes();
    let hmac_sess = 0x0200_0001u32.to_be_bytes();
    let nv_index = 0x0100_0001u32.to_be_bytes();
    let act_0 = 0x4000_0110u32.to_be_bytes();
    let ac_0 = 0x9000_0001u32.to_be_bytes();

    // 1. Single non-null object handles (TPMI_DH_OBJECT)
    assert_eq!(
        MACHandles::unmarshal(&mut &transient[..]).unwrap().handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        MACHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert_eq!(
        ZGen2PhaseHandles::unmarshal(&mut &persistent[..])
            .unwrap()
            .key_a,
        Handle(0x8100_0001)
    );
    assert_eq!(
        ZGen2PhaseHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert_eq!(
        ECCEncryptHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .key_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        ECCEncryptHandles::unmarshal(&mut &rh_owner[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert_eq!(
        ECCDecryptHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .key_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        ECCDecryptHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert_eq!(
        EncapsulateHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .key_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        EncapsulateHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert_eq!(
        DecapsulateHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .key_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        DecapsulateHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert_eq!(
        MACStartHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        MACStartHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert_eq!(
        SignSequenceStartHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .key_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        SignSequenceStartHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert_eq!(
        VerifySequenceStartHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .key_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        VerifySequenceStartHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert_eq!(
        VerifyDigestSignatureHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .key_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        VerifyDigestSignatureHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert_eq!(
        SignDigestHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .key_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        SignDigestHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    // 2. Two-handle object commands (VerifySequenceComplete, SignSequenceComplete, CertifyX509)
    let mut two_objs = [0u8; 8];
    two_objs[0..4].copy_from_slice(&transient);
    two_objs[4..8].copy_from_slice(&persistent);

    let mut bad_h1 = two_objs;
    bad_h1[0..4].copy_from_slice(&rh_null);
    let mut bad_h2 = two_objs;
    bad_h2[4..8].copy_from_slice(&rh_null);

    assert!(VerifySequenceCompleteHandles::unmarshal(&mut &two_objs[..]).is_ok());
    assert_eq!(
        VerifySequenceCompleteHandles::unmarshal(&mut &bad_h1[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );
    assert_eq!(
        VerifySequenceCompleteHandles::unmarshal(&mut &bad_h2[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(2)
    );

    assert!(SignSequenceCompleteHandles::unmarshal(&mut &two_objs[..]).is_ok());
    assert_eq!(
        SignSequenceCompleteHandles::unmarshal(&mut &bad_h1[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );
    assert_eq!(
        SignSequenceCompleteHandles::unmarshal(&mut &bad_h2[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(2)
    );

    assert!(CertifyX509Handles::unmarshal(&mut &two_objs[..]).is_ok());
    assert_eq!(
        CertifyX509Handles::unmarshal(&mut &bad_h1[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );
    assert_eq!(
        CertifyX509Handles::unmarshal(&mut &bad_h2[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(2)
    );

    // LoadHandles (TPMI_DH_OBJECT) and ObjectChangeAuthHandles (TPMI_DH_OBJECT, TPMI_DH_OBJECT)
    assert_eq!(
        LoadHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .parent_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        LoadHandles::unmarshal(&mut &persistent[..])
            .unwrap()
            .parent_handle,
        Handle(0x8100_0001)
    );
    for bad_parent in [
        rh_owner,
        rh_platform,
        Handle::RH_ENDORSEMENT.0.to_be_bytes(),
        rh_null,
        0x4000_0140u32.to_be_bytes(), // TPM_RH_FW_OWNER
        0x4001_0000u32.to_be_bytes(), // TPM_RH_SVN_OWNER_BASE
    ] {
        assert_eq!(
            LoadHandles::unmarshal(&mut &bad_parent[..]).unwrap_err(),
            UnmarshalError::VALUE.in_handle(1)
        );
        let mut oca_bad_parent = two_objs;
        oca_bad_parent[4..8].copy_from_slice(&bad_parent);
        assert_eq!(
            ObjectChangeAuthHandles::unmarshal(&mut &oca_bad_parent[..]).unwrap_err(),
            UnmarshalError::VALUE.in_handle(2)
        );
    }
    assert_eq!(
        ObjectChangeAuthHandles::unmarshal(&mut &two_objs[..]).unwrap(),
        ObjectChangeAuthHandles {
            object_handle: Handle(0x8000_0001),
            parent_handle: Handle(0x8100_0001),
        }
    );
    assert_eq!(
        ObjectChangeAuthHandles::unmarshal(&mut &bad_h1[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    // 3. Platform handles (ReadOnlyControl, PPCommands, SetAlgorithmSet, FieldUpgradeStart)
    assert!(ReadOnlyControlHandles::unmarshal(&mut &rh_platform[..]).is_ok());
    assert_eq!(
        ReadOnlyControlHandles::unmarshal(&mut &rh_owner[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert!(PPCommandsHandles::unmarshal(&mut &rh_platform[..]).is_ok());
    assert_eq!(
        PPCommandsHandles::unmarshal(&mut &rh_owner[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert!(SetAlgorithmSetHandles::unmarshal(&mut &rh_platform[..]).is_ok());
    assert_eq!(
        SetAlgorithmSetHandles::unmarshal(&mut &rh_owner[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    let mut fu_handles = [0u8; 8];
    fu_handles[0..4].copy_from_slice(&rh_platform);
    fu_handles[4..8].copy_from_slice(&transient);
    assert!(FieldUpgradeStartHandles::unmarshal(&mut &fu_handles[..]).is_ok());
    let mut fu_bad_h1 = fu_handles;
    fu_bad_h1[0..4].copy_from_slice(&rh_owner);
    let mut fu_bad_h2 = fu_handles;
    fu_bad_h2[4..8].copy_from_slice(&rh_null);
    assert_eq!(
        FieldUpgradeStartHandles::unmarshal(&mut &fu_bad_h1[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );
    assert_eq!(
        FieldUpgradeStartHandles::unmarshal(&mut &fu_bad_h2[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(2)
    );

    // 4. Hierarchy / Provision / NV / ACT / AC / Policy handles
    assert!(SetCapabilityHandles::unmarshal(&mut &rh_lockout[..]).is_ok());
    assert!(SetCapabilityHandles::unmarshal(&mut &rh_null[..]).is_ok());
    assert_eq!(
        SetCapabilityHandles::unmarshal(&mut &transient[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert!(SetCommandCodeAuditStatusHandles::unmarshal(&mut &rh_owner[..]).is_ok());
    assert!(SetCommandCodeAuditStatusHandles::unmarshal(&mut &rh_platform[..]).is_ok());
    assert_eq!(
        SetCommandCodeAuditStatusHandles::unmarshal(&mut &rh_lockout[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert!(NVDefineSpace2Handles::unmarshal(&mut &rh_owner[..]).is_ok());
    assert_eq!(
        NVDefineSpace2Handles::unmarshal(&mut &rh_lockout[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert!(NVReadPublic2Handles::unmarshal(&mut &nv_index[..]).is_ok());
    assert_eq!(
        NVReadPublic2Handles::unmarshal(&mut &transient[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert!(ACTSetTimeoutHandles::unmarshal(&mut &act_0[..]).is_ok());
    assert_eq!(
        ACTSetTimeoutHandles::unmarshal(&mut &rh_platform[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    assert!(ACGetCapabilityHandles::unmarshal(&mut &ac_0[..]).is_ok());
    assert_eq!(
        ACGetCapabilityHandles::unmarshal(&mut &transient[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );

    let mut ac_send = [0u8; 12];
    ac_send[0..4].copy_from_slice(&transient);
    ac_send[4..8].copy_from_slice(&nv_index);
    ac_send[8..12].copy_from_slice(&ac_0);
    assert!(ACSendHandles::unmarshal(&mut &ac_send[..]).is_ok());
    let mut ac_send_bad3 = ac_send;
    ac_send_bad3[8..12].copy_from_slice(&transient);
    assert_eq!(
        ACSendHandles::unmarshal(&mut &ac_send_bad3[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(3)
    );

    for policy_res in [
        PolicyACSendSelectHandles::unmarshal(&mut &policy_sess[..]).map(|h| h.policy_session),
        PolicyPhysicalPresenceHandles::unmarshal(&mut &policy_sess[..]).map(|h| h.policy_session),
        PolicyCapabilityHandles::unmarshal(&mut &policy_sess[..]).map(|h| h.policy_session),
        PolicyParametersHandles::unmarshal(&mut &policy_sess[..]).map(|h| h.policy_session),
        PolicyTransportSPDMHandles::unmarshal(&mut &policy_sess[..]).map(|h| h.policy_session),
    ] {
        assert_eq!(policy_res.unwrap(), Handle(0x0300_0001));
    }

    for bad_policy_err in [
        PolicyACSendSelectHandles::unmarshal(&mut &hmac_sess[..]).unwrap_err(),
        PolicyPhysicalPresenceHandles::unmarshal(&mut &hmac_sess[..]).unwrap_err(),
        PolicyCapabilityHandles::unmarshal(&mut &hmac_sess[..]).unwrap_err(),
        PolicyParametersHandles::unmarshal(&mut &hmac_sess[..]).unwrap_err(),
        PolicyTransportSPDMHandles::unmarshal(&mut &hmac_sess[..]).unwrap_err(),
    ] {
        assert_eq!(bad_policy_err, UnmarshalError::VALUE.in_handle(1));
    }

    let mut policy_secret_handles = [0u8; 8];
    policy_secret_handles[0..4].copy_from_slice(&rh_owner);
    policy_secret_handles[4..8].copy_from_slice(&policy_sess);
    assert_eq!(
        PolicySecretHandles::unmarshal(&mut &policy_secret_handles[..]).unwrap(),
        PolicySecretHandles {
            auth_handle: Handle::RH_OWNER,
            policy_session: Handle(0x0300_0001),
        }
    );
    let mut policy_secret_null_auth = policy_secret_handles;
    policy_secret_null_auth[0..4].copy_from_slice(&rh_null);
    assert_eq!(
        PolicySecretHandles::unmarshal(&mut &policy_secret_null_auth[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(1)
    );
    let mut policy_secret_bad_session = policy_secret_handles;
    policy_secret_bad_session[4..8].copy_from_slice(&hmac_sess);
    assert_eq!(
        PolicySecretHandles::unmarshal(&mut &policy_secret_bad_session[..]).unwrap_err(),
        UnmarshalError::VALUE.in_handle(2)
    );
}

#[test]
fn test_response_handles_validate_types_without_command_handle_modifier() {
    let transient = 0x8000_0001u32.to_be_bytes();
    let hmac_sess = 0x0200_0001u32.to_be_bytes();
    let rs_pw = Handle::RS_PW.0.to_be_bytes();
    let rh_null = Handle::RH_NULL.0.to_be_bytes();
    let short = [0x80u8, 0x00];

    // ContextLoadRespHandles (TPMI_DH_CONTEXT)
    assert_eq!(
        ContextLoadRespHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .loaded_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        ContextLoadRespHandles::unmarshal(&mut &hmac_sess[..])
            .unwrap()
            .loaded_handle,
        Handle(0x0200_0001)
    );
    assert_eq!(
        ContextLoadRespHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        ContextLoadRespHandles::unmarshal(&mut &short[..]).unwrap_err(),
        UnmarshalError::INSUFFICIENT
    );

    // StartAuthSessionRespHandles (TPMI_SH_AUTH_SESSION::<false>)
    assert_eq!(
        StartAuthSessionRespHandles::unmarshal(&mut &hmac_sess[..])
            .unwrap()
            .session_handle,
        Handle(0x0200_0001)
    );
    assert_eq!(
        StartAuthSessionRespHandles::unmarshal(&mut &rs_pw[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        StartAuthSessionRespHandles::unmarshal(&mut &short[..]).unwrap_err(),
        UnmarshalError::INSUFFICIENT
    );

    // Object / sequence response handles (TPMI_DH_OBJECT::<false>)
    assert_eq!(
        HmacStartRespHandles::unmarshal(&mut &transient[..])
            .unwrap()
            .sequence_handle,
        Handle(0x8000_0001)
    );
    assert_eq!(
        HmacStartRespHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        MACStartRespHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        HashSequenceStartRespHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        SignSequenceStartRespHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        VerifySequenceStartRespHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        CreatePrimaryRespHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        LoadRespHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        LoadExternalRespHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        CreateLoadedRespHandles::unmarshal(&mut &rh_null[..]).unwrap_err(),
        UnmarshalError::VALUE
    );
    assert_eq!(
        CreateLoadedRespHandles::unmarshal(&mut &short[..]).unwrap_err(),
        UnmarshalError::INSUFFICIENT
    );
}

// --- From commands/field_upgrade.rs ---

#[cfg(feature = "sha256")]
#[test]
fn test_field_upgrade_data_rsp_marshal_unmarshal_with_next_digest() {
    let next_bytes = [0x11u8; 32];
    let first_bytes = [0x22u8; 32];
    let rsp = FieldUpgradeDataRsp {
        next_digest: Some(TpmtHa::Sha256(&next_bytes)),
        first_digest: TpmtHa::Sha256(&first_bytes),
    };

    let mut buf = [0u8; FieldUpgradeDataRsp::MAX_SIZE];
    let len = rsp.marshal(&mut buf);
    assert_eq!(len, (2 + 32) + (2 + 32));
    assert_eq!(&buf[0..2], &Alg::SHA256.id().to_be_bytes());
    assert_eq!(&buf[2..34], &next_bytes);
    assert_eq!(&buf[34..36], &Alg::SHA256.id().to_be_bytes());
    assert_eq!(&buf[36..68], &first_bytes);

    let mut src = &buf[..len];
    let decoded = FieldUpgradeDataRsp::unmarshal(&mut src).unwrap();
    assert!(src.is_empty());
    assert_eq!(decoded, rsp);
}

#[cfg(feature = "sha256")]
#[test]
fn test_field_upgrade_data_rsp_marshal_unmarshal_null_next_digest() {
    let first_bytes = [0x33u8; 32];
    let rsp = FieldUpgradeDataRsp {
        next_digest: None,
        first_digest: TpmtHa::Sha256(&first_bytes),
    };

    let mut buf = [0u8; FieldUpgradeDataRsp::MAX_SIZE];
    let len = rsp.marshal(&mut buf);
    assert_eq!(len, 2 + (2 + 32));
    assert_eq!(&buf[0..2], &Alg::NULL.id().to_be_bytes());
    assert_eq!(&buf[2..4], &Alg::SHA256.id().to_be_bytes());
    assert_eq!(&buf[4..36], &first_bytes);

    let mut src = &buf[..len];
    let decoded = FieldUpgradeDataRsp::unmarshal(&mut src).unwrap();
    assert!(src.is_empty());
    assert_eq!(decoded, rsp);
}

#[test]
fn test_field_upgrade_data_rsp_rejects_null_first_digest() {
    // nextDigest = TPM_ALG_NULL (0x0010), firstDigest = TPM_ALG_NULL (0x0010) -> invalid
    let mut buf = [0u8; 4];
    buf[0..2].copy_from_slice(&Alg::NULL.id().to_be_bytes());
    buf[2..4].copy_from_slice(&Alg::NULL.id().to_be_bytes());

    let mut src = &buf[..];
    let err = FieldUpgradeDataRsp::unmarshal(&mut src).unwrap_err();
    assert_eq!(err, UnmarshalError::HASH);
    // Verify nextDigest (first 2 bytes) was parsed as None before firstDigest failed
    assert!(src.is_empty());
}

// --- From commands/context.rs ---

#[test]
fn test_flush_context_models_flush_handle_as_parameter() {
    // Verify zero command handles and zero response handles/parameters
    assert_eq!(<<FlushContext as Command>::Handles as Marshal>::MAX_SIZE, 0);
    assert_eq!(
        <<FlushContext as Command>::RespHandles as Marshal>::MAX_SIZE,
        0
    );
    assert_eq!(
        <<FlushContext as Command>::Response<'static> as Marshal>::MAX_SIZE,
        0
    );

    // Verify valid TPMI_DH_CONTEXT handles round-trip in parameter stream
    for handle in [
        0x8000_0000,
        Handle::TRANSIENT_LAST.0,
        0x0200_0000,
        0x0300_0001,
    ] {
        let cmd = FlushContext {
            flush_handle: Handle(handle),
        };
        let mut buf = [0u8; FlushContext::MAX_SIZE];
        let len = cmd.marshal(&mut buf);
        assert_eq!(len, 4);
        let mut slice = &buf[..];
        let unmarshalled = FlushContext::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshalled, cmd);
        assert!(slice.is_empty());
    }

    // Verify truncated buffer returns INSUFFICIENT with parameter(1) modifier (not handle(1))
    let short = [0x80u8, 0x00, 0x00];
    let mut slice = &short[..];
    let err = FlushContext::unmarshal(&mut slice).unwrap_err();
    assert_eq!(err, UnmarshalError::INSUFFICIENT.in_parameter(1));
    assert_eq!(err.position, Some(Position::parameter(1)));

    // Verify invalid handle types return VALUE with parameter(1) modifier (not handle(1))
    for invalid in [
        0x80FF_FFFFu32,
        0x02FF_FFFF,
        0x03FF_FFFF,
        0x8100_0000,
        0x4000_0001,
        0x0100_0000,
        0x0000_0000,
    ] {
        let bytes = invalid.to_be_bytes();
        let mut slice = &bytes[..];
        let err = FlushContext::unmarshal(&mut slice).unwrap_err();
        assert_eq!(err, UnmarshalError::VALUE.in_parameter(1));
        assert_eq!(err.position, Some(Position::parameter(1)));
    }
}

// --- From commands/testing.rs ---

#[test]
fn test_incremental_self_test_unmarshal_accepts_reserved_algs_and_preserves_trailing_bytes() {
    for reserved_id in [0x0000u16, 0x00C1, 0x00C4, 0x00C6, 0x8000, 0x8021, 0xFFFF] {
        // TPML_ALG with count = 1, algorithms[0] = reserved_id, followed by 1 trailing byte (0xAA)
        let mut buf = [0u8; 7];
        buf[0..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4..6].copy_from_slice(&reserved_id.to_be_bytes());
        buf[6] = 0xAA;

        let mut slice = &buf[..];
        let cmd = IncrementalSelfTest::unmarshal(&mut slice)
            .expect("IncrementalSelfTest::unmarshal should accept reserved TPM_ALG_ID values");
        assert_eq!(cmd.to_test.count(), 1);
        assert_eq!(cmd.to_test.algorithms()[0].id(), reserved_id);
        // Trailing byte remains unconsumed so dispatcher returns TPM_RC_SIZE
        assert_eq!(slice, &[0xAA]);
    }
}

#[test]
fn test_incremental_self_test_unmarshal_truncated_after_reserved_alg_returns_insufficient() {
    for reserved_id in [0x0000u16, 0x00C1, 0x8000, 0xFFFF] {
        // TPML_ALG with count = 2, algorithms[0] = reserved_id, truncated before algorithms[1] finishes
        let mut buf = [0u8; 7];
        buf[0..4].copy_from_slice(&2u32.to_be_bytes());
        buf[4..6].copy_from_slice(&reserved_id.to_be_bytes());
        buf[6] = 0x00; // incomplete 2nd algorithm ID

        let mut slice_tpml = &buf[..];
        let err_tpml = TpmlAlg::unmarshal(&mut slice_tpml).unwrap_err();
        assert_eq!(err_tpml, UnmarshalError::INSUFFICIENT);

        let mut slice = &buf[..];
        let err = IncrementalSelfTest::unmarshal(&mut slice).unwrap_err();
        assert_eq!(err, UnmarshalError::INSUFFICIENT.in_parameter(1));
    }
}

// --- From commands/capability.rs ---

#[test]
fn test_set_capability_handles_validation() {
    for valid_handle in [
        Handle::RH_OWNER,
        Handle::RH_PLATFORM,
        Handle::RH_ENDORSEMENT,
        Handle::RH_LOCKOUT,
        Handle::RH_NULL,
    ] {
        let handles = SetCapabilityHandles {
            auth_handle: valid_handle,
        };
        let mut buf = [0u8; SetCapabilityHandles::MAX_SIZE];
        let written = handles.marshal(&mut buf);
        assert_eq!(written, 4);
        let mut slice = &buf[..];
        let unmarshaled = SetCapabilityHandles::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshaled, handles);
        assert!(slice.is_empty());
    }

    // Reject invalid hierarchy auth handle (e.g., TPM_RH_PLATFORM_NV or transient handle) with TPM_RC_VALUE + TPM_RC_H + 1
    for invalid_handle in [
        Handle::RH_PLATFORM_NV,
        Handle(0x8000_0000),
        Handle(0x0100_0000),
    ] {
        let mut buf = [0u8; 4];
        invalid_handle.marshal(&mut buf);
        let mut slice = &buf[..];
        assert_eq!(
            SetCapabilityHandles::unmarshal(&mut slice),
            Err(UnmarshalError::VALUE.in_handle(1))
        );
    }
}

#[test]
fn test_set_capability_marshal_includes_tpm2b_size_prefix() {
    let cmd = SetCapability {
        set_capability_data: Tpm2bSetCapabilityData::new(TpmsSetCapabilityData {
            set_capability: TpmCap::Algs,
            data: TpmuSetCapabilities::new(&[0x11, 0x22, 0x33, 0x44]),
        }),
    };
    let mut buf = [0u8; SetCapability::MAX_SIZE];
    let written = cmd.marshal(&mut buf);
    // 2-byte TPM2B size prefix (4 + 4 = 8) + 4-byte TpmCap (0x00000000) + 4-byte data
    assert_eq!(written, 10);
    assert_eq!(
        &buf[..written],
        &[0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44]
    );

    // Unmarshalling the marshaled packet parses the 2-byte size prefix and 4-byte TpmCap::Algs,
    // then rejects TpmCap::Algs in TPMU_SET_CAPABILITIES with TPM_RC_SELECTOR + TPM_RC_P + 1.
    let mut slice = &buf[..written];
    assert_eq!(
        SetCapability::unmarshal(&mut slice),
        Err(UnmarshalError::SELECTOR.in_parameter(1))
    );
}

#[test]
fn test_set_capability_unmarshal_rejects_zero_size_and_invalid_selectors() {
    // 1. TPM2B_SET_CAPABILITY_DATA.size == 0 must fail with TPM_RC_SIZE + TPM_RC_P + 1
    let zero_size_wire = [0x00u8, 0x00];
    let mut slice = &zero_size_wire[..];
    assert_eq!(
        SetCapability::unmarshal(&mut slice),
        Err(UnmarshalError::SIZE.in_parameter(1))
    );

    // 2. Truncated buffer (< 2 bytes for size prefix) must fail with TPM_RC_INSUFFICIENT
    let short_wire = [0x00u8];
    let mut slice = &short_wire[..];
    assert_eq!(
        SetCapability::unmarshal(&mut slice),
        Err(UnmarshalError::INSUFFICIENT.in_parameter(1))
    );

    // 3. Invalid TPM_CAP selector (e.g., 0xFFFF_FFFF) must fail with TPM_RC_VALUE + TPM_RC_P + 1
    let invalid_cap_wire = [0x00u8, 0x04, 0xFF, 0xFF, 0xFF, 0xFF];
    let mut slice = &invalid_cap_wire[..];
    assert_eq!(
        SetCapability::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE.in_parameter(1))
    );

    // 4. All valid TPM_CAP selectors are not part of TPMU_SET_CAPABILITIES and must fail with TPM_RC_SELECTOR + TPM_RC_P + 1
    for cap in [
        TpmCap::Algs,
        TpmCap::Handles,
        TpmCap::Commands,
        TpmCap::PPCommands,
        TpmCap::AuditCommands,
        TpmCap::PCRs,
        TpmCap::TPMProperties,
        TpmCap::PCRProperties,
        TpmCap::ECCCurves,
        TpmCap::AuthPolicies,
        TpmCap::ACT,
        TpmCap::PubKeys,
        TpmCap::SpdmSessionInfo,
        TpmCap::VendorProperty,
    ] {
        let mut wire = [0u8; 10];
        wire[..2].copy_from_slice(&8u16.to_be_bytes());
        wire[2..6].copy_from_slice(&u32::from(cap).to_be_bytes());
        // 4 bytes of dummy union payload (e.g., count = 0)
        wire[6..10].copy_from_slice(&0u32.to_be_bytes());
        let mut slice = &wire[..];
        assert_eq!(
            SetCapability::unmarshal(&mut slice),
            Err(UnmarshalError::SELECTOR.in_parameter(1))
        );
    }
}

// --- From commands/asymmetric.rs ---

#[cfg(feature = "rsa")]
#[test]
fn test_rsa_encrypt_and_decrypt_reject_signature_schemes_on_unmarshal() {
    for invalid_alg in [
        Alg::RSASSA,
        Alg::RSAPSS,
        Alg::ECDSA,
        Alg::AES,
        Alg::from(0x0000),
        Alg::from(0xFFFF),
    ] {
        // Build raw parameter buffer:
        // param 1: message / cipher_text (Tpm2bPublicKeyRsa: size = 2, bytes = [0x01, 0x02])
        // param 2: in_scheme (invalid_alg: 2 bytes, plus 2 bytes of SHA256 hash alg just in case)
        // param 3: label (Tpm2bData: size = 0)
        let mut buf = [0u8; 10];
        buf[0..2].copy_from_slice(&2u16.to_be_bytes());
        buf[2..4].copy_from_slice(&[0x01, 0x02]);
        buf[4..6].copy_from_slice(&invalid_alg.id().to_be_bytes());
        buf[6..8].copy_from_slice(&Alg::SHA256.id().to_be_bytes());
        buf[8..10].copy_from_slice(&0u16.to_be_bytes());

        let mut src_enc = &buf[..];
        assert_eq!(
            RSAEncrypt::unmarshal(&mut src_enc),
            Err(UnmarshalError::VALUE.in_parameter(2)),
            "RSAEncrypt should reject scheme {:?} with VALUE in parameter 2",
            invalid_alg
        );

        let mut src_dec = &buf[..];
        assert_eq!(
            RSADecrypt::unmarshal(&mut src_dec),
            Err(UnmarshalError::VALUE.in_parameter(2)),
            "RSADecrypt should reject scheme {:?} with VALUE in parameter 2",
            invalid_alg
        );
    }

    // OAEP with invalid inner hash algorithm (e.g. Alg::NULL) returns HASH in parameter 2
    let mut buf = [0u8; 10];
    buf[0..2].copy_from_slice(&2u16.to_be_bytes());
    buf[2..4].copy_from_slice(&[0x01, 0x02]);
    buf[4..6].copy_from_slice(&Alg::OAEP.id().to_be_bytes());
    buf[6..8].copy_from_slice(&Alg::NULL.id().to_be_bytes());
    buf[8..10].copy_from_slice(&0u16.to_be_bytes());

    let mut src_enc = &buf[..];
    assert_eq!(
        RSAEncrypt::unmarshal(&mut src_enc),
        Err(UnmarshalError::HASH.in_parameter(2))
    );
    let mut src_dec = &buf[..];
    assert_eq!(
        RSADecrypt::unmarshal(&mut src_dec),
        Err(UnmarshalError::HASH.in_parameter(2))
    );

    // Verify valid schemes roundtrip
    for scheme in [
        None,
        Some(TpmtRsaDecrypt::Rsaes),
        Some(TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha256)),
    ] {
        let enc = RSAEncrypt {
            message: Tpm2bPublicKeyRsa::from_bytes(&[0xAA, 0xBB]).unwrap(),
            in_scheme: scheme,
            label: Tpm2bData::default(),
        };
        let mut dst = [0u8; RSAEncrypt::MAX_SIZE];
        let len = enc.marshal(&mut dst);
        let mut src = &dst[..len];
        assert_eq!(RSAEncrypt::unmarshal(&mut src), Ok(enc));
        assert!(src.is_empty());

        let dec = RSADecrypt {
            cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0xCC, 0xDD]).unwrap(),
            in_scheme: scheme,
            label: Tpm2bData::default(),
        };
        let mut dst = [0u8; RSADecrypt::MAX_SIZE];
        let len = dec.marshal(&mut dst);
        let mut src = &dst[..len];
        assert_eq!(RSADecrypt::unmarshal(&mut src), Ok(dec));
        assert!(src.is_empty());
    }
}

#[cfg(all(feature = "ecc", feature = "ecdh"))]
#[test]
fn test_zgen_2phase_in_scheme_rejects_null_and_roundtrips_valid_schemes() {
    let point_a = Tpm2bEccPoint::new(TpmsEccPoint {
        x: Tpm2bEccParameter::from_bytes(&[0x01, 0x02]).unwrap(),
        y: Tpm2bEccParameter::from_bytes(&[0x03, 0x04]).unwrap(),
    });
    let point_b = Tpm2bEccPoint::new(TpmsEccPoint {
        x: Tpm2bEccParameter::from_bytes(&[0x05, 0x06]).unwrap(),
        y: Tpm2bEccParameter::from_bytes(&[0x07, 0x08]).unwrap(),
    });

    let valid_schemes: &[TpmiEccKeyExchange] = &[
        #[cfg(feature = "ecdh")]
        TpmiEccKeyExchange::Ecdh,
        #[cfg(feature = "sm2")]
        TpmiEccKeyExchange::Sm2,
        #[cfg(feature = "ecmqv")]
        TpmiEccKeyExchange::Ecmqv,
    ];
    for &valid_scheme in valid_schemes {
        let cmd = ZGen2Phase {
            in_qs_b: point_a,
            in_qe_b: point_b,
            in_scheme: valid_scheme,
            counter: 0x1234,
        };
        let mut dst = [0u8; ZGen2Phase::MAX_SIZE];
        let len = cmd.marshal(&mut dst);
        let mut src = &dst[..len];
        assert_eq!(ZGen2Phase::unmarshal(&mut src), Ok(cmd));
        assert!(src.is_empty());
    }

    // Verify TPM_ALG_NULL (0x0010) and other invalid schemes are rejected with
    // TPM_RC_SCHEME + TPM_RC_P + TPM_RC_3.
    let base_cmd = ZGen2Phase {
        in_qs_b: point_a,
        in_qe_b: point_b,
        in_scheme: TpmiEccKeyExchange::Ecdh,
        counter: 0x1234,
    };
    let mut dst = [0u8; ZGen2Phase::MAX_SIZE];
    let len = base_cmd.marshal(&mut dst);
    // in_scheme is the 2 bytes immediately preceding the trailing 2-byte counter
    let scheme_offset = len - 4;

    for invalid_alg in [
        Alg::NULL,
        Alg::ECDSA,
        Alg::ECDAA,
        Alg::ECSCHNORR,
        Alg::SHA256,
        Alg::from(0x0000),
        Alg::from(0xFFFF),
    ] {
        dst[scheme_offset..scheme_offset + 2].copy_from_slice(&invalid_alg.id().to_be_bytes());
        let mut src = &dst[..len];
        let err = ZGen2Phase::unmarshal(&mut src).unwrap_err();
        assert_eq!(
            err,
            UnmarshalError::SCHEME.in_parameter(3),
            "ZGen2Phase should reject scheme {:?} with SCHEME in parameter 3",
            invalid_alg
        );
        let rc = TpmRc::from(err);
        assert_eq!(
            rc,
            TpmRc::SCHEME.with(Position::parameter(3)),
            "Expected TPM_RC_SCHEME + TPM_RC_P + TPM_RC_3"
        );
        assert_eq!(rc.get(), 0x000003D2);
    }
}

// --- From commands/enhanced_auth.rs ---

#[test]
fn test_policy_secret_handles_rejects_rh_null() {
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&Handle::RH_NULL.0.to_be_bytes());
    buf[4..8].copy_from_slice(&0x0300_0001u32.to_be_bytes());

    assert_eq!(
        PolicySecretHandles::unmarshal(&mut &buf[..]),
        Err(UnmarshalError::VALUE.in_handle(1))
    );

    buf[0..4].copy_from_slice(&Handle::RH_OWNER.0.to_be_bytes());
    assert_eq!(
        PolicySecretHandles::unmarshal(&mut &buf[..]),
        Ok(PolicySecretHandles {
            auth_handle: Handle::RH_OWNER,
            policy_session: Handle(0x0300_0001),
        })
    );
}
