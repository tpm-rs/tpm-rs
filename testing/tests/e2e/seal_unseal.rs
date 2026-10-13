//! Sealed data objects: creation and TPM2_Unseal with different authorization values.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{Create, CreatePrimary, Unseal};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bSensitiveData, TpmSe,
    TpmaObject, TpmaSession, TpmiAlgHash, TpmlPcrSelection, TpmsSensitiveCreate, TpmtPublic,
    Unmarshal, *,
};

/// TPMS_DERIVE marshalled as sealed data round-trips locally and through Create/Load/Unseal
///
/// Marshals a `TPMS_DERIVE` into the sensitive data of a sealed data object,
/// round-trips the `TPM2B_SENSITIVE_CREATE` locally, then creates the object
/// on the simulator and checks that `TPM2_Unseal` returns the same bytes.
#[test]
fn derive_structure_round_trips_through_seal() {
    use testing::tpm::Tpm;
    use tpm2::commands::{CreatePrimary, Unseal};

    let tpms_derive = TpmsDerive {
        label: Tpm2bLabel::from_bytes(b"label").unwrap(),
        context: Tpm2bLabel::from_bytes(b"context").unwrap(),
    };
    let mut derive_buf = [0u8; 1024];
    let derive_len = marshal_to_slice(&tpms_derive, &mut derive_buf);
    let derive_bytes = &derive_buf[..derive_len];

    let password: &[u8] = b"p@ssw0rd";
    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::from_bytes(derive_bytes).unwrap(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);
    let mut serialized = [0u8; 1024];
    let len = marshal_to_slice(&in_sensitive, &mut serialized);

    // Local unmarshal round trip.
    let mut unmarshal_buf = &serialized[..len];
    let unmarshaled = Tpm2bSensitiveCreate::unmarshal(&mut unmarshal_buf).unwrap();
    assert!(unmarshal_buf.is_empty());
    assert_eq!(unmarshaled.0.user_auth.get_buffer(), password);
    assert_eq!(unmarshaled.0.data.get_buffer(), derive_bytes);

    // End to end: seal the data under the owner hierarchy and unseal it.
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    });
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: unmarshaled,
        in_public,
        ..Default::default()
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create, 1, &[])
        .expect("CreatePrimary of sealed data object failed");

    let unseal = execute_with_password_sessions(
        &mut sim,
        &Unseal {
            item_handle: create_rsp.object_handle,
        },
        1,
        password,
    )
    .expect("Unseal failed");
    assert_eq!(unseal.out_data.get_buffer(), derive_bytes);
}

/// A sealed data object created with CreatePrimary unseals to the original data.
#[test]
fn primary_sealed_object_unseals() {
    let mut sim = Tpm::new();

    let secret_message = b"my_secret_data_1234";

    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    });

    let primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_NULL,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(secret_message).unwrap(),
        }),
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let primary_rsp = execute_tpm_command_offsets::<CreatePrimary>(
        &mut sim,
        &primary_cmd,
        &[empty_password_auth()],
    )
    .expect("CreatePrimary sealed data failed");

    let object_handle = primary_rsp.object_handle;

    // Unseal the sealed data object
    let unseal_cmd = Unseal {
        item_handle: object_handle,
    };
    let unseal_resp =
        execute_tpm_command_offsets::<Unseal>(&mut sim, &unseal_cmd, &[empty_password_auth()])
            .expect("Unseal failed");

    assert_eq!(unseal_resp.out_data.get_buffer(), secret_message);
}

/// Sealed objects with empty auth or auth with trailing zeros unseal with password and HMAC sessions using the stripped auth
#[test]
fn seal_unseal_auth_value_trailing_zeros() {
    let mut sim = Tpm::new();
    let srk_template = get_rsa_srk_template();
    let srk_auth = b"mySRK";
    let (srk_handle, _) = create_srk_with_template(&mut sim, &srk_template, srk_auth);

    // Case A: Empty auth sealing/unsealing
    {
        let data = b"empty_auth_secrets";
        let auth = b"";

        // Create
        let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        });
        let in_public = tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        });
        let create_cmd = Create {
            parent_handle: srk_handle,
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let create_rsp =
            execute_with_password_sessions(&mut sim, &create_cmd, 1, srk_auth).unwrap();

        // Load
        let load_cmd = tpm2::commands::Load {
            parent_handle: srk_handle,
            in_private: create_rsp.out_private,
            in_public: create_rsp.out_public,
        };
        let load_rsp = execute_with_password_sessions(&mut sim, &load_cmd, 1, srk_auth).unwrap();

        // Unseal with empty auth
        let unseal_cmd = Unseal {
            item_handle: load_rsp.object_handle,
        };
        let unseal_rsp = execute_with_password_sessions(&mut sim, &unseal_cmd, 1, auth).unwrap();
        assert_eq!(unseal_rsp.out_data.get_buffer(), data);

        flush_context(&mut sim, load_rsp.object_handle).unwrap();
    }

    // Case B: Sealing with trailing zeros in auth, unsealing with stripped auth (E2E HMAC)
    {
        let data = b"padded_auth_secrets";
        let auth = b"p@ssw0rd\x00\x00\x00";

        // Create
        let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        });
        let in_public = tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        });
        let create_cmd = Create {
            parent_handle: srk_handle,
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let create_rsp =
            execute_with_password_sessions(&mut sim, &create_cmd, 1, srk_auth).unwrap();

        // Load
        let load_cmd = tpm2::commands::Load {
            parent_handle: srk_handle,
            in_private: create_rsp.out_private,
            in_public: create_rsp.out_public,
        };
        let load_rsp = execute_with_password_sessions(&mut sim, &load_cmd, 1, srk_auth).unwrap();

        // Start HMAC session for unseal
        let mut sess = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        sess.attributes = TpmaSession::CONTINUE_SESSION;

        // Verify unseal works when client uses stripped auth "p@ssw0rd"
        let unseal_cmd = Unseal {
            item_handle: load_rsp.object_handle,
        };
        let unseal_res = execute_with_hmac_sessions(
            &mut sim,
            &unseal_cmd,
            &[],
            &mut [sess.clone()],
            &[b"p@ssw0rd"],
        );
        assert!(unseal_res.is_ok());
        let unseal_rsp = unseal_res.unwrap();
        assert_eq!(unseal_rsp.out_data.get_buffer(), data);

        flush_context(&mut sim, sess.session_handle).unwrap();
        flush_context(&mut sim, load_rsp.object_handle).unwrap();
    }

    // Case C: Sealing with maximum size auth value (64 bytes)
    {
        let data = b"max_auth_secrets";
        let auth = [0xAAu8; 48];

        // Create
        let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(&auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        });
        let in_public = tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha384),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        });
        let create_cmd = Create {
            parent_handle: srk_handle,
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let create_rsp =
            execute_with_password_sessions(&mut sim, &create_cmd, 1, srk_auth).unwrap();

        // Load
        let load_cmd = tpm2::commands::Load {
            parent_handle: srk_handle,
            in_private: create_rsp.out_private,
            in_public: create_rsp.out_public,
        };
        let load_rsp = execute_with_password_sessions(&mut sim, &load_cmd, 1, srk_auth).unwrap();

        // Unseal
        let unseal_cmd = Unseal {
            item_handle: load_rsp.object_handle,
        };
        let unseal_rsp = execute_with_password_sessions(&mut sim, &unseal_cmd, 1, &auth).unwrap();
        assert_eq!(unseal_rsp.out_data.get_buffer(), data);

        flush_context(&mut sim, load_rsp.object_handle).unwrap();
    }

    flush_context(&mut sim, srk_handle).unwrap();
}

/// Sealing an empty payload fails (ATTRIBUTES + P2), a 128-byte payload round-trips, 129 bytes cannot be built
#[test]
fn seal_unseal_payload_size_bounds() {
    let mut sim = Tpm::new();
    let srk_template = get_rsa_srk_template();
    let srk_auth = b"mySRK";
    let (srk_handle, _) = create_srk_with_template(&mut sim, &srk_template, srk_auth);

    // Case A: Sealing empty payload (0 bytes)
    {
        let data = b"";
        let auth = b"pwd";

        let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        });
        let in_public = tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        });
        let create_cmd = Create {
            parent_handle: srk_handle,
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        // C CreateChecks (Object_spt.c:343-346): with sensitiveDataOrigin CLEAR
        // the caller must provide data, so an empty sealed payload is rejected
        // with TPM_RCS_ATTRIBUTES + RC_Create_inPublic (ATTRIBUTES+P2, 0x2C2).
        let res = execute_with_password_sessions(&mut sim, &create_cmd, 1, srk_auth);
        assert_eq!(res.err(), Some(0x2c2));
    }

    // Case B: Sealing maximum size payload (128 bytes for TPM2_MAX_SYM_DATA)
    {
        let data = [0xFFu8; tpm2::TPM2_MAX_SYM_DATA as usize];
        let auth = b"pwd";

        let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(&data).unwrap(),
        });
        let in_public = tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        });
        let create_cmd = Create {
            parent_handle: srk_handle,
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let create_rsp =
            execute_with_password_sessions(&mut sim, &create_cmd, 1, srk_auth).unwrap();

        // Load
        let load_cmd = tpm2::commands::Load {
            parent_handle: srk_handle,
            in_private: create_rsp.out_private,
            in_public: create_rsp.out_public,
        };
        let load_rsp = execute_with_password_sessions(&mut sim, &load_cmd, 1, srk_auth).unwrap();

        // Unseal
        let unseal_cmd = Unseal {
            item_handle: load_rsp.object_handle,
        };
        let unseal_rsp = execute_with_password_sessions(&mut sim, &unseal_cmd, 1, auth).unwrap();
        assert_eq!(unseal_rsp.out_data.get_buffer(), data);

        flush_context(&mut sim, load_rsp.object_handle).unwrap();
    }

    // Case C: Sealing payload that exceeds maximum size (129 bytes) -> must fail during creation of Tpm2bSensitiveData
    {
        let data = [0x55u8; tpm2::TPM2_MAX_SYM_DATA as usize + 1];
        let res = Tpm2bSensitiveData::from_bytes(&data);
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(err, tpm2::errors::UnmarshalError::SIZE);
    }

    flush_context(&mut sim, srk_handle).unwrap();
}
