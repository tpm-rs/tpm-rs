//! TPM2_Load validation: parent handle type, parent attributes and inPrivate size.

use crate::_common::{load_with_name as load, try_create_owner_primary as create_primary, *};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{CreateLoaded, Load};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

// Adversarial test: loading a primary object via Load command with a hierarchy parent (should fail)
/// Load with a hierarchy as parentHandle fails with TPM_RC_VALUE + H1.
#[test]
#[allow(deprecated)]
fn load_with_hierarchy_parent_rejected() {
    let mut sim = Tpm::new();

    // Create the SRK (Primary Object) via CreateLoaded with RHOwner
    let mut srk_pub = get_ecc_srk_template();
    srk_pub.object_attributes = TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::RESTRICTED
        | TpmaObject::DECRYPT;
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let create_srk_rsp = execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
    let srk_handle = create_srk_rsp.object_handle;

    // Try to load the private area using Load command, passing Handle::RH_OWNER as parent.
    // This should fail because parent cannot be a hierarchy handle for Load command.
    let load_cmd = Load {
        parent_handle: Handle::RH_OWNER,
        in_private: create_srk_rsp.out_private,
        in_public: create_srk_rsp.out_public,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]);

    // We expect this to fail with TPM_RC_VALUE on handle 1 because parentHandle is TPMI_DH_OBJECT (cannot be a hierarchy handle).
    assert_eq!(
        res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(1)).get()
    );

    flush_context(&mut sim, srk_handle).unwrap();
}

/// Load of a SHA-1 named object with a malformed 3-byte inPrivate fails with TPM_RC_SIZE on inPrivate.
///
/// `TPM2_Load` of a SHA-1 named object with a malformed 3-byte `inPrivate`
/// fails with `TPM_RC_SIZE` on `inPrivate`.
#[test]
fn sha1_object_malformed_private_size_error() {
    let mut sim = Tpm::new();

    let parent = create_srk(&mut sim);

    // Key public area with name algorithm SHA1
    let target_public = rsa_public(
        TpmiAlgHash::Sha1,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        &[],
        None,
    );

    let res = load(
        &mut sim,
        parent,
        Tpm2bPrivate::from_bytes(&[1, 2, 3]).unwrap(),
        Tpm2b(target_public),
    );
    // SHA-1 is an implemented nameAlg in the C reference, so the public area is accepted; the
    // malformed 3-byte inPrivate then fails in UnwrapOuter's TPM2B_DIGEST_Unmarshal (size 0x0102
    // exceeds the digest buffer -> TPM_RC_SIZE), reported as RC_Load_inPrivate (P1).
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(1)).get())
    );
}

/// Load under a parent that is not a restricted decryption key fails with TPM_RC_TYPE on the parent.
///
/// `TPM2_Load` under a parent that is not a restricted decryption key fails
/// with `TPM_RC_TYPE` on the parent handle.
#[test]
fn unrestricted_parent_rejected() {
    let mut sim = Tpm::new();

    // 1. A parent key that is NOT restricted (decrypt only)
    let (parent, _) = create_primary(
        &mut sim,
        rsa_public(
            TpmiAlgHash::Sha256,
            TpmaObject::DECRYPT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::FIXED_PARENT
                | TpmaObject::FIXED_TPM,
            &[],
            None,
        ),
    )
    .expect("CreatePrimary failed");

    // 2. Target key public area
    let target_public = rsa_public(
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        &[],
        None,
    );

    // 3. Call Load under this parent -> should fail with Type on the parent handle
    let res = load(
        &mut sim,
        parent,
        Tpm2bPrivate::from_bytes(&[1, 2, 3]).unwrap(),
        Tpm2b(target_public),
    );
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(1)).get()));
}
