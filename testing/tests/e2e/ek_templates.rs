//! Endorsement key (EK) templates: policy digests and primary creation for RSA and ECC EKs.

use crate::_common::{ecc_ek_template, rsa_ek_template, test_ek_policy_with_template};

/// ECC EK template policy digest and primary creation.
#[test]
fn ecc_ek_policy_digest_and_creation() {
    test_ek_policy_with_template(ecc_ek_template());
}

/// RSA EK template policy digest and primary creation.
#[test]
fn rsa_ek_policy_digest_and_creation() {
    test_ek_policy_with_template(rsa_ek_template());
}
