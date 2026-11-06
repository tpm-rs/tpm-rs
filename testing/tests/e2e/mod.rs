//! End-to-end tests of the full TPM stack, one file per command or feature
//! area. Every test talks to a `testing::tpm::Tpm` (an in-process `tpm-rs`
//! simulator, mirrored to the TCG C reference TPM with the `differential`
//! feature) through its command interface only; shared helpers live in the
//! `testing` library (`testing::_common`).

#![forbid(unsafe_code)]
#![allow(dead_code)]

use testing::{_common, test_utils};

mod act_capability;
mod act_countdown;
mod act_set_timeout;
mod activate_credential;
mod activate_credential_secret;
mod algorithm_self_tests;
mod attestation_key_validation;
mod attestation_orderly_state;
mod attestation_privacy;
mod auth_role;
mod authorization_area;
mod camellia;
mod certify;
mod certify_creation;
mod change_pps_eps;
mod clear;
mod clock;
mod cmac;
mod command_audit;
mod command_dispatch;
mod command_wire_format;
mod commit;
mod context_load_blob_validation;
mod context_load_foreign_contents;
mod context_save_load_object;
mod context_save_load_session;
mod context_save_validation;
mod create_auth_size_order;
mod create_loaded_authorization;
mod create_loaded_derivation;
mod create_loaded_validation;
mod create_null_hierarchy_parent;
mod create_object_slots;
mod create_primary_keys;
mod create_primary_validation;
mod create_public_unmarshal_order;
mod create_validation;
mod dictionary_attack;
mod digest_size_limit;
mod drtm;
mod duplicate;
mod duplicate_import_round_trip;
#[cfg(feature = "cc-ec-ephemeral")]
mod ec_ephemeral;
mod ecc_command_availability;
mod ecc_curve_domain_parameters;
mod ecc_curve_ecdh;
mod ecc_curve_ecdsa;
mod ecc_curve_keys;
#[cfg(any(feature = "cc-ecc-encrypt", feature = "cc-ecc-decrypt"))]
mod ecc_encrypt_decrypt;
mod ecc_key_binding;
mod ecc_parameters;
#[cfg(feature = "bn_p638")]
mod ecdaa_bn_p638;
mod ecdh;
mod ecschnorr_signature;
mod ek_templates;
#[cfg(all(
    feature = "mlkem",
    any(feature = "cc-encapsulate", feature = "cc-decapsulate")
))]
mod encapsulate_decapsulate;
mod encrypt_decrypt;
mod encrypt_decrypt_modes;
mod event_digest_banks;
mod event_sequence;
mod evict_control_authorization;
mod evict_control_public_only;
mod evict_control_validation;
mod flush_context;
mod get_capability;
mod get_session_audit_digest;
mod get_time;
mod handle_validation;
mod hash;
mod hash_sequence_digest;
mod hash_sequence_validation;
mod hierarchy_change_auth;
mod hierarchy_control;
mod hmac;
mod import_check_order;
mod import_validation;
mod limited_hierarchies;
mod load_external_ecc_private_only;
mod load_external_hierarchy;
mod load_external_key_usage;
mod load_external_name;
mod load_external_public_only;
mod load_external_public_validation;
mod load_external_sensitive;
mod load_external_sensitive_validation;
mod load_validation;
mod make_credential;
#[cfg(feature = "mldsa")]
mod mldsa_attestation;
#[cfg(feature = "mldsa")]
mod mldsa_keys;
#[cfg(feature = "mldsa")]
mod mldsa_policy_signed;
mod mldsa_signing_commands;
#[cfg(feature = "mlkem")]
mod mlkem_keys;
#[cfg(feature = "mlkem")]
mod mlkem_storage_parent;
mod no_sessions_commands;
mod ntc2_vendor_commands;
mod nv_authorization;
mod nv_availability;
mod nv_capacity;
mod nv_certify;
mod nv_change_auth;
mod nv_define_space;
mod nv_define_space2;
mod nv_extend_set_bits;
mod nv_increment;
mod nv_index_accessibility;
mod nv_lock;
mod nv_read_public;
mod nv_read_public2;
mod nv_read_write;
mod nv_undefine_space;
mod object_change_auth;
mod parameter_decryption;
mod parameter_encryption;
mod parameter_encryption_decryption;
mod parameter_encryption_validation;
mod password_auth;
mod pcr_allocate;
mod pcr_auth;
mod pcr_banks;
mod pcr_event;
mod pcr_extend;
mod pcr_handle_bounds;
mod pcr_locality;
mod pcr_read;
mod pcr_reset;
mod persistent_handle_resolution;
mod persistent_object_handles;
mod platform_signals;
#[cfg(feature = "cc-policy-ac-send-select")]
mod policy_ac_send_select;
mod policy_authorize;
mod policy_authorize_message_digest_tickets;
mod policy_authorize_nv;
#[cfg(feature = "cc-policy-capability")]
mod policy_capability;
mod policy_command_availability;
mod policy_command_code;
mod policy_counter_timer;
mod policy_cp_hash;
mod policy_duplication_select;
mod policy_locality;
mod policy_name_hash_template;
mod policy_nv;
mod policy_or;
#[cfg(feature = "cc-policy-parameters")]
mod policy_parameters;
mod policy_password;
mod policy_pcr;
#[cfg(feature = "cc-policy-physical-presence")]
mod policy_physical_presence;
mod policy_secret;
mod policy_session_authorization;
mod policy_session_state;
mod policy_signed;
mod policy_transport_spdm;
#[cfg(feature = "cc-pp-commands")]
mod pp_commands;
mod pqc_availability;
mod privacy_admin_handle;
mod profile_limits;
mod public_only_object_auth;
mod quote;
mod random;
mod read_only_control;
mod reserved_bits;
mod reset_determinism;
mod rewrap;
mod rsa_decrypt_ciphertext;
mod rsa_encrypt_decrypt;
mod rsa_large_keys;
mod rsa_prime_range;
mod rsa_sensitive_crt_form;
mod seal_unseal;
mod secure_channel_capabilities;
mod self_test_commands;
mod sensitive_area_encoding;
mod sequence_hmac;
mod sequence_object_as_key;
mod sequence_object_handles;
mod session_attribute_validation;
mod session_audit_digest;
mod session_audit_exclusive;
mod session_binding;
mod session_capacity;
mod session_handle_validation;
mod session_hmac;
mod session_lifecycle;
mod session_response_hmac;
#[cfg(feature = "cc-set-algorithm-set")]
mod set_algorithm_set;
mod set_command_code_audit_status;
mod set_primary_policy;
mod shutdown;
mod sign;
mod sign_digest;
mod sign_sequence;
mod signing_command_availability;
mod sm2_signature;
mod start_auth_session;
mod start_auth_session_salt;
mod start_auth_session_tpm_key;
mod start_auth_session_validation;
mod startup;
mod testparms_ecc;
mod testparms_keyed_hash;
mod testparms_rsa;
mod testparms_symcipher;
mod testparms_validation;
mod ticket_tag_unmarshal;
mod tickets;
mod transient_handle_numbering;
mod transient_object_capacity;
mod unmarshal_error_positions;
mod vendor_command_capabilities;
mod vendor_permanent_auth;
mod vendor_tcg_test;
mod verify_digest_signature;
mod verify_sequence;
mod verify_signature;
mod wrapped_digest_size_limit;
#[cfg(all(feature = "cc-zgen-2phase", feature = "cc-ec-ephemeral"))]
mod zgen_2phase;
