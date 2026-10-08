#![forbid(unsafe_code)]
#![allow(dead_code)]

pub mod test_utils;

#[cfg(test)]
mod adv_activate_credential;
#[cfg(test)]
mod adv_certify;
#[cfg(test)]
mod adv_commit;
#[cfg(test)]
mod adv_commit_auth;
#[cfg(test)]
mod adv_commit_decrypt_attr;
#[cfg(test)]
mod adv_commit_ecc_no_sign;
#[cfg(test)]
mod adv_commit_no_user_with_auth;
#[cfg(test)]
mod adv_commit_rsa;
#[cfg(test)]
mod adv_commit_s2_empty_y2_not_empty;
#[cfg(test)]
mod adv_commit_s2_size_spec;
#[cfg(test)]
mod adv_commit_trailing_valid;
#[cfg(test)]
mod adv_commit_y2_without_p1_spec;
#[cfg(test)]
mod adv_commit_zero;
#[cfg(test)]
mod adv_context_save_hierarchy;
#[cfg(test)]
mod adv_context_save_kdfa;
#[cfg(test)]
mod adv_context_save_keystream;
#[cfg(test)]
mod adv_create_loaded;
#[cfg(test)]
mod adv_create_loaded_auth;
#[cfg(test)]
mod adv_create_loaded_auth_spec;
#[cfg(test)]
mod adv_create_loaded_data_size;
#[cfg(test)]
mod adv_create_loaded_decrypt_attr;
#[cfg(test)]
mod adv_create_loaded_invalid_permanent;
#[cfg(test)]
mod adv_create_loaded_no_user_with_auth;
#[cfg(test)]
mod adv_create_loaded_oob;
#[cfg(test)]
mod adv_create_loaded_rh_null;
#[cfg(test)]
mod adv_create_loaded_trailing_public;
#[cfg(test)]
mod adv_create_loaded_trailing_sensitive;
#[cfg(test)]
mod adv_create_loaded_zero_auth;
#[cfg(test)]
mod adv_create_loaded_zero_sessions_bypass;
#[cfg(test)]
mod adv_create_primary;
#[cfg(test)]
mod adv_crypt_ops_tests;
#[cfg(test)]
mod adv_evict_control;
#[cfg(test)]
mod adv_evict_control2;
#[cfg(test)]
mod adv_evict_control_auth_missing;
#[cfg(test)]
mod adv_evict_control_auth_precedence;
#[cfg(test)]
mod adv_evict_control_bug_check;
#[cfg(test)]
mod adv_evict_control_bugs;
#[cfg(test)]
mod adv_evict_control_challenge_create_loaded;
#[cfg(test)]
mod adv_evict_control_challenge_sessions;
#[cfg(test)]
mod adv_evict_control_critic;
#[cfg(test)]
mod adv_evict_control_critic_test2;
#[cfg(test)]
mod adv_evict_control_endorsement;
#[cfg(test)]
mod adv_evict_control_owner_evict_platform;
#[cfg(test)]
mod adv_evict_control_stress;
#[cfg(test)]
mod adv_evict_control_stress2;
#[cfg(test)]
mod adv_handle_lifecycle_compliance;
#[cfg(test)]
mod adv_load_external;
#[cfg(test)]
mod adv_nv_storage;
#[cfg(test)]
mod adv_param_crypt_stress;
#[cfg(test)]
mod adv_start_auth_session;
#[cfg(test)]
mod adv_ticket_matrix;
#[cfg(test)]
mod auth_size_stress;
#[cfg(test)]
mod bounds_test;
#[cfg(test)]
mod challenger_m1_tests;
#[cfg(test)]
mod challenger_m2_verification;
#[cfg(test)]
mod challenger_m3_verification;
#[cfg(test)]
mod challenger_milestone2_tests;
#[cfg(test)]
mod challenger_milestone3_verification_tests;
#[cfg(test)]
mod challenger_nv_certify_tests;
#[cfg(test)]
mod challenger_param_crypt_stress;
#[cfg(test)]
mod challenger_sealing_stress;
#[cfg(test)]
mod challenger_session_decrypt_stress;
#[cfg(test)]
mod challenger_stress_tests;
#[cfg(test)]
mod combined_context_corrupt;
#[cfg(test)]
mod combined_context_flush_first;
#[cfg(test)]
mod combined_context_invalid_handle;
#[cfg(test)]
mod combined_context_stress;
#[cfg(test)]
mod context_stress;
#[cfg(test)]
mod get_time_stress;
#[cfg(test)]
mod go;
#[cfg(test)]
mod load_external_tests;
#[cfg(test)]
mod milestone2_stress;
#[cfg(test)]
mod orderly_stress;
#[cfg(test)]
mod session_e2e_tests;
#[cfg(test)]
mod stress_combined_context;
#[cfg(test)]
mod stress_hierarchy_change_auth;
#[cfg(test)]
mod test_layout;
#[cfg(test)]
mod test_tpmt;

#[cfg(test)]
mod adv_clear_custom;
#[cfg(test)]
mod adv_ek_custom;
#[cfg(test)]
mod adv_get_time_custom;
#[cfg(test)]
mod adv_hash_sequence_hash_custom;
#[cfg(test)]
mod adv_import_custom;
#[cfg(test)]
mod adv_names_custom;
#[cfg(test)]
mod adv_object_change_auth_custom;
#[cfg(test)]
mod adv_pcr_custom;
#[cfg(test)]
mod adv_policy_custom;
#[cfg(test)]
mod adv_sign_custom;

// Non-Go-parity tests moved out of src/go.
#[cfg(test)]
mod combined_context_extra;
#[cfg(test)]
mod commit_extra;
#[cfg(test)]
mod create_loaded_extra;
#[cfg(test)]
mod ek_extra;
#[cfg(test)]
mod evict_control_extra;
#[cfg(test)]
mod hash_sequence_hash_extra;
