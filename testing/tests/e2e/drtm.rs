//! Dynamic root of trust measurement (_TPM_Hash_Start/Data/End) and its effect on the DRTM PCRs.

use crate::_common::{
    PW_AREA, hash_data, hash_end, hash_start, marshal_to_vec, rc_of, read_pcr_value, restart_count,
    send_raw_at, sha256,
};
use tpm2::commands::PCRExtend;
use tpm2::{TpmCc, TpmiAlgHash, TpmlDigestValues, TpmtHa};
use tpm2_simulator::create_simulator;

/// _TPM_Hash_Start/Data/End resets PCRs 17-22, bumps restartCount and extends PCR 17; a command aborts the sequence.
///
/// A post-Startup DRTM sequence (`_TPM_Hash_Start/Data/End`) resets the
/// dynamic PCRs 17..=22, increments `restartCount` and extends PCR 17 with the
/// digest of the hashed data; any regular command aborts an in-flight
/// sequence, so a later `_TPM_Hash_End` leaves PCR 17 unchanged.
#[test]
fn hash_sequence_resets_dynamic_pcrs() {
    let mut sim = create_simulator!();

    // Pre-populate PCR 18 with non-zero data (extend at locality 3) to verify that
    // PCRResetDynamics resets 17..=22.
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&[0xAA; 32])).unwrap();
    let mut extend = Vec::new();
    extend.extend_from_slice(&0x8002u16.to_be_bytes());
    extend.extend_from_slice(&[0u8; 4]);
    extend.extend_from_slice(&TpmCc::PCRExtend.code().to_be_bytes());
    extend.extend_from_slice(&18u32.to_be_bytes());
    extend.extend_from_slice(&PW_AREA);
    extend.extend_from_slice(&marshal_to_vec(&PCRExtend {
        pcr_handle: tpm2::Handle(18),
        digests,
    }));
    let len = extend.len() as u32;
    extend[2..6].copy_from_slice(&len.to_be_bytes());
    assert_eq!(rc_of(&send_raw_at(&mut sim, 3, &extend)), 0);
    assert_ne!(
        read_pcr_value(&mut sim, TpmiAlgHash::Sha256, 18),
        vec![0u8; 32]
    );
    let initial_restart_count = restart_count(&mut sim);

    // Run a DRTM sequence (_TPM_Hash_Start / _TPM_Hash_Data / _TPM_Hash_End)
    let payload = b"DRTM Measurement Payload";
    hash_start(&mut sim);
    hash_data(&mut sim, payload);
    hash_end(&mut sim);

    // Dynamic PCRs 17..=22 were reset; PCR 18 must be 0x00
    assert_eq!(
        read_pcr_value(&mut sim, TpmiAlgHash::Sha256, 18),
        vec![0u8; 32]
    );
    // restart_count must have incremented
    assert_eq!(restart_count(&mut sim), initial_restart_count + 1);

    // Expected PCR 17 value: Hash(0x00..00 || Hash(payload))
    let expected_pcr17 = sha256(&[&[0u8; 32], &sha256(&[payload])]);
    assert_eq!(
        read_pcr_value(&mut sim, TpmiAlgHash::Sha256, 17),
        expected_pcr17
    );

    // Executing any regular TPM command aborts an in-flight DRTM sequence
    hash_start(&mut sim);
    hash_data(&mut sim, b"interrupted");
    let get_random_req = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b, 0x00, 0x08,
    ];
    assert_eq!(rc_of(&send_raw_at(&mut sim, 0, &get_random_req)), 0);
    // A subsequent _TPM_Hash_End must not modify PCR 17
    hash_end(&mut sim);
    assert_eq!(
        read_pcr_value(&mut sim, TpmiAlgHash::Sha256, 17),
        expected_pcr17
    );
}
