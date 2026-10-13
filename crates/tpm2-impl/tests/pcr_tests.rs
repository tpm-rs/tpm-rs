mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use tpm2::Handle;
use tpm2::TpmiAlgHash;
use tpm2_impl::{TpmEngine, TpmPlatform};

#[test]
fn test_hcrtm_pre_startup_sequence_and_slot_eviction() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.init_storage();
    tpm.state.nv_available = true;
    tpm.state.locality = 0;
    tpm.state.g_nv_ok = true;
    tpm.state.ph_enable = true;

    // Fill all 3 sequence/transient slots before starting H-CRTM sequence
    for (i, slot) in tpm.state.active_sequences.iter_mut().enumerate().take(3) {
        *slot = Some(tpm2_impl::ActiveSequence::new(
            0x8000_0000 | (i as u32),
            tpm2::Tpm2bAuth::default(),
            tpm2_impl::SequenceType::Event,
        ));
    }

    // 1. Pre-startup _TPM_Hash_Start must evict slot 0 (0x80000000) and succeed
    assert!(tpm.hash_start());
    assert_eq!(tpm.state.drtm_handle, 0x80000000);

    // 2. Feed H-CRTM data
    let hcrtm_data = b"H-CRTM Bootloader Measurement";
    assert!(tpm.hash_data(hcrtm_data));

    // 3. Complete H-CRTM before TPM2_Startup
    assert!(tpm.hash_end());
    assert!(tpm.state.drtm_pre_startup);
    assert_eq!(tpm.state.drtm_handle, Handle::RH_UNASSIGNED.0);

    // Expected PCR 0 before and after Startup(CLEAR): Hash(0x00..04 || Hash(hcrtm_data))
    use tpm2_impl::hash_state::StreamingHashState;
    let mut h_payload = StreamingHashState::new(TpmiAlgHash::Sha256);
    h_payload.update(hcrtm_data);
    let (digest, _) = h_payload.finalize();

    let mut initial_pcr0 = [0u8; 32];
    initial_pcr0[31] = 4;
    let mut h_pcr0 = StreamingHashState::new(TpmiAlgHash::Sha256);
    h_pcr0.update(&initial_pcr0);
    h_pcr0.update(&digest[..32]);
    let (expected_pcr0, _) = h_pcr0.finalize();
    assert_eq!(tpm.state.pcrs.sha256[0], expected_pcr0[..32]);

    // 4. Issue TPM2_Startup(CLEAR) and verify PCR 0 is preserved
    let startup_req = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&startup_req, &mut resp);
    assert_eq!(u32::from_be_bytes(resp[6..10].try_into().unwrap()), 0);
    assert_eq!(tpm.state.pcrs.sha256[0], expected_pcr0[..32]);
}
