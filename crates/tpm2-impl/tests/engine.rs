use tpm2::Unmarshal;
use tpm2::errors::TpmRc;
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

#[test]
#[cfg_attr(
    feature = "reference-rng",
    ignore = "checks the default random sources; `reference-rng` draws from the reference DRBG"
)]
fn get_random_in_place() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.init_storage();

    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(&startup_request[..], &mut startup_response[..]);

    let request = hex!(
        "8001" // tag
        "0000000c" // size
        "0000017B" // command code
        "000c" // requested random bytes
    );
    let expected_response = &hex!(
        "8001" // session
        "00000018" // size
        "00000000" // successful response
        "000c"     // 2B size prefix
        // Random bytes after 384 FakeRng draws at manufacture (EPS, SPS, PPS, phProof,
        // shProof, ehProof; 64 bytes each) and 256 at Startup (null_proof, null_seed,
        // drbg_state instantiation, plus the 64-byte commit nonce drawn at TPM Reset, as in C
        // TPM_Reset -> CryptStartup/commitNonce); FakeRng's u8 counter is then at 0x81.
        "8182838485868788898a8b8c"
    );

    let mut response = request.to_vec();
    response.resize(256, 0xFF);
    let size = tpm.execute_command_in_place(response.as_mut_slice(), request.len());
    assert_eq!(&response[..size], expected_response);
}

#[test]
fn test_find_empty_transient_slot_primary_vs_child_and_fallback_reuse() {
    let mut state = tpm2_impl::GlobalState::default();
    // 1. When empty, both primary and child allocations assign sequential slots starting at index 0
    let (slot0, handle0) = state.find_empty_transient_slot(true).unwrap();
    assert_eq!(slot0, 0);
    assert_eq!(handle0, 0x80000000);

    // 2. Fill all MAX_LOADED_OBJECTS slots to test capacity behavior when transient RAM is exhausted
    let mut tpmt_public_buf = [0u8; 1024];
    tpmt_public_buf[0] = 0x00;
    tpmt_public_buf[1] = 0x08; // KeyedHash
    tpmt_public_buf[2] = 0x00;
    tpmt_public_buf[3] = 0x0B; // Sha256
    tpmt_public_buf[10] = 0x00;
    tpmt_public_buf[11] = 0x10; // Null scheme

    for (i, slot) in state.transient_objects.iter_mut().enumerate() {
        *slot = Some(TransientObject {
            handle: 0x80000000 | (i as u32),
            seed: [0u8; 64],
            seed_len: 32,
            external: false,
            public_only: false,
            name: (tpm2::Tpm2bName::default()).into(),
            auth: (tpm2::Tpm2bAuth::default()).into(),
            public: (tpm2::TpmtPublic::unmarshal(&mut (&tpmt_public_buf[..])).unwrap()).into(),
            private: [0u8; 1536],
            private_len: 0,
            qualified_name: (tpm2::Tpm2bName::default()).into(),
            hierarchy: 0x40000001,
            st_clear: false,
        });
    }

    // 3. Creating a Primary Key when RAM is full MUST return ObjectMemory (0x902) to preserve strict limits
    let primary_err = state.find_empty_transient_slot(true);
    assert_eq!(primary_err, Err(TpmRc::OBJECT_MEMORY));

    // 4. Creating a non-primary child key when RAM is full also returns ObjectMemory
    let child_err = state.find_empty_transient_slot(false);
    assert_eq!(child_err, Err(TpmRc::OBJECT_MEMORY));
}

#[test]
#[cfg_attr(
    feature = "reference-rng",
    ignore = "checks the default random sources; `reference-rng` draws from the reference DRBG"
)]
fn test_drbg_state_persistence_and_reseed_across_shutdown_startup() {
    use tpm2::platform::storage::NvStorage;

    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.init_storage();
    tpm.state.g_nv_ok = true;

    // 1. Initial Startup (SU_CLEAR) instantiates a fresh DRBG state with magic = DRBG_MAGIC
    let startup_clear = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // TPM2_Startup
        "0000" // TPM_SU_CLEAR
    );
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&startup_clear[..], &mut resp[..]);

    assert_eq!(tpm.state.drbg_state.magic, tpm2_impl::DRBG_MAGIC);
    assert_eq!(tpm.state.drbg_state.reseed_counter, 1);
    let seed_after_boot = tpm.state.drbg_state.seed;

    // 2. Orderly Shutdown (SU_STATE) persists the DRBG state to NV storage (offset 36..112)
    let shutdown_state = hex!(
        "8001" // tag
        "0000000c" // size
        "00000145" // TPM2_Shutdown
        "0001" // TPM_SU_STATE
    );
    tpm.execute_command_separate(&shutdown_state[..], &mut resp[..]);

    let mut nv_drbg_buf = [0u8; 76];
    tpm.platform.storage.read_nv(36, &mut nv_drbg_buf).unwrap();
    let persisted_drbg = tpm2_impl::DrbgState::from_bytes(&nv_drbg_buf);
    assert_eq!(persisted_drbg.magic, tpm2_impl::DRBG_MAGIC);
    assert_eq!(persisted_drbg.seed, seed_after_boot);

    // 3. Orderly Startup (SU_STATE) restores the DRBG state from NV and reseeds it (XORing fresh entropy)
    // Simulate _TPM_Init before issuing TPM2_Startup
    tpm.state.initialized = false;
    let startup_state = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // TPM2_Startup
        "0001" // TPM_SU_STATE
    );
    tpm.execute_command_separate(&startup_state[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    assert_eq!(tpm.state.drbg_state.magic, tpm2_impl::DRBG_MAGIC);
    assert_eq!(tpm.state.drbg_state.reseed_counter, 1);
    assert_ne!(
        tpm.state.drbg_state.seed, seed_after_boot,
        "Orderly startup must reseed the saved DRBG seed with fresh entropy"
    );
}

#[test]
fn test_platform_construction_with_generic_rng() {
    use tpm2_impl::storage::ram_storage_mock::RamStorageMock;
    use tpm2_impl::timer::SoftwareTimer;

    let mut crypto = FakeCrypto;
    let mut storage = RamStorageMock::<128>::new();
    let mut timer = SoftwareTimer { tick: 0 };
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let tpm = TpmEngine::new(platform).unwrap();

    // Before manufacture there are no Primary Seeds.
    assert_eq!(tpm.state.sp_seed_size, 0);
    assert_eq!(tpm.state.ep_seed_size, 0);
    assert_eq!(tpm.state.pp_seed_size, 0);
}

/// Manufacture (`init_storage`) draws the three Primary Seeds and the three hierarchy proofs as
/// independent 64-byte values from the platform RNG, in the reference order (EPS, SPS, PPS,
/// phProof, shProof, ehProof), and they survive `_TPM_Init` (`reset`) through NV.
#[test]
#[cfg_attr(
    feature = "reference-rng",
    ignore = "checks the default random sources; `reference-rng` draws from the reference DRBG"
)]
fn manufacture_draws_independent_seeds_and_proofs() {
    let mut crypto = common::TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = common::FakeRng::new();
    let mut tpm = common::setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    // FakeRng yields 1, 2, 3, ... (mod 256): each value is the next 64 bytes of the stream.
    let expected = |k: usize| -> [u8; 64] { core::array::from_fn(|i| (1 + 64 * k + i) as u8) };
    assert_eq!(tpm.state.ep_seed, expected(0));
    assert_eq!(tpm.state.sp_seed, expected(1));
    assert_eq!(tpm.state.pp_seed, expected(2));
    assert_eq!(tpm.state.ph_proof, expected(3));
    assert_eq!(tpm.state.sh_proof, expected(4));
    assert_eq!(tpm.state.eh_proof, expected(5));
    for size in [
        tpm.state.ep_seed_size,
        tpm.state.sp_seed_size,
        tpm.state.pp_seed_size,
        tpm.state.ph_proof_size,
        tpm.state.sh_proof_size,
        tpm.state.eh_proof_size,
    ] {
        assert_eq!(size, 64);
    }

    // `_TPM_Init` reloads them from NV unchanged.
    let (ep, sp, pp) = (tpm.state.ep_seed, tpm.state.sp_seed, tpm.state.pp_seed);
    let (ph, sh, eh) = (tpm.state.ph_proof, tpm.state.sh_proof, tpm.state.eh_proof);
    tpm.reset();
    assert_eq!(
        (tpm.state.ep_seed, tpm.state.sp_seed, tpm.state.pp_seed),
        (ep, sp, pp)
    );
    assert_eq!(
        (tpm.state.ph_proof, tpm.state.sh_proof, tpm.state.eh_proof),
        (ph, sh, eh)
    );
}
