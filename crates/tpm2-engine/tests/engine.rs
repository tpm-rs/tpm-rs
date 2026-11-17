use tpm2::Unmarshal;
use tpm2::errors::TpmRc;
mod common;

use common::FakePlatform;
use common::{FakeCrypto, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_engine::TpmEngine;
use tpm2_engine::handler::TransientObject;

#[test]
fn get_random_in_place() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let platform = FakePlatform::new(&mut crypto, &mut timer);

    let mut tpm = TpmEngine::new(platform, &mut storage).unwrap();
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
    // Random bytes of the TPM's DRBG (FakeCrypto's FakeRng) after the draws at manufacture (the
    // commit nonce of `CryptStartup()`, the largest digest size: 64 bytes with SHA-512, 48
    // without; then EPS, SPS, PPS, phProof, shProof, ehProof, 64 bytes each) and at the TPM
    // Reset of Startup (the commit nonce, nullProof and nullSeed, as in the reference's
    // `CryptStartup()` and `HierarchyStartup()`).
    let drawn = 2 * tpm2::TpmiAlgHash::MAX_DIGEST_BYTES + 384 + 128;
    let mut expected_response = hex!(
        "8001" // session
        "00000018" // size
        "00000000" // successful response
        "000c"     // 2B size prefix
    )
    .to_vec();
    expected_response.extend((0..12).map(|i| ((drawn + 1 + i) % 256) as u8));

    let mut response = request.to_vec();
    response.resize(256, 0xFF);
    let size = tpm.execute_command_in_place(response.as_mut_slice(), request.len());
    assert_eq!(&response[..size], &expected_response[..]);
}

#[test]
fn test_find_empty_transient_slot_primary_vs_child_and_fallback_reuse() {
    let mut state = common::TestState::default();
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
            private: [0u8; tpm2_engine::handler::MAX_PRIVATE_KEY_SIZE],
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

std::thread_local! {
    /// The calls of the [`StatefulRng`] lifecycle hooks of this thread, in order.
    static STATEFUL_RNG_CALLS: std::cell::RefCell<Vec<&'static str>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// A TPM random number generator with persistent state ([`tpm2::crypto::Rng::STATE_SIZE`] =
/// [`tpm2_engine::DRBG_STATE_SIZE`]): its output is a byte counter, its state the counter and
/// whether it is instantiated (as `DrbgState::reseed_counter` and `DrbgState::magic`). A startup
/// instantiates it (counter 1) or reseeds it (counter + 100).
#[derive(Default)]
struct StatefulRng {
    counter: u64,
    instantiated: bool,
}

impl tpm2::crypto::Rng for StatefulRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), tpm2::crypto::CryptoError> {
        for b in dest {
            *b = self.counter as u8;
            self.counter += 1;
        }
        Ok(())
    }

    fn stir_bytes(&mut self, _data: &[u8]) -> Result<(), tpm2::crypto::CryptoError> {
        Ok(())
    }

    fn startup(&mut self) -> Result<(), tpm2::crypto::CryptoError> {
        STATEFUL_RNG_CALLS.with_borrow_mut(|calls| calls.push("startup"));
        if self.instantiated {
            self.counter += 100;
        } else {
            (self.counter, self.instantiated) = (1, true);
        }
        Ok(())
    }

    const STATE_SIZE: usize = tpm2_engine::DRBG_STATE_SIZE;

    fn save_state(&self, out: &mut [u8]) -> Result<(), tpm2::crypto::CryptoError> {
        STATEFUL_RNG_CALLS.with_borrow_mut(|calls| calls.push("save_state"));
        let state = tpm2_engine::DrbgState {
            reseed_counter: self.counter,
            magic: if self.instantiated {
                tpm2_engine::DRBG_MAGIC
            } else {
                0
            },
            ..Default::default()
        };
        out.copy_from_slice(&state.to_bytes());
        Ok(())
    }

    fn load_state(&mut self, state: &[u8]) -> Result<(), tpm2::crypto::CryptoError> {
        STATEFUL_RNG_CALLS.with_borrow_mut(|calls| calls.push("load_state"));
        let state = tpm2_engine::DrbgState::from_bytes(state.try_into().unwrap());
        self.counter = state.reseed_counter;
        self.instantiated = state.magic == tpm2_engine::DRBG_MAGIC;
        Ok(())
    }
}

/// The fake crypto backend with a [`StatefulRng`].
struct StatefulRngCrypto;

impl_fake_crypto!(common, StatefulRngCrypto, StatefulRng);

/// The state of the TPM's DRBG is kept in NV like the reference's `go.drbgState`: written at
/// manufacture and `TPM2_Shutdown` (not at `TPM2_Startup`), reloaded at `_TPM_Init` (so values
/// drawn since the last write are drawn again after a power cycle), and reseeded or instantiated
/// by `TPM2_Startup`.
#[test]
fn test_drbg_state_persistence_and_reseed_across_shutdown_startup() {
    use tpm2::crypto::Rng;
    use tpm2::platform::storage::NvStorage;

    let mut crypto = StatefulRngCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let platform = FakePlatform::new(&mut crypto, &mut timer);

    let mut tpm = TpmEngine::new(platform, &mut storage).unwrap();
    STATEFUL_RNG_CALLS.with_borrow_mut(Vec::clear);
    tpm.init_storage();
    tpm.state.g_nv_ok = true;
    // Manufacture instantiates the DRBG (from an all-zero state), draws the commit nonce and the
    // hierarchy secrets, and writes the state to NV.
    assert_eq!(
        STATEFUL_RNG_CALLS.with_borrow_mut(std::mem::take),
        ["load_state", "startup", "save_state"]
    );
    let manufactured = 1 + tpm2::TpmiAlgHash::MAX_DIGEST_BYTES as u64 + 384;
    type Engine<'a> =
        TpmEngine<FakePlatform<'a, StatefulRngCrypto, &'a mut FakeStorage, FakeTimer>>;
    let nv_state = |tpm: &Engine<'_>| {
        let mut buf = [0u8; tpm2_engine::DRBG_STATE_SIZE];
        tpm.state.nv.index.read_nv(36, &mut buf).unwrap();
        tpm2_engine::DrbgState::from_bytes(&buf)
    };
    assert_eq!(nv_state(&tpm).reseed_counter, manufactured);
    assert_eq!(nv_state(&tpm).magic, tpm2_engine::DRBG_MAGIC);
    assert_eq!(tpm.state.nv.orderly.drbg_state, nv_state(&tpm));

    // `_TPM_Init` reloads the state; TPM2_Startup reseeds it without writing it to NV.
    tpm.reset();
    let startup_clear = hex!("80010000000c000001440000");
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&startup_clear[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    assert_eq!(
        STATEFUL_RNG_CALLS.with_borrow_mut(std::mem::take),
        ["load_state", "startup"]
    );
    assert_eq!(nv_state(&tpm).reseed_counter, manufactured);

    // An orderly shutdown writes the state to NV.
    let shutdown_state = hex!("80010000000c000001450001");
    tpm.execute_command_separate(&shutdown_state[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    let mut saved = [0u8; tpm2_engine::DRBG_STATE_SIZE];
    tpm.crypto_rng.save_state(&mut saved).unwrap();
    assert_eq!(nv_state(&tpm), tpm2_engine::DrbgState::from_bytes(&saved));

    // Values drawn after the write are drawn again after a power cycle.
    let get_random = hex!("80010000000c0000017b0008");
    tpm.execute_command_separate(&get_random[..], &mut resp[..]);
    let first = resp[12..20].to_vec();
    tpm.reset();
    let mut reloaded = [0u8; tpm2_engine::DRBG_STATE_SIZE];
    tpm.crypto_rng.save_state(&mut reloaded).unwrap();
    assert_eq!(reloaded, saved);
    let mut again = [0u8; 8];
    tpm.crypto_rng.fill_bytes(&mut again).unwrap();
    assert_eq!(&again[..], &first[..]);
}

#[test]
fn test_platform_construction_before_manufacture() {
    use tpm2_engine::storage::ram_storage_mock::RamStorageMock;
    use tpm2_engine::timer::SoftwareTimer;

    let mut crypto = FakeCrypto;
    let mut storage = RamStorageMock::<128>::new();
    let mut timer = SoftwareTimer { tick: 0 };
    let platform = FakePlatform::new(&mut crypto, &mut timer);
    let tpm = TpmEngine::new(platform, &mut storage).unwrap();

    // Before manufacture there are no Primary Seeds.
    assert_eq!(tpm.state.nv.persistent.sp_seed_size, 0);
    assert_eq!(tpm.state.nv.persistent.ep_seed_size, 0);
    assert_eq!(tpm.state.nv.persistent.pp_seed_size, 0);
}

/// Manufacture (`init_storage`) draws the three Primary Seeds and the three hierarchy proofs as
/// independent 64-byte values from the TPM's DRBG, in the reference order (EPS, SPS, PPS,
/// phProof, shProof, ehProof), and they survive `_TPM_Init` (`reset`) through NV.
#[test]
fn manufacture_draws_independent_seeds_and_proofs() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let platform = FakePlatform::new(&mut crypto, &mut timer);
    let mut tpm = TpmEngine::new(platform, &mut storage).unwrap();
    tpm.init_storage();

    // The TPM's DRBG (FakeCrypto's FakeRng) yields 1, 2, 3, ... (mod 256): after the commit
    // nonce (the largest digest size), each value is the next 64 bytes of the stream.
    let nonce = tpm2::TpmiAlgHash::MAX_DIGEST_BYTES;
    let expected =
        |k: usize| -> [u8; 64] { core::array::from_fn(|i| (1 + nonce + 64 * k + i) as u8) };
    assert_eq!(tpm.state.nv.persistent.ep_seed, expected(0));
    assert_eq!(tpm.state.nv.persistent.sp_seed, expected(1));
    assert_eq!(tpm.state.nv.persistent.pp_seed, expected(2));
    assert_eq!(tpm.state.nv.persistent.ph_proof, expected(3));
    assert_eq!(tpm.state.nv.persistent.sh_proof, expected(4));
    assert_eq!(tpm.state.nv.persistent.eh_proof, expected(5));
    for size in [
        tpm.state.nv.persistent.ep_seed_size,
        tpm.state.nv.persistent.sp_seed_size,
        tpm.state.nv.persistent.pp_seed_size,
        tpm.state.nv.persistent.ph_proof_size,
        tpm.state.nv.persistent.sh_proof_size,
        tpm.state.nv.persistent.eh_proof_size,
    ] {
        assert_eq!(size, 64);
    }

    // `_TPM_Init` reloads them from NV unchanged.
    let (ep, sp, pp) = (
        tpm.state.nv.persistent.ep_seed,
        tpm.state.nv.persistent.sp_seed,
        tpm.state.nv.persistent.pp_seed,
    );
    let (ph, sh, eh) = (
        tpm.state.nv.persistent.ph_proof,
        tpm.state.nv.persistent.sh_proof,
        tpm.state.nv.persistent.eh_proof,
    );
    tpm.reset();
    assert_eq!(
        (
            tpm.state.nv.persistent.ep_seed,
            tpm.state.nv.persistent.sp_seed,
            tpm.state.nv.persistent.pp_seed
        ),
        (ep, sp, pp)
    );
    assert_eq!(
        (
            tpm.state.nv.persistent.ph_proof,
            tpm.state.nv.persistent.sh_proof,
            tpm.state.nv.persistent.eh_proof
        ),
        (ph, sh, eh)
    );
}
