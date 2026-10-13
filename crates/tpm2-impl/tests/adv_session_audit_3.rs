use common::marshal_to_slice;

extern crate alloc;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{Command, FlushContext};
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::crypto::{CryptoError, CryptoProvider};
use tpm2::{Handle, Marshal};
use tpm2::{TpmiAlgHash, TpmsAuthCommand};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::SessionState;

struct StressTestCrypto;

impl_fake_hash!(StressTestCrypto);

impl AsymmetricSign for StressTestCrypto {
    /// Fills the signature with `0xee` bytes (64 for ECDSA, 256 otherwise). A `signature_out`
    /// that is too small fails with [`CryptoError::Internal`] (formerly `BufferTooSmall`).
    fn sign_inner(
        &self,
        sign_alg: tpm2::Alg,
        _private_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let len = match sign_alg {
            tpm2::Alg::ECDSA => {
                if signature_out.len() < 64 {
                    return Err(CryptoError::Internal);
                }
                signature_out[..64].fill(0xee);
                64
            }
            _ => {
                if signature_out.len() < 256 {
                    return Err(CryptoError::Internal);
                }
                signature_out[..256].fill(0xee);
                256
            }
        };
        Ok(Some(len))
    }
}

impl Asymmetric for StressTestCrypto {
    /// Accepts every signature (formerly `Ok(())`).
    fn verify_inner(
        &self,
        _sign_alg: tpm2::Alg,
        _public_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        _signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Ok(true)
    }
    fn encrypt(
        &self,
        _scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        _public_key: &[u8],
        _data: &[u8],
        _ciphertext: &mut [u8],
        _label: &[u8],
    ) -> Result<Option<usize>, CryptoError> {
        Ok(Some(0))
    }
    /// Copies `ciphertext` to `plaintext`. An empty private key fails with
    /// [`CryptoError::Internal`] (formerly `HardwareFailure`), and so does a `plaintext` buffer
    /// that is too small (formerly `BufferTooSmall`).
    fn decrypt(
        &self,
        _scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        _label: &[u8],
    ) -> Result<Option<usize>, CryptoError> {
        if private_key.is_empty() {
            return Err(CryptoError::Internal);
        }
        let len = ciphertext.len();
        if plaintext.len() < len {
            return Err(CryptoError::Internal);
        }
        plaintext[..len].copy_from_slice(ciphertext);
        Ok(Some(len))
    }
    fn generate_key(
        &self,
        scheme: tpm2::Alg,
        _params: Option<tpm2::crypto::asymmetric::KeyParams>,
        public_key: &mut [u8],
        private_key: &mut [u8],
        _seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        match scheme {
            tpm2::Alg::RSA => {
                public_key[..256].fill(0xcc);
                private_key[..256].fill(0xdd);
                Ok((256, 256))
            }
            tpm2::Alg::ECC => {
                public_key[..64].fill(0xcc);
                private_key[..32].fill(0xdd);
                Ok((64, 32))
            }
            _ => Err(CryptoError::Internal),
        }
    }
}

impl CryptoProvider for StressTestCrypto {
    /// The provider CSPRNG: fills `dest` with `0xaa` bytes.
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        dest.fill(0xaa);
        Ok(())
    }
}

fn setup_tpm<'a>(
    crypto: &'a mut StressTestCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a mut FakeRng,
) -> (
    TpmEngine<'a, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    // Startup
    let startup_request = hex_literal::hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command_with_auths<C: Command>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    for handle in cmd.handles().as_ref() {
        let mut handle_buf = [0u8; Handle::MAX_SIZE];
        let handle_len = handle.marshal(&mut handle_buf);
        request_buf[offset..offset + handle_len].copy_from_slice(&handle_buf[..handle_len]);
        offset += handle_len;
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = (offset - auth_start) as u32;
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);

    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    Ok(())
}

// 4. Flushing the exclusive audit session via FlushContext must clear global exclusive session state.
#[test]
fn test_flush_exclusive_audit_session_clears_exclusivity() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    let session_handle = 0x02000001;

    let s = SessionState {
        session_handle,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0xab; 64]),
        audit_digest_len: 32,
        audit_cp_hash: [0u8; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0u8; 64],
        policy_digest_len: 0,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(s).unwrap();
    global_state.exclusive_audit_session = Some(session_handle);

    let flush_cmd = FlushContext {
        flush_handle: Handle(session_handle),
    };

    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &flush_cmd, &[])
        .expect("Flush failed");

    assert_eq!(
        global_state.exclusive_audit_session, None,
        "Exclusivity state should be cleared after flushing the session."
    );
}
