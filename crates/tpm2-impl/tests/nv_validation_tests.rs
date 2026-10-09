use common::marshal_to_slice;

use tpm2::Unmarshal;
extern crate alloc;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{
    Command, NVCertify, NVCertifyHandles, NVDefineSpace, NVDefineSpaceHandles, NVIncrement,
    NVIncrementHandles, NVRead, NVReadHandles, NVReadLock, NVReadLockHandles, NVReadPublic,
    NVReadPublicHandles, NVUndefineSpace, NVUndefineSpaceHandles, NVWrite, NVWriteHandles,
    NVWriteLock, NVWriteLockHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bMaxNvBuffer, TpmaNv, TpmaSession, TpmiAlgHash,
    TpmsAuthCommand, TpmsNvPublic,
};
use tpm2::{Marshal, TpmNt};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

use tpm2::crypto::{Asymmetric, AsymmetricSign};

use tpm2::crypto::{CryptoError, CryptoProvider};

use tpm2::crypto::Rng;

struct StressTestCrypto;

impl_fake_hash!(StressTestCrypto);

impl AsymmetricSign for StressTestCrypto {
    fn sign_inner(
        &self,
        sign_alg: tpm2::Alg,
        _private_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = match sign_alg {
            tpm2::Alg::ECDSA => {
                if signature_out.len() < 64 {
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..64].fill(0xee);
                64
            }
            _ => {
                if signature_out.len() < 256 {
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..256].fill(0xee);
                256
            }
        };
        Ok(len)
    }
}

impl Asymmetric for StressTestCrypto {
    fn verify_inner(
        &self,
        _sign_alg: tpm2::Alg,
        _public_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }
    fn encrypt(
        &self,
        _scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        _public_key: &[u8],
        _data: &[u8],
        _ciphertext: &mut [u8],
        _label: &[u8],
    ) -> Result<usize, CryptoError> {
        Ok(0)
    }
    fn decrypt(
        &self,
        _scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        _label: &[u8],
    ) -> Result<usize, CryptoError> {
        if private_key.is_empty() {
            return Err(CryptoError::HardwareFailure);
        }
        let len = ciphertext.len();
        if plaintext.len() < len {
            return Err(CryptoError::BufferTooSmall);
        }
        plaintext[..len].copy_from_slice(ciphertext);
        Ok(len)
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
            _ => Err(CryptoError::HardwareFailure),
        }
    }
}

impl Rng for StressTestCrypto {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        dest.fill(0xaa);
        Ok(())
    }
}

impl CryptoProvider for StressTestCrypto {}

fn setup_tpm<'a>(
    crypto: &'a mut StressTestCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
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
    let startup_request = hex!("8001 0000000c 00000144 0000");
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
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    // Tag
    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    // Command code
    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

    // Marshal auth area if tag is 0x8002
    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4; // place holder for auth size
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

    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;

    // Fill in total Size
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    let params_offset = if resp_tag == 0x8002 {
        14 // Skip header (10) and parameter size (4)
    } else {
        10 // Skip header (10)
    };

    let mut unmarshal_buf: &'static [u8] =
        std::vec::Vec::leak(response_buf[params_offset..resp_size].to_vec());
    let resp =
        <C::Response<'static>>::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    Ok(resp)
}

fn execute_tpm_nv_certify<'a>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &NVCertifyHandles,
    cmd: &NVCertify,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 16384],
) -> Result<<NVCertify<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(NVCertify::CMD_CODE.code()).to_be_bytes());
    offset += marshal_to_slice(handles, &mut request_buf[offset..]);

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

    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    let params_offset = if resp_tag == 0x8002 { 14 } else { 10 };
    let mut unmarshal_buf: &'static [u8] =
        std::vec::Vec::leak(response_buf[params_offset..resp_size].to_vec());
    Unmarshal::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())
}

fn make_auth_session(hmac: &[u8]) -> TpmsAuthCommand<'_> {
    TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(hmac).unwrap(),
    }
}

// 1. Validate that writing to Counter/Bits/Extend indexes fails with TPM_RC_ATTRIBUTES.
#[test]
fn test_write_to_counter_bits_extend_fails() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    // A. Define Counter index (NT=0x1, data_size=8)
    let nv_index_counter = Handle(0x01000001);
    let mut attributes = TpmaNv::from(TpmNt::Counter);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_counter = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: nv_index_counter,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 8,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: public_counter,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Counter NV space");

    // Write to Counter index (should fail with TPM_RC_ATTRIBUTES)
    let write_handles = NVWriteHandles {
        auth_handle: nv_index_counter,
        nv_index: nv_index_counter,
    };
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
        offset: 0,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles,
        &write_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res.err(), Some(TpmRc::ATTRIBUTES.get()));

    // B. Define Bits index (NT=0x2, data_size=8)
    let nv_index_bits = Handle(0x01000002);
    let mut attributes_bits = TpmaNv::from(TpmNt::Bits);
    attributes_bits.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_bits = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: nv_index_bits,
        name_alg: TpmiAlgHash::Sha256,
        attributes: attributes_bits,
        auth_policy: Tpm2bDigest::default(),
        data_size: 8,
    });
    let define_cmd_bits = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: public_bits,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd_bits,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Bits NV space");

    // Write to Bits index (should fail with TPM_RC_ATTRIBUTES)
    let write_handles_bits = NVWriteHandles {
        auth_handle: nv_index_bits,
        nv_index: nv_index_bits,
    };
    let res_bits = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles_bits,
        &write_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res_bits.err(), Some(TpmRc::ATTRIBUTES.get()));

    // C. Define Extend index (NT=0x4, data_size=32)
    let nv_index_extend = Handle(0x01000003);
    let mut attributes_extend = TpmaNv::from(TpmNt::Extend);
    attributes_extend.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_extend = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: nv_index_extend,
        name_alg: TpmiAlgHash::Sha256,
        attributes: attributes_extend,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    });
    let define_cmd_extend = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: public_extend,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd_extend,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Extend NV space");

    // Write to Extend index (should fail with TPM_RC_ATTRIBUTES)
    let write_handles_extend = NVWriteHandles {
        auth_handle: nv_index_extend,
        nv_index: nv_index_extend,
    };
    let write_cmd_extend = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0u8; 32]).unwrap(),
        offset: 0,
    };
    let res_extend = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles_extend,
        &write_cmd_extend,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res_extend.err(), Some(TpmRc::ATTRIBUTES.get()));
}

// 2. Validate that writing partial sizes to a WRITEALL NV index fails with TPM_RC_NV_RANGE.
#[test]
fn test_write_partial_to_writeall_index_fails() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    let nv_index = Handle(0x01000004);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes
        .insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::WRITEALL | TpmaNv::PLATFORMCREATE);
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define WRITEALL Ordinary NV space");

    // Write partial size (16 bytes instead of 32 bytes)
    let write_handles = NVWriteHandles {
        auth_handle: nv_index,
        nv_index,
    };
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[1u8; 16]).unwrap(),
        offset: 0,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles,
        &write_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res.err(), Some(TpmRc::NV_RANGE.get()));

    // Write complete size (32 bytes) should succeed
    let write_cmd_full = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[1u8; 32]).unwrap(),
        offset: 0,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles,
        &write_cmd_full,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to write full size to WRITEALL index");
}

// 3. Validate that certifying an unwritten NV index fails with TPM_RC_NV_UNINITIALIZED.
#[test]
fn test_certify_unwritten_index_fails() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    let nv_index = Handle(0x01000005);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 16,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Ordinary NV space");

    // Certify the NV index (unwritten)
    let certify_handles = NVCertifyHandles {
        sign_handle: Handle(0x40000007),
        auth_handle: nv_index,
        nv_index,
    };
    let certify_cmd = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 16,
        offset: 0,
    };

    let mut response_buf = [0u8; 16384];
    let res = execute_tpm_nv_certify(
        &mut tpm,
        &mut global_state,
        &certify_handles,
        &certify_cmd,
        // One session per authorization handle, incl. the TPM_RH_NULL signHandle.
        &[auth_session, auth_session],
        &mut response_buf,
    );
    assert_eq!(res.err(), Some(TpmRc::NV_UNINITIALIZED.get()));
}

// 4. Validate that writing data successfully sets the WRITTEN attribute and subsequent certifies succeed.
#[test]
fn test_written_attribute_and_certify_success() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    let nv_index = Handle(0x01000006);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 16,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Ordinary NV space");

    // Check that WRITTEN is NOT set originally
    let read_pub_handles = NVReadPublicHandles { nv_index };
    let read_pub_cmd = NVReadPublic {};
    let read_pub_resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_pub_handles,
        &read_pub_cmd,
        &[],
    )
    .expect("Failed to read public info of unwritten index");
    let initial_pub = read_pub_resp.nv_public.0;
    assert!(!initial_pub.attributes.contains(TpmaNv::WRITTEN));

    // Write data to the NV index
    let write_handles = NVWriteHandles {
        auth_handle: nv_index,
        nv_index,
    };
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xaau8; 16]).unwrap(),
        offset: 0,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles,
        &write_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to write data to NV index");

    // Check that WRITTEN is now set
    let read_pub_resp_after = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_pub_handles,
        &read_pub_cmd,
        &[],
    )
    .expect("Failed to read public info of written index");
    let after_pub = read_pub_resp_after.nv_public.0;
    assert!(after_pub.attributes.contains(TpmaNv::WRITTEN));

    // Certify the NV index should now succeed
    let certify_handles = NVCertifyHandles {
        sign_handle: Handle(0x40000007),
        auth_handle: nv_index,
        nv_index,
    };
    let certify_cmd = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 16,
        offset: 0,
    };

    let mut response_buf = [0u8; 16384];
    let certify_resp = execute_tpm_nv_certify(
        &mut tpm,
        &mut global_state,
        &certify_handles,
        &certify_cmd,
        // One session per authorization handle, incl. the TPM_RH_NULL signHandle.
        &[auth_session, auth_session],
        &mut response_buf,
    )
    .expect("NV Certify failed after writing data");

    // Verify certified info contains our data
    let attest = certify_resp.certify_info.0;
    if let tpm2::TpmuAttest::Nv(ref nv_cert_info) = attest.attested {
        assert_eq!(nv_cert_info.offset, 0);
        assert_eq!(nv_cert_info.nv_contents.get_size(), 16);
        assert_eq!(nv_cert_info.nv_contents.get_buffer(), &[0xaau8; 16]);
    } else {
        panic!("Expected Nv attest type");
    }
}

#[test]
fn test_nv_read_success_and_errors() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    // 1. Define Ordinary NV index
    let nv_index = Handle(0x01000007);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 16,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Ordinary NV space");

    // 2. Try to read unwritten index (should fail with NvUninitialized)
    let read_handles = NVReadHandles {
        auth_handle: nv_index,
        nv_index,
    };
    let read_cmd = NVRead {
        size: 16,
        offset: 0,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res.err(), Some(TpmRc::NV_UNINITIALIZED.get()));

    // 3. Write data
    let write_handles = NVWriteHandles {
        auth_handle: nv_index,
        nv_index,
    };
    let write_data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&write_data).unwrap(),
        offset: 0,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles,
        &write_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to write data");

    // 4. Read data and verify
    let read_resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to read NV index");
    assert_eq!(read_resp.data.get_size(), 16);
    assert_eq!(read_resp.data.get_buffer(), &write_data);

    // 5. Try reading out of bounds (should fail with NvRange)
    let read_cmd_oob = NVRead {
        size: 8,
        offset: 10,
    };
    let res_oob = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd_oob,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res_oob.err(), Some(TpmRc::NV_RANGE.get()));
}

#[test]
fn test_nv_increment_success_and_errors() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    // 1. Define Counter index
    let nv_counter = Handle(0x01000008);
    let mut attributes = TpmaNv::from(TpmNt::Counter);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: nv_counter,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 8,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Counter NV space");

    // 2. Call NV_Increment (first time, starts at 0, should become 1)
    let inc_handles = NVIncrementHandles {
        auth_handle: nv_counter,
        nv_index: nv_counter,
    };
    let inc_cmd = NVIncrement {};
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &inc_handles,
        &inc_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to increment counter");

    // Read counter using NV_Read and verify it is 1
    let read_handles = NVReadHandles {
        auth_handle: nv_counter,
        nv_index: nv_counter,
    };
    let read_cmd = NVRead { size: 8, offset: 0 };
    let read_resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to read counter");
    let val = u64::from_be_bytes(read_resp.data.get_buffer().try_into().unwrap());
    assert_eq!(val, 1);

    // 3. Call NV_Increment again (should become 2)
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &inc_handles,
        &inc_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to increment counter again");

    let read_resp2 = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to read counter again");
    let val2 = u64::from_be_bytes(read_resp2.data.get_buffer().try_into().unwrap());
    assert_eq!(val2, 2);

    // 4. Try to increment an Ordinary index (should fail with Attributes)
    let nv_ordinary = Handle(0x01000009);
    let mut ordinary_attributes = TpmaNv::from(TpmNt::Ordinary);
    ordinary_attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let ordinary_public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: nv_ordinary,
        name_alg: TpmiAlgHash::Sha256,
        attributes: ordinary_attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 16,
    });
    let define_ordinary_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: ordinary_public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_ordinary_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Ordinary NV space");

    let inc_handles_ord = NVIncrementHandles {
        auth_handle: nv_ordinary,
        nv_index: nv_ordinary,
    };
    let res_ord = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &inc_handles_ord,
        &inc_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(
        res_ord.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(2)).get())
    );
}

#[test]
fn test_nv_write_lock() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    // 1. Define Ordinary NV index with WRITEDEFINE attribute
    let nv_index = Handle(0x0100000a);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes.insert(
        TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::WRITEDEFINE | TpmaNv::PLATFORMCREATE,
    );
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 16,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Ordinary NV space");

    // Write data initially
    let write_handles = NVWriteHandles {
        auth_handle: nv_index,
        nv_index,
    };
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[1u8; 16]).unwrap(),
        offset: 0,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles,
        &write_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to write data");

    // 2. Call NV_WriteLock
    let lock_handles = NVWriteLockHandles {
        auth_handle: nv_index,
        nv_index,
    };
    let lock_cmd = NVWriteLock {};
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &lock_handles,
        &lock_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to write lock NV index");

    // 3. Verify subsequent writes fail with NvLocked
    let res_write = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles,
        &write_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res_write.err(), Some(TpmRc::NV_LOCKED.get()));

    // 4. Verify locking an index without WRITEDEFINE or WRITE_STCLEAR fails with Attributes
    let nv_no_lock = Handle(0x0100000b);
    let mut ordinary_attributes = TpmaNv::from(TpmNt::Ordinary);
    ordinary_attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_no_lock = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: nv_no_lock,
        name_alg: TpmiAlgHash::Sha256,
        attributes: ordinary_attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 16,
    });
    let define_no_lock_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: public_no_lock,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_no_lock_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Ordinary NV space");

    let lock_handles_no_lock = NVWriteLockHandles {
        auth_handle: nv_no_lock,
        nv_index: nv_no_lock,
    };
    let res_no_lock = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &lock_handles_no_lock,
        &lock_cmd,
        core::slice::from_ref(&auth_session),
    );
    // TPM_RC_ATTRIBUTES + RC_NV_WriteLock_nvIndex (H2).
    assert_eq!(
        res_no_lock.err(),
        Some(
            TpmRc::ATTRIBUTES
                .with(tpm2::errors::Position::handle(2))
                .get()
        )
    );
}

#[test]
fn test_nv_read_lock() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    // 1. Define Ordinary NV index with READ_STCLEAR attribute
    let nv_index = Handle(0x0100000c);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes.insert(
        TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::READ_STCLEAR | TpmaNv::PLATFORMCREATE,
    );
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 16,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Ordinary NV space");

    // Write data initially
    let write_handles = NVWriteHandles {
        auth_handle: nv_index,
        nv_index,
    };
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[1u8; 16]).unwrap(),
        offset: 0,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles,
        &write_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to write data");

    // Read initially (should succeed)
    let read_handles = NVReadHandles {
        auth_handle: nv_index,
        nv_index,
    };
    let read_cmd = NVRead {
        size: 16,
        offset: 0,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to read NV index initially");

    // 2. Call NV_ReadLock
    let lock_handles = NVReadLockHandles {
        auth_handle: nv_index,
        nv_index,
    };
    let lock_cmd = NVReadLock {};
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &lock_handles,
        &lock_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to read lock NV index");

    // 3. Verify subsequent reads fail with NvLocked
    let res_read = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res_read.err(), Some(TpmRc::NV_LOCKED.get()));
}

#[test]
fn test_nv_undefine_space() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    // 1. Try to undefine a non-existent index (should fail with Handle)
    let non_existent_index = Handle(0x01000007);
    let undef_handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: non_existent_index,
    };
    let undef_cmd = NVUndefineSpace {};
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &undef_handles,
        &undef_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::HANDLE.with(Position::handle(2)).get())
    );

    // 2. Define an Owner-created index
    let owner_index = Handle(0x01000008);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE); // No PLATFORMCREATE
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: owner_index,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 16,
    });
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Owner-created space");

    // 3. Define a Platform-created index
    let platform_index = Handle(0x01000009);
    let mut attributes_plat = TpmaNv::from(TpmNt::Ordinary);
    attributes_plat.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info_plat = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: platform_index,
        name_alg: TpmiAlgHash::Sha256,
        attributes: attributes_plat,
        auth_policy: Tpm2bDigest::default(),
        data_size: 16,
    });

    let define_handles_plat = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd_plat = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: public_info_plat,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles_plat,
        &define_cmd_plat,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Platform-created space");

    // 4. Define an index with POLICY_DELETE set
    let policy_del_index = Handle(0x0100000a);
    let mut attributes_del = TpmaNv::from(TpmNt::Ordinary);
    attributes_del.insert(
        TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE | TpmaNv::POLICY_DELETE,
    );
    let public_info_del = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: policy_del_index,
        name_alg: TpmiAlgHash::Sha256,
        attributes: attributes_del,
        auth_policy: Tpm2bDigest::default(),
        data_size: 16,
    });

    let define_cmd_del = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: public_info_del,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles_plat, // platform auth
        &define_cmd_del,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define POLICY_DELETE space");

    // 5. Undefine Platform-created index under Owner Auth (should fail with NvAuthorization)
    let undef_plat_by_owner_handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: platform_index,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &undef_plat_by_owner_handles,
        &undef_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res.err(), Some(TpmRc::NV_AUTHORIZATION.get()));

    // 6. Undefine Owner-created index under Owner Auth -> Success
    let undef_owner_by_owner_handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: owner_index,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &undef_owner_by_owner_handles,
        &undef_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to undefine Owner-created index under Owner Auth");

    // Re-define Owner-created index for further testing
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to re-define Owner-created space");

    // 7. Undefine Owner-created index under Platform Auth when sh_enable is true -> Success
    let undef_owner_by_plat_handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: owner_index,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &undef_owner_by_plat_handles,
        &undef_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to undefine Owner-created index under Platform Auth when sh_enable is true");

    // Re-define Owner-created index for further testing
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to re-define Owner-created space");

    // Disable storage hierarchy (sh_enable = false)
    global_state.sh_enable = false;

    // 8. Undefine Owner-created index under Platform Auth when sh_enable is false -> should fail with Handle (visibility check fails)
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &undef_owner_by_plat_handles,
        &undef_cmd,
        core::slice::from_ref(&auth_session),
    );
    // C `NvIndexIsAccessible`: TPM_RC_HANDLE + RC_H2 for nvIndex.
    assert_eq!(
        res.err(),
        Some(TpmRc::HANDLE.with(tpm2::errors::Position::handle(2)).get())
    );

    // Re-enable storage hierarchy
    global_state.sh_enable = true;

    // 9. Undefine Platform-created index under Platform Auth -> Success
    let undef_plat_by_plat_handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: platform_index,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &undef_plat_by_plat_handles,
        &undef_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to undefine Platform-created index under Platform Auth");

    // 10. Undefine index with POLICY_DELETE set under Platform Auth -> should fail with Attributes
    let undef_del_by_plat_handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: policy_del_index,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &undef_del_by_plat_handles,
        &undef_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(2)).get())
    );
}
