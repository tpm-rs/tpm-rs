use common::marshal_to_slice;

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use tpm2::Handle;
use tpm2::commands::HierarchyChangeAuth;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

#[test]
fn test_no_direct_nv_write() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    storage.fail_on_write = true; // MUST NOT write to NV directly
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.init_storage();
    tpm.state.nv_available = true;
    tpm.state.initialized = true;
    tpm.state.locality = 0;

    tpm.state.platform_auth = tpm2::Tpm2bAuth::from_bytes(&[1, 2, 3]).unwrap().into();

    let request_auth = tpm2::TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: tpm2::TpmaSession(1),
        hmac: tpm2::Tpm2bAuth::from_bytes(&[1, 2, 3]).unwrap(),
    };
    let request_cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_PLATFORM,
        new_auth: tpm2::Tpm2bAuth::from_bytes(&[4, 5, 6]).unwrap(),
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(0x129u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&request_cmd.auth_handle, &mut req_buf[offset..]);
    let auth_len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    let auth_start = offset;
    offset += marshal_to_slice(&request_auth, &mut req_buf[offset..]);
    let auth_len = (offset - auth_start) as u32;
    offset += marshal_to_slice(&request_cmd, &mut req_buf[offset..]);
    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    req_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());

    let mut response = [0u8; 1024];
    let _ = tpm.execute_command_separate(&req_buf[..offset], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(rc, 0); // Success
}

// Stress tests below
extern crate alloc;

struct CountingStorage {
    data: alloc::vec::Vec<u8>,
    writes: usize,
}

impl tpm2_impl::storage::NvStorage for CountingStorage {
    fn capacity(&self) -> usize {
        self.data.len()
    }
    fn read_nv(
        &self,
        offset: usize,
        buffer: &mut [u8],
    ) -> Result<usize, tpm2_impl::storage::StorageError> {
        let end = core::cmp::min(offset + buffer.len(), self.data.len());
        let len = end - offset;
        buffer[..len].copy_from_slice(&self.data[offset..end]);
        Ok(len)
    }
    fn write_nv(
        &mut self,
        offset: usize,
        buffer: &[u8],
    ) -> Result<usize, tpm2_impl::storage::StorageError> {
        self.writes += 1;
        if offset + buffer.len() > self.data.len() {
            self.data.resize(offset + buffer.len(), 0);
        }
        self.data[offset..offset + buffer.len()].copy_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> Result<(), tpm2_impl::storage::StorageError> {
        Ok(())
    }
}

#[test]
#[cfg_attr(
    feature = "reference-rng",
    ignore = "checks the default random sources; `reference-rng` draws from the reference DRBG"
)]
fn test_no_nv_writes_stress() {
    let mut crypto = FakeCrypto;
    let mut storage = CountingStorage {
        data: alloc::vec![0; 4096],
        writes: 0,
    };
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.init_storage();
    tpm.state.nv_available = true;
    tpm.state.initialized = true;
    tpm.state.locality = 0;

    tpm.state.owner_auth = tpm2::Tpm2bAuth::from_bytes(&[1, 2, 3]).unwrap().into();

    let request_auth = tpm2::TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: tpm2::TpmaSession(1),
        hmac: tpm2::Tpm2bAuth::from_bytes(&[1, 2, 3]).unwrap(),
    };
    let request_cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: tpm2::Tpm2bAuth::from_bytes(&[4, 5, 6]).unwrap(),
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(0x129u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&request_cmd.auth_handle, &mut req_buf[offset..]);
    let auth_len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    let auth_start = offset;
    offset += marshal_to_slice(&request_auth, &mut req_buf[offset..]);
    let auth_len = (offset - auth_start) as u32;
    offset += marshal_to_slice(&request_cmd, &mut req_buf[offset..]);
    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    req_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());

    let mut response = [0u8; 1024];
    let _ = tpm.execute_command_separate(&req_buf[..offset], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(rc, 0);
    assert_eq!(storage.writes, 66);
}
