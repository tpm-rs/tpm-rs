use crate::owned::{OwnedAuthCommand, OwnedDigest};
use crate::storage::manager::StorageManager;
use crate::storage::{NvStorage, Tpm2Storage};
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{
    NVCertify, NVCertifyHandles, NVChangeAuth, NVChangeAuthHandles, NVDefineSpace,
    NVDefineSpaceHandles, NVExtend, NVExtendHandles, NVGlobalWriteLock, NVGlobalWriteLockHandles,
    NVIncrement, NVIncrementHandles, NVRead, NVReadHandles, NVReadLock, NVReadLockHandles,
    NVReadPublic, NVReadPublicHandles, NVSetBits, NVSetBitsHandles, NVUndefineSpace,
    NVUndefineSpaceHandles, NVUndefineSpaceSpecial, NVUndefineSpaceSpecialHandles, NVWrite,
    NVWriteHandles, NVWriteLock, NVWriteLockHandles,
};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmGenerated, TpmNt};
use tpm2::{Marshal, Unmarshal};
use tpm2::{
    Tpm2bAuth, Tpm2bMaxNvBuffer, Tpm2bNvPublic, TpmaNv, TpmsAttest, TpmsNvCertifyInfo,
    TpmsNvDigestCertifyInfo, TpmsNvPinCounterParameters, TpmsNvPublic, TpmuAttest,
};

pub(crate) trait NvHeaderAuth {
    fn marshal_auth(&self, buf: &mut [u8]) -> usize;
}

impl NvHeaderAuth for Tpm2bAuth<'_> {
    fn marshal_auth(&self, buf: &mut [u8]) -> usize {
        self.marshal((&mut buf[..Tpm2bAuth::MAX_SIZE]).try_into().unwrap())
    }
}

impl NvHeaderAuth for crate::owned::OwnedAuth {
    fn marshal_auth(&self, buf: &mut [u8]) -> usize {
        self.as_tpm2b().marshal_auth(buf)
    }
}

pub(crate) trait NvHeaderPub {
    fn marshal_pub(&self, buf: &mut [u8]) -> usize;
}

impl NvHeaderPub for Tpm2bNvPublic<'_> {
    fn marshal_pub(&self, buf: &mut [u8]) -> usize {
        self.marshal((&mut buf[..Tpm2bNvPublic::MAX_SIZE]).try_into().unwrap())
    }
}

impl NvHeaderPub for crate::owned::OwnedNvPublic {
    fn marshal_pub(&self, buf: &mut [u8]) -> usize {
        self.as_tpm2b().marshal_pub(buf)
    }
}

pub(crate) fn marshal_nv_header(
    auth: &impl NvHeaderAuth,
    public_info: &impl NvHeaderPub,
    buf: &mut [u8],
) -> Result<usize, TpmRc> {
    if buf.len() < Tpm2bAuth::MAX_SIZE + Tpm2bNvPublic::MAX_SIZE {
        return Err(TpmRc::FAILURE);
    }
    let mut offset = 0;
    offset += auth.marshal_auth(&mut buf[offset..]);
    offset += public_info.marshal_pub(&mut buf[offset..]);
    Ok(offset)
}

pub(crate) fn unmarshal_nv_header(
    buf: &[u8],
) -> Result<
    (
        usize,
        crate::owned::OwnedNvPublic,
        crate::owned::OwnedAuth,
        crate::owned::OwnedNvPublic,
    ),
    TpmRc,
> {
    let (metadata_size, nv_public, auth, _, _) = unmarshal_nv_header_bytes(buf)?;
    let owned_pub = crate::owned::OwnedNvPublic::from(nv_public);
    let owned_auth = crate::owned::OwnedAuth::from(auth);
    Ok((metadata_size, owned_pub, owned_auth, owned_pub))
}

pub(crate) fn unmarshal_nv_header_bytes<'a>(
    buf: &'a [u8],
) -> Result<
    (
        usize,
        TpmsNvPublic<'a>,
        Tpm2bAuth<'a>,
        Tpm2bNvPublic<'a>,
        &'a [u8],
    ),
    TpmRc,
> {
    let mut slice = buf;
    let auth = Tpm2bAuth::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
    if slice.len() < 2 {
        return Err(TpmRc::FAILURE);
    }
    let pub_len = u16::from_be_bytes([slice[0], slice[1]]) as usize;
    let public_bytes = slice.get(2..2 + pub_len).ok_or(TpmRc::FAILURE)?;
    let public_info = Tpm2bNvPublic::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
    let metadata_size = buf.len() - slice.len();
    let nv_public = public_info.0;
    Ok((metadata_size, nv_public, auth, public_info, public_bytes))
}

/// Size of a buffer large enough to hold the largest serialized NV Index header
/// (`TPM2B_AUTH || TPM2B_NV_PUBLIC`) stored in front of the index data.
const NV_HEADER_BUF_SIZE: usize =
    Tpm2bAuth::<'static>::MAX_SIZE + Tpm2bNvPublic::<'static>::MAX_SIZE;

/// Maximum data size of an NV Index (`MAX_NV_INDEX_SIZE`).
const MAX_NV_INDEX_SIZE: u16 = 2048;

/// Mask of the counter bits that may change without forcing an NV update of an
/// orderly counter (`MAX_ORDERLY_COUNT = (1 << ORDERLY_BITS) - 1`, `ORDERLY_BITS = 8`).
const MAX_ORDERLY_COUNT: u64 = (1 << 8) - 1;

/// The header of a defined NV Index as stored in front of its data.
#[derive(Clone, Copy)]
struct NvIndexHeader {
    /// Size in bytes of the serialized `TPM2B_AUTH || TPM2B_NV_PUBLIC` header, i.e. the
    /// storage offset of the first data byte of the index.
    metadata_size: u16,
    /// The public area of the index (with the current attributes).
    public: crate::owned::OwnedNvPublic,
    /// The authValue of the index.
    auth: crate::owned::OwnedAuth,
}

/// Common validation of an NV write operation (C `NvWriteAccessChecks`).
///
/// Used by `TPM2_NV_Write`, `TPM2_NV_Increment`, `TPM2_NV_Extend`, `TPM2_NV_SetBits`, and
/// `TPM2_NV_WriteLock`. When `auth_handle` is the index itself, the `TPMA_NV_AUTHWRITE` /
/// `TPMA_NV_POLICYWRITE` checks belong to session authorization (see
/// [`CommandHandler::nv_check_index_auth_available`]), so nothing else is checked here.
///
/// # Errors
/// - `TPM_RC_NV_LOCKED` if the index is write locked.
/// - `TPM_RC_NV_AUTHORIZATION` if `TPM_RH_OWNER` / `TPM_RH_PLATFORM` provided authorization and
///   `TPMA_NV_OWNERWRITE` / `TPMA_NV_PPWRITE` is clear, or if `auth_handle` is neither of those
///   nor the index itself.
fn nv_write_access_checks(
    auth_handle: u32,
    nv_index: u32,
    attributes: TpmaNv,
) -> Result<(), TpmRc> {
    if attributes.contains(TpmaNv::WRITELOCKED) {
        return Err(TpmRc::NV_LOCKED);
    }
    let allowed = if auth_handle == Handle::RH_OWNER.0 {
        attributes.contains(TpmaNv::OWNERWRITE)
    } else if auth_handle == Handle::RH_PLATFORM.0 {
        attributes.contains(TpmaNv::PPWRITE)
    } else {
        auth_handle == nv_index
    };
    if !allowed {
        return Err(TpmRc::NV_AUTHORIZATION);
    }
    Ok(())
}

/// Common validation of an NV read operation (C `NvReadAccessChecks`).
///
/// Used by `TPM2_NV_Read`, `TPM2_NV_ReadLock`, and `TPM2_NV_Certify`.
///
/// # Errors
/// - `TPM_RC_NV_LOCKED` if the index is read locked.
/// - `TPM_RC_NV_AUTHORIZATION` if `TPM_RH_OWNER` / `TPM_RH_PLATFORM` provided authorization and
///   `TPMA_NV_OWNERREAD` / `TPMA_NV_PPREAD` is clear, or if `auth_handle` is neither of those
///   nor the index itself.
/// - `TPM_RC_NV_UNINITIALIZED` if the index has not been written. This comes last so that
///   `TPM2_NV_ReadLock` can tell a properly authorized request apart.
fn nv_read_access_checks(auth_handle: u32, nv_index: u32, attributes: TpmaNv) -> Result<(), TpmRc> {
    if attributes.contains(TpmaNv::READLOCKED) {
        return Err(TpmRc::NV_LOCKED);
    }
    let allowed = if auth_handle == Handle::RH_OWNER.0 {
        attributes.contains(TpmaNv::OWNERREAD)
    } else if auth_handle == Handle::RH_PLATFORM.0 {
        attributes.contains(TpmaNv::PPREAD)
    } else {
        auth_handle == nv_index
    };
    if !allowed {
        return Err(TpmRc::NV_AUTHORIZATION);
    }
    if !attributes.contains(TpmaNv::WRITTEN) {
        return Err(TpmRc::NV_UNINITIALIZED);
    }
    Ok(())
}

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Reads and parses the header of the NV Index `nv_index`.
    ///
    /// Returns `missing` if the index is not defined.
    fn nv_read_index_header(
        &mut self,
        nv_index: u32,
        missing: TpmRc,
    ) -> Result<NvIndexHeader, TpmRc> {
        let storage = StorageManager::new(&mut *self.context.platform.storage);
        let metadata = storage.get_metadata(nv_index).map_err(|_| missing)?;
        let read_len = core::cmp::min(metadata.data_size as usize, NV_HEADER_BUF_SIZE);
        let mut read_buf = [0u8; NV_HEADER_BUF_SIZE];
        storage
            .read_item(nv_index, 0, &mut read_buf[..read_len])
            .map_err(|_| TpmRc::FAILURE)?;
        let (metadata_size, public, auth, _) = unmarshal_nv_header(&read_buf[..read_len])?;
        Ok(NvIndexHeader {
            metadata_size: metadata_size as u16,
            public,
            auth,
        })
    }

    /// Rewrites the header of `nv_index` with `attributes` replacing the stored attributes.
    ///
    /// The header size does not change, so the index data is left untouched.
    fn nv_write_index_attributes(
        &mut self,
        nv_index: u32,
        header: &NvIndexHeader,
        attributes: TpmaNv,
    ) -> Result<(), TpmRc> {
        let mut updated_public = header.public;
        updated_public.attributes = attributes;
        let mut write_buf = [0u8; NV_HEADER_BUF_SIZE];
        let len = marshal_nv_header(&header.auth, &updated_public, &mut write_buf)?;
        let mut storage = StorageManager::new(&mut *self.context.platform.storage);
        storage
            .write_item(nv_index, 0, &write_buf[..len])
            .map_err(|_| TpmRc::FAILURE)
    }

    /// Checks that NV Index `nv_index` is accessible (C `NvIndexIsAccessible`): it must be
    /// defined, and its hierarchy (`phEnableNV` for `TPMA_NV_PLATFORMCREATE` indices, `shEnable`
    /// otherwise) must be enabled.
    ///
    /// Returns the index header, or `TPM_RC_HANDLE` at `pos` if the index is not accessible.
    fn nv_accessible_index_header(
        &mut self,
        nv_index: u32,
        pos: Position,
    ) -> Result<NvIndexHeader, TpmRc> {
        let header = self.nv_read_index_header(nv_index, TpmRc::HANDLE.with(pos))?;
        let enabled = if header.public.attributes.contains(TpmaNv::PLATFORMCREATE) {
            self.global_state.ph_enable_nv
        } else {
            self.global_state.sh_enable
        };
        if !enabled {
            return Err(TpmRc::HANDLE.with(pos));
        }
        Ok(header)
    }

    /// Checks that the NV Index authorizing itself with session `session_idx` may be authorized
    /// by that session type (the NV part of C `IsAuthValueAvailable` / `IsAuthPolicyAvailable`,
    /// checked by `CheckAuthSession`).
    ///
    /// - Policy sessions need a non-empty `authPolicy` and `TPMA_NV_POLICYWRITE` (write
    ///   operations) or `TPMA_NV_POLICYREAD` (read operations).
    /// - Password / HMAC sessions need `TPMA_NV_AUTHWRITE` for write operations. For read
    ///   operations they need `TPMA_NV_AUTHREAD`, except for PIN indices, whose availability
    ///   (`pinCount < pinLimit`) is enforced by the engine's session processing.
    ///
    /// Returns `TPM_RC_AUTH_UNAVAILABLE` (a format-zero code, so without a session position)
    /// if the authorization is not available. Does nothing if the session is missing (that
    /// case is reported as `TPM_RC_AUTH_MISSING` by the caller).
    fn nv_check_index_auth_available(
        &mut self,
        session_idx: usize,
        header: &NvIndexHeader,
        write: bool,
    ) -> Result<(), TpmRc> {
        if session_idx >= self.global_state.parsed_auths_len {
            return Ok(());
        }
        let session_handle = self.global_state.parsed_auths[session_idx].session_handle.0;
        let attributes = header.public.attributes;
        let available = if Handle(session_handle).handle_type() == Some(tpm2::TpmHt::PolicySession)
        {
            header.public.auth_policy.get_size() != 0
                && attributes.contains(if write {
                    TpmaNv::POLICYWRITE
                } else {
                    TpmaNv::POLICYREAD
                })
        } else if write {
            attributes.contains(TpmaNv::AUTHWRITE)
        } else if matches!(
            attributes.get_index_type(),
            Ok(TpmNt::PinFail) | Ok(TpmNt::PinPass)
        ) {
            // The authValue of a PIN index is available while `pinCount < pinLimit`. That is
            // checked (and `pinCount` updated) by the engine's session processing before the
            // command runs, so the count can't be re-checked here.
            true
        } else {
            attributes.contains(TpmaNv::AUTHREAD)
        };
        if !available {
            return Err(TpmRc::AUTH_UNAVAILABLE);
        }
        Ok(())
    }

    /// Prepares an update of the data or attributes of the NV Index described by `attributes`
    /// before anything is written, so that a failure leaves NV untouched:
    /// - orderly indices clear the orderly state (C `NvClearOrderly`);
    /// - other indices need NV memory to be available (`NvConditionallyWrite`).
    fn nv_prepare_index_update(&mut self, attributes: TpmaNv) -> Result<(), TpmRc> {
        if attributes.contains(TpmaNv::ORDERLY) {
            self.nv_clear_orderly()
        } else {
            self.return_if_nv_is_not_available()
        }
    }

    /// Writes `data` at `offset` of the data area of `nv_index`, setting `TPMA_NV_WRITTEN` on
    /// the first write (C `NvWriteIndexData`).
    ///
    /// On the first write of an ordinary index with a partial write (`data` smaller than the
    /// index), the whole data area is cleared first so that stale bytes never become readable.
    fn nv_write_index_data(
        &mut self,
        nv_index: u32,
        header: &NvIndexHeader,
        offset: u16,
        data: &[u8],
    ) -> Result<(), TpmRc> {
        let attributes = header.public.attributes;
        self.nv_prepare_index_update(attributes)?;
        if !attributes.contains(TpmaNv::WRITTEN) {
            let mut written = attributes;
            written.insert(TpmaNv::WRITTEN);
            self.nv_write_index_attributes(nv_index, header, written)?;
            if attributes.get_index_type() == Ok(TpmNt::Ordinary)
                && (header.public.data_size as usize) > data.len()
            {
                let zeros = [0u8; MAX_NV_INDEX_SIZE as usize];
                StorageManager::new(&mut *self.context.platform.storage)
                    .write_item(
                        nv_index,
                        header.metadata_size,
                        &zeros[..header.public.data_size as usize],
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
            }
            if attributes.contains(TpmaNv::ORDERLY)
                && attributes.get_index_type() == Ok(TpmNt::Counter)
            {
                self.global_state.update_nv |= crate::engine::UT_ORDERLY;
            }
        }
        StorageManager::new(&mut *self.context.platform.storage)
            .write_item(nv_index, header.metadata_size + offset, data)
            .map_err(|_| TpmRc::FAILURE)?;
        if !attributes.contains(TpmaNv::ORDERLY) {
            self.global_state.update_nv |= crate::engine::UT_NV;
        }
        Ok(())
    }

    /// Reads the 8-byte value of a counter, bit field, or PIN index.
    fn nv_read_u64_data(&mut self, nv_index: u32, header: &NvIndexHeader) -> Result<u64, TpmRc> {
        let mut val_bytes = [0u8; 8];
        StorageManager::new(&mut *self.context.platform.storage)
            .read_item(nv_index, header.metadata_size, &mut val_bytes)
            .map_err(|_| TpmRc::FAILURE)?;
        Ok(u64::from_be_bytes(val_bytes))
    }

    /// Deletes NV Index `nv_index` (C `NvDeleteIndex`), folding the value of a written counter
    /// into the persistent maximum counter value first.
    fn nv_delete_index(&mut self, nv_index: u32, header: &NvIndexHeader) -> Result<(), TpmRc> {
        self.return_if_nv_is_not_available()?;
        let attributes = header.public.attributes;
        let counter_val = if attributes.get_index_type() == Ok(TpmNt::Counter)
            && attributes.contains(TpmaNv::WRITTEN)
        {
            Some(self.nv_read_u64_data(nv_index, header)?)
        } else {
            None
        };
        StorageManager::new(&mut *self.context.platform.storage)
            .undefine_space(nv_index)
            .map_err(|_| TpmRc::FAILURE)?;
        if let Some(val) = counter_val {
            if val > self.global_state.max_counter {
                self.global_state.max_counter = val;
            }
            self.nv_sync_persistent_max_counter()?;
        }
        Ok(())
    }

    /// Handles the [TpmCc::NVDefineSpace] (`0x12a`) command.
    ///
    /// # Description
    /// This command defines an NV Index, allocating storage space in the TPM's Non-Volatile storage
    /// according to the attributes and size specified in the request.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.2 (TPM2_NV_DefineSpace).
    ///
    /// # Relationships
    /// - An NV Index must be defined before any operations like [TpmCc::NVWrite](nv_storage.rs) or [TpmCc::NVRead](nv_storage.rs) can be performed.
    /// - It is removed using [TpmCc::NVUndefineSpace](nv_storage.rs).
    pub fn nv_define_space(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVDefineSpaceHandles>()?;
        let auth_handle = handles.auth_handle;
        let auth_handle_u32 = auth_handle.0;

        if auth_handle_u32 != Handle::RH_OWNER.0 && auth_handle_u32 != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.global_state.parsed_auths[..self.global_state.parsed_auths_len]
            .first()
            .cloned();

        // 1. Verify credentials for TPMI_RH_PROVISION
        if !self.state().in_shadow_execution || provided_auth.is_some() {
            self.validate_nv_define_space_auth(auth_handle_u32, provided_auth)?;
        }

        let cmd = request.try_unmarshal::<NVDefineSpace>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let nv_public_struct = cmd
            .public_info
            .to_struct()
            .map_err(|e| e.in_parameter(2).to_rc())?;

        // 2. Validate index, attributes, and size consistency
        Self::validate_nv_public_attributes(
            &nv_public_struct,
            auth_handle_u32,
            cmd.auth.get_buffer(),
            self.global_state.ph_enable_nv,
        )?;

        // C `NvAdd` (`RETURN_IF_NV_IS_NOT_AVAILABLE`).
        self.return_if_nv_is_not_available()?;

        // C `NvDefineSpace` stores the authValue with trailing zeros removed.
        let auth = Tpm2bAuth::from_bytes(crate::util::strip_trailing_zeros(cmd.auth.get_buffer()))
            .map_err(|_| TpmRc::SIZE.with(Position::parameter(1)))?;

        let mut storage = StorageManager::new(&mut *self.context.platform.storage);

        // 3. Allocate NV Index space and write metadata header
        Self::allocate_nv_space(
            nv_public_struct.nv_index.0,
            &auth,
            &cmd.public_info,
            nv_public_struct.data_size,
            nv_public_struct.attributes.0,
            &mut storage,
        )?;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVUndefineSpace] (`0x122`) command.
    ///
    /// # Description
    /// This command deletes a defined NV Index and frees the allocated storage space in the TPM's Non-Volatile storage.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.3 (TPM2_NV_UndefineSpace).
    ///
    /// # Relationships
    /// - Removes an NV Index created by [TpmCc::NVDefineSpace](nv_storage.rs).
    pub fn nv_undefine_space(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVUndefineSpaceHandles>()?;
        let auth_handle = handles.auth_handle;
        let nv_index = handles.nv_index;

        if auth_handle.0 != Handle::RH_OWNER.0 && auth_handle.0 != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        if Handle(nv_index.0).handle_type() != Some(tpm2::TpmHt::NVIndex) {
            return Err(TpmRc::VALUE.with(Position::handle(2)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVUndefineSpace>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // C `NvIndexIsAccessible` (handle unmarshaling) for `nvIndex`.
        let header = self.nv_accessible_index_header(nv_index.0, Position::handle(2))?;

        // C `CheckAuthNoSession`: a missing authorization is reported before the command
        // action inspects the index.
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }
        let attributes = header.public.attributes;

        if attributes.contains(TpmaNv::POLICY_DELETE) {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }
        if auth_handle.0 == Handle::RH_OWNER.0 && attributes.contains(TpmaNv::PLATFORMCREATE) {
            return Err(TpmRc::NV_AUTHORIZATION);
        }

        self.nv_delete_index(nv_index.0, &header)?;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVUndefineSpaceSpecial] (`0x11f`) command.
    ///
    /// # Description
    /// This command allows removal of a platform-created NV Index or owner-created NV Index that has `TPMA_NV_POLICY_DELETE` SET.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.14 (TPM2_NV_UndefineSpaceSpecial).
    pub fn nv_undefine_space_special(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVUndefineSpaceSpecialHandles>()?;
        let nv_index = handles.nv_index;
        let platform = handles.platform;

        if Handle(nv_index.0).handle_type() != Some(tpm2::TpmHt::NVIndex) {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        // `@platform` is a `TPMI_RH_PLATFORM`: only `TPM_RH_PLATFORM` is accepted.
        if platform.0 != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(2)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVUndefineSpaceSpecial>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // C `NvIndexIsAccessible` (handle unmarshaling) for `nvIndex`.
        let header = self.nv_accessible_index_header(nv_index.0, Position::handle(1))?;

        // C `CheckAuthNoSession` / `ParseSessionBuffer`: both handles need a session, which is
        // reported before the command action inspects the index.
        if num_sessions < 2 {
            return Err(TpmRc::AUTH_MISSING);
        }

        // `nvIndex` has the ADMIN role, so a policy session is required (C
        // `IsPolicySessionRequired`), the index must have an authPolicy
        // (`IsAuthPolicyAvailable`), and the policy must be bound to this command
        // (`CheckPolicyAuthSession`).
        let auth_0 = self.global_state.parsed_auths[0];
        let session_state = self
            .global_state
            .session(auth_0.session_handle.0)
            .filter(|s| s.session_type == tpm2::TpmSe::Policy)
            .ok_or(TpmRc::AUTH_TYPE)?;
        let command_code = session_state.command_code;
        if header.public.auth_policy.get_size() == 0 {
            return Err(TpmRc::AUTH_UNAVAILABLE);
        }
        if command_code == 0 {
            return Err(TpmRc::POLICY_FAIL.with(Position::session(1)));
        }
        if command_code != tpm2::TpmCc::NVUndefineSpaceSpecial.code() {
            return Err(TpmRc::POLICY_CC.with(Position::session(1)));
        }

        if !header.public.attributes.contains(TpmaNv::POLICY_DELETE) {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        self.nv_delete_index(nv_index.0, &header)?;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVReadPublic] (`0x169`) command.
    ///
    /// # Description
    /// This command reads the public area (attributes, size, name algorithm, etc.) and the computed name
    /// of a defined NV Index.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.5 (TPM2_NV_ReadPublic).
    ///
    /// # Relationships
    /// - Used to query metadata for an NV Index defined by [TpmCc::NVDefineSpace](nv_storage.rs).
    pub fn nv_read_public(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVReadPublicHandles>()?;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVReadPublic>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // C `NvIndexIsAccessible` (handle unmarshaling): undefined indices and indices of a
        // disabled hierarchy are reported as `TPM_RC_HANDLE + RC_H1`.
        self.nv_accessible_index_header(nv_index, Position::handle(1))?;

        let storage = StorageManager::new(&mut *self.context.platform.storage);
        let metadata = storage
            .get_metadata(nv_index)
            .map_err(|_| TpmRc::HANDLE.with(Position::handle(1)))?;
        let read_len = core::cmp::min(metadata.data_size as usize, 1536);
        let mut read_buf = [0u8; 1536];
        storage
            .read_item(nv_index, 0, &mut read_buf[..read_len])
            .map_err(|_| TpmRc::FAILURE)?;

        let (_, nv_public_struct, _, public_info, hash_target) =
            unmarshal_nv_header_bytes(&read_buf[..read_len])?;
        let nv_name = self.compute_name(Some(nv_public_struct.name_alg), hash_target)?;

        let rsp = responses::NVReadPublic {
            nv_public: public_info,
            nv_name: nv_name.as_tpm2b(),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Verifies password credentials for the NV provision handle.
    fn validate_nv_define_space_auth(
        &mut self,
        auth_handle_u32: u32,
        provided_auth: Option<OwnedAuthCommand>,
    ) -> Result<(), TpmRc> {
        if auth_handle_u32 != Handle::RH_OWNER.0 && auth_handle_u32 != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let expected_auth_struct = self.context.handle_auth(self.global_state, auth_handle_u32);
        let expected_auth = expected_auth_struct.get_buffer();

        if let Some(auth) = provided_auth {
            if !self.verify_password_auth(&auth, expected_auth) {
                return Err(TpmRc::AUTH_FAIL.with(Position::session(1)));
            }
            Ok(())
        } else {
            Err(TpmRc::AUTH_MISSING)
        }
    }

    /// Validates the public area and authValue of a new NV Index (C `TPM2_NV_DefineSpace` and
    /// `NvDefineSpace`), in the same order and with the same response codes as the reference
    /// implementation.
    ///
    /// `ph_enable_nv` is the current `phEnableNV` state: an index cannot be defined by the
    /// platform while platform NV is disabled.
    fn validate_nv_public_attributes(
        nv_public_struct: &TpmsNvPublic,
        auth_handle_u32: u32,
        auth: &[u8],
        ph_enable_nv: bool,
    ) -> Result<(), TpmRc> {
        let blame_public = Position::parameter(2);
        let blame_auth = Position::parameter(1);
        let blame_auth_handle = Position::handle(1);

        // `publicInfo.nvIndex` is a `TPMI_RH_NV_LEGACY_INDEX` (C `TPMS_NV_PUBLIC_Unmarshal`), so
        // any handle that is not an NV Index handle (including external and permanent NV
        // handles) is a `TPM_RC_VALUE` unmarshaling error.
        if Handle(nv_public_struct.nv_index.0).handle_type() != Some(tpm2::TpmHt::NVIndex) {
            return Err(TpmRc::VALUE.with(blame_public));
        }

        let attributes = nv_public_struct.attributes;
        let name_size = nv_public_struct.name_alg.digest_size() as u16;

        // The authPolicy must be empty or a digest of the index nameAlg.
        let auth_policy_size = nv_public_struct.auth_policy.get_size();
        if auth_policy_size != 0 && auth_policy_size != name_size {
            return Err(TpmRc::SIZE.with(blame_public));
        }

        // The authValue (without trailing zeros) may not be larger than a nameAlg digest.
        if crate::util::strip_trailing_zeros(auth).len() > name_size as usize {
            return Err(TpmRc::SIZE.with(blame_auth));
        }

        if auth_handle_u32 == Handle::RH_PLATFORM.0 && !ph_enable_nv {
            return Err(TpmRc::HIERARCHY.with(blame_auth_handle));
        }

        // Unsupported index types.
        let nv_index_type = attributes
            .get_index_type()
            .map_err(|_| TpmRc::ATTRIBUTES.with(blame_public))?;

        // Type-specific sizes.
        let size_ok = match nv_index_type {
            TpmNt::Ordinary => nv_public_struct.data_size <= MAX_NV_INDEX_SIZE,
            TpmNt::Extend => nv_public_struct.data_size == name_size,
            TpmNt::Counter | TpmNt::Bits | TpmNt::PinFail | TpmNt::PinPass => {
                nv_public_struct.data_size == TpmsNvPinCounterParameters::MAX_SIZE as u16
            }
        };
        if !size_ok {
            return Err(TpmRc::SIZE.with(blame_public));
        }

        // Type-specific attributes.
        match nv_index_type {
            // Counters can't be cleared.
            TpmNt::Counter if attributes.contains(TpmaNv::CLEAR_STCLEAR) => {
                return Err(TpmRc::ATTRIBUTES.with(blame_public));
            }
            TpmNt::PinFail | TpmNt::PinPass => {
                // A PIN Fail index must be exempt from dictionary attack protection.
                if nv_index_type == TpmNt::PinFail && !attributes.contains(TpmaNv::NO_DA) {
                    return Err(TpmRc::ATTRIBUTES.with(blame_public));
                }
                // PIN indices can't be written with their own authValue and can't be locked.
                if attributes
                    .intersects(TpmaNv::AUTHWRITE | TpmaNv::GLOBALLOCK | TpmaNv::WRITEDEFINE)
                {
                    return Err(TpmRc::ATTRIBUTES.with(blame_public));
                }
            }
            _ => {}
        }

        // Locks may not be SET and WRITTEN cannot be SET.
        if attributes.intersects(TpmaNv::WRITTEN | TpmaNv::WRITELOCKED | TpmaNv::READLOCKED) {
            return Err(TpmRc::ATTRIBUTES.with(blame_public));
        }

        // There must be a way to read and a way to write the index.
        if !attributes
            .intersects(TpmaNv::OWNERREAD | TpmaNv::PPREAD | TpmaNv::AUTHREAD | TpmaNv::POLICYREAD)
        {
            return Err(TpmRc::ATTRIBUTES.with(blame_public));
        }
        if !attributes.intersects(
            TpmaNv::OWNERWRITE | TpmaNv::PPWRITE | TpmaNv::AUTHWRITE | TpmaNv::POLICYWRITE,
        ) {
            return Err(TpmRc::ATTRIBUTES.with(blame_public));
        }

        // An index that is cleared on TPM2_Startup(CLEAR) can't be write-locked until deleted.
        if attributes.contains(TpmaNv::CLEAR_STCLEAR) && attributes.contains(TpmaNv::WRITEDEFINE) {
            return Err(TpmRc::ATTRIBUTES.with(blame_public));
        }

        // The creator of the index must be able to delete it.
        let platform_create = attributes.contains(TpmaNv::PLATFORMCREATE);
        if (platform_create && auth_handle_u32 == Handle::RH_OWNER.0)
            || (!platform_create && auth_handle_u32 == Handle::RH_PLATFORM.0)
        {
            return Err(TpmRc::ATTRIBUTES.with(blame_auth_handle));
        }

        // Only the platform may define an index that is deleted with a policy.
        if attributes.contains(TpmaNv::POLICY_DELETE) && auth_handle_u32 != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::ATTRIBUTES.with(blame_public));
        }

        // TPMA_NV_WRITEALL can't be SET if the index can't be written in one command.
        if nv_public_struct.data_size > tpm2::TPM2_MAX_NV_BUFFER_SIZE as u16
            && attributes.contains(TpmaNv::WRITEALL)
        {
            return Err(TpmRc::SIZE.with(blame_public));
        }

        Ok(())
    }

    /// Allocates NV space and writes serialized metadata.
    fn allocate_nv_space(
        nv_index: u32,
        auth: &Tpm2bAuth,
        public_info: &Tpm2bNvPublic,
        data_size: u16,
        attributes: u32,
        storage: &mut StorageManager<'_>,
    ) -> Result<(), TpmRc> {
        if storage.get_metadata(nv_index).is_ok() {
            return Err(TpmRc::NV_DEFINED);
        }

        let mut buf = [0u8; 4096];
        let offset = marshal_nv_header(auth, public_info, &mut buf)?;

        let metadata_size = offset as u16;
        let total_size_u32 = (metadata_size as u32) + (data_size as u32);
        if total_size_u32 > (u16::MAX as u32) {
            return Err(TpmRc::SIZE.to_rc());
        }
        let total_size = total_size_u32 as u16;

        if let Err(e) = storage.define_space(nv_index, total_size, attributes) {
            return match e {
                crate::storage::StorageError::OutOfBounds => Err(TpmRc::NV_SPACE),
                crate::storage::StorageError::AccessDenied => Err(TpmRc::NV_DEFINED),
                crate::storage::StorageError::HardwareError => Err(TpmRc::FAILURE),
            };
        }

        if storage.write_item(nv_index, 0, &buf[..offset]).is_err() {
            let _ = storage.undefine_space(nv_index);
            return Err(TpmRc::FAILURE);
        }
        Ok(())
    }

    /// Handles the [TpmCc::NVWrite] (`0x137`) command.
    ///
    /// # Description
    /// This command writes data to a defined NV Index.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.6 (TPM2_NV_Write).
    ///
    /// # Relationships
    /// - Writes to an NV Index defined by [TpmCc::NVDefineSpace](nv_storage.rs).
    /// - Fails if the index is locked via [TpmCc::NVWriteLock](nv_storage.rs).
    /// - Can be read back using [TpmCc::NVRead](nv_storage.rs).
    pub fn nv_write(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVWriteHandles>()?;
        let auth_handle = handles.auth_handle.0;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVWrite>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Authorization (C session processing, before the command action).
        let header = self.nv_accessible_index_header(nv_index, Position::handle(2))?;
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }
        if auth_handle == nv_index {
            self.nv_check_index_auth_available(0, &header, true)?;
        }

        // 2. Command action (C `TPM2_NV_Write`).
        let attributes = header.public.attributes;
        nv_write_access_checks(auth_handle, nv_index, attributes)?;
        if matches!(
            attributes.get_index_type()?,
            TpmNt::Counter | TpmNt::Bits | TpmNt::Extend
        ) {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }
        let data_size = header.public.data_size;
        if cmd.offset > data_size {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }
        let write_size = cmd.data.get_size();
        if write_size > data_size - cmd.offset {
            return Err(TpmRc::NV_RANGE);
        }
        if attributes.contains(TpmaNv::WRITEALL) && write_size < data_size {
            return Err(TpmRc::NV_RANGE);
        }

        self.nv_write_index_data(nv_index, &header, cmd.offset, cmd.data.get_buffer())?;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVCertify] (`0x18d`) command.
    ///
    /// # Description
    /// This command returns a signed attestation block certifying the contents and metadata of a defined NV Index.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.15 (TPM2_NV_Certify).
    ///
    /// # Relationships
    /// - Uses a signing key (referenced by `sign_handle`) to sign the attestation, similar to [TpmCc::Certify](certify.rs).
    /// - Certifies contents of an NV Index defined by [TpmCc::NVDefineSpace](nv_storage.rs).
    pub fn nv_certify(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVCertifyHandles>()?;
        let sign_handle = handles.sign_handle.0;
        let auth_handle = handles.auth_handle.0;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVCertify>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Handle unmarshaling: `signHandle` is a `TPMI_DH_OBJECT+`, `authHandle` a
        // `TPMI_RH_NV_AUTH`, and `nvIndex` a `TPMI_RH_NV_INDEX`.
        let is_nv_index = |h: u32| Handle(h).handle_type() == Some(tpm2::TpmHt::NVIndex);
        if sign_handle != Handle::RH_NULL.0 && !matches!(sign_handle >> 24, 0x80 | 0x81) {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }
        if auth_handle != Handle::RH_OWNER.0
            && auth_handle != Handle::RH_PLATFORM.0
            && !is_nv_index(auth_handle)
        {
            return Err(TpmRc::VALUE.with(Position::handle(2)));
        }
        if !is_nv_index(nv_index) {
            return Err(TpmRc::VALUE.with(Position::handle(3)));
        }

        // 2. Entity load status, in handle order.
        let signer_obj_opt = if sign_handle == Handle::RH_NULL.0 {
            None
        } else {
            Some(self.resolve_object(sign_handle, Position::handle(1))?)
        };
        let header = self.nv_accessible_index_header(nv_index, Position::handle(3))?;

        // 3. Authorization. The session for `authHandle` follows the one for `signHandle`
        // (which the engine treats as optional when `signHandle` is `TPM_RH_NULL`).
        let auth_session_idx = if signer_obj_opt.is_none() && num_sessions < 2 {
            0
        } else {
            1
        };
        if num_sessions <= auth_session_idx {
            return Err(TpmRc::AUTH_MISSING);
        }
        if auth_handle == nv_index {
            self.nv_check_index_auth_available(auth_session_idx, &header, false)?;
        }

        // 4. Command action (C `TPM2_NV_Certify`): the signing key and scheme are validated
        // before any NV access check (IsSigningObject: TPM_RC_KEY + RC_NV_Certify_signHandle;
        // CryptSelectSignScheme: TPM_RC_SCHEME + RC_NV_Certify_inScheme).
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme = self.resolve_attest_scheme(
            public_opt,
            cmd.in_scheme,
            Position::handle(1),
            Position::parameter(2),
        )?;

        nv_read_access_checks(auth_handle, nv_index, header.public.attributes)?;
        let data_size = header.public.data_size;
        if cmd.size as u32 + cmd.offset as u32 > data_size as u32 {
            return Err(TpmRc::NV_RANGE);
        }
        if cmd.size > tpm2::TPM2_MAX_NV_BUFFER_SIZE as u16 {
            return Err(TpmRc::VALUE.with(Position::parameter(3)));
        }

        // 5. Construct the attestation structure.
        let nv_name = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let mut read_buf = [0u8; NV_HEADER_BUF_SIZE];
            let read_len = core::cmp::min(header.metadata_size as usize, NV_HEADER_BUF_SIZE);
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (_, _, _, _, public_bytes) = unmarshal_nv_header_bytes(&read_buf[..read_len])?;
            self.compute_name(Some(header.public.name_alg), public_bytes)?
        };

        let attest_header = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        let mut nv_data = [0u8; MAX_NV_INDEX_SIZE as usize];
        let digest;
        let attested = if cmd.size != 0 || cmd.offset != 0 {
            // TPM_ST_ATTEST_NV: the selected range of the index data.
            StorageManager::new(&mut *self.context.platform.storage)
                .read_item(
                    nv_index,
                    header.metadata_size + cmd.offset,
                    &mut nv_data[..cmd.size as usize],
                )
                .map_err(|_| TpmRc::FAILURE)?;
            TpmuAttest::Nv(TpmsNvCertifyInfo {
                index_name: nv_name.as_tpm2b(),
                offset: cmd.offset,
                nv_contents: Tpm2bMaxNvBuffer::from_bytes(&nv_data[..cmd.size as usize])
                    .map_err(|_| TpmRc::FAILURE)?,
            })
        } else {
            // TPM_ST_ATTEST_NV_DIGEST: a digest of the whole index data, computed with the
            // hash algorithm of the selected signing scheme (empty for an unsigned
            // attestation, whose scheme is TPM_ALG_NULL).
            digest = match actual_in_scheme.and_then(|s| s.hash_alg()) {
                Some(hash_alg) => {
                    StorageManager::new(&mut *self.context.platform.storage)
                        .read_item(
                            nv_index,
                            header.metadata_size,
                            &mut nv_data[..data_size as usize],
                        )
                        .map_err(|_| TpmRc::FAILURE)?;
                    let (hash, hash_len) =
                        self.compute_hash(hash_alg, &[&nv_data[..data_size as usize]])?;
                    OwnedDigest::from_bytes(&hash[..hash_len]).map_err(|_| TpmRc::FAILURE)?
                }
                None => OwnedDigest::default(),
            };
            TpmuAttest::NvDigest(TpmsNvDigestCertifyInfo {
                index_name: nv_name.as_tpm2b(),
                nv_digest: digest.as_tpm2b(),
            })
        };

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer: attest_header.qualified_signer,
            extra_data: attest_header.extra_data,
            clock_info: attest_header.clock_info,
            firmware_version: attest_header.firmware_version,
            attested,
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);

        // 6. Sign the attestation payload
        let owned_sig = self.sign_attestation_block(
            signer_obj_opt.as_ref(),
            actual_in_scheme,
            &attest_buf[..attest_len],
            cmd.qualifying_data.get_buffer(),
        )?;

        let rsp = responses::NVCertify {
            certify_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVRead] (`0x14e`) command.
    ///
    /// # Description
    /// This command reads data from a defined NV Index.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.12 (TPM2_NV_Read).
    ///
    /// # Relationships
    /// - Reads from an NV Index defined by [TpmCc::NVDefineSpace](nv_storage.rs) and written to by [TpmCc::NVWrite](nv_storage.rs).
    /// - Fails if the index is locked via [TpmCc::NVReadLock](nv_storage.rs).
    pub fn nv_read(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVReadHandles>()?;
        let auth_handle = handles.auth_handle.0;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVRead>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Authorization (C session processing, before the command action).
        let header = self.nv_accessible_index_header(nv_index, Position::handle(2))?;
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }
        if auth_handle == nv_index {
            self.nv_check_index_auth_available(0, &header, false)?;
        }

        // 2. Command action (C `TPM2_NV_Read`).
        nv_read_access_checks(auth_handle, nv_index, header.public.attributes)?;
        if cmd.size > tpm2::TPM2_MAX_NV_BUFFER_SIZE as u16 {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let data_size = header.public.data_size;
        if cmd.offset > data_size {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }
        if cmd.size > data_size - cmd.offset {
            return Err(TpmRc::NV_RANGE);
        }

        let mut read_data = [0u8; tpm2::TPM2_MAX_NV_BUFFER_SIZE as usize];
        StorageManager::new(&mut *self.context.platform.storage)
            .read_item(
                nv_index,
                header.metadata_size + cmd.offset,
                &mut read_data[..cmd.size as usize],
            )
            .map_err(|_| TpmRc::FAILURE)?;

        let rsp = responses::NVRead {
            data: Tpm2bMaxNvBuffer::from_bytes(&read_data[..cmd.size as usize])
                .map_err(|_| TpmRc::FAILURE)?,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVIncrement] (`0x138`) command.
    ///
    /// # Description
    /// This command increments the value of a counter-type NV Index by 1.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.7 (TPM2_NV_Increment).
    ///
    /// # Relationships
    /// - Operates on an NV Index defined by [TpmCc::NVDefineSpace](nv_storage.rs) that has its index type attribute set to counter (`TPM_NT_COUNTER`).
    pub fn nv_increment(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVIncrementHandles>()?;
        let auth_handle = handles.auth_handle.0;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVIncrement>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Authorization (C session processing, before the command action).
        let header = self.nv_accessible_index_header(nv_index, Position::handle(2))?;
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }
        if auth_handle == nv_index {
            self.nv_check_index_auth_available(0, &header, true)?;
        }

        // 2. Command action (C `TPM2_NV_Increment`).
        let attributes = header.public.attributes;
        nv_write_access_checks(auth_handle, nv_index, attributes)?;
        if attributes.get_index_type()? != TpmNt::Counter {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }

        // A counter that has never been written starts from the largest value of any deleted
        // counter (C `NvReadMaxCount`), so counter values never roll back.
        let counter_val = if attributes.contains(TpmaNv::WRITTEN) {
            self.nv_read_u64_data(nv_index, &header)?
        } else {
            self.global_state.max_counter
        };
        let counter_val = counter_val.checked_add(1).ok_or(TpmRc::FAILURE)?;
        self.nv_write_index_data(nv_index, &header, 0, &counter_val.to_be_bytes())?;

        // An orderly counter only forces an NV update when the low-order bits roll over.
        if attributes.contains(TpmaNv::ORDERLY) && (counter_val & MAX_ORDERLY_COUNT) == 0 {
            self.global_state.update_nv |= crate::engine::UT_ORDERLY;
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVExtend] (`0x136`) command.
    ///
    /// # Description
    /// This command extends a value to an area in NV memory that was previously defined by `TpmCc::NVDefineSpace`
    /// and configured with `TpmaNv::EXTEND`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.9 (TPM2_NV_Extend).
    ///
    /// # Relationships
    /// - Operates on an NV Index defined by [TpmCc::NVDefineSpace](nv_storage.rs) that has its index type attribute set to extend (`TPM_NT_EXTEND`).
    pub fn nv_extend(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVExtendHandles>()?;
        let auth_handle = handles.auth_handle.0;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVExtend>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Authorization (C session processing, before the command action).
        let header = self.nv_accessible_index_header(nv_index, Position::handle(2))?;
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }
        if auth_handle == nv_index {
            self.nv_check_index_auth_available(0, &header, true)?;
        }

        // 2. Command action (C `TPM2_NV_Extend`): access checks come before the type check.
        let attributes = header.public.attributes;
        nv_write_access_checks(auth_handle, nv_index, attributes)?;
        if attributes.get_index_type()? != TpmNt::Extend {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }

        // newDigest = H_nameAlg(oldDigest || data), with an all-zero oldDigest before the first
        // extend.
        let mut old_bytes = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
        let data_size = header.public.data_size as usize;
        if data_size > old_bytes.len() {
            return Err(TpmRc::FAILURE);
        }
        if attributes.contains(TpmaNv::WRITTEN) {
            StorageManager::new(&mut *self.context.platform.storage)
                .read_item(nv_index, header.metadata_size, &mut old_bytes[..data_size])
                .map_err(|_| TpmRc::FAILURE)?;
        }
        let (new_hash, new_hash_len) = self.compute_hash(
            header.public.name_alg,
            &[&old_bytes[..data_size], cmd.data.get_buffer()],
        )?;
        if new_hash_len != data_size {
            return Err(TpmRc::FAILURE);
        }

        self.nv_write_index_data(nv_index, &header, 0, &new_hash[..new_hash_len])?;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVWriteLock] (`0x13c`) command.
    ///
    /// # Description
    /// This command locks a defined NV Index against further writes.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.10 (TPM2_NV_WriteLock).
    ///
    /// # Relationships
    /// - Restricts further calls to [TpmCc::NVWrite](nv_storage.rs) or [TpmCc::NVIncrement](nv_storage.rs) on the targeted NV Index.
    pub fn nv_write_lock(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVWriteLockHandles>()?;
        let auth_handle = handles.auth_handle.0;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVWriteLock>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Authorization (C session processing, before the command action).
        let header = self.nv_accessible_index_header(nv_index, Position::handle(2))?;
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }
        if auth_handle == nv_index {
            self.nv_check_index_auth_available(0, &header, true)?;
        }

        // 2. Command action (C `TPM2_NV_WriteLock`): an index that is already write locked is
        // reported as success.
        let attributes = header.public.attributes;
        match nv_write_access_checks(auth_handle, nv_index, attributes) {
            Ok(()) => {
                if !attributes.intersects(TpmaNv::WRITEDEFINE | TpmaNv::WRITE_STCLEAR) {
                    return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
                }
                self.nv_prepare_index_update(attributes)?;
                let mut locked = attributes;
                locked.insert(TpmaNv::WRITELOCKED);
                self.nv_write_index_attributes(nv_index, &header, locked)?;
                if !attributes.contains(TpmaNv::ORDERLY) {
                    self.global_state.update_nv |= crate::engine::UT_NV;
                }
            }
            Err(rc) if rc == TpmRc::NV_AUTHORIZATION => return Err(rc),
            Err(_) => {}
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVGlobalWriteLock] (`0x14D`) command.
    ///
    /// # Description
    /// Sets TPMA_NV_WRITELOCKED for all NV Indexes that have TPMA_NV_GLOBALLOCK SET.
    pub fn nv_global_write_lock(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVGlobalWriteLockHandles>()?;
        let auth_handle = handles.auth_handle.0;

        if auth_handle != Handle::RH_OWNER.0 && auth_handle != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVGlobalWriteLock>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // `authHandle` is authorized by the engine's session processing; only a missing
        // session is reported here (C `CheckAuthNoSession`).
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        // C `NvSetGlobalLock`: set TPMA_NV_WRITELOCKED on every index with TPMA_NV_GLOBALLOCK.
        // Changing a non-orderly index needs NV memory; storage errors are reported.
        let toc = StorageManager::new(&mut *self.context.platform.storage)
            .read_toc()
            .map_err(|_| TpmRc::FAILURE)?;
        for item in toc.iter().filter(|item| item.in_use != 0) {
            if Handle(item.handle).handle_type() != Some(tpm2::TpmHt::NVIndex) {
                continue;
            }
            let header = self.nv_read_index_header(item.handle, TpmRc::FAILURE)?;
            let attributes = header.public.attributes;
            if !attributes.contains(TpmaNv::GLOBALLOCK) || attributes.contains(TpmaNv::WRITELOCKED)
            {
                continue;
            }
            if !attributes.contains(TpmaNv::ORDERLY) {
                self.return_if_nv_is_not_available()?;
            }
            let mut locked = attributes;
            locked.insert(TpmaNv::WRITELOCKED);
            self.nv_write_index_attributes(item.handle, &header, locked)?;
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVReadLock] (`0x150`) command.
    ///
    /// # Description
    /// This command locks a defined NV Index against further reads.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.13 (TPM2_NV_ReadLock).
    ///
    /// # Relationships
    /// - Restricts further calls to [TpmCc::NVRead](nv_storage.rs) or [TpmCc::NVCertify](nv_storage.rs) on the targeted NV Index.
    pub fn nv_read_lock(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVReadLockHandles>()?;
        let auth_handle = handles.auth_handle.0;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVReadLock>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Authorization (C session processing, before the command action).
        let header = self.nv_accessible_index_header(nv_index, Position::handle(2))?;
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }
        if auth_handle == nv_index {
            self.nv_check_index_auth_available(0, &header, false)?;
        }

        // 2. Command action (C `TPM2_NV_ReadLock`): an index that is already read locked is
        // reported as success, and an index that has not been written can still be locked.
        let attributes = header.public.attributes;
        match nv_read_access_checks(auth_handle, nv_index, attributes) {
            Err(rc) if rc == TpmRc::NV_AUTHORIZATION => return Err(rc),
            Err(rc) if rc == TpmRc::NV_LOCKED => {}
            _ => {
                if !attributes.contains(TpmaNv::READ_STCLEAR) {
                    return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
                }
                self.nv_prepare_index_update(attributes)?;
                let mut locked = attributes;
                locked.insert(TpmaNv::READLOCKED);
                self.nv_write_index_attributes(nv_index, &header, locked)?;
                if !attributes.contains(TpmaNv::ORDERLY) {
                    self.global_state.update_nv |= crate::engine::UT_NV;
                }
            }
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVSetBits] (`0x135`) command.
    ///
    /// # Description
    /// This command bitwise ORs new bits into a defined NV Index that has index type [TpmNt::Bits].
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.10 (TPM2_NV_SetBits).
    ///
    /// # Relationships
    /// - Operates on an NV Index defined by [TpmCc::NVDefineSpace](nv_storage.rs) that has its index type attribute set to bit field (`TPM_NT_BITS`).
    pub fn nv_set_bits(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVSetBitsHandles>()?;
        let auth_handle = handles.auth_handle.0;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVSetBits>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Authorization (C session processing, before the command action).
        let header = self.nv_accessible_index_header(nv_index, Position::handle(2))?;
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }
        if auth_handle == nv_index {
            self.nv_check_index_auth_available(0, &header, true)?;
        }

        // 2. Command action (C `TPM2_NV_SetBits`): access checks come before the type check.
        let attributes = header.public.attributes;
        nv_write_access_checks(auth_handle, nv_index, attributes)?;
        if attributes.get_index_type()? != TpmNt::Bits {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }

        let old_value = if attributes.contains(TpmaNv::WRITTEN) {
            self.nv_read_u64_data(nv_index, &header)?
        } else {
            0
        };
        let new_value = old_value | cmd.bits;
        self.nv_write_index_data(nv_index, &header, 0, &new_value.to_be_bytes())?;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::NVChangeAuth] (`0x13B`) command.
    ///
    /// # Description
    /// This command allows the authorization secret for an NV Index to be changed.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.15 (TPM2_NV_ChangeAuth).
    ///
    /// # Relationships
    /// - Updates the authorization value (`authValue`) of an NV Index defined by [TpmCc::NVDefineSpace](nv_storage.rs).
    pub fn nv_change_auth(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<NVChangeAuthHandles>()?;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVChangeAuth>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let header = self.nv_accessible_index_header(nv_index, Position::handle(1))?;
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        // 1. `nvIndex` has the ADMIN role, so a policy session is required for this NV Index
        // (C `IsPolicySessionRequired`: password and HMAC sessions fail with
        // `TPM_RC_AUTH_TYPE`), the index must have an authPolicy (`IsAuthPolicyAvailable`), and
        // the policy must have been bound to this command (`CheckPolicyAuthSession`).
        let auth_0 = self.global_state.parsed_auths[0];
        let session_state = self
            .global_state
            .session(auth_0.session_handle.0)
            .filter(|s| s.session_type == tpm2::TpmSe::Policy)
            .ok_or(TpmRc::AUTH_TYPE)?;
        let command_code = session_state.command_code;
        if header.public.auth_policy.get_size() == 0 {
            return Err(TpmRc::AUTH_UNAVAILABLE);
        }
        if command_code == 0 {
            return Err(TpmRc::POLICY_FAIL.with(Position::session(1)));
        }
        if command_code != tpm2::TpmCc::NVChangeAuth.code() {
            return Err(TpmRc::POLICY_CC.with(Position::session(1)));
        }

        // 2. Check newAuth size vs digest size of nameAlg
        let digest_size = header.public.name_alg.digest_size();
        let stripped = crate::util::strip_trailing_zeros(cmd.new_auth.get_buffer());
        if stripped.len() > digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        let new_nv_auth = Tpm2bAuth::from_bytes(stripped)
            .map_err(|_| TpmRc::SIZE.with(Position::parameter(1)))?;

        // 3. Rewrite the header with the new authValue (C `NvWriteIndexAuth`). Like
        // `NvConditionallyWrite`, nothing is written (and NV availability is not needed) when the
        // authValue does not change. The header size changes with the authValue size, so the
        // complete data area (up to `MAX_NV_INDEX_SIZE` bytes) is saved and moved behind the new
        // header.
        if stripped != header.auth.get_buffer() {
            self.return_if_nv_is_not_available()?;
            let data_len = header.public.data_size as usize;
            let mut data_buf = [0u8; MAX_NV_INDEX_SIZE as usize];
            let mut header_buf = [0u8; NV_HEADER_BUF_SIZE];
            let header_len = marshal_nv_header(&new_nv_auth, &header.public, &mut header_buf)?;
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            storage
                .read_item(nv_index, header.metadata_size, &mut data_buf[..data_len])
                .map_err(|_| TpmRc::FAILURE)?;
            if header_len != header.metadata_size as usize {
                storage
                    .resize_item(nv_index, (header_len + data_len) as u16)
                    .map_err(|_| TpmRc::FAILURE)?;
            }
            storage
                .write_item(nv_index, 0, &header_buf[..header_len])
                .map_err(|_| TpmRc::FAILURE)?;
            if data_len > 0 {
                storage
                    .write_item(nv_index, header_len as u16, &data_buf[..data_len])
                    .map_err(|_| TpmRc::FAILURE)?;
            }
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
