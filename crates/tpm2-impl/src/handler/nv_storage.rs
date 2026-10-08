use crate::owned::OwnedAuthCommand;
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
    TpmsNvPinCounterParameters, TpmsNvPublic, TpmuAttest,
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

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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
            cmd.auth.get_size(),
        )?;

        let mut storage = StorageManager::new(&mut *self.context.platform.storage);

        // 3. Allocate NV Index space and write metadata header
        Self::allocate_nv_space(
            nv_public_struct.nv_index.0,
            &cmd.auth,
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

        let (nv_public, _nv_auth, counter_val_opt) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index.0)
                .map_err(|_| TpmRc::HANDLE.with(Position::handle(2)))?;

            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            storage
                .read_item(nv_index.0, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (metadata_size, nv_public, nv_auth, _) =
                unmarshal_nv_header(&read_buf[..read_len])?;
            let counter_val_opt = if nv_public.attributes.get_index_type() == Ok(TpmNt::Counter)
                && nv_public.attributes.contains(TpmaNv::WRITTEN)
                && read_len >= metadata_size + 8
            {
                let mut val_bytes = [0u8; 8];
                val_bytes.copy_from_slice(&read_buf[metadata_size..metadata_size + 8]);
                Some(u64::from_be_bytes(val_bytes))
            } else {
                None
            };
            (nv_public, nv_auth, counter_val_opt)
        };

        if nv_public.attributes.contains(TpmaNv::POLICY_DELETE) {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }

        let platform_create = nv_public.attributes.contains(TpmaNv::PLATFORMCREATE);
        if auth_handle.0 == Handle::RH_OWNER.0 && platform_create {
            return Err(TpmRc::NV_AUTHORIZATION);
        }

        if platform_create {
            if !self.global_state.ph_enable_nv {
                return Err(TpmRc::HANDLE.to_rc());
            }
        } else if !self.global_state.sh_enable {
            return Err(TpmRc::HANDLE.to_rc());
        }

        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let expected_auth = self.context.handle_auth(self.global_state, auth_handle.0);
        let provided_auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
            return Err(TpmRc::AUTH_FAIL.to_rc());
        }

        {
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            storage
                .undefine_space(nv_index.0)
                .map_err(|_| TpmRc::FAILURE)?;
        }

        if let Some(val) = counter_val_opt {
            if val > self.global_state.max_counter {
                self.global_state.max_counter = val;
            }
            self.nv_sync_persistent_max_counter()?;
        }

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

        if platform.0 != Handle::RH_PLATFORM.0 && platform.0 != Handle::RH_OWNER.0 {
            return Err(TpmRc::VALUE.with(Position::handle(2)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVUndefineSpaceSpecial>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let (nv_public, _nv_auth, counter_val_opt) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index.0)
                .map_err(|_| TpmRc::HANDLE.with(Position::handle(1)))?;

            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            storage
                .read_item(nv_index.0, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (metadata_size, nv_public, nv_auth, _) =
                unmarshal_nv_header(&read_buf[..read_len])?;
            let counter_val_opt = if nv_public.attributes.get_index_type() == Ok(TpmNt::Counter)
                && nv_public.attributes.contains(TpmaNv::WRITTEN)
                && read_len >= metadata_size + 8
            {
                let mut val_bytes = [0u8; 8];
                val_bytes.copy_from_slice(&read_buf[metadata_size..metadata_size + 8]);
                Some(u64::from_be_bytes(val_bytes))
            } else {
                None
            };
            (nv_public, nv_auth, counter_val_opt)
        };

        if !nv_public.attributes.contains(TpmaNv::POLICY_DELETE) {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        let platform_create = nv_public.attributes.contains(TpmaNv::PLATFORMCREATE);
        if platform_create {
            if !self.global_state.ph_enable_nv {
                return Err(TpmRc::HANDLE.to_rc());
            }
        } else if !self.global_state.sh_enable {
            return Err(TpmRc::HANDLE.to_rc());
        }

        if platform.0 == Handle::RH_PLATFORM.0 && !platform_create {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        if platform.0 == Handle::RH_OWNER.0 && platform_create {
            return Err(TpmRc::NV_AUTHORIZATION);
        }

        if num_sessions < 2 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let auth_0 = self.global_state.parsed_auths[0];
        let auth_1 = self.global_state.parsed_auths[1];

        if auth_0.session_handle == Handle::RS_PW {
            return Err(TpmRc::AUTH_TYPE);
        }
        if let Some(session_state) = self.global_state.session(auth_0.session_handle.0) {
            if session_state.session_type != tpm2::TpmSe::Policy {
                return Err(TpmRc::AUTH_TYPE);
            }
            if session_state.command_code != tpm2::TpmCc::NVUndefineSpaceSpecial.code() {
                return Err(TpmRc::POLICY_FAIL.with(Position::session(1)));
            }
        }

        let expected_auth = self.context.handle_auth(self.global_state, platform.0);
        if auth_1.session_handle == Handle::RS_PW
            && !self.verify_password_auth(&auth_1, expected_auth.get_buffer())
        {
            return Err(TpmRc::AUTH_FAIL.to_rc());
        }

        {
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            storage
                .undefine_space(nv_index.0)
                .map_err(|_| TpmRc::FAILURE)?;
        }

        if let Some(val) = counter_val_opt {
            if val > self.global_state.max_counter {
                self.global_state.max_counter = val;
            }
            self.nv_sync_persistent_max_counter()?;
        }

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

        let storage = StorageManager::new(&mut *self.context.platform.storage);
        let metadata = storage
            .get_metadata(nv_index)
            .map_err(|_| TpmRc::HANDLE.to_rc())?;
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

    /// Validates NV index types, sizes, clear/lock states, read/write flags,
    /// and provision authority rules.
    fn validate_nv_public_attributes(
        nv_public_struct: &TpmsNvPublic,
        auth_handle_u32: u32,
        auth_size: u16,
    ) -> Result<(), TpmRc> {
        let nv_index = nv_public_struct.nv_index.0;
        if (nv_index >> 24) != 1 {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }

        let nv_index_type = nv_public_struct.attributes.get_index_type()?;
        match nv_index_type {
            TpmNt::Ordinary
            | TpmNt::Counter
            | TpmNt::Bits
            | TpmNt::Extend
            | TpmNt::PinFail
            | TpmNt::PinPass => {}
        }

        if nv_public_struct.attributes.contains(TpmaNv::WRITTEN)
            || nv_public_struct.attributes.contains(TpmaNv::READLOCKED)
            || nv_public_struct.attributes.contains(TpmaNv::WRITELOCKED)
        {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        if (matches!(nv_index_type, TpmNt::Counter | TpmNt::Bits)
            && nv_public_struct.data_size != 8)
            || (matches!(nv_index_type, TpmNt::PinFail | TpmNt::PinPass)
                && nv_public_struct.data_size != TpmsNvPinCounterParameters::MAX_SIZE as u16)
        {
            return Err(TpmRc::SIZE.to_rc());
        }

        if nv_index_type == TpmNt::Extend
            && nv_public_struct.data_size != nv_public_struct.name_alg.digest_size() as u16
        {
            return Err(TpmRc::SIZE.to_rc());
        }

        if !nv_public_struct
            .attributes
            .intersects(TpmaNv::PPREAD | TpmaNv::OWNERREAD | TpmaNv::AUTHREAD | TpmaNv::POLICYREAD)
        {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }
        if !nv_public_struct.attributes.intersects(
            TpmaNv::PPWRITE | TpmaNv::OWNERWRITE | TpmaNv::AUTHWRITE | TpmaNv::POLICYWRITE,
        ) {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        if nv_public_struct.attributes.contains(TpmaNv::CLEAR_STCLEAR)
            && nv_index_type == TpmNt::Counter
        {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        let platform_create = nv_public_struct.attributes.contains(TpmaNv::PLATFORMCREATE);
        if auth_handle_u32 == Handle::RH_PLATFORM.0 && !platform_create {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }
        if auth_handle_u32 == Handle::RH_OWNER.0 && platform_create {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        if nv_public_struct.attributes.contains(TpmaNv::POLICY_DELETE)
            && auth_handle_u32 != Handle::RH_PLATFORM.0
        {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        if nv_index_type == TpmNt::PinFail && !nv_public_struct.attributes.contains(TpmaNv::NO_DA) {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        if matches!(nv_index_type, TpmNt::PinFail | TpmNt::PinPass) {
            if !nv_public_struct
                .attributes
                .intersects(TpmaNv::PPWRITE | TpmaNv::OWNERWRITE | TpmaNv::POLICYWRITE)
            {
                return Err(TpmRc::ATTRIBUTES.to_rc());
            }
            if nv_public_struct.attributes.contains(TpmaNv::AUTHWRITE) {
                return Err(TpmRc::ATTRIBUTES.to_rc());
            }
        }

        let name_alg_digest_size = nv_public_struct.name_alg.digest_size() as u16;
        if auth_size > name_alg_digest_size {
            return Err(TpmRc::SIZE.to_rc());
        }

        if nv_public_struct.data_size > 2048
            && nv_public_struct.attributes.contains(TpmaNv::WRITEALL)
        {
            return Err(TpmRc::SIZE.to_rc());
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
        let auth_handle = handles.auth_handle;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVWrite>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Read metadata from storage
        let (metadata_size, nv_public, nv_auth) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;

            // 2. Parse auth and public area
            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;

            let (metadata_size, nv_public, nv_auth, _) =
                unmarshal_nv_header(&read_buf[..read_len])?;
            (metadata_size as u16, nv_public, nv_auth)
        };

        let nv_index_type = nv_public.attributes.get_index_type()?;
        if matches!(nv_index_type, TpmNt::Counter | TpmNt::Bits | TpmNt::Extend) {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        // Verify locked attributes first
        if nv_public.attributes.contains(TpmaNv::WRITELOCKED) {
            return Err(TpmRc::NV_LOCKED);
        }

        // 3. Verify write offset/bounds
        let write_size = cmd.data.get_size();
        if nv_public.attributes.contains(TpmaNv::WRITEALL) && write_size != nv_public.data_size {
            return Err(TpmRc::NV_RANGE);
        }
        let end_offset = cmd.offset.checked_add(write_size).ok_or(TpmRc::NV_RANGE)?;
        if end_offset > nv_public.data_size {
            return Err(TpmRc::NV_RANGE);
        }

        // 4. Verify attributes/authorization
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let is_owner_or_platform =
            auth_handle.0 == Handle::RH_OWNER.0 || auth_handle.0 == Handle::RH_PLATFORM.0;
        let expected_auth_opt = if is_owner_or_platform {
            Some(self.context.handle_auth(self.global_state, auth_handle.0))
        } else {
            None
        };

        let provided_auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];
        let is_policy_session =
            num_sessions > 0 && (provided_auths[0].session_handle.0 >> 24) == 0x03;

        if auth_handle.0 == nv_index {
            if is_policy_session {
                if !nv_public.attributes.contains(TpmaNv::POLICYWRITE) {
                    return Err(TpmRc::NV_AUTHORIZATION);
                }
            } else {
                if !nv_public.attributes.contains(TpmaNv::AUTHWRITE) {
                    return Err(TpmRc::NV_AUTHORIZATION);
                }
                if !self.verify_password_auth(&provided_auths[0], nv_auth.get_buffer()) {
                    return Err(TpmRc::AUTH_FAIL.to_rc());
                }
            }
        } else if auth_handle.0 == Handle::RH_OWNER.0 {
            if !nv_public.attributes.contains(TpmaNv::OWNERWRITE) {
                return Err(TpmRc::NV_AUTHORIZATION);
            }
            if !is_policy_session {
                let expected_auth = expected_auth_opt.unwrap();
                if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                    return Err(TpmRc::AUTH_FAIL.to_rc());
                }
            }
        } else if auth_handle.0 == Handle::RH_PLATFORM.0 {
            if !nv_public.attributes.contains(TpmaNv::PPWRITE) {
                return Err(TpmRc::NV_AUTHORIZATION);
            }
            if !is_policy_session {
                let expected_auth = expected_auth_opt.unwrap();
                if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                    return Err(TpmRc::AUTH_FAIL.to_rc());
                }
            }
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        }

        // 5. Write the data
        {
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            storage
                .write_item(nv_index, metadata_size + cmd.offset, cmd.data.get_buffer())
                .map_err(|_| TpmRc::FAILURE)?;

            if !nv_public.attributes.contains(TpmaNv::WRITTEN) {
                let mut updated_public = nv_public;
                updated_public.attributes.insert(TpmaNv::WRITTEN);
                let updated_public_info =
                    Ok::<_, TpmRc>(updated_public.as_tpm2b()).map_err(|_| TpmRc::FAILURE)?;

                let mut write_buf = [0u8; 1536];
                let offset = marshal_nv_header(&nv_auth, &updated_public_info, &mut write_buf)?;
                storage
                    .write_item(nv_index, 0, &write_buf[..offset])
                    .map_err(|_| TpmRc::FAILURE)?;
            }
        }

        if nv_public.attributes.contains(TpmaNv::ORDERLY) {
            self.nv_clear_orderly()?;
            self.global_state.update_nv |= crate::engine::UT_ORDERLY;
        } else {
            self.global_state.update_nv |= crate::engine::UT_NV;
        }

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
        let sign_handle = handles.sign_handle;
        let auth_handle = handles.auth_handle;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVCertify>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve NV Index metadata from storage
        let mut read_buf = [0u8; 1536];
        let (metadata_size, nv_public, nv_auth, _, public_bytes) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;

            // 2. Parse auth and public area
            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (metadata_size, nv_public, nv_auth, public_info, public_bytes) =
                unmarshal_nv_header_bytes(&read_buf[..read_len])?;
            (
                metadata_size as u16,
                nv_public,
                nv_auth,
                public_info,
                public_bytes,
            )
        };

        if !nv_public.attributes.contains(TpmaNv::WRITTEN) {
            return Err(TpmRc::NV_UNINITIALIZED);
        }

        // 3. Compute NV Name
        let nv_name = self.compute_name(Some(nv_public.name_alg), public_bytes)?;

        // 4. Verify read size/bounds
        let end_offset = cmd.offset.checked_add(cmd.size).ok_or(TpmRc::NV_RANGE)?;
        if end_offset > nv_public.data_size {
            return Err(TpmRc::NV_RANGE);
        }

        // Verify locked attributes
        if nv_public.attributes.contains(TpmaNv::READLOCKED) {
            return Err(TpmRc::NV_LOCKED);
        }

        // 5. Verify authorizations
        let expected_sessions = if sign_handle.0 == 0x40000007 { 1 } else { 2 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        let signer_obj_opt = if sign_handle.0 == 0x40000007 {
            None
        } else {
            Some(self.resolve_object(sign_handle.0, Position::handle(1))?)
        };

        let is_owner_or_platform =
            auth_handle.0 == Handle::RH_OWNER.0 || auth_handle.0 == Handle::RH_PLATFORM.0;
        let expected_auth_opt = if is_owner_or_platform {
            Some(self.context.handle_auth(self.global_state, auth_handle.0))
        } else {
            None
        };

        let auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        if let Some(ref signer) = signer_obj_opt
            && !self.verify_password_auth(&auths[0], signer.auth.get_buffer())
        {
            return Err(TpmRc::AUTH_FAIL.to_rc());
        }

        let auth_session_idx = if signer_obj_opt.is_some() { 1 } else { 0 };
        if auth_handle.0 == nv_index {
            if !nv_public.attributes.contains(TpmaNv::AUTHREAD) {
                return Err(TpmRc::NV_AUTHORIZATION);
            }
            if !self.verify_password_auth(&auths[auth_session_idx], nv_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else if auth_handle.0 == Handle::RH_OWNER.0 {
            if !nv_public.attributes.contains(TpmaNv::OWNERREAD) {
                return Err(TpmRc::NV_AUTHORIZATION);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&auths[auth_session_idx], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else if auth_handle.0 == Handle::RH_PLATFORM.0 {
            if !nv_public.attributes.contains(TpmaNv::PPREAD) {
                return Err(TpmRc::NV_AUTHORIZATION);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&auths[auth_session_idx], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        }

        // 6. Read data from NV index
        let mut nv_contents = [0u8; 1024];
        if cmd.size > 1024 {
            return Err(TpmRc::SIZE.to_rc());
        }
        {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            storage
                .read_item(
                    nv_index,
                    metadata_size + cmd.offset,
                    &mut nv_contents[..cmd.size as usize],
                )
                .map_err(|_| TpmRc::FAILURE)?;
        }

        let nv_cert_data = Tpm2bMaxNvBuffer::from_bytes(&nv_contents[..cmd.size as usize])
            .map_err(|_| TpmRc::FAILURE)?;

        // 7. Construct attestation structure
        let clock_info = self.get_clock_info();

        // 8. Resolve signature scheme and verify consistency with public attributes
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme =
            self.resolve_attest_scheme(sign_handle, public_opt, cmd.in_scheme)?;

        let (qualified_signer, extra_data) = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version: 0x00010001,
            attested: TpmuAttest::Nv(TpmsNvCertifyInfo {
                index_name: nv_name.as_tpm2b(),
                offset: cmd.offset,
                nv_contents: nv_cert_data,
            }),
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);

        // 9. Sign the attestation payload
        let priv_key_opt = signer_obj_opt.as_ref().map(|s| (s.private, s.private_len));
        let owned_sig = self.sign_attestation_block(
            sign_handle,
            priv_key_opt.as_ref(),
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
        let auth_handle = handles.auth_handle;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVRead>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Read metadata from storage
        let (metadata_size, nv_public, nv_auth) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;

            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;

            let (metadata_size, nv_public, nv_auth, _) =
                unmarshal_nv_header(&read_buf[..read_len])?;
            (metadata_size as u16, nv_public, nv_auth)
        };

        // Validate locked attributes first
        if nv_public.attributes.contains(TpmaNv::READLOCKED) {
            return Err(TpmRc::NV_LOCKED);
        }

        // 4. Verify read size/bounds
        if cmd.size > tpm2::TPM2_MAX_NV_BUFFER_SIZE as u16 {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let end_offset = cmd.offset.checked_add(cmd.size).ok_or(TpmRc::NV_RANGE)?;
        if end_offset > nv_public.data_size {
            return Err(TpmRc::NV_RANGE);
        }

        // 3. Check if it has been written
        if !nv_public.attributes.contains(TpmaNv::WRITTEN) {
            return Err(TpmRc::NV_UNINITIALIZED);
        }

        // 5. Verify authorization
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let is_owner_or_platform =
            auth_handle.0 == Handle::RH_OWNER.0 || auth_handle.0 == Handle::RH_PLATFORM.0;
        let expected_auth_opt = if is_owner_or_platform {
            Some(self.context.handle_auth(self.global_state, auth_handle.0))
        } else {
            None
        };

        let provided_auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];
        let is_policy_session =
            num_sessions > 0 && (provided_auths[0].session_handle.0 >> 24) == 0x03;

        if auth_handle.0 == nv_index {
            if is_policy_session {
                if !nv_public.attributes.contains(TpmaNv::POLICYREAD) {
                    return Err(TpmRc::NV_AUTHORIZATION);
                }
            } else {
                if !nv_public.attributes.contains(TpmaNv::AUTHREAD) {
                    return Err(TpmRc::NV_AUTHORIZATION);
                }
                if !self.verify_password_auth(&provided_auths[0], nv_auth.get_buffer()) {
                    return Err(TpmRc::AUTH_FAIL.to_rc());
                }
            }
        } else if auth_handle.0 == Handle::RH_OWNER.0 {
            if !nv_public.attributes.contains(TpmaNv::OWNERREAD) {
                return Err(TpmRc::NV_AUTHORIZATION);
            }
            if !is_policy_session {
                let expected_auth = expected_auth_opt.unwrap();
                if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                    return Err(TpmRc::AUTH_FAIL.to_rc());
                }
            }
        } else if auth_handle.0 == Handle::RH_PLATFORM.0 {
            if !nv_public.attributes.contains(TpmaNv::PPREAD) {
                return Err(TpmRc::NV_AUTHORIZATION);
            }
            if !is_policy_session {
                let expected_auth = expected_auth_opt.unwrap();
                if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                    return Err(TpmRc::AUTH_FAIL.to_rc());
                }
            }
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        }

        // 6. Read the data
        let mut read_data = [0u8; tpm2::TPM2_MAX_NV_BUFFER_SIZE as usize];
        {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            storage
                .read_item(
                    nv_index,
                    metadata_size + cmd.offset,
                    &mut read_data[..cmd.size as usize],
                )
                .map_err(|_| TpmRc::FAILURE)?;
        }

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
        let auth_handle = handles.auth_handle;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVIncrement>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Read metadata from storage
        let (metadata_size, nv_public, nv_auth) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;

            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (metadata_size, nv_public, nv_auth, _) =
                unmarshal_nv_header(&read_buf[..read_len])?;
            (metadata_size as u16, nv_public, nv_auth)
        };

        let platform_create = nv_public.attributes.contains(TpmaNv::PLATFORMCREATE);
        if platform_create {
            if !self.global_state.ph_enable_nv {
                return Err(TpmRc::HANDLE.with(Position::handle(2)));
            }
        } else if !self.global_state.sh_enable {
            return Err(TpmRc::HANDLE.with(Position::handle(2)));
        }

        // 2. Validate !WRITELOCKED first (as per NvWriteAccessChecks in tpm-c)
        if nv_public.attributes.contains(TpmaNv::WRITELOCKED) {
            return Err(TpmRc::NV_LOCKED);
        }

        // 3. Verify authorizations
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let is_owner_or_platform =
            auth_handle.0 == Handle::RH_OWNER.0 || auth_handle.0 == Handle::RH_PLATFORM.0;
        let expected_auth_opt = if is_owner_or_platform {
            Some(self.context.handle_auth(self.global_state, auth_handle.0))
        } else {
            None
        };

        let provided_auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        if auth_handle.0 == nv_index {
            if !nv_public.attributes.contains(TpmaNv::AUTHWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            if !self.verify_password_auth(&provided_auths[0], nv_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else if auth_handle.0 == Handle::RH_OWNER.0 {
            if !nv_public.attributes.contains(TpmaNv::OWNERWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else if auth_handle.0 == Handle::RH_PLATFORM.0 {
            if !nv_public.attributes.contains(TpmaNv::PPWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        }

        // 4. Validate index type is Counter
        let nv_index_type = nv_public.attributes.get_index_type()?;
        if nv_index_type != TpmNt::Counter {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }

        // 5. Read, increment, and write back
        {
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            let mut counter_val = if nv_public.attributes.contains(TpmaNv::WRITTEN) {
                let mut val_bytes = [0u8; 8];
                storage
                    .read_item(nv_index, metadata_size, &mut val_bytes)
                    .map_err(|_| TpmRc::FAILURE)?;
                u64::from_be_bytes(val_bytes)
            } else {
                self.global_state.max_counter
            };
            counter_val = counter_val.checked_add(1).ok_or(TpmRc::FAILURE)?;
            if counter_val > self.global_state.max_counter {
                self.global_state.max_counter = counter_val;
            }
            let val_bytes = counter_val.to_be_bytes();
            storage
                .write_item(nv_index, metadata_size, &val_bytes)
                .map_err(|_| TpmRc::FAILURE)?;

            if !nv_public.attributes.contains(TpmaNv::WRITTEN) {
                let mut updated_public = nv_public;
                updated_public.attributes.insert(TpmaNv::WRITTEN);
                let updated_public_info =
                    Ok::<_, TpmRc>(updated_public.as_tpm2b()).map_err(|_| TpmRc::FAILURE)?;

                let mut write_buf = [0u8; 1536];
                let offset = marshal_nv_header(&nv_auth, &updated_public_info, &mut write_buf)?;
                storage
                    .write_item(nv_index, 0, &write_buf[..offset])
                    .map_err(|_| TpmRc::FAILURE)?;
            }
        }

        self.nv_sync_persistent_max_counter()?;

        if nv_public.attributes.contains(TpmaNv::ORDERLY) {
            self.nv_clear_orderly()?;
            self.global_state.update_nv |= crate::engine::UT_ORDERLY;
        } else {
            self.global_state.update_nv |= crate::engine::UT_NV;
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
        let auth_handle = handles.auth_handle;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVExtend>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Read metadata from storage
        let (metadata_size, nv_public, nv_auth) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;

            let read_len = core::cmp::min(metadata.data_size as usize, 512);
            let mut read_buf = [0u8; 512];
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (metadata_size, nv_public, nv_auth, _) =
                unmarshal_nv_header(&read_buf[..read_len])?;
            (metadata_size as u16, nv_public, nv_auth)
        };

        // 2. Validate index type is Extend
        let nv_index_type = nv_public.attributes.get_index_type()?;
        if nv_index_type != TpmNt::Extend {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        // 4. Verify authorizations
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let is_owner_or_platform =
            auth_handle.0 == Handle::RH_OWNER.0 || auth_handle.0 == Handle::RH_PLATFORM.0;
        let expected_auth_opt = if is_owner_or_platform {
            Some(self.context.handle_auth(self.global_state, auth_handle.0))
        } else {
            None
        };

        let provided_auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        if auth_handle.0 == nv_index {
            if !nv_public.attributes.contains(TpmaNv::AUTHWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            if !self.verify_password_auth(&provided_auths[0], nv_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else if auth_handle.0 == Handle::RH_OWNER.0 {
            if !nv_public.attributes.contains(TpmaNv::OWNERWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else if auth_handle.0 == Handle::RH_PLATFORM.0 {
            if !nv_public.attributes.contains(TpmaNv::PPWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        }

        // 3. Validate !WRITELOCKED
        if nv_public.attributes.contains(TpmaNv::WRITELOCKED) {
            return Err(TpmRc::NV_LOCKED);
        }

        // 5. Read old digest, compute new digest, and write back
        let mut old_bytes = [0u8; tpm2::TPM2_MAX_NV_BUFFER_SIZE as usize];
        let data_size = nv_public.data_size as usize;
        if data_size > tpm2::TPM2_MAX_NV_BUFFER_SIZE as usize {
            return Err(TpmRc::SIZE.to_rc());
        }
        if nv_public.attributes.contains(TpmaNv::WRITTEN) {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            storage
                .read_item(nv_index, metadata_size, &mut old_bytes[..data_size])
                .map_err(|_| TpmRc::FAILURE)?;
        }

        let (new_hash, new_hash_len) = self.compute_hash(
            nv_public.name_alg,
            &[&old_bytes[..data_size], cmd.data.get_buffer()],
        )?;

        if new_hash_len as u16 != nv_public.data_size {
            return Err(TpmRc::FAILURE);
        }

        {
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            storage
                .write_item(nv_index, metadata_size, &new_hash[..new_hash_len])
                .map_err(|_| TpmRc::FAILURE)?;

            if !nv_public.attributes.contains(TpmaNv::WRITTEN) {
                let mut updated_public = nv_public;
                updated_public.attributes.insert(TpmaNv::WRITTEN);
                let updated_public_info =
                    Ok::<_, TpmRc>(updated_public.as_tpm2b()).map_err(|_| TpmRc::FAILURE)?;

                let mut write_buf = [0u8; 1536];
                let offset = marshal_nv_header(&nv_auth, &updated_public_info, &mut write_buf)?;
                storage
                    .write_item(nv_index, 0, &write_buf[..offset])
                    .map_err(|_| TpmRc::FAILURE)?;
            }
        }

        if nv_public.attributes.contains(TpmaNv::ORDERLY) {
            self.nv_clear_orderly()?;
            self.global_state.update_nv |= crate::engine::UT_ORDERLY;
        } else {
            self.global_state.update_nv |= crate::engine::UT_NV;
        }

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
        let auth_handle = handles.auth_handle;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVWriteLock>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Read metadata from storage
        let (_metadata_size, nv_public, nv_auth) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;

            let read_len = core::cmp::min(metadata.data_size as usize, 512);
            let mut read_buf = [0u8; 512];
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;

            let (metadata_size, nv_public, nv_auth, _) =
                unmarshal_nv_header(&read_buf[..read_len])?;
            (metadata_size as u16, nv_public, nv_auth)
        };

        // 4. Verify authorizations
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let is_owner_or_platform =
            auth_handle.0 == Handle::RH_OWNER.0 || auth_handle.0 == Handle::RH_PLATFORM.0;
        let expected_auth_opt = if is_owner_or_platform {
            Some(self.context.handle_auth(self.global_state, auth_handle.0))
        } else {
            None
        };

        let provided_auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        if auth_handle.0 == nv_index {
            if !nv_public.attributes.contains(TpmaNv::AUTHWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            if !self.verify_password_auth(&provided_auths[0], nv_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else if auth_handle.0 == Handle::RH_OWNER.0 {
            if !nv_public.attributes.contains(TpmaNv::OWNERWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else if auth_handle.0 == Handle::RH_PLATFORM.0 {
            if !nv_public.attributes.contains(TpmaNv::PPWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        }

        // 2. If WRITELOCKED is already set, return success
        if nv_public.attributes.contains(TpmaNv::WRITELOCKED) {
            let response = request.into_response();
            self.write_response_none(response, &session_responses[..num_sessions])?;
            return Ok(());
        }

        // 3. Validate that WRITEDEFINE or WRITE_STCLEAR is set
        if !nv_public.attributes.contains(TpmaNv::WRITEDEFINE)
            && !nv_public.attributes.contains(TpmaNv::WRITE_STCLEAR)
        {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        // 5. Set WRITELOCKED in public attributes and write updated metadata
        {
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            let mut updated_public = nv_public;
            updated_public.attributes.insert(TpmaNv::WRITELOCKED);
            let updated_public_info =
                Ok::<_, TpmRc>(updated_public.as_tpm2b()).map_err(|_| TpmRc::FAILURE)?;

            let mut write_buf = [0u8; 512];
            let offset = marshal_nv_header(&nv_auth, &updated_public_info, &mut write_buf)?;
            storage
                .write_item(nv_index, 0, &write_buf[..offset])
                .map_err(|_| TpmRc::FAILURE)?;
        }

        if nv_public.attributes.contains(TpmaNv::ORDERLY) {
            self.nv_clear_orderly()?;
            self.global_state.update_nv |= crate::engine::UT_ORDERLY;
        } else {
            self.global_state.update_nv |= crate::engine::UT_NV;
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

        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let expected_auth = self.context.handle_auth(self.global_state, auth_handle);
        let provided_auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];
        if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
            return Err(TpmRc::AUTH_FAIL.to_rc());
        }

        {
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            if let Ok(toc) = storage.read_toc() {
                let mut locked_handles = [0u32; 64];
                let mut locked_count = 0;
                for item in toc.iter() {
                    if item.in_use != 0 && (item.handle >> 24) == 0x01 && locked_count < 64 {
                        locked_handles[locked_count] = item.handle;
                        locked_count += 1;
                    }
                }
                for &h in &locked_handles[..locked_count] {
                    if let Ok(metadata) = storage.get_metadata(h) {
                        let read_len = core::cmp::min(metadata.data_size as usize, 512);
                        let mut read_buf = [0u8; 512];
                        if storage.read_item(h, 0, &mut read_buf[..read_len]).is_ok()
                            && let Ok((_, nv_public, nv_auth, _)) =
                                unmarshal_nv_header(&read_buf[..read_len])
                            && nv_public.attributes.contains(TpmaNv::GLOBALLOCK)
                            && !nv_public.attributes.contains(TpmaNv::WRITELOCKED)
                        {
                            let mut updated_public = nv_public;
                            updated_public.attributes.insert(TpmaNv::WRITELOCKED);
                            if let Ok(updated_public_info) =
                                Ok::<_, TpmRc>(updated_public.as_tpm2b())
                            {
                                let mut write_buf = [0u8; 512];
                                if let Ok(offset) = marshal_nv_header(
                                    &nv_auth,
                                    &updated_public_info,
                                    &mut write_buf,
                                ) {
                                    let _ = storage.write_item(h, 0, &write_buf[..offset]);
                                }
                            }
                        }
                    }
                }
            }
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
        let auth_handle = handles.auth_handle;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<NVReadLock>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Read metadata from storage
        let (_metadata_size, nv_public, nv_auth) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;

            let read_len = core::cmp::min(metadata.data_size as usize, 512);
            let mut read_buf = [0u8; 512];
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;

            let (metadata_size, nv_public, nv_auth, _) =
                unmarshal_nv_header(&read_buf[..read_len])?;
            (metadata_size as u16, nv_public, nv_auth)
        };

        // 4. Verify authorizations
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let is_owner_or_platform =
            auth_handle.0 == Handle::RH_OWNER.0 || auth_handle.0 == Handle::RH_PLATFORM.0;
        let expected_auth_opt = if is_owner_or_platform {
            Some(self.context.handle_auth(self.global_state, auth_handle.0))
        } else {
            None
        };

        let provided_auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        if auth_handle.0 == nv_index {
            if !nv_public.attributes.contains(TpmaNv::AUTHREAD) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            if !self.verify_password_auth(&provided_auths[0], nv_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else if auth_handle.0 == Handle::RH_OWNER.0 {
            if !nv_public.attributes.contains(TpmaNv::OWNERREAD) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else if auth_handle.0 == Handle::RH_PLATFORM.0 {
            if !nv_public.attributes.contains(TpmaNv::PPREAD) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        }

        // 2. If READLOCKED is already set, return success
        if nv_public.attributes.contains(TpmaNv::READLOCKED) {
            let response = request.into_response();
            self.write_response_none(response, &session_responses[..num_sessions])?;
            return Ok(());
        }

        // 3. Validate that READ_STCLEAR is set
        if !nv_public.attributes.contains(TpmaNv::READ_STCLEAR) {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        // 5. Set READLOCKED in public attributes and write updated metadata
        {
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            let mut updated_public = nv_public;
            updated_public.attributes.insert(TpmaNv::READLOCKED);
            let updated_public_info =
                Ok::<_, TpmRc>(updated_public.as_tpm2b()).map_err(|_| TpmRc::FAILURE)?;

            let mut write_buf = [0u8; 1536];
            let offset = marshal_nv_header(&nv_auth, &updated_public_info, &mut write_buf)?;
            storage
                .write_item(nv_index, 0, &write_buf[..offset])
                .map_err(|_| TpmRc::FAILURE)?;
        }

        if nv_public.attributes.contains(TpmaNv::ORDERLY) {
            self.nv_clear_orderly()?;
            self.global_state.update_nv |= crate::engine::UT_ORDERLY;
        } else {
            self.global_state.update_nv |= crate::engine::UT_NV;
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
        let auth_handle = handles.auth_handle;
        let nv_index = handles.nv_index.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<NVSetBits>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Read metadata from storage
        let (metadata_size, nv_public, nv_auth) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;

            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (metadata_size, nv_public, nv_auth, _) =
                unmarshal_nv_header(&read_buf[..read_len])?;
            (metadata_size as u16, nv_public, nv_auth)
        };

        // 2. Validate index type is Bits
        let nv_index_type = nv_public.attributes.get_index_type()?;
        if nv_index_type != TpmNt::Bits {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        // 4. Verify authorizations
        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let is_owner_or_platform =
            auth_handle.0 == Handle::RH_OWNER.0 || auth_handle.0 == Handle::RH_PLATFORM.0;
        let expected_auth_opt = if is_owner_or_platform {
            Some(self.context.handle_auth(self.global_state, auth_handle.0))
        } else {
            None
        };

        let provided_auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        if auth_handle.0 == nv_index {
            if !nv_public.attributes.contains(TpmaNv::AUTHWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            if !self.verify_password_auth(&provided_auths[0], nv_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.with(Position::session(1)));
            }
        } else if auth_handle.0 == Handle::RH_OWNER.0 {
            if !nv_public.attributes.contains(TpmaNv::OWNERWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.with(Position::session(1)));
            }
        } else if auth_handle.0 == Handle::RH_PLATFORM.0 {
            if !nv_public.attributes.contains(TpmaNv::PPWRITE) {
                return Err(TpmRc::AUTH_UNAVAILABLE);
            }
            let expected_auth = expected_auth_opt.unwrap();
            if !self.verify_password_auth(&provided_auths[0], expected_auth.get_buffer()) {
                return Err(TpmRc::AUTH_FAIL.with(Position::session(1)));
            }
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        }

        // 3. Validate !WRITELOCKED
        if nv_public.attributes.contains(TpmaNv::WRITELOCKED) {
            return Err(TpmRc::NV_LOCKED);
        }

        // 5. Read, bitwise OR, and write back
        {
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            let mut bits_val = 0u64;
            if nv_public.attributes.contains(TpmaNv::WRITTEN) {
                let mut val_bytes = [0u8; 8];
                storage
                    .read_item(nv_index, metadata_size, &mut val_bytes)
                    .map_err(|_| TpmRc::FAILURE)?;
                bits_val = u64::from_be_bytes(val_bytes);
            }
            bits_val |= cmd.bits;
            let val_bytes = bits_val.to_be_bytes();
            storage
                .write_item(nv_index, metadata_size, &val_bytes)
                .map_err(|_| TpmRc::FAILURE)?;

            if !nv_public.attributes.contains(TpmaNv::WRITTEN) {
                let mut updated_public = nv_public;
                updated_public.attributes.insert(TpmaNv::WRITTEN);
                let updated_public_info =
                    Ok::<_, TpmRc>(updated_public.as_tpm2b()).map_err(|_| TpmRc::FAILURE)?;

                let mut write_buf = [0u8; 1536];
                let offset = marshal_nv_header(&nv_auth, &updated_public_info, &mut write_buf)?;
                storage
                    .write_item(nv_index, 0, &write_buf[..offset])
                    .map_err(|_| TpmRc::FAILURE)?;
            }
        }

        if nv_public.attributes.contains(TpmaNv::ORDERLY) {
            self.nv_clear_orderly()?;
            self.global_state.update_nv |= crate::engine::UT_ORDERLY;
        } else {
            self.global_state.update_nv |= crate::engine::UT_NV;
        }

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

        if num_sessions < 1 {
            return Err(TpmRc::AUTH_MISSING);
        }

        // 1. Read metadata from storage
        let (metadata_size, nv_public, _nv_auth, public_info, total_len, saved_buf) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;

            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (metadata_size, nv_public, nv_auth, public_info) =
                unmarshal_nv_header(&read_buf[..read_len])?;
            (
                metadata_size as u16,
                nv_public,
                nv_auth,
                public_info,
                read_len,
                read_buf,
            )
        };

        // 2. Check authorization on nv_index
        let provided_auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];
        let auth_0 = provided_auths[0];

        if auth_0.session_handle == Handle::RS_PW {
            return Err(TpmRc::AUTH_TYPE);
        } else if let Some(session_state) = self.global_state.session(auth_0.session_handle.0)
            && session_state.session_type == tpm2::TpmSe::Policy
            && session_state.command_code != 0
            && session_state.command_code != tpm2::TpmCc::NVChangeAuth.code()
        {
            return Err(TpmRc::POLICY_FAIL.with(Position::session(1)));
        }

        // 3. Check newAuth size vs digest size of nameAlg
        let digest_size = nv_public.name_alg.digest_size();
        let new_auth_slice = cmd.new_auth.get_buffer();
        let stripped = crate::util::strip_trailing_zeros(new_auth_slice);
        if stripped.len() > digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        let new_nv_auth = Tpm2bAuth::from_bytes(stripped)
            .map_err(|_| TpmRc::SIZE.with(Position::parameter(1)))?;

        // 4. Write updated metadata to offset 0 (and preserve user data if size changed)
        {
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            let mut write_buf = [0u8; 1536];
            let offset = marshal_nv_header(&new_nv_auth, &public_info, &mut write_buf)?;
            let user_data_len = total_len.saturating_sub(metadata_size as usize);
            if (offset as u16) + (user_data_len as u16) != (total_len as u16) {
                storage
                    .resize_item(nv_index, (offset as u16) + (user_data_len as u16))
                    .map_err(|_| TpmRc::FAILURE)?;
            }
            storage
                .write_item(nv_index, 0, &write_buf[..offset])
                .map_err(|_| TpmRc::FAILURE)?;
            if user_data_len > 0 {
                storage
                    .write_item(
                        nv_index,
                        offset as u16,
                        &saved_buf[metadata_size as usize..total_len],
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
            }
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
