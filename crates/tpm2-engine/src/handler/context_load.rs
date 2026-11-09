use crate::Platform;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::errors::{Position, TpmRc};

/// `MAX_CONTEXT_SIZE` of this TPM's profile: the capacity of `TPM2B_CONTEXT_SENSITIVE` (TPM 2.0
/// Part 2, Table "Definition of TPM2B_CONTEXT_SENSITIVE Structure": "buffer\[size\]{:MAX_CONTEXT_SIZE}").
/// The value is implementation-specific: 2264 octets by default, or the value of a C reference
/// TPM with the `max-context-size-2168` (the public TCG reference, which has no SHA-512),
/// `max-context-size-2680` (`ibmswtpm2`) or `max-context-size-4344` (the TCG reference version
/// 185) feature; with several, the largest applies.
pub(crate) const MAX_CONTEXT_SIZE: usize = if cfg!(feature = "max-context-size-4344") {
    4344
} else if cfg!(feature = "max-context-size-2680") {
    2680
} else if cfg!(feature = "max-context-size-2168") {
    2168
} else {
    2264
};

/// The capacity of `TPM2B_CONTEXT_DATA`: TPM 2.0 Part 2, Table "Definition of TPM2B_CONTEXT_DATA
/// Structure": "buffer\[size\] {:sizeof(TPMS_CONTEXT_DATA)}", where Table "Definition of
/// TPMS_CONTEXT_DATA Structure" is "integrity | TPM2B_DIGEST" followed by "encrypted |
/// TPM2B_CONTEXT_SENSITIVE": `(2 + sizeof(TPMU_HA)) + (2 + MAX_CONTEXT_SIZE)`, with the largest
/// implemented digest (SHA-512, 64 octets). A larger `contextBlob` size is `TPM_RC_SIZE` while it
/// is unmarshaled, before any missing bytes (`TPM_RC_INSUFFICIENT`).
pub(crate) const CONTEXT_DATA_CAPACITY: usize = (2 + 64) + (2 + MAX_CONTEXT_SIZE);

impl<'b, P: Platform> CommandHandler<'b, P> {
    /// Handles the [TpmCc::ContextLoad] (`0x113`) command.
    ///
    /// # Description
    /// This command is used to reload an object or session context back into the TPM's volatile memory
    /// from a context blob that was previously returned by [TpmCc::ContextSave](context_save.rs).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 28.2 (TPM2_ContextLoad).
    ///
    /// # Relationships
    /// - Re-establishes a saved session or transient object previously serialized by [TpmCc::ContextSave](context_save.rs).
    /// - Unlike transient objects, persistent objects cannot be saved or loaded using context commands (use [TpmCc::EvictControl](evict_control.rs) instead).
    pub fn context_load(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let sequence = request
            .try_unmarshal::<u64>()
            .map_err(|e| e.with_position(Position::parameter(1)))?;
        let saved_handle = request
            .try_unmarshal::<Handle>()
            .map_err(|e| e.with_position(Position::parameter(1)))?;
        // TPM 2.0 Part 2, Table "Definition of (TPM_HANDLE) TPMI_DH_SAVED Type": "{HMAC_SESSION_FIRST
        // : HMAC_SESSION_LAST} | an HMAC session context", "{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}
        // | a policy session context", "0x80000000", "0x80000001", "0x80000002", "#TPM_RC_VALUE";
        // and TPM_HC: "HMAC_SESSION_LAST | (HMAC_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1)". A
        // session handle beyond MAX_ACTIVE_SESSIONS fails here, before `hierarchy` is read.
        if tpm2::TpmiDhSaved::try_from(saved_handle).is_err() {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let hierarchy = request
            .try_unmarshal::<Handle>()
            .map_err(|e| e.with_position(Position::parameter(1)))?;
        // `TPMI_RH_HIERARCHY+`, including the firmware-limited and SVN-limited hierarchies (Part 2,
        // Table "Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY Type"), whose derived proof
        // protects the context (`resolve_hierarchy_proof`; `TPM_RC_FW_LIMITED`/
        // `TPM_RC_SVN_LIMITED` if their additional secret is unavailable).
        if tpm2::TpmiRhHierarchy::try_from(hierarchy).is_err() {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let blob_size = request
            .try_unmarshal::<u16>()
            .map_err(|e| e.with_position(Position::parameter(1)))? as usize;
        if blob_size > CONTEXT_DATA_CAPACITY {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        if request.remaining_bytes() < blob_size {
            return Err(TpmRc::INSUFFICIENT.with(Position::parameter(1)));
        }
        if request.remaining_bytes() > blob_size {
            return Err(TpmRc::SIZE.to_rc());
        }
        let blob = request
            .read_slice(blob_size)
            .ok_or(TpmRc::INSUFFICIENT.with(Position::parameter(1)))?;

        // The context of the TCG reference (`context_format.rs`).
        let loaded_handle = self.tcg_context_load(sequence, saved_handle, hierarchy, blob)?;
        let rsp = responses::ContextLoad {
            loaded_handle: Handle(loaded_handle),
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])
    }
}
