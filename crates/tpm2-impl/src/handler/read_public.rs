use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmHt;
use tpm2::commands::{ReadPublic, responses};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::ReadPublic] (`0x173`) command.
    ///
    /// # Description
    /// This command returns the public area, Name, and Qualified Name of a loaded transient or persistent object.
    /// Since this information is public, no authorization is required to execute this command.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.4 (TPM2_ReadPublic).
    ///
    /// # Relationships
    /// - Can be used on objects created by [TpmCc::CreatePrimary](create_primary.rs)
    ///   or loaded by [TpmCc::Load](load.rs) / [TpmCc::LoadExternal](load_external.rs).
    pub fn read_public(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let [object] = request.try_unmarshal_handles::<ReadPublic>()?;
        check(object, Tpmi::DhObject, Position::handle(1))?;
        let object_handle = object.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal_command::<ReadPublic>([object])?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = match object.handle_type() {
            Some(TpmHt::Transient) => self
                .context
                .lookup_transient_object(self.global_state, object_handle, Position::handle(1))?
                .clone(),
            Some(TpmHt::Persistent) => self
                .context
                .load_persistent_object(self.global_state, object_handle)
                .map_err(|_| TpmRc::HANDLE.with(Position::handle(1)))?,
            _ => return Err(TpmRc::HANDLE.to_rc()),
        };

        let out_public = obj.public.as_tpm2b();

        let rsp = responses::ReadPublic {
            out_public,
            name: obj.name.as_tpm2b(),
            qualified_name: obj.qualified_name.as_tpm2b(),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
