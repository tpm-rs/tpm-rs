use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{ReadPublic, ReadPublicHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::ReadPublic] (`0x18E`) command.
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

        let handles = request.try_unmarshal::<ReadPublicHandles>()?;
        let object_handle = handles.object_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<ReadPublic>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // C `ReadPublic.c`: a sequence object has no public area (`TPM_RC_SEQUENCE`).
        if self
            .global_state
            .find_active_sequence(object_handle)
            .is_some()
        {
            return Err(TpmRc::SEQUENCE);
        }

        let obj = if (0x80000000..=0x80FFFFFF).contains(&object_handle) {
            self.context
                .lookup_transient_object(self.global_state, object_handle, Position::handle(1))?
                .clone()
        } else if object_handle >> 24 == 0x81 {
            self.context
                .load_persistent_object(self.global_state, object_handle)
                .map_err(|_| TpmRc::HANDLE.with(Position::handle(1)))?
        } else {
            // `objectHandle` is a `TPMI_DH_OBJECT`: anything else is an invalid value.
            return Err(TpmRc::VALUE.with(Position::handle(1)));
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
