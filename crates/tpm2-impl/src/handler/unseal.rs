#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{Unseal, responses};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bSensitiveData, TpmaObject};

use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::owned::OwnedPublicParmsAndId;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::Unseal] (`0x15E`) command.
    ///
    /// # Description
    /// This command returns the data portion of a sealed data object (a `KeyedHash` object).
    /// The object must first be loaded, and the caller must satisfy the object's authorization requirements.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 12.7 (TPM2_Unseal).
    ///
    /// # Relationships
    /// - Used to retrieve data sealed inside an object created via [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreatePrimary](create_primary.rs).
    /// - The target object (`item_handle`) must have been loaded into the TPM volatile memory (typically via [TpmCc::Load](load.rs)).
    pub fn unseal(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let [item] = request.try_unmarshal_handles::<Unseal>()?;
        check(item, Tpmi::DhObject, Position::handle(1))?;
        let item_handle = item.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal_command::<Unseal>([item])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Retrieve the loaded object
        let item_obj = self.resolve_object(item_handle, Position::handle(1))?;

        // 2. Verify object type is KeyedHash (Sealed Data Object)
        if !matches!(
            item_obj.public.parms_and_id,
            OwnedPublicParmsAndId::KeyedHash(_, _)
        ) {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }

        // 3. Verify object attributes
        let attributes = item_obj.public.object_attributes;
        if attributes.contains(TpmaObject::RESTRICTED)
            || attributes.contains(TpmaObject::DECRYPT)
            || attributes.contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        // 4. Retrieve unsealed data
        let out_data =
            Tpm2bSensitiveData::new(item_obj.sensitive.as_bytes()).ok_or(TpmRc::FAILURE)?;

        let rsp = responses::Unseal { out_data };

        // 5. Write the response
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
