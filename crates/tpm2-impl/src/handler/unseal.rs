#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{Unseal, UnsealHandles};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bSensitiveData, TpmaObject};

use crate::owned::OwnedPublicParmsAndId;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::crypto::{CryptoProvider, Rng};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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

        let handles = request.try_unmarshal::<UnsealHandles>()?;
        let item_handle = handles.item_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<Unseal>()?;
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
        if item_obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            || item_obj
                .public
                .object_attributes
                .contains(TpmaObject::DECRYPT)
            || item_obj
                .public
                .object_attributes
                .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        // 4. Retrieve unsealed data
        let out_data = Tpm2bSensitiveData::from_bytes(&item_obj.private[..item_obj.private_len])
            .map_err(|_| TpmRc::FAILURE)?;

        let rsp = responses::Unseal { out_data };

        // 5. Write the response
        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
