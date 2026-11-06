//! Vendor-specific commands (command codes with the `V` bit, `CC_VEND`).
//!
//! * `TPM2_Vendor_TCG_Test` (TPM 2.0 Part 3, "Vendor Specific"): "a placeholder to allow
//!   testing of the dispatch code". It has no handles, and its response returns the command's
//!   `inputData` as `outputData` (the reference's `Vendor_TCG_Test.c`). Both parameters are
//!   `TPM2B_DATA`, so the command allows parameter encryption in both directions (Part 1: "Any
//!   first parameter can be encrypted as long as the parameter has a size field").
//! * The platform's vendor commands ([`crate::Platform::vendor_commands`]), which the platform
//!   executes ([`crate::Platform::execute_vendor_command`]): no handles and no sessions.

use crate::Platform;
use crate::engine::{MAX_COMMAND_SIZE, MAX_RESPONSE_SIZE};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{VendorTcgTest, responses};
use tpm2::errors::TpmRc;

use crate::{handler::CommandHandler, req_resp::RequestThenResponse};

impl<'b, P: Platform> CommandHandler<'b, P> {
    /// Handles the [TpmCc::VendorTcgTest] (`0x20000000`) command.
    ///
    /// # Description
    /// A placeholder vendor command that tests the dispatch of vendor-specific commands: it
    /// returns its `inputData` as `outputData`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, "Vendor Specific",
    /// TPM2_Vendor_TCG_Test.
    pub fn vendor_tcg_test(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<VendorTcgTest>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<VendorTcgTest>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let rsp = responses::VendorTcgTest {
            output_data: cmd.input_data,
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])
    }

    /// Handles a vendor command of the platform ([`Platform::vendor_commands`]): its whole
    /// parameter area goes to [`Platform::execute_vendor_command`], whose response parameters
    /// become the response (the command has no handles and no sessions).
    pub fn platform_vendor_command(
        &mut self,
        cc: TpmCc,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let mut parameters = [0u8; MAX_COMMAND_SIZE];
        let len = request.remaining_bytes();
        let parameters = parameters.get_mut(..len).ok_or(TpmRc::FAILURE)?;
        request.read_bytes(parameters).ok_or(TpmRc::FAILURE)?;

        let mut rsp = [0u8; MAX_RESPONSE_SIZE];
        let written = self
            .context
            .platform
            .execute_vendor_command(cc, parameters, &mut rsp)?;
        let rsp = rsp.get(..written).ok_or(TpmRc::FAILURE)?;
        let mut response = request.into_response();
        response.write(rsp).map_err(|_| TpmRc::FAILURE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{
        ImplementedCommands, SUPPORTED_COMMANDS, VENDOR_COMMANDS, command_list_start,
        get_command_attribute, is_command_supported, is_session_allowed,
    };
    use crate::platform::VendorCommand;
    use tpm2::TpmaCc;

    #[test]
    fn vendor_commands_are_sorted_vendor_codes() {
        assert_eq!(VENDOR_COMMANDS[0], TpmCc::VendorTcgTest);
        assert!(VENDOR_COMMANDS.iter().all(|cc| cc.is_vendor()));
        assert!(
            VENDOR_COMMANDS
                .windows(2)
                .all(|w| w[0].code() < w[1].code())
        );
        assert!(SUPPORTED_COMMANDS.iter().all(|cc| !cc.is_vendor()));
        assert_eq!(VENDOR_COMMANDS, &[TpmCc::VendorTcgTest]);
        assert!(is_command_supported(TpmCc::VendorTcgTest));
        assert!(!is_command_supported(TpmCc::new(0x2000_0100)));
        assert!(!is_command_supported(TpmCc::NTC2GetConfig));
    }

    #[test]
    fn implemented_commands_list_library_then_vendor() {
        let commands = ImplementedCommands::BUILTIN;
        let all: alloc::vec::Vec<TpmCc> = commands.in_order().collect();
        assert_eq!(all.len(), commands.total());
        assert!(all.windows(2).all(|w| w[0].code() < w[1].code()));
        let (library, vendor) = all.split_at(SUPPORTED_COMMANDS.len());
        assert!(library.iter().all(|cc| SUPPORTED_COMMANDS.contains(cc)));
        assert_eq!(vendor, VENDOR_COMMANDS);
    }

    /// The platform's vendor commands join the engine's in ascending order; codes without
    /// the `V` bit, duplicates and the engine's own command are ignored.
    #[test]
    fn implemented_commands_with_platform_vendor_commands() {
        let v = |code: u32| VendorCommand {
            code: TpmCc::new(code),
            attributes: TpmaCc::default(),
        };
        let platform = [
            v(0x2000_0213),
            v(0x2000_0211),
            v(0x0000_0144),
            v(0x2000_0211),
            v(0x2000_0000),
        ];
        let commands = ImplementedCommands::new(&platform);
        assert_eq!(
            commands.vendor(),
            &[
                TpmCc::VendorTcgTest,
                TpmCc::new(0x2000_0211),
                TpmCc::new(0x2000_0213)
            ]
        );
        assert_eq!(commands.total(), SUPPORTED_COMMANDS.len() + 3);
        assert!(commands.is_supported(TpmCc::new(0x2000_0213)));
        assert!(!commands.is_supported(TpmCc::new(0x2000_0212)));
        let all: alloc::vec::Vec<TpmCc> = commands.in_order().collect();
        assert!(all.windows(2).all(|w| w[0].code() < w[1].code()));

        let many: alloc::vec::Vec<VendorCommand> = (0..40).map(|i| v(0x2000_1000 + i)).collect();
        assert_eq!(
            ImplementedCommands::new(&many).vendor().len(),
            1 + crate::MAX_PLATFORM_VENDOR_COMMANDS
        );
    }

    #[test]
    fn command_list_start_rejects_non_command_codes() {
        for property in [0, 0x144, 0xFFFF, 0x2000_0000, 0x2000_FFFF] {
            assert_eq!(
                command_list_start(property),
                Some(property),
                "{property:#x}"
            );
        }
        for property in [0x1_0000, 0x1000_0000, 0x2001_0000, 0x4000_0000, 0xFFFF_FFFF] {
            assert_eq!(command_list_start(property), None, "{property:#x}");
        }
    }

    #[test]
    fn vendor_command_attributes() {
        assert_eq!(get_command_attribute(TpmCc::VendorTcgTest), TpmaCc::V);
        assert!(is_session_allowed(TpmCc::VendorTcgTest));
    }
}
