use crate::get_started_tpm;
use tpm2_rs_base::commands::GetCapabilityCmd;
use tpm2_rs_base::constants::{TpmCap, TpmPt};
use tpm2_rs_base::{TpmlTaggedTpmProperty, TpmsCapabilityData, TpmsTaggedProperty};
use tpm2_rs_client::run_command;

#[test]
fn test_get_capability_manufacturer_id() {
    let (_sim_lifeline, mut tpm) = get_started_tpm();

    let mut expected = TpmlTaggedTpmProperty {
        count: 1,
        tpm_property: [TpmsTaggedProperty::default(); 127],
    };

    expected.tpm_property[0] = TpmsTaggedProperty {
        property: TpmPt::Manufacturer,
        value: 0x58595A20,
    };

    let command = GetCapabilityCmd {
        capability: TpmCap::TPMProperties,
        property: TpmPt::Manufacturer,
        property_count: 1,
    };

    // We allow panic in test cases.
    let resp = run_command(&command, &mut tpm).expect("Failed running command.");

    // Extract the TpmlTaggedTpmProperty data form the response.
    let TpmsCapabilityData::TpmProperties(received) = resp.capability_data else {
        panic!("Unexpected variant data.")
    };

    assert_eq!(
        received, expected,
        "Received did not match the expected response."
    );
}
