/// These tests are enabled with the tpm-simulator-tests feature and only run against a TPM
/// simulator. The docker container in this crate builds a simulator binary, or you may provide
/// your own simulator binary by setting the TPM_RS_SIMULATOR env var for `cargo test` on the
/// command line.
///
/// To run locally in the docker container:
///  `cd client && docker compose run simulator_tests``
///
/// These tests must be run with `--test-threads=1`, because they use a single TCP port.

#[cfg(feature = "tpm-simulator-tests")]
mod common;

#[cfg(feature = "tpm-simulator-tests")]
mod simulator_tests {

    use crate::common::tcp_simulator::*;
    use tpm2_rs_base::{
        commands::StartupCmd,
        constants::{TPM2ECCCurve, TPM2SU, TPM2_SHA256_DIGEST_SIZE},
        PublicParmsAndId, Tpm2bDigest, Tpm2bSimple, TpmaObject, TpmiAlgHash, TpmiEccCurve,
        TpmiRhHierarchy, TpmsEccPoint, TpmsEmpty, TpmsSchemeHash, TpmtEccScheme, TpmtKdfScheme,
        TpmtPublic, TpmtSymDefObject,
    };
    use tpm2_rs_client::run_command;
    use tpm2_rs_features_client::*;

    const TPM_SIMULATOR_ENV_VAR: &str = "TPM_RS_SIMULATOR";
    fn get_simulator_path() -> String {
        std::env::var(TPM_SIMULATOR_ENV_VAR)
            .expect("Set TPM_RS_SIMULATOR to run tests against a simulator")
    }

    fn unrestricted_signing_key_template() -> TpmtPublic {
        TpmtPublic {
            name_alg: TpmiAlgHash::SHA256,
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                tpm2_rs_base::TpmsEccParms {
                    symmetric: TpmtSymDefObject::Null(TpmsEmpty, TpmsEmpty),
                    scheme: TpmtEccScheme::Ecdsa(TpmsSchemeHash {
                        hash_alg: TpmiAlgHash::SHA256,
                    }),
                    curve_id: TpmiEccCurve::new(TPM2ECCCurve::NistP256),
                    kdf: TpmtKdfScheme::Null(TpmsEmpty),
                },
                TpmsEccPoint::default(),
            ),
        }
    }

    #[test]
    fn test_startup_tpm() {
        let (_sim_lifeline, mut tpm) = run_tpm_simulator(&get_simulator_path()).unwrap();
        let startup = StartupCmd {
            startup_type: TPM2SU::Clear,
        };
        assert!(run_command(&startup, &mut tpm).is_ok());
    }

    // If test_startup_tpm passes, this will not panic.
    fn get_started_tpm() -> (TpmSim, TpmClient<TcpTpm>) {
        let (sim_lifeline, mut tpm) = run_tpm_simulator(&get_simulator_path()).unwrap();
        let startup = StartupCmd {
            startup_type: TPM2SU::Clear,
        };
        run_command(&startup, &mut tpm).unwrap();
        (sim_lifeline, TpmClient { tpm: tpm })
    }

    #[test]
    fn test_get_manufacturer_id() {
        let (_sim_lifeline, mut client) = get_started_tpm();
        assert!(client.get_manufacturer_id().is_ok());
    }

    #[test]
    fn test_create_primary() {
        let (_sim_lifeline, mut client) = get_started_tpm();

        let mut template = unrestricted_signing_key_template();
        template.auth_policy =
            Tpm2bDigest::from_bytes(&[0u8; TPM2_SHA256_DIGEST_SIZE as usize]).unwrap();
        assert!(client
            .create_primary(TpmiRhHierarchy::Endorsement, template, None)
            .is_ok());
    }
}
