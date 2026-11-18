//! Tests that need no simulator binary. The tests that run one are in
//! `tpm2-client`.

use super::*;

/// Reads `N` bytes that a client sent.
fn read_bytes<const N: usize>(stream: &mut TcpStream) -> [u8; N] {
    let mut bytes = [0; N];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

#[test]
fn connection_speaks_the_simulator_protocol() {
    let tpm = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let platform = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut connection =
        TcpConnection::connect(tpm.local_addr().unwrap(), platform.local_addr().unwrap()).unwrap();

    // Plays the simulator's side of each request made below.
    let simulator = thread::spawn(move || {
        let (mut tpm, _) = tpm.accept().unwrap();
        let (mut platform, _) = platform.accept().unwrap();

        // Remote handshake: command code and client version in; server
        // version, endpoint information and terminator out.
        assert_eq!(read_bytes(&mut tpm), [0, 0, 0, 15, 0, 0, 0, 1]);
        tpm.write_all(&[0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 0])
            .unwrap();

        // Power on: signal in, terminator out.
        assert_eq!(read_bytes(&mut platform), [0, 0, 0, 1]);
        platform.write_all(&[0; 4]).unwrap();

        // Send command: command code, locality, length and command in; length,
        // response and terminator out.
        assert_eq!(read_bytes(&mut tpm), [0, 0, 0, 8, 2, 0, 0, 0, 3, 1, 2, 3]);
        tpm.write_all(&[0, 0, 0, 3, 4, 5, 6, 0, 0, 0, 0]).unwrap();

        // Stop: command code in on each port, then the client hangs up.
        for mut stream in [platform, tpm] {
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            assert_eq!(rest, [0, 0, 0, 21]);
        }
    });

    let handshake = connection.remote_handshake(1).unwrap();
    assert_eq!(handshake.server_version(), 1);
    assert_eq!(handshake.endpoint_info(), 7);

    connection
        .platform_signal(SimulatorPlatformSignal::PowerOn)
        .unwrap();

    connection.set_locality(2);
    let mut response = [0; 8];
    let response = connection.transact(&[1, 2, 3], &mut response).unwrap();
    assert_eq!(response, [4, 5, 6]);

    connection.stop_simulator().unwrap();
    simulator.join().unwrap();
}

#[test]
fn launch_needs_an_absolute_path() {
    let err = TcpSimulator::launch_in(Path::new("simulator"), Path::new("unused")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err}");
    assert!(!Path::new("unused").exists());
}

#[cfg(feature = "tempfile")]
#[test]
fn launch_fails_when_the_program_exits() {
    // This test program is not a simulator. Given a port number, it runs the
    // tests with that number in their name (there are none), and exits.
    let not_a_simulator = std::env::current_exe().unwrap();
    let err = TcpSimulator::launch(&not_a_simulator).unwrap_err();
    assert!(err.to_string().contains("exited during startup"), "{err}");
}
