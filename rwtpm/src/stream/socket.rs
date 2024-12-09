use super::Stream;
use crate::args::SocketArgs;
use std::{
    io::Result,
    net::{SocketAddr, TcpListener},
    os::unix::net::UnixListener,
};
use tracing::debug;

pub fn open_socket(socket_args: &SocketArgs) -> Result<Box<dyn Stream>> {
    match (socket_args.tcp, &socket_args.unixio) {
        (None, Some(unixio)) => open_unixio_socket(unixio),
        (Some(saddr), None) => open_tcp_socket(&saddr),
        _ => unreachable!(),
    }
}

fn open_tcp_socket(saddr: &SocketAddr) -> Result<Box<dyn Stream>> {
    debug!("Opening UnixListener at {}", saddr);
    let listener = TcpListener::bind(saddr)?;
    debug!("Waiting for a connection");
    let (stream, saddr) = listener.accept()?;
    debug!("received connection from {}", saddr);
    Ok(Box::new(stream))
}

fn open_unixio_socket(path: &str) -> Result<Box<dyn Stream>> {
    debug!("opening UnixListener at {path}");
    let listener = UnixListener::bind(path)?;
    debug!("waiting for a connection");
    let (stream, saddr) = listener.accept()?;
    debug!("received connection from {:?}", saddr);
    Ok(Box::new(stream))
}
