mod socket;

use crate::args::Command;
use socket::open_socket;
use std::io::{Read, Result, Write};

pub trait Stream: Read + Write {}

impl<T: Read + Write> Stream for T {}

pub fn open_stream(command: &Command) -> Result<Box<dyn Stream>> {
    match command {
        Command::Socket(socket_args) => open_socket(socket_args),
        Command::Chardev => todo!(),
        Command::Cuse => todo!(),
    }
}
