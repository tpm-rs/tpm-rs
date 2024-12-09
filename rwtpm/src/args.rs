use clap::{ArgGroup, Args, Parser, Subcommand};
use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Parser)]
#[command(name = "rwtpm")]
#[command(version = "0.1")]
#[command(about = "rustware TPM implementation for userspace", long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Sets the level of verbosity (use -v, -vv, -vvv)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbosity: u8,
    /// Disable colored logs.
    #[arg(short, long, global = true)]
    pub no_color: bool,
    /// Specify file to redirect logs to.
    #[arg(short, long, global = true)]
    pub logfile: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create socket based software tpm instance
    Socket(SocketArgs),
    Chardev,
    Cuse,
}

#[derive(Args)]
#[clap(group(ArgGroup::new("sockets").required(true).args(&["tcp", "unixio"])))]
pub struct SocketArgs {
    /// Expose TPM over TCP/IP based socket
    #[arg(short, long, value_parser = validate_socket_address)]
    pub tcp: Option<SocketAddr>,
    /// Expose TPM over Unix based socket
    #[arg(short, long)]
    pub unixio: Option<String>,
}

fn validate_socket_address(addr: &str) -> Result<SocketAddr, String> {
    let mut addrs = addr
        .to_socket_addrs()
        .map_err(|_| format!("Invalid socket address: {}", addr))?;
    addrs
        .next()
        .ok_or_else(|| format!("No valid socket address found for: {}", addr))
}
