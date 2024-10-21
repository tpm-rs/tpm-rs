use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rwtpm")]
#[command(version = "0.1")]
#[command(about = "rustware tpm implementation for userspace", long_about = None)]
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
pub struct SocketArgs {
    /// Expose TPM over TCP/IP based socket
    #[arg(short, long, global = true)]
    pub saddr: Option<String>,
    /// Expose TPM over Unix based socket
    #[arg(short, long, global = true)]
    pub unixio: Option<String>,
}
