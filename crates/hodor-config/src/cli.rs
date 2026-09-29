//! Command-line surface: global flags, the subcommand trait, and the backend
//! switch shared by generation and serving.
//!
//! The globals live beside the config overlay because [`load`](crate::config::load)
//! takes them as its highest-precedence layer. Each subcommand's args struct
//! lives with its implementation — workspace commands in `hodor-compose`, the
//! rest in the binary — and implements [`CliCommand`].

use std::path::PathBuf;

use clap::{Args, ValueEnum};

/// Global flags, flattened into the binary's parser.
#[derive(Args, Debug, Clone)]
pub struct Cli {
  /// Config file replacing the project layer.
  #[arg(long, global = true, help = "config file replacing the project layer")]
  pub config: Option<PathBuf>,
}

/// One subcommand: its args struct plus how it runs. The binary dispatches
/// each parsed subcommand through this one method, so adding a command is a
/// new args struct plus one impl — never another match arm with inline logic.
pub trait CliCommand {
  /// This command's failure; the binary renders it.
  type Error;
  /// Run the command against the parsed globals.
  ///
  /// `hodor_version` is the binary's own version for anything naming the
  /// hodor image; commands that need nothing versioned ignore it.
  ///
  /// # Errors
  ///
  /// Returns whatever the command's own fallibility is: a missing workspace,
  /// an unreadable file, a failed child process.
  fn run(self, cli: &Cli, hodor_version: &str) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Transparent capture backend. All three are peers: same interception contract
/// (the destination is the identity), different mechanism and different UDP
/// behaviour.
#[derive(ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProxyBackend {
  /// Explicit listener only; no transparent capture.
  #[default]
  None,
  /// Userspace: a TUN device plus an in-process TCP/IP stack, which also
  /// relays UDP (DNS to the system resolver, QUIC dropped). Needs root.
  Tun,
  /// Kernel: nftables rules and policy routes hand TCP to an
  /// `IP_TRANSPARENT` listener; UDP passes through untouched. Needs
  /// `CAP_NET_ADMIN`.
  Tproxy,
  /// Kernel: cgroup socket hooks rewrite destinations to loopback
  /// listeners; captures TCP and connected UDP (relay only). Needs
  /// `CAP_BPF` + `CAP_NET_ADMIN`, and a cgroup holding the workload with
  /// hodor itself outside it.
  Ebpf,
}
