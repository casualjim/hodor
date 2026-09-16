//! Command-line surface: global flags plus subcommands.
//!
//! The CLI lives beside the config overlay because `load` takes the parsed
//! command line as its highest-precedence layer.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Command-line interface: global flags plus a subcommand.
#[derive(Parser, Debug)]
#[command(name = "hodor", about = "grant-scoped MITM proxy")]
pub struct Cli {
  /// Config file replacing the project layer.
  #[arg(long, global = true, help = "config file replacing the project layer")]
  pub config: Option<PathBuf>,
  /// Subcommand; absent means `serve`.
  #[command(subcommand)]
  pub command: Option<Command>,
}

/// Available subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
  /// Serve the proxy: the explicit listener, plus transparent capture when
  /// `--proxy-backend` selects one.
  Serve(ServeArgs),
  /// Print the deterministic fake for an env var name.
  Fake(FakeArgs),
  /// Generate (or load) the CA, print its certificate PEM to stdout, and write
  /// the certificate and the key beside the CA file as `ca.crt` and `ca.key`.
  ///
  /// The printed PEM is the trust anchor to install into workload
  /// containers; the private key stays in the CA file and in `ca.key`.
  Ca,
  /// Print `[rules.*]` for the secrets this workspace can get (fnox ∩ registry).
  Rules,
  /// Confine a workspace: generate its stack once as an editable file, then
  /// start and stop the layered docker compose project.
  Confine(ConfineArgs),
}

/// Arguments for [`Command::Confine`].
#[derive(clap::Args, Debug, Clone)]
pub struct ConfineArgs {
  /// What to do with the confined workspace.
  #[command(subcommand)]
  pub action: ConfineAction,
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
}

/// What to do with the confined workspace.
#[derive(Subcommand, Debug, Clone)]
pub enum ConfineAction {
  /// Generate the workspace stack into
  /// `<state-dir>/hodor/ws/<slug>/compose.yml` if absent, and write the CA and
  /// agent entrypoint the stack mounts when they are missing; existing files
  /// are left untouched so edits survive.
  Init,
  /// Start the layered compose project from the files on disk.
  Up,
  /// Stop the layered compose project.
  Down,
  /// Enter the agent environment in the translated workspace directory.
  Shell,
}

/// Arguments for [`Command::Serve`].
#[derive(clap::Args, Debug, Clone, Default)]
pub struct ServeArgs {
  /// Proxy settings (CLI layer of the config overlay).
  #[command(flatten)]
  pub proxy: <crate::config::ProxyCfg as confique::Config>::Layer,
  // Deployment-mode switch: CLI + env only, deliberately not a file key —
  // both backends mutate host routes/nft rules and must be an explicit
  // intention, not ambient configuration.
  /// Capture traffic transparently with this backend, instead of only
  /// serving the explicit listener. `none` (the default) runs the explicit
  /// proxy alone.
  #[arg(long, env = "HODOR_PROXY_BACKEND", value_enum, default_value_t = ProxyBackend::None)]
  pub proxy_backend: ProxyBackend,
  /// Allow unscoped TPROXY rules in the current (host) network namespace.
  /// Without this, unscoped capture outside an isolated netns is refused:
  /// the rules reroute every outbound TCP packet, and an unclean exit
  /// leaves the machine without TCP egress until manually cleaned.
  #[arg(
    long,
    env = "HODOR_TPROXY_ALLOW_ROOT_NETNS",
    help = "allow unscoped TPROXY rules in the host network namespace (disposable machines only)"
  )]
  pub tproxy_allow_root_netns: bool,
  /// cgroup v2 directory whose member processes get captured by
  /// `--proxy-backend ebpf`. Required for that backend: there is deliberately
  /// no default, because defaulting to the root cgroup would capture every
  /// process on the machine. hodor must live *outside* this cgroup.
  #[arg(long, env = "HODOR_EBPF_CGROUP")]
  pub ebpf_cgroup: Option<PathBuf>,
}

/// Transparent capture backend. All three are peers: same interception contract
/// (the destination is the identity), different mechanism and different UDP
/// behaviour.
#[derive(clap::ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
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

/// Arguments for [`Command::Fake`].
#[derive(clap::Args, Debug, Clone)]
pub struct FakeArgs {
  /// Env var name the fake is derived from.
  pub env: String,
  /// Explicit fake pattern overriding the prefix default.
  #[arg(long)]
  pub pattern: Option<String>,
}
