//! Command-line surface: global flags plus subcommands.
//!
//! The CLI lives beside the config overlay because `load` takes the parsed
//! command line as its highest-precedence layer.

use std::ffi::OsString;
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
  /// Curate an `oauth2` registry fragment from a discovery or `OpenAPI`
  /// document. Reads a local file; prints TOML to stdout. Never touches
  /// the bundled registry or runtime config.
  Registry(RegistryArgs),
  /// Generate this workspace's stack as an editable file: the workspace
  /// `[rules.*]` config when it has none, the CA, the agent entrypoint, and
  /// the compose file. Existing files are left untouched; the stack is
  /// regenerated when the workspace config changed since it was generated.
  Init(InitArgs),
  /// Enter the confined agent environment in one go: generate what is missing,
  /// start the stack, then run the configured shell (or the command after
  /// `--`). The stack keeps running when that exits, unless `--rm` stops it.
  Agent(AgentArgs),
  /// Start the layered compose project `hodor init` generated.
  Up(WorkspaceArgs),
  /// Stop the layered compose project.
  Down(WorkspaceArgs),
  /// Read the stack's logs.
  Logs(LogsArgs),
}

/// Arguments for the commands that address a workspace and nothing else.
#[derive(clap::Args, Debug, Clone)]
pub struct WorkspaceArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
}

/// Arguments for [`Command::Logs`].
#[derive(clap::Args, Debug, Clone)]
pub struct LogsArgs {
  /// Workspace directory; defaults to the current directory. A flag rather
  /// than a positional because the service names already take that slot.
  #[arg(long)]
  pub workspace: Option<PathBuf>,
  /// Keep the output open and follow new lines.
  #[arg(long, short = 'f')]
  pub follow: bool,
  /// Print bare log lines, without the service name in front of each one.
  #[arg(long)]
  pub no_log_prefix: bool,
  /// How many lines to show from the end of each service's log; `all` for
  /// everything.
  #[arg(long, default_value = "all")]
  pub tail: String,
  /// Services to read; every service in the stack when none are named.
  #[arg(value_name = "SERVICE")]
  pub services: Vec<String>,
}

/// Arguments for [`Command::Init`].
#[derive(clap::Args, Debug, Clone)]
pub struct InitArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
  /// Capture backend the generated stack runs. Linux only: the backend is
  /// chosen at generation time and defaults to `ebpf`.
  #[arg(long, value_enum)]
  pub backend: Option<ProxyBackend>,
}

/// Arguments for [`Command::Agent`].
#[derive(clap::Args, Debug, Clone)]
pub struct AgentArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
  /// Stop the workspace stack when the shell or command exits; without it the
  /// stack keeps running.
  #[arg(long)]
  pub rm: bool,
  /// Command to run in the agent instead of the configured shell; the
  /// arguments after `--`.
  #[arg(last = true)]
  pub command: Vec<OsString>,
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
  /// process on the machine. Without `enclosing`, hodor must live *outside* the
  /// named cgroup. The literal `enclosing` attaches to the cgroup this
  /// process's own cgroup lives under — what a stack that gives both services
  /// one `cgroup_parent` needs, since the daemon resolves that parent relative
  /// to its own cgroup root. hodor is a member of the attached subtree then,
  /// and the recorded proxy PID is what keeps its own sockets out of the loop.
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

/// `hodor registry` subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum RegistryCommand {
  /// Map an OIDC discovery document (`<issuer>/.well-known/openid-configuration`)
  /// onto one `[providers.<slug>.oauth2]` fragment. The flow comes from
  /// `grant_types_supported`.
  FromOidc(ImportArgs),
  /// Map an `OpenAPI` document's `components.securitySchemes` (`type: oauth2`)
  /// onto fragments, one per scheme. `openIdConnect` schemes are reported
  /// and skipped.
  FromOpenapi(ImportArgs),
}

/// Arguments for [`Command::Registry`].
#[derive(clap::Args, Debug, Clone)]
pub struct RegistryArgs {
  /// Which document kind to import.
  #[command(subcommand)]
  pub command: RegistryCommand,
}

/// Arguments for the registry import commands.
#[derive(clap::Args, Debug, Clone)]
pub struct ImportArgs {
  /// Path to the saved discovery or `OpenAPI` JSON document.
  pub file: PathBuf,
  /// Provider slug for the generated `[providers.<slug>]` entry.
  pub slug: String,
  /// Environment name the generated entry claims.
  pub env: String,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn agent_takes_a_command_after_the_separator_and_no_workspace() {
    let cli = Cli::try_parse_from(["hodor", "agent", "--", "claude", "--resume"]).unwrap();
    match cli.command {
      Some(Command::Agent(args)) => {
        assert_eq!(args.workspace, None);
        assert_eq!(args.command, vec![OsString::from("claude"), OsString::from("--resume")]);
      }
      other => panic!("expected agent, got {other:?}"),
    }
  }

  #[test]
  fn agent_defaults_to_the_configured_shell_without_a_command() {
    let cli = Cli::try_parse_from(["hodor", "agent", "/srv/project"]).unwrap();
    match cli.command {
      Some(Command::Agent(args)) => {
        assert_eq!(args.workspace, Some(PathBuf::from("/srv/project")));
        assert!(args.command.is_empty());
      }
      other => panic!("expected agent, got {other:?}"),
    }
  }

  #[test]
  fn init_takes_the_backend_flag_and_the_workspace() {
    let cli = Cli::try_parse_from(["hodor", "init", "--backend", "tproxy", "/srv/project"]).unwrap();
    match cli.command {
      Some(Command::Init(args)) => {
        assert_eq!(args.backend, Some(ProxyBackend::Tproxy));
        assert_eq!(args.workspace, Some(PathBuf::from("/srv/project")));
      }
      other => panic!("expected init, got {other:?}"),
    }

    let cli = Cli::try_parse_from(["hodor", "init"]).unwrap();
    match cli.command {
      Some(Command::Init(args)) => assert_eq!(args.backend, None, "the OS default resolves later"),
      other => panic!("expected init, got {other:?}"),
    }
    Cli::try_parse_from(["hodor", "init", "--backend", "sideways"]).unwrap_err();
  }

  #[test]
  fn agent_rm_is_off_until_asked_for() {
    let cli = Cli::try_parse_from(["hodor", "agent", "--rm", "--", "claude"]).unwrap();
    match cli.command {
      Some(Command::Agent(args)) => {
        assert!(args.rm, "--rm stops the stack on exit");
        assert_eq!(args.command, vec![OsString::from("claude")]);
      }
      other => panic!("expected agent, got {other:?}"),
    }

    let cli = Cli::try_parse_from(["hodor", "agent"]).unwrap();
    match cli.command {
      Some(Command::Agent(args)) => assert!(!args.rm, "the stack outlives the agent by default"),
      other => panic!("expected agent, got {other:?}"),
    }
  }

  #[test]
  fn the_stack_commands_take_the_workspace_positional() {
    for argv in [vec!["hodor", "up"], vec!["hodor", "down"]] {
      let cli = Cli::try_parse_from(&argv).unwrap();
      let workspace = match cli.command {
        Some(Command::Up(args) | Command::Down(args)) => args.workspace,
        other => panic!("expected a stack command for {argv:?}, got {other:?}"),
      };
      assert_eq!(workspace, None, "absent means the current directory");
    }

    let cli = Cli::try_parse_from(["hodor", "up", "/srv/project"]).unwrap();
    match cli.command {
      Some(Command::Up(args)) => assert_eq!(args.workspace, Some(PathBuf::from("/srv/project"))),
      other => panic!("expected up, got {other:?}"),
    }
  }

  #[test]
  fn logs_takes_its_flags_service_names_and_workspace() {
    let cli = Cli::try_parse_from([
      "hodor",
      "logs",
      "--follow",
      "--no-log-prefix",
      "--tail",
      "50",
      "--workspace",
      "/srv/project",
      "hodor",
      "agent",
    ])
    .unwrap();
    match cli.command {
      Some(Command::Logs(logs)) => {
        assert!(logs.follow && logs.no_log_prefix);
        assert_eq!(logs.tail, "50");
        assert_eq!(logs.workspace, Some(PathBuf::from("/srv/project")));
        assert_eq!(logs.services, vec!["hodor", "agent"], "one or more services, all by default");
      }
      other => panic!("expected logs, got {other:?}"),
    }

    let cli = Cli::try_parse_from(["hodor", "logs"]).unwrap();
    match cli.command {
      Some(Command::Logs(logs)) => {
        assert!(!logs.follow && !logs.no_log_prefix);
        assert_eq!(logs.tail, "all", "the tail default is everything");
        assert_eq!(logs.workspace, None, "absent means the current directory");
        assert!(logs.services.is_empty(), "no services means all of them");
      }
      other => panic!("expected logs, got {other:?}"),
    }
  }
}
