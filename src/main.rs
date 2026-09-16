//! `hodor`: grant-scoped MITM proxy.
//!
//! Terminates client TLS with per-domain leaf certificates, swaps
//! format-valid decoy fakes for real secret values only on URI-grant
//! match, and redacts real values back to fakes on responses. Everything
//! else splices through byte-identical.

mod ca;
mod compose;
mod config;
mod fnox_layers;
mod grants;
mod proxy;
mod secrets;
mod sni;
mod substitute;
#[cfg(target_os = "linux")]
mod tproxy;
#[cfg(all(feature = "tun", target_os = "linux"))]
mod tun;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
  pub proxy: <config::ProxyCfg as confique::Config>::Layer,
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
}

/// Transparent capture backend. Both are peers: same interception contract
/// (the destination is the identity), different mechanism and different UDP
/// behaviour.
#[derive(clap::ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProxyBackend {
  /// Explicit listener only; no transparent capture.
  #[default]
  None,
  /// Userspace: a TUN device plus an in-process TCP/IP stack, which also
  /// relays UDP (DNS to the system resolver, QUIC dropped). Needs root and
  /// a binary built with the `tun` feature.
  Tun,
  /// Kernel: nftables rules and policy routes hand TCP to an
  /// `IP_TRANSPARENT` listener; UDP passes through untouched. Needs
  /// `CAP_NET_ADMIN`.
  Tproxy,
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

/// Resolve the CA file path: config `ca_file` if set, else the default
/// `<config-dir>/hodor/ca.pem`.
fn ca_path(proxy: &config::ProxyCfg) -> eyre::Result<PathBuf> {
  match proxy.ca_file.clone() {
    Some(path) => Ok(path),
    None => dirs::config_dir()
      .map(|dir: PathBuf| dir.join("hodor").join("ca.pem"))
      .ok_or_else(|| eyre::eyre!("unable to resolve user config directory")),
  }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
  ca::install_crypto_provider();
  tracing_subscriber::fmt()
    .pretty()
    .with_line_number(true)
    .with_thread_names(true)
    .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
    .init();
  let cli = Cli::parse();
  let command = cli.command.clone().unwrap_or(Command::Serve(ServeArgs::default()));
  match command {
    Command::Fake(args) => {
      if let Some(pattern) = args.pattern.as_deref() {
        config::validate_pattern(pattern).map_err(|err| eyre::eyre!("bad --pattern: {err}"))?;
      }
      let registry = secrets::Registry::load(config::rules_dir().as_deref())?;
      println!("{}", registry.decoy(&args.env, args.pattern.as_deref()));
      Ok(())
    }
    Command::Ca => {
      let (config, _) = config::load(&cli)?;
      let ca = ca::load_or_generate(&ca_path(&config.proxy)?)?;
      print!("{}", String::from_utf8_lossy(&ca.cert_pem()));
      Ok(())
    }
    Command::Rules => {
      print!("{}", compose::rules_command()?);
      Ok(())
    }
    Command::Confine(args) => {
      let workspace = args.workspace.clone().unwrap_or_else(|| PathBuf::from("."));
      compose::confine_command(&args.action, &workspace)
    }
    Command::Serve(args) => serve(&cli, args).await,
  }
}

/// `hodor serve`: bind the explicit listener, then run the selected capture
/// backend alongside it.
async fn serve(cli: &Cli, args: ServeArgs) -> eyre::Result<()> {
  #[cfg(not(target_os = "linux"))]
  if args.proxy_backend != ProxyBackend::None {
    eyre::bail!("transparent capture (--proxy-backend) is only supported on Linux");
  }
  #[cfg(not(feature = "tun"))]
  if args.proxy_backend == ProxyBackend::Tun {
    eyre::bail!("--proxy-backend tun needs a binary built with the `tun` feature; rebuild with --features tun");
  }
  let (mut config, workspace) = config::load(cli)?;
  let registry = secrets::Registry::load(config::rules_dir().as_deref())?;
  // fnox is needed when a rule has no inline value, and when a provider
  // credential it may declare is missing from the environment.
  let needs_fnox =
    config.rules.values().any(|rule| rule.value.is_none()) || secrets::FNOX_ENV.iter().any(|name| std::env::var_os(name).is_none());
  let fnox = if needs_fnox { secrets::FnoxSource::open()? } else { None };
  if let Some(source) = &fnox {
    for name in secrets::export_provider_env(source).await? {
      tracing::debug!(name, "provider credential taken from fnox");
    }
  }
  secrets::resolve(&mut config, &registry, fnox).await?;
  let resolved = grants::resolve(&config)?;
  if let Some(ws) = &workspace {
    tracing::info!(
      root = %ws.root().display(),
      kind = ?ws.kind(),
      ecosystems = %ws.ecosystem_label(),
      "workspace"
    );
  } else {
    tracing::debug!("no workspace root, global config only");
  }
  let ca = ca::load_or_generate(&ca_path(&resolved.proxy)?)?;
  let listen_addr = resolved.proxy.listen;
  let grant_count = resolved.grants.len();
  #[cfg(target_os = "linux")]
  let fwmark = match args.proxy_backend {
    ProxyBackend::None => None,
    ProxyBackend::Tproxy => Some(tproxy::EGRESS_MARK),
    #[cfg(feature = "tun")]
    ProxyBackend::Tun => Some(tun::FWMARK),
    // Unreachable: `serve` bails on `tun` in a build without the feature.
    #[cfg(not(feature = "tun"))]
    ProxyBackend::Tun => None,
  };
  #[cfg(not(target_os = "linux"))]
  let fwmark = None;
  let state = std::sync::Arc::new(match fwmark {
    Some(mark) => proxy::ProxyState::new(resolved, ca).with_fwmark(mark),
    None => proxy::ProxyState::new(resolved, ca),
  });
  // Bind before capture side effects: a bad listen addr must fail
  // before nft rules and routes touch the host.
  let listener = tokio::net::TcpListener::bind(listen_addr).await?;
  if !listen_addr.ip().is_loopback() {
    tracing::warn!(listen = %listen_addr, "listening on a non-loopback address: anyone reaching this port can trigger real-secret substitution");
  }
  tracing::info!(listen = %listen_addr, grants = grant_count, "serving");
  #[cfg(all(feature = "tun", target_os = "linux"))]
  if args.proxy_backend == ProxyBackend::Tun {
    let tun_state = std::sync::Arc::clone(&state);
    let mut tun_handle = tokio::spawn(async move { tun::run_tun(tun_state).await });
    // Fail closed: capture was explicitly requested, so a dead TUN ends
    // the process instead of silently serving explicit-proxy only.
    return tokio::select! {
      result = proxy::serve(listener, state) => result,
      tun_result = &mut tun_handle => match tun_result {
        Ok(inner) => inner.map_err(|err| eyre::eyre!("TUN capture failed: {err:?}")),
        Err(err) => Err(eyre::eyre!("TUN task failed: {err}")),
      },
      // Dropping the capture task runs its teardown guard, which removes
      // the policy routes; a leaked default route in the capture table
      // blackholes all egress. Handlers live here at process level only,
      // never inside the task.
      _ = tokio::signal::ctrl_c() => {
        tun_handle.abort();
        Ok(())
      }
    };
  }
  #[cfg(target_os = "linux")]
  if args.proxy_backend == ProxyBackend::Tproxy {
    let tproxy_state = std::sync::Arc::clone(&state);
    let mut tproxy_handle = tokio::spawn(async move { tproxy::run_tproxy(tproxy_state, args.tproxy_allow_root_netns).await });
    // Fail closed: capture was explicitly requested, so a dead TPROXY
    // leg ends the process instead of silently serving explicit-proxy
    // only.
    return tokio::select! {
      result = proxy::serve(listener, state) => result,
      tproxy_result = &mut tproxy_handle => match tproxy_result {
        Ok(inner) => inner.map_err(|err| eyre::eyre!("TPROXY capture failed: {err:?}")),
        Err(err) => Err(eyre::eyre!("TPROXY task failed: {err}")),
      },
      // Dropping the capture task runs its teardown guards; handlers
      // live here at process level only, never inside the task.
      _ = tokio::signal::ctrl_c() => {
        tproxy_handle.abort();
        Ok(())
      }
    };
  }
  proxy::serve(listener, state).await
}
