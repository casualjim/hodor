//! `hodor`: grant-scoped MITM proxy.
//!
//! Terminates client TLS with per-domain leaf certificates, swaps
//! format-valid decoy fakes for real secret values only on URI-grant
//! match, and redacts real values back to fakes on responses. Everything
//! else splices through byte-identical.

mod ca;
mod config;
mod grants;
mod proxy;
mod secrets;
mod sni;
mod substitute;
#[cfg(target_os = "linux")]
mod tproxy;

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
  /// Serve the proxy (explicit listener, plus kernel TPROXY with `--tproxy`).
  Serve(ServeArgs),
  /// Print the deterministic fake for an env var name.
  Fake(FakeArgs),
  /// Generate (or load) the CA, print its certificate PEM to stdout, and write
  /// the certificate and the key beside the CA file as `ca.crt` and `ca.key`.
  ///
  /// The printed PEM is the trust anchor to install into workload
  /// containers; the private key stays in the CA file and in `ca.key`.
  Ca,
}

/// Arguments for [`Command::Serve`].
#[derive(clap::Args, Debug, Clone, Default)]
pub struct ServeArgs {
  /// Proxy settings (CLI layer of the config overlay).
  #[command(flatten)]
  pub proxy: <config::ProxyCfg as confique::Config>::Layer,
  // Deployment-mode switch: CLI + env only, deliberately not a file key —
  // TPROXY mutates host nft rules and routes, an explicit intention, not ambient.
  /// Also capture via kernel TPROXY (needs `CAP_NET_ADMIN`; Linux only).
  #[arg(long, env = "HODOR_TPROXY", help = "also capture via kernel TPROXY (needs CAP_NET_ADMIN)")]
  pub tproxy: bool,
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
    Command::Serve(args) => {
      #[cfg(not(target_os = "linux"))]
      if args.tproxy {
        eyre::bail!("--tproxy is only supported on Linux");
      }
      let (mut config, workspace) = config::load(&cli)?;
      let registry = secrets::Registry::load(config::rules_dir().as_deref())?;
      secrets::resolve(&mut config, &registry).await?;
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
      let fwmark = args.tproxy.then_some(tproxy::EGRESS_MARK);
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
      #[cfg(target_os = "linux")]
      if args.tproxy {
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
  }
}
