//! `hodor`: grant-scoped MITM proxy.
//!
//! Terminates client TLS with per-domain leaf certificates, swaps
//! format-valid decoy fakes for real secret values only on URI-grant
//! match, and redacts values back to fakes on responses. Everything
//! else splices through byte-identical.

mod ca;
mod config;
mod grants;
mod proxy;
mod sni;
mod substitute;
#[cfg(feature = "tun")]
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
  /// Serve the proxy (explicit listener, plus TUN with `--tun`).
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
  // TUN mutates host routes and must be an explicit intention, not ambient.
  /// Also capture via TUN (needs root).
  #[arg(long, env = "HODOR_TUN", help = "also capture via TUN (needs root)")]
  pub tun: bool,
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
fn ca_path(resolved: &grants::ResolvedConfig) -> eyre::Result<PathBuf> {
  match resolved.proxy.ca_file.clone() {
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
      println!("{}", config::fake_for(&args.env, args.pattern.as_deref()));
      Ok(())
    }
    Command::Ca => {
      let (config, _) = config::load(&cli)?;
      let resolved = grants::resolve(&config)?;
      let ca = ca::load_or_generate(&ca_path(&resolved)?)?;
      print!("{}", String::from_utf8_lossy(&ca.cert_pem()));
      Ok(())
    }
    Command::Serve(args) => {
      #[cfg(not(feature = "tun"))]
      if args.tun {
        eyre::bail!("built without the `tun` feature; rebuild with --features tun");
      }
      let (config, workspace) = config::load(&cli)?;
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
      let ca = ca::load_or_generate(&ca_path(&resolved)?)?;
      let listen_addr = resolved.proxy.listen;
      let grant_count = resolved.grants.len();
      #[cfg(feature = "tun")]
      let state = std::sync::Arc::new({
        let base = proxy::ProxyState::new(resolved, ca);
        if args.tun { base.with_fwmark(crate::tun::FWMARK) } else { base }
      });
      #[cfg(not(feature = "tun"))]
      let state = std::sync::Arc::new(proxy::ProxyState::new(resolved, ca));
      // Bind before TUN side effects: a bad listen addr must fail before
      // routes/fwmark touch the host.
      let listener = tokio::net::TcpListener::bind(listen_addr).await?;
      if !listen_addr.ip().is_loopback() {
        tracing::warn!(listen = %listen_addr, "listening on a non-loopback address: anyone reaching this port can trigger real-secret substitution");
      }
      tracing::info!(listen = %listen_addr, grants = grant_count, "serving");
      #[cfg(feature = "tun")]
      if args.tun {
        let tun_state = std::sync::Arc::clone(&state);
        let tun_handle = tokio::spawn(async move { crate::tun::run_tun(tun_state).await });
        // Fail closed: capture was explicitly requested, so a dead TUN ends
        // the process instead of silently serving explicit-proxy only.
        return tokio::select! {
          result = proxy::serve(listener, state) => result,
          tun_result = tun_handle => match tun_result {
            Ok(inner) => inner.map_err(|err| eyre::eyre!("TUN capture failed: {err:?}")),
            Err(err) => Err(eyre::eyre!("TUN task failed: {err}")),
          },
        };
      }
      proxy::serve(listener, state).await
    }
  }
}
