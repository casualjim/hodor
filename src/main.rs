//! `hodor`: grant-scoped MITM proxy.
//!
//! Terminates client TLS with per-domain leaf certificates, swaps
//! format-valid decoy fakes for real secret values only on URI-grant
//! match, and redacts real values back to fakes on responses. Everything
//! else splices through byte-identical.

pub use hodor_config::cli::{
  AgentArgs, Cli, Command, FakeArgs, ImportArgs, InitArgs, LogsArgs, ProxyBackend, RegistryCommand, ServeArgs, WorkspaceArgs,
};

use std::path::{Path, PathBuf};

use clap::Parser as _;

mod fwd;

/// The workspace a command names, or the current directory.
fn workspace_arg(workspace: Option<&Path>) -> PathBuf {
  workspace.unwrap_or(Path::new(".")).to_path_buf()
}

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Resolve the CA file path: config `ca_file` if set, else the default
/// `<config-dir>/hodor/ca.pem`.
fn ca_path(proxy: &hodor_config::config::ProxyCfg) -> eyre::Result<PathBuf> {
  match proxy.ca_file.clone() {
    Some(path) => Ok(path),
    None => dirs::config_dir()
      .map(|dir: PathBuf| dir.join("hodor").join("ca.pem"))
      .ok_or_else(|| eyre::eyre!("unable to resolve user config directory")),
  }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
  hodor_pki::ca::install_crypto_provider();
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
        hodor_config::config::validate_pattern(pattern).map_err(|err| eyre::eyre!("bad --pattern: {err}"))?;
      }
      let registry = hodor_config::registry::Registry::load(hodor_config::config::rules_dir().as_deref())?;
      let (mut config, _) = hodor_config::config::load(&cli)?;
      // Resolve the rule's value the way `serve` does, so a `tcp://` rule
      // previews the length-matched decoy the proxy will actually use.
      let needs_fnox = config.rules.values().any(|rule| rule.env == args.env && rule.value.is_none());
      if needs_fnox {
        let fnox = hodor_fnox::FnoxSource::open()?;
        hodor_fnox::resolve(&mut config, &registry, fnox).await?;
      }
      let rule = config.rules.values().find(|rule| rule.env == args.env);
      let Some(rule) = rule else {
        println!("{}", registry.decoy(&args.env, args.pattern.as_deref()));
        return Ok(());
      };
      let Some(value) = rule.value.as_ref() else {
        println!("{}", registry.decoy(&args.env, args.pattern.as_deref()));
        return Ok(());
      };
      let allow: Vec<hodor_config::grants::EndpointScope> = rule
        .allow
        .iter()
        .map(|entry| entry.parse())
        .collect::<Result<_, _>>()
        .map_err(|err| eyre::eyre!("bad allow entry: {err}"))?;
      let (decoy, length_matched) = hodor_config::grants::decoy_for_rule(
        &rule.env,
        rule.pattern.as_deref().or(args.pattern.as_deref()),
        &allow,
        hodor_config::ExposeSecret::expose_secret(value).len(),
      );
      if length_matched {
        eprintln!("# length-matched for a tcp:// allow entry; the registry shape rendered another length");
      }
      println!("{decoy}");
      Ok(())
    }
    Command::Ca => {
      let (config, _) = hodor_config::config::load(&cli)?;
      let ca = hodor_pki::ca::load_or_generate(&ca_path(&config.proxy)?)?;
      print!("{}", String::from_utf8_lossy(&ca.cert_pem()));
      Ok(())
    }
    Command::Rules => {
      print!("{}", hodor_compose::rules_command()?);
      Ok(())
    }
    Command::Registry(args) => {
      let import = match &args.command {
        RegistryCommand::FromOidc(import) | RegistryCommand::FromOpenapi(import) => import,
      };
      let doc = std::fs::read_to_string(&import.file).map_err(|err| eyre::eyre!("read {}: {err}", import.file.display()))?;
      let flows = match &args.command {
        RegistryCommand::FromOidc(_) => vec![(
          import.slug.clone(),
          hodor_config::import::flow_from_oidc(&doc).map_err(|err| err.to_string()),
        )],
        RegistryCommand::FromOpenapi(_) => hodor_config::import::flows_from_openapi(&doc)?,
      };
      for (slug, flow) in flows {
        match flow {
          Ok(flow) => print!("{}", hodor_config::import::to_toml_fragment(&slug, &import.env, &flow)?),
          Err(reason) => tracing::warn!(scheme = %slug, reason, "skipped security scheme"),
        }
      }
      Ok(())
    }
    Command::Init(args) => {
      let workspace = workspace_arg(args.workspace.as_deref());
      hodor_compose::init_command(&workspace, args.backend)
    }
    Command::Agent(args) => {
      let workspace = workspace_arg(args.workspace.as_deref());
      hodor_compose::agent_command(&workspace, &args.command, args.rm)
    }
    Command::Up(args) => hodor_compose::up_command(&workspace_arg(args.workspace.as_deref())),
    Command::Down(args) => hodor_compose::down_command(&workspace_arg(args.workspace.as_deref())),
    Command::Logs(args) => hodor_compose::logs_command(&workspace_arg(args.workspace.as_deref()), &args),
    Command::Fwd => {
      #[cfg(not(target_os = "linux"))]
      eyre::bail!("hodor fwd reads /proc/net/tcp and exists on Linux only");
      #[cfg(target_os = "linux")]
      crate::fwd::run().await
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
  // No default cgroup: attaching to the root cgroup would capture every
  // process on the machine, hodor's own upstream dials included.
  if args.proxy_backend == ProxyBackend::Ebpf && args.ebpf_cgroup.is_none() {
    eyre::bail!("--ebpf-cgroup is required for --proxy-backend ebpf");
  }
  let (mut config, workspace) = hodor_config::config::load(cli)?;
  let registry = hodor_config::registry::Registry::load(hodor_config::config::rules_dir().as_deref())?;
  // fnox is needed exactly when a rule has no inline value: every
  // credential the proxy runs with resolves from fnox, age-encrypted secrets
  // included — never from the environment that started this process.
  let needs_fnox = config.rules.values().any(|rule| rule.value.is_none() || rule.is_database());
  let fnox = if needs_fnox { hodor_fnox::FnoxSource::open()? } else { None };
  if let Some(source) = &fnox {
    for name in hodor_fnox::export_provider_env(source).await? {
      tracing::debug!(name, "provider credential taken from fnox");
    }
  }
  hodor_fnox::resolve(&mut config, &registry, fnox).await?;
  let resolved = hodor_config::grants::resolve(&config)?;
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
  let ca = hodor_pki::ca::load_or_generate(&ca_path(&resolved.proxy)?)?;
  let listen_addr = resolved.proxy.listen;
  let grant_count = resolved.grants.len();
  #[cfg(target_os = "linux")]
  let fwmark = match args.proxy_backend {
    // eBPF needs no fwmark: exclusion is cgroup membership plus the proxy PID
    // the programs compare against, not a routing loop to break.
    ProxyBackend::None | ProxyBackend::Ebpf => None,
    ProxyBackend::Tproxy => Some(hodor_tproxy::EGRESS_MARK),
    ProxyBackend::Tun => Some(hodor_tun::FWMARK),
  };
  #[cfg(not(target_os = "linux"))]
  let fwmark = None;
  #[cfg(target_os = "linux")]
  let state = std::sync::Arc::new(match fwmark {
    Some(mark) => hodor_proxy::ProxyState::new(resolved, &ca)?.with_fwmark(mark),
    None => hodor_proxy::ProxyState::new(resolved, &ca)?,
  });
  #[cfg(not(target_os = "linux"))]
  let state = std::sync::Arc::new(hodor_proxy::ProxyState::new(resolved, &ca)?);
  // Bind before capture side effects: a bad listen addr must fail
  // before nft rules and routes touch the host.
  let listener = hodor_proxy::bind_explicit(listen_addr).await?;
  if !listen_addr.ip().is_loopback() {
    tracing::warn!(listen = %listen_addr, "listening on a non-loopback address: anyone reaching this port can trigger real-secret substitution");
  }
  tracing::info!(listen = %listen_addr, grants = grant_count, "serving");
  #[cfg(target_os = "linux")]
  if args.proxy_backend == ProxyBackend::Tun {
    let capture = std::sync::Arc::clone(&state);
    // Dropping the task runs its teardown guard, which removes the policy
    // routes; a leaked default route in the capture table blackholes all egress.
    return with_capture(listener, state, "TUN", async move { hodor_tun::run_tun(capture).await }).await;
  }
  #[cfg(target_os = "linux")]
  if args.proxy_backend == ProxyBackend::Tproxy {
    let capture = std::sync::Arc::clone(&state);
    let allow_root_netns = args.tproxy_allow_root_netns;
    return with_capture(listener, state, "TPROXY", async move {
      hodor_tproxy::run_tproxy(capture, allow_root_netns).await
    })
    .await;
  }
  #[cfg(target_os = "linux")]
  if args.proxy_backend == ProxyBackend::Ebpf {
    let cgroup = args
      .ebpf_cgroup
      .clone()
      .ok_or_else(|| eyre::eyre!("--ebpf-cgroup is required for --proxy-backend ebpf"))?;
    let capture = std::sync::Arc::clone(&state);
    return with_capture(listener, state, "eBPF", async move { hodor_ebpf::run_ebpf(capture, cgroup).await }).await;
  }
  hodor_proxy::serve(listener, state).await;
  Ok(())
}

/// Serve the explicit listener while a capture backend runs beside it, failing
/// closed.
///
/// Capture was explicitly requested, so a backend that dies ends the process
/// instead of silently degrading to explicit-proxy only. The signal handler
/// lives here, at process level, never inside the capture task: aborting the
/// task is what runs its teardown, and every backend has host state to unwind.
async fn with_capture<F>(
  listener: hodor_proxy::RamaTcpListener,
  state: std::sync::Arc<hodor_proxy::ProxyState>,
  name: &'static str,
  capture: F,
) -> eyre::Result<()>
where
  F: Future<Output = eyre::Result<()>> + Send + 'static,
{
  let mut handle = tokio::spawn(capture);
  tokio::select! {
    () = hodor_proxy::serve(listener, state) => Ok(()),
    capture_result = &mut handle => match capture_result {
      Ok(inner) => inner.map_err(|err| eyre::eyre!("{name} capture failed: {err:?}")),
      Err(err) => Err(eyre::eyre!("{name} task failed: {err}")),
    },
    _ = tokio::signal::ctrl_c() => {
      handle.abort();
      Ok(())
    }
  }
}
