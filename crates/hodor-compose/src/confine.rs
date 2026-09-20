//! `hodor init` plus the stack commands (`up`, `down`, `logs`):
//! generate-once-then-edit, then drive the compose project and enter the agent.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use eyre::WrapErr as _;

use hodor_config::cli::{LogsArgs, ProxyBackend};

use crate::paths::translate;
use crate::stack::{current_uid, generate_stack, rules_command, workspace_config, workspace_file, workspace_state_dir};

/// The entrypoint the generated agent service runs: it makes hodor's CA trusted
/// inside the container before handing off, by installing it into the system
/// store every tool already reads, then chains to the image's own init —
/// `HODOR_INIT` when set, the common entrypoint script names otherwise, and
/// the command directly as the safe default. `hodor init` writes it when
/// absent, so an edited copy survives regeneration.
pub(crate) const ENTRYPOINT_SCRIPT: &str = r#"#!/bin/sh
set -e
# The compose file mounts hodor's certificate at the system CA location, so
# refreshing the store is the whole job. That needs root: run the agent service
# as root, or grant it passwordless sudo (devcontainer images usually do).
if [ "$(id -u)" = "0" ]; then
  update-ca-certificates >/dev/null 2>&1 || true
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo -n update-ca-certificates >/dev/null 2>&1 || true
else
  echo "hodor: not root and no passwordless sudo, so the CA is not in the system store;" >&2
  echo "hodor: run the agent as root or bake the certificate into the image" >&2
  echo "hodor: https://github.com/casualjim/hodor/blob/main/docs/user/how-to/trust-the-ca.md" >&2
fi
# Hand over to the image's own init when there is one, so the container's real
# startup (service supervisors, sockets, whatever the image ships) still runs:
# HODOR_INIT names it for images without a common name, the usual entrypoint
# script names are tried next, and with none of them the command runs directly.
if [ -n "${HODOR_INIT:-}" ] && [ -x "$HODOR_INIT" ]; then
  exec "$HODOR_INIT" "$@"
fi
for init in /usr/local/bin/docker-entrypoint.sh /docker-entrypoint.sh /usr/local/bin/entrypoint.sh /entrypoint.sh; do
  if [ -x "$init" ]; then
    exec "$init" "$@"
  fi
done
exec "$@"
"#;

/// Create the host files the generated stack mounts, when they are missing: the
/// CA at `<dir>/ca.pem` (`ca.crt` and `ca.key` come with it, and the stack
/// mounts `ca.pem` for hodor and `ca.crt` for the agent) and the agent
/// entrypoint. The CA is never overwritten, so one you installed elsewhere
/// survives; the entrypoint is regenerated whenever it differs from the
/// generated script, so stale or hand-edited copies cannot linger. The
/// directory is the hodor config directory, which is what the compose defaults
/// point at, not `[proxy] ca_file`: that describes a host-run hodor, not the
/// container's mount. The storage directory is this workspace's, under the
/// state directory.
pub(crate) fn ensure_support_files(dir: &Path, storage: &Path) -> eyre::Result<Vec<(PathBuf, bool)>> {
  let ca = dir.join("ca.pem");
  let entrypoint = dir.join("agent-entrypoint.sh");
  let mut files = Vec::new();
  let created = !ca.exists();
  match hodor_pki::ca::load_or_generate(&ca) {
    Ok(_) => files.push((ca, created)),
    // A read-only or unwritable config directory only warns: the stack still
    // starts when a compose layer mounts a CA made with `hodor ca`.
    Err(err) => println!("warning: could not prepare {}: {err}", dir.join("ca.pem").display()),
  }
  files.push((entrypoint.clone(), write_entrypoint(&entrypoint)?));
  // The agent's inner container storage — see the generated compose file for
  // why this directory has to exist before the stack starts.
  let storage_created = !storage.exists();
  match std::fs::create_dir_all(storage) {
    Ok(()) => files.push((storage.to_path_buf(), storage_created)),
    Err(err) => println!("warning: could not prepare {}: {err}", storage.display()),
  }
  Ok(files)
}

/// Write the agent entrypoint, replacing a stale or edited copy so the two
/// never drift: the file is generated output, and a compose layer overriding
/// `entrypoint:` is the way to run a custom script instead. Executable: docker
/// runs it directly.
pub(crate) fn write_entrypoint(path: &Path) -> eyre::Result<bool> {
  use std::os::unix::fs::PermissionsExt as _;
  if let Ok(existing) = std::fs::read_to_string(path)
    && existing == ENTRYPOINT_SCRIPT
  {
    return Ok(false);
  }
  let regenerated = path.exists();
  std::fs::write(path, ENTRYPOINT_SCRIPT).wrap_err_with(|| format!("write {}", path.display()))?;
  std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).wrap_err_with(|| format!("chmod {}", path.display()))?;
  if regenerated {
    println!("regenerated {} (replaced a stale or edited copy)", path.display());
  }
  Ok(!regenerated)
}

/// Resolve the config directory and this workspace's state directory, then
/// create what the stack mounts from them.
pub(crate) fn prepare_support_files(root: &Path) -> eyre::Result<Vec<(PathBuf, bool)>> {
  let dir = hodor_config::config::config_dir().ok_or_else(|| eyre::eyre!("unable to resolve the hodor config directory"))?;
  ensure_support_files(&dir, &workspace_state_dir(root).join("containers"))
}

/// Report the files the call actually created; absent ones are already there.
pub(crate) fn report_created(files: &[(PathBuf, bool)]) {
  for (path, created) in files {
    if *created {
      println!("wrote {}", path.display());
    }
  }
}

/// The capture backend the generated stack runs: `--backend` when given,
/// `ebpf` otherwise. Linux only — the generated serve command and the host
/// wiring that goes with it exist for Linux capture backends, so any other
/// host is refused here rather than producing a stack that cannot capture.
pub(crate) fn resolve_backend(backend: Option<ProxyBackend>) -> eyre::Result<ProxyBackend> {
  eyre::ensure!(
    cfg!(target_os = "linux"),
    "hodor init supports Linux only: there is no capture backend for this host"
  );
  match backend {
    None => Ok(ProxyBackend::Ebpf),
    Some(ProxyBackend::None) => {
      eyre::bail!("`--backend none` is not valid for init: the generated stack needs a capture backend")
    }
    Some(backend) => Ok(backend),
  }
}

/// Canonicalize the workspace root the commands operate on.
fn resolve_root(workspace: &Path) -> eyre::Result<PathBuf> {
  workspace
    .canonicalize()
    .wrap_err_with(|| format!("resolve workspace {}", workspace.display()))
}

/// The workspace layer of the config overlay: the file `hodor init` writes when
/// the workspace has none, and whose content decides whether the generated
/// stack is still current.
fn workspace_config_file(root: &Path) -> PathBuf {
  root.join(".config").join("hodor.toml")
}

/// Write `content` unless the file is already there; `true` means it was
/// written now. Nothing existing is ever overwritten — that file is the
/// user's.
pub(crate) fn write_if_absent(path: &Path, content: &str) -> eyre::Result<bool> {
  if path.exists() {
    return Ok(false);
  }
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).wrap_err_with(|| format!("create {}", parent.display()))?;
  }
  std::fs::write(path, content).wrap_err_with(|| format!("write {}", path.display()))?;
  Ok(true)
}

/// Generate the workspace config when the workspace has none, from `hodor
/// rules`: every fnox-declared name the registry knows, as `[rules.*]` blocks.
/// Without a rule nothing is substituted — every decoy the agent holds stays a
/// decoy — so `init` writes the file rather than serving a workspace that
/// cannot swap anything. The file is the user's to trim from then on.
fn ensure_workspace_config(root: &Path) -> eyre::Result<(PathBuf, bool)> {
  let path = workspace_config_file(root);
  if path.exists() {
    return Ok((path, false));
  }
  let content = rules_command().wrap_err("generate the workspace rules")?;
  let written = write_if_absent(&path, &content)?;
  Ok((path, written))
}

/// A warning when no rule is in play, since then nothing would be substituted
/// and every credential the agent holds stays a decoy; `None` when at least
/// one rule is in effect.
pub(crate) fn rules_warning(rules: &BTreeMap<String, hodor_config::config::RuleCfg>, config_file: &Path) -> Option<String> {
  if !rules.is_empty() {
    return None;
  }
  Some(format!(
    "warning: no [rules.*] in play, so nothing will be substituted and every credential the agent holds stays a decoy; `hodor rules` prints the blocks to add to {}",
    config_file.display()
  ))
}

/// Digest of both config layers' bytes — global and workspace — so a stack
/// generated from different settings can be told apart from a current one:
/// generation reads both, so editing either must regenerate. `DefaultHasher`
/// is enough: this only ever compares digests written by the same binary.
pub(crate) fn config_digest(root: &Path) -> u64 {
  use std::hash::{Hash as _, Hasher as _};
  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  let global = hodor_config::config::config_dir().map(|dir| dir.join("config.toml"));
  for path in global.into_iter().chain([workspace_config_file(root)]) {
    match std::fs::read(&path) {
      Ok(bytes) => bytes.hash(&mut hasher),
      Err(_) => "absent".hash(&mut hasher),
    }
    path.hash(&mut hasher);
  }
  hasher.finish()
}

/// Whether the stack on disk was generated from a different workspace config
/// — which matters because the decoys are derived from the rules: a stack made
/// before a rule existed hands the agent a decoy that can never be swapped.
/// A stack with no digest beside it predates the check and counts as stale.
pub(crate) fn stack_is_stale(state_ws: &Path, root: &Path) -> bool {
  match std::fs::read_to_string(state_ws.join("config.digest")) {
    Ok(stored) => stored.trim() != config_digest(root).to_string(),
    Err(_) => true,
  }
}

/// The capture backend the stack on disk was generated with, when it can be
/// read back — a regeneration must not silently switch how traffic is
/// captured just because this run did not name a backend.
pub(crate) fn generated_backend(compose: &str) -> Option<ProxyBackend> {
  [
    ("ebpf", ProxyBackend::Ebpf),
    ("tun", ProxyBackend::Tun),
    ("tproxy", ProxyBackend::Tproxy),
  ]
  .into_iter()
  .find_map(|(name, backend)| compose.contains(&format!("\"--proxy-backend\", \"{name}\"")).then_some(backend))
}

/// Generate the workspace stack when it is absent, and regenerate it when the
/// workspace config changed since it was generated; a stack whose config is
/// unchanged is left alone, so hand edits survive until then.
fn init_workspace(root: &Path, backend: ProxyBackend, explicit_backend: bool) -> eyre::Result<()> {
  let state_ws = workspace_state_dir(root);
  let ws_compose = state_ws.join("compose.yml");
  std::fs::create_dir_all(&state_ws).wrap_err_with(|| format!("create {}", state_ws.display()))?;
  let (config_file, written) = ensure_workspace_config(root)?;
  if written {
    println!("wrote {}", config_file.display());
  }
  if let Some(warning) = rules_warning(&workspace_config(root)?.rules, &config_file) {
    println!("{warning}");
  }
  report_created(&prepare_support_files(root)?);
  let existing = std::fs::read_to_string(&ws_compose).ok();
  if existing.is_some() {
    if !stack_is_stale(&state_ws, root) {
      println!("exists, left untouched: {}", ws_compose.display());
      return Ok(());
    }
    println!(
      "regenerating {}: the workspace config changed since it was generated, so hand edits to it are replaced",
      ws_compose.display()
    );
  }
  // An unnamed backend keeps whatever the stack on disk already runs.
  let backend = match (explicit_backend, existing.as_deref().and_then(generated_backend)) {
    (false, Some(existing)) => existing,
    _ => backend,
  };
  let stack = generate_stack(root, backend)?;
  std::fs::write(&ws_compose, stack).wrap_err_with(|| format!("write {}", ws_compose.display()))?;
  std::fs::write(state_ws.join("config.digest"), config_digest(root).to_string())
    .wrap_err_with(|| format!("write {}", state_ws.join("config.digest").display()))?;
  println!("generated: {}", ws_compose.display());
  Ok(())
}

/// The compose files on disk, in layer order.
fn compose_layers(root: &Path) -> Vec<PathBuf> {
  [
    hodor_config::config::config_dir().map(|dir| dir.join("compose.yml")),
    Some(workspace_state_dir(root).join("compose.yml")),
    Some(workspace_file(root)),
  ]
  .into_iter()
  .flatten()
  .filter(|path| path.is_file())
  .collect()
}

/// A `docker compose` command over those layers.
fn compose_command(root: &Path) -> eyre::Result<std::process::Command> {
  let layers = compose_layers(root);
  eyre::ensure!(
    !layers.is_empty(),
    "no compose layers for {}; run `hodor init` first or create one of the layer files",
    root.display()
  );
  let mut command = std::process::Command::new("docker");
  command.arg("compose");
  for layer in layers {
    command.arg("-f").arg(layer);
  }
  Ok(command)
}

/// Run a compose command and fail on a non-zero exit; its output is the user's.
fn compose_status(command: &mut std::process::Command) -> eyre::Result<()> {
  let status = command.status().wrap_err("spawn docker compose")?;
  eyre::ensure!(status.success(), "docker compose failed: {status}");
  Ok(())
}

/// The same, for a compose command the user is meant to interrupt — an exec
/// session, a `--follow` log read. compose reports that interrupt as 130, and
/// an interrupt is the user getting what they asked for, not a failure.
fn compose_status_interruptible(command: &mut std::process::Command) -> eyre::Result<()> {
  let status = command.status().wrap_err("spawn docker compose")?;
  eyre::ensure!(status.success() || status.code() == Some(130), "docker compose failed: {status}");
  Ok(())
}

/// Start the layered project, making sure what it mounts exists first.
fn up_workspace(root: &Path) -> eyre::Result<()> {
  report_created(&prepare_support_files(root)?);
  let mut command = compose_command(root)?;
  command.arg("up").arg("-d");
  compose_status(&mut command)
}

/// Stop the layered project.
fn down_workspace(root: &Path) -> eyre::Result<()> {
  let mut command = compose_command(root)?;
  command.arg("down");
  compose_status(&mut command)
}

/// The compose arguments `hodor logs` maps to: its flags only when they were
/// asked for, the tail always (compose defaults it to everything), then the
/// named services — none means every service in the stack.
pub(crate) fn logs_argv(args: &LogsArgs) -> Vec<OsString> {
  let mut compose: Vec<OsString> = vec!["logs".into()];
  if args.follow {
    compose.push("--follow".into());
  }
  if args.no_log_prefix {
    compose.push("--no-log-prefix".into());
  }
  compose.push("--tail".into());
  compose.push(args.tail.clone().into());
  compose.extend(args.services.iter().map(Into::into));
  compose
}

/// Read the stack's logs.
fn logs_workspace(root: &Path, args: &LogsArgs) -> eyre::Result<()> {
  let mut command = compose_command(root)?;
  command.args(logs_argv(args));
  compose_status_interruptible(&mut command)
}

/// Enter the agent environment at the translated workspace directory: the
/// configured shell, or `command` when the caller passed one.
fn exec_agent(root: &Path, command: &[OsString]) -> eyre::Result<()> {
  let config = workspace_config(root)?;
  let home = config
    .workspace
    .home
    .clone()
    .ok_or_else(|| eyre::eyre!("[workspace] home is required for the agent workdir"))?;
  let workdir = translate(root, dirs::home_dir().as_deref(), &home);
  let uid = current_uid();
  let argv: Vec<OsString> = if command.is_empty() {
    vec![config.workspace.shell.clone().unwrap_or_else(|| "sh".to_string()).into()]
  } else {
    command.to_vec()
  };
  let mut compose = compose_command(root)?;
  compose
    .arg("exec")
    .arg("-i")
    .arg("--workdir")
    .arg(&workdir)
    .arg("--user")
    .arg(uid.to_string())
    .arg("agent")
    .args(argv);
  compose_status_interruptible(&mut compose)
}

/// `hodor init [--backend <backend>] [workspace]`: write the support files, the
/// workspace config when it has none (`[rules.*]` for every fnox-declared name
/// the registry knows, so the stack can actually substitute), and the workspace
/// stack into `<state-dir>/hodor/ws/<slug>/compose.yml` — the one editable file
/// where generated services and secret mounts live. An existing stack is
/// regenerated only when the workspace config changed since it was generated.
///
/// # Errors
///
/// Returns an error when the host is not Linux, when the workspace cannot be
/// resolved or its stack generated, when `hodor rules` cannot be computed, or
/// when a file cannot be written.
pub fn init_command(workspace: &Path, backend: Option<ProxyBackend>) -> eyre::Result<()> {
  let root = resolve_root(workspace)?;
  init_workspace(&root, resolve_backend(backend)?, backend.is_some())
}

/// `hodor agent [workspace] [-- <command>...]`: the whole workspace lifecycle
/// in one idempotent run — generate what is missing, start the stack, then
/// enter the agent with the configured shell or `<command>`. The stack keeps
/// running when that exits, unless `rm` stops it, so the next call starts at
/// the exec.
///
/// # Errors
///
/// Returns an error under the same conditions as [`init_command`], plus when
/// the compose command fails. A failed `rm` teardown is reported too, because
/// the stack the caller asked to stop is still up.
pub fn agent_command(workspace: &Path, command: &[OsString], rm: bool) -> eyre::Result<()> {
  let root = resolve_root(workspace)?;
  init_workspace(&root, resolve_backend(None)?, false)?;
  up_workspace(&root)?;
  if !rm {
    return exec_agent(&root, command);
  }
  let exec = {
    let _survive_interrupt = SurviveInterrupt::new();
    exec_agent(&root, command)
  };
  let down = down_workspace(&root);
  exec?;
  down
}

/// Ignore the terminal's interrupt for as long as it lives, so hodor reaches
/// the `rm` teardown after the agent session ends instead of dying beside it.
///
/// A handler rather than `SIG_IGN`: ignored dispositions survive `exec`, and
/// the agent would then be uninterruptible as well.
struct SurviveInterrupt;

impl SurviveInterrupt {
  #[must_use]
  fn new() -> Self {
    // Safety: the handler only returns, so no work happens inside the signal.
    unsafe { libc::signal(libc::SIGINT, swallow_interrupt as *const () as libc::sighandler_t) };
    Self
  }
}

impl Drop for SurviveInterrupt {
  fn drop(&mut self) {
    // Safety: restores the disposition every process starts with.
    unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
  }
}

extern "C" fn swallow_interrupt(_: libc::c_int) {}

/// `hodor up [workspace]`: start the layered compose project `hodor init`
/// generated, making sure what it mounts exists first.
///
/// # Errors
///
/// Returns an error when the workspace cannot be resolved, when the support
/// files cannot be written, or when the compose command fails.
pub fn up_command(workspace: &Path) -> eyre::Result<()> {
  up_workspace(&resolve_root(workspace)?)
}

/// `hodor down [workspace]`: stop the layered compose project.
///
/// # Errors
///
/// Returns an error when the workspace cannot be resolved or when the compose
/// command fails.
pub fn down_command(workspace: &Path) -> eyre::Result<()> {
  down_workspace(&resolve_root(workspace)?)
}

/// `hodor logs [workspace]`: read the stack's logs.
///
/// # Errors
///
/// Returns an error when the workspace cannot be resolved or when the compose
/// command fails.
pub fn logs_command(workspace: &Path, args: &LogsArgs) -> eyre::Result<()> {
  logs_workspace(&resolve_root(workspace)?, args)
}
