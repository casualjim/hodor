//! `hodor init` plus the stack commands (`up`, `down`, `logs`):
//! generate-once-then-edit, then drive the compose project and enter the agent.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::Error;
use crate::paths::translate;
use crate::stack::{
  STACK_SHAPE, current_uid, generate_stack, generation_registry, open_fnox, rules_command, stack_shape_in, uncovered_names,
  uncovered_warning, workspace_config, workspace_file, workspace_state_dir,
};
use dirs::home_dir;
use hodor_config::cli::{LogsArgs, ProxyBackend};
use hodor_config::config::{AppConfig, config_dir};
use hodor_fnox::selected_envs;
use hodor_pki::ca::load_or_generate;
use libc::{SIG_DFL, SIGINT, c_int, sighandler_t, signal};
use toml_edit::{DocumentMut, Formatted, Item, Value};

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
pub(crate) fn ensure_support_files(dir: &Path, storage: &Path) -> Result<Vec<(PathBuf, bool)>, Error> {
  let ca = dir.join("ca.pem");
  let entrypoint = dir.join("agent-entrypoint.sh");
  let mut files = Vec::new();
  let created = !ca.exists();
  match load_or_generate(&ca) {
    Ok(_) => files.push((ca, created)),
    // A read-only or unwritable config directory only warns: the stack still
    // starts when a compose layer mounts a CA made with `hodor ca`.
    Err(err) => println!("warning: could not prepare {}: {err}", dir.join("ca.pem").display()),
  }
  files.push((entrypoint.clone(), write_entrypoint(&entrypoint)?));
  // The agent's inner container storage — see the generated compose file for
  // why this directory has to exist before the stack starts.
  let storage_created = !storage.exists();
  match fs::create_dir_all(storage) {
    Ok(()) => files.push((storage.to_path_buf(), storage_created)),
    Err(err) => println!("warning: could not prepare {}: {err}", storage.display()),
  }
  Ok(files)
}

/// Write the agent entrypoint, replacing a stale or edited copy so the two
/// never drift: the file is generated output, and a compose layer overriding
/// `entrypoint:` is the way to run a custom script instead. Executable: docker
/// runs it directly.
pub(crate) fn write_entrypoint(path: &Path) -> Result<bool, Error> {
  if let Ok(existing) = fs::read_to_string(path)
    && existing == ENTRYPOINT_SCRIPT
  {
    return Ok(false);
  }
  let regenerated = path.exists();
  fs::write(path, ENTRYPOINT_SCRIPT).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|source| Error::ChmodFile {
    path: path.to_path_buf(),
    source,
  })?;
  if regenerated {
    println!("regenerated {} (replaced a stale or edited copy)", path.display());
  }
  Ok(!regenerated)
}

/// Resolve the config directory and this workspace's state directory, then
/// create what the stack mounts from them.
pub(crate) fn prepare_support_files(root: &Path) -> Result<Vec<(PathBuf, bool)>, Error> {
  let dir = config_dir().ok_or_else(|| Error::ConfigDir {
    detail: "unable to resolve the hodor config directory".to_string(),
  })?;
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
pub(crate) fn resolve_backend(backend: Option<ProxyBackend>) -> Result<ProxyBackend, Error> {
  if !cfg!(target_os = "linux") {
    return Err(Error::LinuxOnly);
  }
  match backend {
    None => Ok(ProxyBackend::Ebpf),
    Some(ProxyBackend::None) => Err(Error::BackendNone),
    Some(backend) => Ok(backend),
  }
}

/// Canonicalize the workspace root the commands operate on.
fn resolve_root(workspace: &Path) -> Result<PathBuf, Error> {
  workspace.canonicalize().map_err(|source| Error::ResolveWorkspace {
    path: workspace.to_path_buf(),
    source,
  })
}

/// The workspace layer of the config overlay: the file `hodor init` writes when
/// the workspace has none, and whose content decides whether the generated
/// stack is still current. Always the unified path; reads fall back to the
/// legacy flat file.
fn workspace_config_file(root: &Path) -> PathBuf {
  hodor_config::config::project_config_write_path(root)
}

/// Write `content` unless the file is already there; `true` means it was
/// written now. Nothing existing is ever overwritten — that file is the
/// user's.
pub(crate) fn write_if_absent(path: &Path, content: &str) -> Result<bool, Error> {
  if path.exists() {
    return Ok(false);
  }
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
      path: parent.to_path_buf(),
      source,
    })?;
  }
  fs::write(path, content).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  Ok(true)
}

/// Generate the workspace config when the workspace has none, from `hodor
/// rules`: every fnox-declared name the registry knows, as `[rules.*]` blocks.
/// Without a rule nothing is substituted — every decoy the agent holds stays a
/// decoy — so `init` writes the file rather than serving a workspace that
/// cannot swap anything. The file is the user's to trim from then on.
fn ensure_workspace_config(root: &Path) -> Result<(PathBuf, bool), Error> {
  if let Some(existing) = hodor_config::config::project_config_file(root) {
    return Ok((existing, false));
  }
  let path = workspace_config_file(root);
  let content = rules_command(Some(root)).map_err(|source| Error::GenerateRules { source: source.into() })?;
  let written = write_if_absent(&path, &content)?;
  Ok((path, written))
}

/// Write `mise.agent.toml` from `mise.local.toml` when the workspace uses
/// mise for local tasks and has no agent file yet: host-home path prefixes
/// become the container home so the agent's tasks find the same files.
/// Never overwrites; `true` means it was written now.
///
/// # Errors
///
/// Returns an error when the local file cannot be read, rewritten, or
/// written.
pub(crate) fn ensure_mise_agent(root: &Path, home: &str) -> Result<bool, Error> {
  if !root.join("mise.toml").is_file() || !root.join("mise.local.toml").is_file() || root.join("mise.agent.toml").exists() {
    return Ok(false);
  }
  let local = root.join("mise.local.toml");
  let content = fs::read_to_string(&local).map_err(|source| Error::ReadFile {
    path: local.clone(),
    source,
  })?;
  let rewritten = rewrite_mise_toml(&content, home_dir().as_deref(), home)?;
  write_if_absent(&root.join("mise.agent.toml"), &rewritten)
}

/// Copy `mise.local.toml` with host-home prefixes rewritten to the container
/// home, reusing [`translate`] semantics on path-looking string values.
/// URLs and non-paths stay intact.
///
/// # Errors
///
/// Returns an error when the content is not valid TOML.
pub(crate) fn rewrite_mise_toml(content: &str, host_home: Option<&Path>, home: &str) -> Result<String, Error> {
  let mut document: DocumentMut = content.parse().map_err(|source| Error::MiseParse { source })?;
  rewrite_mise_item(document.as_item_mut(), host_home, home);
  Ok(document.to_string())
}

/// Rewrite one TOML value tree in place: every string under a home prefix
/// moves to the container home.
fn rewrite_mise_item(item: &mut Item, host_home: Option<&Path>, home: &str) {
  match item {
    Item::Value(value) => rewrite_mise_value(value, host_home, home),
    Item::Table(table) => {
      for (_, item) in table.iter_mut() {
        rewrite_mise_item(item, host_home, home);
      }
    }
    Item::ArrayOfTables(tables) => {
      for table in tables.iter_mut() {
        for (_, item) in table.iter_mut() {
          rewrite_mise_item(item, host_home, home);
        }
      }
    }
    Item::None => {}
  }
}
/// Rewrite one TOML value: arrays recurse, strings under the host home move
/// to the container home, everything else stays.
fn rewrite_mise_value(value: &mut Value, host_home: Option<&Path>, home: &str) {
  match value {
    Value::String(text) => {
      let rewritten = rewrite_mise_string(text.value(), host_home, home);
      *text = Formatted::new(rewritten);
    }
    Value::Array(items) => {
      for item in items.iter_mut() {
        rewrite_mise_value(item, host_home, home);
      }
    }
    Value::InlineTable(table) => {
      for (_, value) in table.iter_mut() {
        rewrite_mise_value(value, host_home, home);
      }
    }
    _ => {}
  }
}

/// One mise string: URLs and non-paths stay intact; a value under the host
/// home (after `~` expansion) moves to the container home prefix.
fn rewrite_mise_string(value: &str, host_home: Option<&Path>, home: &str) -> String {
  if value.contains("://") {
    return value.to_string();
  }
  let expanded = if value == "~" || value.starts_with("~/") {
    match host_home {
      Some(host_home) => format!("{}{}", host_home.display(), &value[1..]),
      None => return value.to_string(),
    }
  } else {
    value.to_string()
  };
  match host_home.and_then(|host_home| Path::new(&expanded).strip_prefix(host_home).ok()) {
    Some(rest) => Path::new(home).join(rest).to_string_lossy().into_owned(),
    None => value.to_string(),
  }
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

/// Digest of both config layers' bytes — global and workspace — plus the
/// `rules.d` override trees both sides, so a stack generated from different
/// settings can be told apart from a current one: generation reads all of
/// them, so editing any must regenerate. `DefaultHasher`
/// is enough: this only ever compares digests written by the same binary.
pub(crate) fn config_digest(root: &Path) -> u64 {
  use std::hash::{Hash as _, Hasher as _};
  fn hash_file(path: &Path, hasher: &mut std::collections::hash_map::DefaultHasher) {
    match std::fs::read(path) {
      Ok(bytes) => bytes.hash(hasher),
      Err(_) => "absent".hash(hasher),
    }
    path.hash(hasher);
  }
  fn hash_rules_dir(dir: &Path, hasher: &mut std::collections::hash_map::DefaultHasher) {
    let mut files = std::fs::read_dir(dir)
      .ok()
      .map(|entries| {
        entries
          .flatten()
          .map(|entry| entry.path())
          .filter(|path| path.is_file())
          .collect::<Vec<_>>()
      })
      .unwrap_or_default();
    files.sort();
    if files.is_empty() {
      "absent".hash(hasher);
      dir.hash(hasher);
      return;
    }
    for path in files {
      hash_file(&path, hasher);
    }
  }
  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  let global = hodor_config::config::config_dir().map(|dir| dir.join("config.toml"));
  let legacy = root.join(".config").join("hodor.toml");
  for path in global.into_iter().chain([workspace_config_file(root), legacy]) {
    hash_file(&path, &mut hasher);
  }
  if let Some(global_rules) = hodor_config::config::rules_dir() {
    hash_rules_dir(&global_rules, &mut hasher);
  }
  hash_rules_dir(&hodor_config::config::project_rules_dir(root), &mut hasher);
  hasher.finish()
}

/// Whether the stack on disk was generated from a different workspace config
/// — which matters because the decoys are derived from the rules: a stack made
/// before a rule existed hands the agent a decoy that can never be swapped —
/// or by an older stack shape, which matters because `hodor agent` bundles
/// generation and must not leave an old wiring behind. A stack with no digest
/// beside it predates the check and counts as stale.
pub(crate) fn stack_is_stale(state_ws: &Path, root: &Path) -> bool {
  let shape_stale = std::fs::read_to_string(state_ws.join("compose.yml")).is_ok_and(|body| stack_shape_in(&body) != Some(STACK_SHAPE));
  if shape_stale {
    return true;
  }
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
fn init_workspace(root: &Path, backend: ProxyBackend, explicit_backend: bool) -> Result<(), Error> {
  let state_ws = workspace_state_dir(root);
  let ws_compose = state_ws.join("compose.yml");
  fs::create_dir_all(&state_ws).map_err(|source| Error::CreateDir {
    path: state_ws.clone(),
    source,
  })?;
  let (config_file, written) = ensure_workspace_config(root)?;
  if written {
    println!("wrote {}", config_file.display());
  }
  let workspace = workspace_config(root)?;
  if let Some(warning) = rules_warning(&workspace.rules, &config_file) {
    println!("{warning}");
  }
  report_created(&prepare_support_files(root)?);
  if let Some(home) = workspace.workspace.home.as_deref()
    && ensure_mise_agent(root, home)?
  {
    println!("wrote {}", root.join("mise.agent.toml").display());
  }
  let existing = fs::read_to_string(&ws_compose).ok();
  if existing.is_some() {
    if !stack_is_stale(&state_ws, root) {
      println!("exists, left untouched: {}", ws_compose.display());
      return Ok(());
    }
    println!(
      "regenerating {}: the workspace config or the stack shape changed since it was generated, so hand edits to it are replaced",
      ws_compose.display()
    );
  }
  // An unnamed backend keeps whatever the stack on disk already runs.
  let backend = match (explicit_backend, existing.as_deref().and_then(generated_backend)) {
    (false, Some(existing)) => existing,
    _ => backend,
  };
  let stack = generate_stack(root, backend)?;
  fs::write(&ws_compose, stack).map_err(|source| Error::WriteFile {
    path: ws_compose.clone(),
    source,
  })?;
  fs::write(state_ws.join("config.digest"), config_digest(root).to_string()).map_err(|source| Error::WriteFile {
    path: state_ws.join("config.digest"),
    source,
  })?;
  println!("generated: {}", ws_compose.display());
  Ok(())
}

/// The compose files on disk, in layer order.
fn compose_layers(root: &Path) -> Vec<PathBuf> {
  [
    config_dir().map(|dir| dir.join("compose.yml")),
    Some(workspace_state_dir(root).join("compose.yml")),
    Some(workspace_file(root)),
  ]
  .into_iter()
  .flatten()
  .filter(|path| path.is_file())
  .collect()
}

/// A `docker compose` command over those layers.
fn compose_command(root: &Path) -> Result<Command, Error> {
  let layers = compose_layers(root);
  if layers.is_empty() {
    return Err(Error::NoComposeLayers { root: root.to_path_buf() });
  }
  let mut command = Command::new("docker");
  command.arg("compose");
  for layer in layers {
    command.arg("-f").arg(layer);
  }
  Ok(command)
}

/// Run a compose command and fail on a non-zero exit; its output is the user's.
fn compose_status(command: &mut Command) -> Result<(), Error> {
  let status = command.status().map_err(|source| Error::SpawnCompose { source })?;
  if !status.success() {
    return Err(Error::ComposeFailed {
      status: status.to_string(),
    });
  }
  Ok(())
}

/// The same, for a compose command the user is meant to interrupt — an exec
/// session, a `--follow` log read. compose reports that interrupt as 130, and
/// an interrupt is the user getting what they asked for, not a failure.
fn compose_status_interruptible(command: &mut Command) -> Result<(), Error> {
  let status = command.status().map_err(|source| Error::SpawnCompose { source })?;
  if !(status.success() || status.code() == Some(130)) {
    return Err(Error::ComposeFailed {
      status: status.to_string(),
    });
  }
  Ok(())
}

/// Start the layered project, making sure what it mounts exists first.
fn up_workspace(root: &Path) -> Result<(), Error> {
  report_created(&prepare_support_files(root)?);
  let mut command = compose_command(root)?;
  command.arg("up").arg("-d");
  compose_status(&mut command)
}

/// Stop the layered project.
fn down_workspace(root: &Path) -> Result<(), Error> {
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
fn logs_workspace(root: &Path, args: &LogsArgs) -> Result<(), Error> {
  let mut command = compose_command(root)?;
  command.args(logs_argv(args));
  compose_status_interruptible(&mut command)
}

/// Enter the agent environment at the translated workspace directory: the
/// configured shell, or `command` when the caller passed one.
fn exec_agent(root: &Path, command: &[OsString]) -> Result<(), Error> {
  let config = workspace_config(root)?;
  let home = config.workspace.home.clone().ok_or_else(|| Error::HomeRequired {
    detail: "for the agent workdir".to_string(),
  })?;
  let workdir = translate(root, home_dir().as_deref(), &home);
  warn_uncovered(root, &config);
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

/// Print one sorted warning for fnox-declared names no rule, passthrough, or
/// provider wiring covers, every time the agent is entered. Never prints
/// values. A missing fnox setup means nothing to cover, so it stays silent.
fn warn_uncovered(root: &Path, config: &AppConfig) {
  let Ok(fnox) = open_fnox() else {
    return;
  };
  let Some(fnox) = fnox else {
    return;
  };
  let Ok(registry) = generation_registry(Some(root)) else {
    return;
  };
  let selected = selected_envs(Some(&fnox), &registry);
  if let Some(warning) = uncovered_warning(&uncovered_names(fnox.declared(), &selected, &config.workspace.passthrough)) {
    println!("{warning}");
  }
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
pub fn init_command(workspace: &Path, backend: Option<ProxyBackend>) -> Result<(), Error> {
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
pub fn agent_command(workspace: &Path, command: &[OsString], rm: bool) -> Result<(), Error> {
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
    unsafe { signal(SIGINT, swallow_interrupt as *const () as sighandler_t) };
    Self
  }
}

impl Drop for SurviveInterrupt {
  fn drop(&mut self) {
    // Safety: restores the disposition every process starts with.
    unsafe { signal(SIGINT, SIG_DFL) };
  }
}

extern "C" fn swallow_interrupt(_: c_int) {}

/// `hodor up [workspace]`: start the layered compose project `hodor init`
/// generated, making sure what it mounts exists first.
///
/// # Errors
///
/// Returns an error when the workspace cannot be resolved, when the support
/// files cannot be written, or when the compose command fails.
pub fn up_command(workspace: &Path) -> Result<(), Error> {
  up_workspace(&resolve_root(workspace)?)
}

/// `hodor down [workspace]`: stop the layered compose project.
///
/// # Errors
///
/// Returns an error when the workspace cannot be resolved or when the compose
/// command fails.
pub fn down_command(workspace: &Path) -> Result<(), Error> {
  down_workspace(&resolve_root(workspace)?)
}

/// `hodor logs [workspace]`: read the stack's logs.
///
/// # Errors
///
/// Returns an error when the workspace cannot be resolved or when the compose
/// command fails.
pub fn logs_command(workspace: &Path, args: &LogsArgs) -> Result<(), Error> {
  logs_workspace(&resolve_root(workspace)?, args)
}
