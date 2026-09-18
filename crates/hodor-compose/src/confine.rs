//! `hodor confine`: generate-once-then-edit, then drive the compose project.

use std::path::{Path, PathBuf};

use eyre::WrapErr as _;

use hodor_config::cli::ConfineAction;

use crate::paths::translate;
use crate::stack::{generate_stack, workspace_config, workspace_file, workspace_state_dir};

/// The entrypoint the generated agent service runs: it makes hodor's CA trusted
/// inside the container before handing off to the command, by installing it into
/// the system store every tool already reads. `confine init` writes it when
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
exec "$@"
"#;

/// Create the host files the generated stack mounts, when they are missing: the
/// CA at `<dir>/ca.pem` (`ca.crt` and `ca.key` come with it, and the stack
/// mounts `ca.pem` for hodor and `ca.crt` for the agent) and the agent
/// entrypoint. Nothing existing is overwritten, so an edited entrypoint or a CA
/// you installed elsewhere survives. The directory is the hodor config
/// directory, which is what the compose defaults point at, not `[proxy]
/// ca_file`: that describes a host-run hodor, not the container's mount. The
/// storage directory is this workspace's, under the state directory.
pub(crate) fn ensure_support_files(dir: &Path, storage: &Path) -> eyre::Result<Vec<(PathBuf, bool)>> {
  let ca = dir.join("ca.pem");
  let entrypoint = dir.join("proxy-entrypoint.sh");
  let mut files = Vec::new();
  let created = !ca.exists();
  match hodor_pki::ca::load_or_generate(&ca) {
    Ok(_) => files.push((ca, created)),
    // A read-only or unwritable config directory only warns: the stack still
    // starts when HODOR_CA points at a CA made with `hodor ca`.
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

/// Write the agent entrypoint when absent. Executable: docker runs it directly.
pub(crate) fn write_entrypoint(path: &Path) -> eyre::Result<bool> {
  use std::os::unix::fs::PermissionsExt as _;
  if path.exists() {
    return Ok(false);
  }
  std::fs::write(path, ENTRYPOINT_SCRIPT).wrap_err_with(|| format!("write {}", path.display()))?;
  std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).wrap_err_with(|| format!("chmod {}", path.display()))?;
  Ok(true)
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

/// `hodor confine <action>`: generate-once-then-edit, start, and stop the
/// layered compose project. `init` generates the workspace stack into
/// `<state-dir>/hodor/ws/<slug>/compose.yml` only when absent — the same
/// file where real secrets are provided to hodor — so generated services
/// and secret mounts live in one editable file; `up` and `down` run docker
/// compose over the files found on disk, edits respected; `shell` execs the
/// configured shell in the agent at the translated workspace directory.
///
/// # Errors
///
/// Returns an error when the workspace cannot be resolved, when the support
/// files cannot be written, or when the compose command fails.
pub fn confine_command(action: &ConfineAction, workspace: &Path) -> eyre::Result<()> {
  let root = workspace
    .canonicalize()
    .wrap_err_with(|| format!("resolve workspace {}", workspace.display()))?;
  let state_ws = workspace_state_dir(&root);
  let ws_compose = state_ws.join("compose.yml");
  match action {
    ConfineAction::Init => {
      std::fs::create_dir_all(&state_ws).wrap_err_with(|| format!("create {}", state_ws.display()))?;
      report_created(&prepare_support_files(&root)?);
      if ws_compose.is_file() {
        println!("exists, left untouched: {}", ws_compose.display());
        return Ok(());
      }
      let stack = generate_stack(&root)?;
      std::fs::write(&ws_compose, stack).wrap_err_with(|| format!("write {}", ws_compose.display()))?;
      println!("generated: {}", ws_compose.display());
      Ok(())
    }
    ConfineAction::Up | ConfineAction::Down | ConfineAction::Shell => {
      let layers = [
        hodor_config::config::config_dir().map(|dir| dir.join("compose.yml")),
        Some(ws_compose),
        Some(workspace_file(&root)),
      ]
      .into_iter()
      .flatten()
      .filter(|path| path.is_file())
      .collect::<Vec<_>>();
      if layers.is_empty() {
        eyre::bail!(
          "no compose layers for {}; run `hodor confine init` first or create one of the layer files",
          root.display()
        );
      }
      let mut command = std::process::Command::new("docker");
      command.arg("compose");
      for layer in &layers {
        command.arg("-f").arg(layer);
      }
      let status = match action {
        ConfineAction::Shell => {
          let config = workspace_config(&root)?;
          let home = config
            .workspace
            .home
            .clone()
            .ok_or_else(|| eyre::eyre!("[workspace] home is required for the agent workdir"))?;
          let workdir = translate(&root, dirs::home_dir().as_deref(), &home);
          let shell = config.workspace.shell.clone().unwrap_or_else(|| "sh".to_string());
          let uid = {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata("/proc/self")?.uid()
          };
          command
            .arg("exec")
            .arg("-i")
            .arg("--workdir")
            .arg(&workdir)
            .arg("--user")
            .arg(uid.to_string())
            .arg("agent")
            .arg(shell)
            .status()
        }
        ConfineAction::Up => {
          report_created(&prepare_support_files(&root)?);
          command.arg("up").arg("-d").status()
        }
        _ => command.arg("down").status(),
      }
      .wrap_err("spawn docker compose")?;
      eyre::ensure!(status.success(), "docker compose failed: {status}");
      Ok(())
    }
  }
}
