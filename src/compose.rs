//! Workspace confinement: `hodor rules` prints env-only rules for the
//! fnox-declared names the registry knows; `hodor confine` generates the
//! workspace stack once as an editable file and drives the layered compose
//! project.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use eyre::WrapErr as _;

use crate::config::AgentCfg;

/// One selected env var with its decoy value.
pub struct Decoy {
  /// Env var name as the rule declares it.
  pub env: String,
  /// Decoy value for the agent environment.
  pub value: String,
}

/// Select every fnox-declared name the registry knows, with its decoy.
pub(crate) fn select(fnox: Option<&crate::secrets::FnoxSource>, registry: &crate::secrets::Registry) -> Vec<Decoy> {
  crate::secrets::selected_envs(fnox, registry)
    .into_iter()
    .map(|env| {
      let value = registry.decoy(&env, None);
      Decoy { env, value }
    })
    .collect()
}

/// Reshape a selection with each rule's own pattern. Serve-time substitution
/// derives its fake from `rule.pattern`, so a decoy built from the registry
/// default instead would never match and the swap would silently not happen.
fn with_rule_patterns(
  decoys: Vec<Decoy>,
  registry: &crate::secrets::Registry,
  rules: &BTreeMap<String, crate::config::RuleCfg>,
) -> Vec<Decoy> {
  decoys
    .into_iter()
    .map(|decoy| {
      let pattern = rules
        .values()
        .find(|rule| rule.env == decoy.env)
        .and_then(|rule| rule.pattern.as_deref());
      Decoy {
        value: registry.decoy(&decoy.env, pattern),
        ..decoy
      }
    })
    .collect()
}

/// Split a selection by whether the registry states hosts for the name.
/// Active rules come first, names with no endpoint second.
fn by_hosts(registry: &crate::secrets::Registry, decoys: Vec<Decoy>) -> (Vec<Decoy>, Vec<Decoy>) {
  decoys
    .into_iter()
    .partition(|decoy| registry.lookup(&decoy.env).is_some_and(|known| !known.hosts.is_empty()))
}

/// `hodor rules`: env-only rules for the secrets this workspace can get, plus
/// a note naming the fnox declarations no registry entry covers.
pub(crate) fn rules_command() -> eyre::Result<String> {
  let registry = generation_registry()?;
  let fnox = open_fnox()?;
  let (with_hosts, hostless) = by_hosts(&registry, select(fnox.as_ref(), &registry));
  let known = crate::secrets::selected_envs(fnox.as_ref(), &registry);
  let unknown = fnox
    .as_ref()
    .map(|fnox| {
      fnox
        .declared()
        .iter()
        .filter(|name| !known.contains(name))
        .cloned()
        .collect::<Vec<_>>()
    })
    .unwrap_or_default();
  Ok(rules_toml(&with_hosts, &hostless, &unknown))
}

/// One generated mount: host path, translated container path, read-only flag.
#[derive(Debug)]
pub(crate) struct Mount {
  /// Host path as configured.
  host: PathBuf,
  /// Translated path inside the containers.
  container: PathBuf,
  /// Whether the mount is read-only.
  ro: bool,
}

/// Split a trailing `:ro` or `:rw` off an include entry; bare paths are rw.
fn split_mode(entry: &Path) -> (PathBuf, bool) {
  let text = entry.as_os_str().to_str().unwrap_or_default();
  if let Some(rest) = text.strip_suffix(":ro") {
    return (PathBuf::from(rest), true);
  }
  if let Some(rest) = text.strip_suffix(":rw") {
    return (PathBuf::from(rest), false);
  }
  (entry.to_path_buf(), false)
}

/// Generate the stack for a workspace directory: decoys for every
/// fnox-declared name the registry knows (same selection as `hodor rules`)
/// plus the translated mounts from `[workspace]`.
/// What the hodor service mounts and forwards so the container's fnox resolves
/// what the host's does: its config directory (identity, providers, config),
/// hodor's own fnox level, and the provider credentials the shell already has.
#[derive(Default)]
pub(crate) struct FnoxBinds {
  mounts: Vec<Mount>,
  env: Vec<String>,
}

/// The fnox config directory fnox itself resolves: `FNOX_CONFIG_DIR`, else
/// `<config-dir>/fnox`.
fn fnox_config_dir(host_home: Option<&Path>) -> Option<PathBuf> {
  if let Some(dir) = std::env::var_os("FNOX_CONFIG_DIR") {
    return Some(PathBuf::from(dir));
  }
  dirs::config_dir()
    .or_else(|| host_home.map(|home| home.join(".config")))
    .map(|dir| dir.join("fnox"))
}

/// Bind mounts and environment the hodor service needs to act like fnox does.
/// Every mount is conditional on the host path existing: docker turns a bind of
/// a missing path into a directory, which is never what we want. Container paths
/// are what fnox and hodor look at inside, where the home is `/root`.
fn fnox_binds(fnox_dir: Option<&Path>, config_dir: Option<&Path>) -> FnoxBinds {
  let env = crate::secrets::FNOX_ENV
    .iter()
    .filter(|name| std::env::var_os(name).is_some())
    .map(|name| (*name).to_string())
    .collect();
  let mut binds = FnoxBinds { mounts: Vec::new(), env };
  if let Some(dir) = fnox_dir.filter(|dir| dir.is_dir()) {
    binds.mounts.push(Mount {
      host: dir.to_path_buf(),
      container: PathBuf::from("/root/.config/fnox"),
      ro: true,
    });
  }
  let mut levels = config_dir
    .and_then(|dir| std::fs::read_dir(dir).ok())
    .into_iter()
    .flatten()
    .flatten()
    .map(|entry| entry.path())
    .filter(|path| {
      path.is_file()
        && path.file_name().is_some_and(|name| {
          let name = name.to_string_lossy();
          name.starts_with("fnox") && name.ends_with(".toml")
        })
    })
    .collect::<Vec<_>>();
  levels.sort();
  for path in levels {
    binds.mounts.push(Mount {
      container: Path::new("/root/.config/hodor").join(path.file_name().unwrap_or_default()),
      host: path,
      ro: true,
    });
  }
  binds
}

/// Mount entries for the workspace root and `[workspace] include`, ordered the
/// way `covering` wants them: parents first, so a covering mount wins and
/// covered paths drop out. A path that is not there is an error rather than a
/// warning, because docker mounts an empty directory in its place.
fn include_entries(root: &Path, includes: &[PathBuf], host_home: Option<&Path>) -> eyre::Result<Vec<(PathBuf, bool)>> {
  let mut entries = vec![(root.to_path_buf(), false)];
  for entry in includes {
    let (path, ro) = split_mode(entry);
    let host = expand(&path, root, host_home);
    eyre::ensure!(
      host.exists(),
      "[workspace] include `{}` does not exist; docker would mount an empty directory in its place",
      entry.display()
    );
    entries.push((host, ro));
  }
  entries.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
  Ok(entries)
}

fn generate_stack(root: &Path) -> eyre::Result<String> {
  let registry = generation_registry()?;
  let config = workspace_config(root)?;
  let home = config
    .workspace
    .home
    .clone()
    .ok_or_else(|| eyre::eyre!("[workspace] home is required for stack generation"))?;
  let host_home = dirs::home_dir();
  let entries = include_entries(root, &config.workspace.include, host_home.as_deref())?;
  let mounts = covering(
    entries
      .into_iter()
      .map(|(host, ro)| Mount {
        container: translate(&host, host_home.as_deref(), &home),
        host,
        ro,
      })
      .collect(),
  );
  let decoys = with_rule_patterns(select(open_fnox()?.as_ref(), &registry), &registry, &config.rules);
  let agent_configs = agent_config_mounts(crate::config::config_dir().as_deref(), &config.agents, &home)?;
  let fnox = fnox_binds(
    fnox_config_dir(host_home.as_deref()).as_deref(),
    crate::config::config_dir().as_deref(),
  );
  let root_container = translate(root, host_home.as_deref(), &home);
  let project = config.workspace.name.clone().unwrap_or_else(|| workspace_slug(root));
  Ok(compose_yaml(
    &decoys,
    &project,
    &root_container,
    &home,
    &mounts,
    &agent_configs,
    &fnox,
  ))
}

/// `[rules.*]` TOML for the selection: env names only, values resolve from
/// fnox at serve time.
pub fn rules_toml(decoys: &[Decoy], hostless: &[Decoy], unregistered: &[String]) -> String {
  let mut out = String::from(
    "# generated by `hodor rules` — values resolve from fnox at serve time.\n\
     #\n\
     # A rule swaps its real value in only for the hosts it lists, so every rule\n\
     # needs at least one. The registry supplies them, which is why most rules\n\
     # below need nothing more. Providers whose hosts are per deployment (self-hosted\n\
     # control planes) are listed commented at the end — name the host to use them.\n\
     # Put the rule in the workspace `.config/hodor.toml` or in the global\n\
     # `<config-dir>/hodor/config.toml`; per label, the workspace file wins:\n\
     #\n\
     #   [rules.my_secret]\n\
     #   env = \"MY_SECRET\"\n\
     #   allow = [\"https://api.internal.example.com\"]\n\
     #\n\
     # To give a name hosts for every workspace instead of one rule, add an\n\
     # override file in `<config-dir>/hodor/rules.d/` or\n\
     # `<workspace root>/.config/hodor/rules.d/`:\n\
     #\n\
     #   [names.MY_SECRET]\n\
     #   hosts = [\"https://api.internal.example.com\"]\n\
     #\n\
     # `allow` takes `scheme://host[:port]` entries and unions with the registry\n\
     # hosts; `registry = false` drops those and keeps only `allow`. A fnox key\n\
     # no registry entry covers gets no rule at all — the names are listed at the\n\
     # end of this output.\n",
  );
  for decoy in decoys {
    let _ = writeln!(
      out,
      "[rules.{}]\nenv = \"{}\"\nif_missing = \"warn\"\n",
      decoy.env.to_lowercase(),
      decoy.env
    );
  }
  if !hostless.is_empty() {
    out.push_str(
      "# The registry knows these names but states no hosts: either the endpoint is\n\
       # per deployment (self-hosted control planes) or the value is a signing input\n\
       # that never reaches the wire (exchange API secrets — see\n\
       # https://github.com/casualjim/hodor/issues/19). Name the endpoint to use the\n\
       # key as a rule, or drop it from fnox to stop emitting a decoy:\n\
       #\n",
    );
    for decoy in hostless {
      let _ = writeln!(
        out,
        "# [rules.{}]\n# env = \"{}\"\n# allow = [\"https://<your-host>\"]\n# if_missing = \"warn\"\n",
        decoy.env.to_lowercase(),
        decoy.env
      );
    }
  }
  if !unregistered.is_empty() {
    let _ = writeln!(
      out,
      "# fnox declares these but no registry entry covers them, so nothing generates a rule:\n# {}\n",
      unregistered.join(", ")
    );
  }
  out
}

/// The generated stack: hodor merges config from its working directory like
/// always and fnox resolves per-workspace inside, and the agent shares
/// hodor's network namespace from the translated workspace directory,
/// decoys only.
pub(crate) fn compose_yaml(
  decoys: &[Decoy],
  project: &str,
  root_container: &Path,
  home: &str,
  mounts: &[Mount],
  agent_configs: &[Mount],
  fnox: &FnoxBinds,
) -> String {
  let mut out = String::new();
  let _ = write!(
    out,
    "# generated by `hodor confine init` — edit freely; regeneration only\n\
     # happens when this file is absent. hodor merges config like always\n\
     # (global layer plus this workspace's .config/hodor.toml, discovered\n\
     # from its working directory); the agent holds decoys only.\n\
     name: {project}\n\
     services:\n\
     \x20 hodor:\n\
     \x20   image: ${{HODOR_IMAGE:-ghcr.io/casualjim/hodor:latest}}\n\
     \x20   working_dir: \"{root}\"\n\
     \x20   command: [\"serve\", \"--tproxy\"]\n\
     \x20   environment:\n\
     \x20     RUST_LOG: info\n\
     \x20     HODOR_CA_FILE: /certs/ca.pem\n\
     \x20     # Provider credentials fnox reads, taken from the environment\n\
     \x20     # this stack starts in; a token fnox itself declares is resolved\n\
     \x20     # inside the container instead.\n",
    root = root_container.display()
  );
  for name in &fnox.env {
    let _ = writeln!(out, "      {name}: \"${{{name}}}\"");
  }
  out.push_str(
    "     \x20   cap_add:\n\
     \x20     - NET_ADMIN\n\
     \x20   stop_grace_period: 1s\n\
     \x20   volumes:\n",
  );
  for mount in mounts {
    let mode = if mount.ro { "ro" } else { "rw" };
    let _ = writeln!(out, "      - {}:{}:{mode}", mount.host.display(), mount.container.display());
  }
  out.push_str("      - ${HODOR_CA:-~/.config/hodor/ca.pem}:/certs/ca.pem\n");
  for mount in &fnox.mounts {
    let _ = writeln!(out, "      - {}:{}:ro", mount.host.display(), mount.container.display());
  }
  let _ = write!(
    out,
    "\n\
     \x20 agent:\n\
     \x20   image: ${{AGENT_IMAGE:-ghcr.io/casualjim/devagent:26.04}}\n\
     \x20   # The agent runs containers of its own, which is what the widened\n\
     \x20   # privileges are for: inner containers mount, chroot and raise their\n\
     \x20   # own networking, so seccomp/systempaths/apparmor are unconfined and\n\
     \x20   # SYS_ADMIN is granted. apparmor=unconfined is what Ubuntu's default\n\
     \x20   # profile requires and is inert where AppArmor is not loaded.\n\
     \x20   # systempaths=unconfined is podman-only: drop it under docker.\n\
     \x20   security_opt: [seccomp=unconfined, systempaths=unconfined, apparmor=unconfined]\n\
     \x20   cap_add: [SYS_CHROOT, AUDIT_WRITE, NET_ADMIN, SETUID, SETGID, SYS_ADMIN]\n\
     \x20   devices: [/dev/net/tun]\n\
     \x20   # docker-init (tini) as pid 1: signal handling and child reaping\n\
     \x20   # for the long-running shells this container hosts\n\
     \x20   init: true\n\
     \x20   user: \"${{UID:-1000}}\"\n\
     \x20   working_dir: \"{root}\"\n\
     \x20   entrypoint: [\"{home}/.config/hodor/proxy-entrypoint.sh\"]\n\
     \x20   command: [\"sleep\", \"infinity\"]\n\
     \x20   environment:\n\
     \x20     # The entrypoint installs the CA into the system store. Node and\n\
     \x20     # Python's requests read their own bundle, so point them at it.\n\
     \x20     NODE_EXTRA_CA_CERTS: /etc/ssl/certs/ca-certificates.crt\n\
     \x20     REQUESTS_CA_BUNDLE: /etc/ssl/certs/ca-certificates.crt\n\
     \x20     # decoys — one per declared rule, swapped by hodor on grant match\n",
    root = root_container.display(),
    home = home
  );
  for decoy in decoys {
    let _ = writeln!(out, "      {}: \"{}\"", decoy.env, decoy.value);
  }
  out.push_str("    volumes:\n");
  for mount in mounts.iter().chain(agent_configs) {
    let mode = if mount.ro { "ro" } else { "rw" };
    let _ = writeln!(out, "      - {}:{}:{mode}", mount.host.display(), mount.container.display());
  }
  let _ = write!(
    out,
    "      - ${{HODOR_ENTRYPOINT:-~/.config/hodor/proxy-entrypoint.sh}}:{home}/.config/hodor/proxy-entrypoint.sh:ro\n\
     \x20     - ${{HODOR_CA_CRT:-~/.config/hodor/ca.crt}}:/usr/local/share/ca-certificates/hodor-ca.crt:ro\n\
     \x20     # Inner container storage. Made at generation time, owned by the\n\
     \x20     # user that runs the agent: a bind source the runtime creates itself\n\
     \x20     # is root-owned, and podman inside then dies without a word. A named\n\
     \x20     # volume needs the same ownership once, by hand.\n\
     \x20     - ${{HODOR_AGENT_STORAGE:-~/.config/hodor/agent-containers}}:{home}/.local/share/containers\n\
     \x20   network_mode: \"service:hodor\"\n"
  );
  out
}

/// Container location each agent reads its config from by default, keyed by the
/// directory name under `<config-dir>/agents/`. `{home}` expands to
/// `[workspace] home`. `[agents.<name>] config_dir` overrides an entry or adds
/// one the table does not carry.
const AGENT_CONFIG_DIRS: &[(&str, &str)] = &[
  ("amazon-q", "{home}/.aws/amazonq"),
  ("amazonq", "{home}/.aws/amazonq"),
  ("amp", "{home}/.config/amp"),
  ("auggie", "{home}/.augment"),
  ("augment", "{home}/.augment"),
  ("claude", "{home}/.claude"),
  ("claude-code", "{home}/.claude"),
  ("cline", "{home}/.cline"),
  ("codebuddy", "{home}/.codebuddy"),
  ("codebuff", "{home}/.config/manicode"),
  ("codex", "{home}/.codex"),
  ("codex-cli", "{home}/.codex"),
  ("continue", "{home}/.continue"),
  ("copilot", "{home}/.copilot"),
  ("crush", "{home}/.config/crush"),
  ("cursor", "{home}/.cursor"),
  ("deepagents", "{home}/.deepagents"),
  ("droid", "{home}/.factory"),
  ("dsh", "{home}/.dsh"),
  ("factory", "{home}/.factory"),
  ("forge", "{home}/.forge"),
  ("gemini", "{home}/.gemini"),
  ("gemini-cli", "{home}/.gemini"),
  ("goose", "{home}/.config/goose"),
  ("gptme", "{home}/.config/gptme"),
  ("grok", "{home}/.grok"),
  ("grok-build", "{home}/.grok"),
  ("hermes", "{home}/.hermes"),
  ("iflow", "{home}/.iflow"),
  ("junie", "{home}/.junie"),
  ("junie-cli", "{home}/.junie"),
  ("kilo", "{home}/.config/kilo"),
  ("kimi", "{home}/.kimi"),
  ("kimi-code", "{home}/.kimi-code"),
  ("kiro", "{home}/.kiro"),
  ("kiro-cli", "{home}/.kiro"),
  ("mimo", "{home}/.mimo-code"),
  ("mimo-code", "{home}/.mimo-code"),
  ("muse", "{home}/.muse-code"),
  ("muse-code", "{home}/.muse-code"),
  ("omp", "{home}/.omp"),
  ("open-interpreter", "{home}/.config/open-interpreter"),
  ("openclaw", "{home}/.openclaw"),
  ("openhands", "{home}/.openhands"),
  ("openinterpreter", "{home}/.config/open-interpreter"),
  ("opencode", "{home}/.config/opencode"),
  ("pi", "{home}/.pi"),
  ("qoder", "{home}/.qoder"),
  ("qwen", "{home}/.qwen"),
  ("qwen-code", "{home}/.qwen"),
  ("roo", "{home}/.config/roo"),
  ("roo-code", "{home}/.config/roo"),
  ("trae", "{home}/.trae"),
  ("vibe", "{home}/.vibe"),
  ("warp", "{home}/.config/warp-terminal"),
  ("workbuddy", "{home}/.codebuddy"),
];

/// Mount every directory under `<config-dir>/agents/` at the location its agent
/// reads by default, so nothing has to point the agent at it. Writable: the
/// agent owns that directory, and its writes land under the hodor config
/// directory on the host. A missing parent directory, a directory whose name no
/// entry covers, or a `config_dir` that does not expand to an absolute
/// container path mounts nothing.
fn agent_config_mounts(config_dir: Option<&Path>, configured: &BTreeMap<String, AgentCfg>, home: &str) -> eyre::Result<Vec<Mount>> {
  let Some(agents) = config_dir.map(|dir| dir.join("agents")) else {
    return Ok(Vec::new());
  };
  let Ok(entries) = std::fs::read_dir(&agents) else {
    return Ok(Vec::new());
  };
  let mut hosts: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).filter(|path| path.is_dir()).collect();
  hosts.sort();
  let mut mounts = Vec::new();
  for host in hosts {
    let Some(name) = host.file_name().and_then(|name| name.to_str()) else {
      continue;
    };
    let template = configured
      .get(name)
      .map(|agent| agent.config_dir.as_str())
      .or_else(|| AGENT_CONFIG_DIRS.iter().find(|(agent, _)| *agent == name).map(|(_, dir)| *dir));
    let Some(template) = template else {
      continue;
    };
    let container = template.replace("{home}", home);
    eyre::ensure!(
      container.starts_with('/'),
      "[agents.{name}] config_dir `{template}` does not expand to an absolute container path"
    );
    mounts.push(Mount {
      host,
      container: PathBuf::from(container),
      ro: false,
    });
  }
  Ok(mounts)
}

/// Expand `~` against the host home and relative paths against the root,
/// normalizing `..` lexically.
fn expand(path: &Path, root: &Path, host_home: Option<&Path>) -> PathBuf {
  if path == Path::new("~") {
    return host_home.map_or_else(|| root.join(path), Path::to_path_buf);
  }
  if let Ok(rest) = path.strip_prefix("~/")
    && let Some(home) = host_home
  {
    return normalize(&home.join(rest));
  }
  if path.is_absolute() {
    normalize(path)
  } else {
    normalize(&root.join(path))
  }
}

/// Lexically remove `.` and resolve `..` without touching the filesystem.
fn normalize(path: &Path) -> PathBuf {
  let mut out = PathBuf::new();
  for component in path.components() {
    match component {
      std::path::Component::ParentDir => {
        out.pop();
      }
      std::path::Component::CurDir => {}
      other => out.push(other.as_os_str()),
    }
  }
  out
}

/// Host path to container path: under-home paths translate into the
/// container home prefix, everything else mounts at its own path.
fn translate(path: &Path, host_home: Option<&Path>, home: &str) -> PathBuf {
  match host_home.and_then(|hh| path.strip_prefix(hh).ok()) {
    Some(rest) => Path::new(home).join(rest),
    None => path.to_path_buf(),
  }
}

/// Drop every mount whose host path is covered by another mount; the
/// covering mount serves the same files at its translated path.
fn covering(mounts: Vec<Mount>) -> Vec<Mount> {
  let mut out: Vec<Mount> = Vec::new();
  for mount in mounts {
    if out.iter().any(|kept| mount.host.starts_with(&kept.host)) {
      continue;
    }
    out.retain(|kept| !kept.host.starts_with(&mount.host));
    out.push(mount);
  }
  out
}

/// Registry for the generation commands: bundled table plus global `rules.d`.
fn generation_registry() -> eyre::Result<crate::secrets::Registry> {
  crate::secrets::Registry::load(crate::config::rules_dir().as_deref())
}

/// Open fnox via its own discovery; no hodor-specific env vars.
fn open_fnox() -> eyre::Result<Option<crate::secrets::FnoxSource>> {
  crate::secrets::FnoxSource::open()
}

/// The workspace's override file: `hodor.compose.yaml` first, then `.yml`.
fn workspace_file(root: &Path) -> PathBuf {
  let yaml = root.join(".config").join("hodor.compose.yaml");
  if yaml.is_file() {
    return yaml;
  }
  root.join(".config").join("hodor.compose.yml")
}

/// Stable directory slug for a workspace root: lowercase path segments
/// joined with dashes.
fn workspace_slug(root: &Path) -> String {
  let slug: Vec<String> = root
    .components()
    .filter_map(|component| match component {
      std::path::Component::Normal(part) => {
        let text = part.to_string_lossy().to_lowercase();
        let cleaned: String = text.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
        (!cleaned.trim_matches('-').is_empty()).then(|| cleaned.trim_matches('-').to_string())
      }
      _ => None,
    })
    .collect();
  slug.join("-")
}

/// The workspace's own config, as generation and support-file setup read it:
/// the project layer at `<root>/.config/hodor.toml` when it exists.
fn workspace_config(root: &Path) -> eyre::Result<crate::config::AppConfig> {
  let project = root.join(".config").join("hodor.toml");
  let cli = crate::Cli {
    config: project.is_file().then_some(project),
    command: None,
  };
  Ok(crate::config::load(&cli)?.0)
}

/// The entrypoint the generated agent service runs: it makes hodor's CA trusted
/// inside the container before handing off to the command, by installing it into
/// the system store every tool already reads. `confine init` writes it when
/// absent, so an edited copy survives regeneration.
const ENTRYPOINT_SCRIPT: &str = r#"#!/bin/sh
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
/// ca_file`: that describes a host-run hodor, not the container's mount.
fn ensure_support_files(dir: &Path) -> eyre::Result<Vec<(PathBuf, bool)>> {
  let ca = dir.join("ca.pem");
  let entrypoint = dir.join("proxy-entrypoint.sh");
  let mut files = Vec::new();
  let created = !ca.exists();
  match crate::ca::load_or_generate(&ca) {
    Ok(_) => files.push((ca, created)),
    // A read-only or unwritable config directory only warns: the stack still
    // starts when HODOR_CA points at a CA made with `hodor ca`.
    Err(err) => println!("warning: could not prepare {}: {err}", dir.join("ca.pem").display()),
  }
  files.push((entrypoint.clone(), write_entrypoint(&entrypoint)?));
  // The agent's inner container storage — see the generated compose file for
  // why this directory has to exist before the stack starts.
  let storage = dir.join("agent-containers");
  let storage_created = !storage.exists();
  match std::fs::create_dir_all(&storage) {
    Ok(()) => files.push((storage, storage_created)),
    Err(err) => println!("warning: could not prepare {}: {err}", storage.display()),
  }
  Ok(files)
}

/// Write the agent entrypoint when absent. Executable: docker runs it directly.
fn write_entrypoint(path: &Path) -> eyre::Result<bool> {
  use std::os::unix::fs::PermissionsExt as _;
  if path.exists() {
    return Ok(false);
  }
  std::fs::write(path, ENTRYPOINT_SCRIPT).wrap_err_with(|| format!("write {}", path.display()))?;
  std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).wrap_err_with(|| format!("chmod {}", path.display()))?;
  Ok(true)
}

/// Resolve the config directory, then create what the stack mounts there.
fn prepare_support_files() -> eyre::Result<Vec<(PathBuf, bool)>> {
  let dir = crate::config::config_dir().ok_or_else(|| eyre::eyre!("unable to resolve the hodor config directory"))?;
  ensure_support_files(&dir)
}

/// Report the files the call actually created; absent ones are already there.
fn report_created(files: &[(PathBuf, bool)]) {
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
pub(crate) fn confine_command(action: &crate::ConfineAction, workspace: &Path) -> eyre::Result<()> {
  let root = workspace
    .canonicalize()
    .wrap_err_with(|| format!("resolve workspace {}", workspace.display()))?;
  let slug = workspace_slug(&root);
  let state_ws = dirs::state_dir()
    .unwrap_or_else(|| PathBuf::from("."))
    .join("hodor")
    .join("ws")
    .join(&slug);
  let ws_compose = state_ws.join("compose.yml");
  match action {
    crate::ConfineAction::Init => {
      std::fs::create_dir_all(&state_ws).wrap_err_with(|| format!("create {}", state_ws.display()))?;
      report_created(&prepare_support_files()?);
      if ws_compose.is_file() {
        println!("exists, left untouched: {}", ws_compose.display());
        return Ok(());
      }
      let stack = generate_stack(&root)?;
      std::fs::write(&ws_compose, stack).wrap_err_with(|| format!("write {}", ws_compose.display()))?;
      println!("generated: {}", ws_compose.display());
      Ok(())
    }
    crate::ConfineAction::Up | crate::ConfineAction::Down | crate::ConfineAction::Shell => {
      let layers = [
        crate::config::config_dir().map(|dir| dir.join("compose.yml")),
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
        crate::ConfineAction::Shell => {
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
        crate::ConfineAction::Up => {
          report_created(&prepare_support_files()?);
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

#[cfg(test)]
mod tests {
  use super::*;

  fn decoys() -> Vec<Decoy> {
    vec![
      Decoy {
        env: "GITHUB_TOKEN".to_string(),
        value: "ghp_2641386f5e0c6b9ea7b79c738a1015a9bc3a9ae3".to_string(),
      },
      Decoy {
        env: "ANTHROPIC_API_KEY".to_string(),
        value: "sk-ant-api03-example".to_string(),
      },
    ]
  }

  fn mount(host: &str, container: &str, ro: bool) -> Mount {
    Mount {
      host: PathBuf::from(host),
      container: PathBuf::from(container),
      ro,
    }
  }

  /// Test-only env write and removal, so the unsafe call lives in one place.
  fn set_env(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    // SAFETY: test-only mutation, and nextest runs one test per process.
    unsafe { std::env::set_var(key, value) };
  }

  fn unset_env(key: &str) {
    // SAFETY: test-only mutation, and nextest runs one test per process.
    unsafe { std::env::remove_var(key) };
  }

  #[test]
  fn rules_toml_lists_every_env_without_values() {
    let toml = rules_toml(&decoys(), &[], &[]);
    assert!(toml.contains("[rules.github_token]"), "{toml}");
    assert!(toml.contains("env = \"GITHUB_TOKEN\""), "{toml}");
    assert!(toml.contains("[rules.anthropic_api_key]"), "{toml}");
    assert!(toml.contains("#   allow = [\"https://api.internal.example.com\"]"), "{toml}");
    assert!(!toml.contains("value ="), "{toml}");
  }

  #[test]
  fn names_the_registry_states_no_hosts_for_split_out_of_the_active_rules() {
    let registry = generation_registry().unwrap();
    let decoys = vec![
      Decoy {
        env: "GITHUB_TOKEN".to_string(),
        value: "decoy".to_string(),
      },
      Decoy {
        env: "VAULT_TOKEN".to_string(),
        value: "decoy".to_string(),
      },
    ];
    let (with_hosts, hostless) = by_hosts(&registry, decoys);
    assert_eq!(with_hosts.len(), 1);
    assert_eq!(with_hosts[0].env, "GITHUB_TOKEN");
    assert_eq!(hostless.len(), 1);
    assert_eq!(hostless[0].env, "VAULT_TOKEN");
  }

  #[test]
  fn rules_toml_comments_out_names_the_registry_knows_without_hosts() {
    let hostless = vec![Decoy {
      env: "ARGO_CD_TOKEN".to_string(),
      value: "decoy".to_string(),
    }];
    let toml = rules_toml(&decoys(), &hostless, &["TAVILY_API_KEY".to_string()]);
    assert!(toml.contains("# [rules.argo_cd_token]"), "{toml}");
    assert!(toml.contains("# env = \"ARGO_CD_TOKEN\""), "{toml}");
    assert!(toml.contains("# allow = [\"https://<your-host>\"]"), "{toml}");
    assert!(!toml.contains("\n[rules.argo_cd_token]"), "{toml}");
    assert!(toml.contains("# TAVILY_API_KEY"), "{toml}");
  }

  #[test]
  fn under_home_paths_translate_into_the_container_home() {
    let host_home = Path::new("/home/ivan");
    assert_eq!(
      translate(Path::new("/home/ivan/github/hodor"), Some(host_home), "/home/eng"),
      PathBuf::from("/home/eng/github/hodor")
    );
    assert_eq!(translate(Path::new("/data"), Some(host_home), "/home/eng"), PathBuf::from("/data"));
    assert_eq!(
      translate(Path::new("/home/ivan"), Some(host_home), "/home/eng"),
      PathBuf::from("/home/eng")
    );
  }

  #[test]
  fn covering_mounts_absorb_overlaps() {
    let mounts = vec![
      mount("/home/ivan/github/hodor", "/home/eng/github/hodor", false),
      mount("/home/ivan/github", "/home/eng/github", false),
      mount("/home/ivan/.config/mise", "/home/eng/.config/mise", true),
      mount("/opt/data", "/opt/data", false),
    ];
    let kept = covering(mounts);
    let hosts: Vec<String> = kept.iter().map(|m| m.host.display().to_string()).collect();
    assert_eq!(hosts, vec!["/home/ivan/github", "/home/ivan/.config/mise", "/opt/data"], "{kept:?}");
    assert!(kept[1].ro, "the surviving mount keeps its own mode");
  }

  #[test]
  fn include_entries_split_their_mount_mode() {
    assert_eq!(split_mode(Path::new("~/.config/mise:ro")), (PathBuf::from("~/.config/mise"), true));
    assert_eq!(split_mode(Path::new("/data/cache:rw")), (PathBuf::from("/data/cache"), false));
    assert_eq!(split_mode(Path::new("/data/cache")), (PathBuf::from("/data/cache"), false));
  }

  #[test]
  fn tilde_and_relative_includes_expand_against_root_and_home() {
    let root = Path::new("/home/ivan/github/hodor");
    let host_home = Some(Path::new("/home/ivan"));
    assert_eq!(
      expand(Path::new("~/.config/mise"), root, host_home),
      PathBuf::from("/home/ivan/.config/mise")
    );
    assert_eq!(
      expand(Path::new("../sibling"), root, host_home),
      PathBuf::from("/home/ivan/github/sibling")
    );
    assert_eq!(expand(Path::new("/opt/data"), root, host_home), PathBuf::from("/opt/data"));
  }

  #[test]
  fn agent_config_directories_mount_at_each_agents_default_location() {
    let host_home = tempfile::tempdir().unwrap();
    let config_dir = host_home.path().join(".config").join("hodor");
    let agents = config_dir.join("agents");
    std::fs::create_dir_all(agents.join("pi")).unwrap();
    std::fs::create_dir_all(agents.join("opencode")).unwrap();
    std::fs::create_dir_all(agents.join("not-an-agent")).unwrap();
    std::fs::write(agents.join("stray-file"), "x").unwrap();

    let mounts = agent_config_mounts(Some(&config_dir), &BTreeMap::new(), "/home/eng").unwrap();
    let rendered: Vec<String> = mounts
      .iter()
      .map(|entry| {
        format!(
          "{}:{}:{}",
          entry.host.display(),
          entry.container.display(),
          if entry.ro { "ro" } else { "rw" }
        )
      })
      .collect();
    assert_eq!(
      rendered,
      vec![
        format!("{}:/home/eng/.config/opencode:rw", agents.join("opencode").display()),
        format!("{}:/home/eng/.pi:rw", agents.join("pi").display()),
      ]
    );

    let yaml = compose_yaml(
      &decoys(),
      "hodor",
      Path::new("/home/eng/github/hodor"),
      "/home/eng",
      &[],
      &mounts,
      &FnoxBinds::default(),
    );
    assert!(
      yaml.contains(&format!("- {}:/home/eng/.pi:rw", agents.join("pi").display())),
      "{yaml}"
    );
    assert!(!yaml.contains("not-an-agent"), "{yaml}");
  }

  #[test]
  fn configured_agents_extend_and_override_the_built_in_table() {
    let host_home = tempfile::tempdir().unwrap();
    let config_dir = host_home.path().join(".config").join("hodor");
    let agents = config_dir.join("agents");
    std::fs::create_dir_all(agents.join("pi")).unwrap();
    std::fs::create_dir_all(agents.join("trae")).unwrap();

    let configured = BTreeMap::from([
      (
        "pi".to_string(),
        AgentCfg {
          config_dir: "{home}/.pi-alt".to_string(),
        },
      ),
      (
        "trae".to_string(),
        AgentCfg {
          config_dir: "{home}/.trae".to_string(),
        },
      ),
    ]);
    let mounts = agent_config_mounts(Some(&config_dir), &configured, "/home/eng").unwrap();
    let rendered: Vec<String> = mounts
      .iter()
      .map(|entry| format!("{}:{}", entry.host.display(), entry.container.display()))
      .collect();
    assert_eq!(
      rendered,
      vec![
        format!("{}:/home/eng/.pi-alt", agents.join("pi").display()),
        format!("{}:/home/eng/.trae", agents.join("trae").display()),
      ]
    );

    let relative = BTreeMap::from([(
      "pi".to_string(),
      AgentCfg {
        config_dir: "relative/pi".to_string(),
      },
    )]);
    let err = agent_config_mounts(Some(&config_dir), &relative, "/home/eng").unwrap_err();
    assert!(err.to_string().contains("absolute"), "{err:?}");
  }

  #[test]
  fn the_agent_service_carries_what_inner_containers_need() {
    let yaml = compose_yaml(
      &decoys(),
      "hodor",
      Path::new("/home/eng"),
      "/home/eng",
      &[],
      &[],
      &FnoxBinds::default(),
    );
    for expected in [
      "image: ${AGENT_IMAGE:-ghcr.io/casualjim/devagent:26.04}",
      "security_opt: [seccomp=unconfined, systempaths=unconfined, apparmor=unconfined]",
      "cap_add: [SYS_CHROOT, AUDIT_WRITE, NET_ADMIN, SETUID, SETGID, SYS_ADMIN]",
      "devices: [/dev/net/tun]",
      "- ${HODOR_AGENT_STORAGE:-~/.config/hodor/agent-containers}:/home/eng/.local/share/containers",
    ] {
      assert!(yaml.contains(expected), "missing {expected}:\n{yaml}");
    }
    // The agent runs its own runtime; it never reaches the host's.
    assert!(!yaml.contains("docker.sock") && !yaml.contains("/var/run/docker"), "{yaml}");
  }

  #[test]
  fn compose_yaml_mounts_the_workspace_at_its_translated_path() {
    let mounts = vec![
      mount("/home/ivan/github/hodor", "/home/eng/github/hodor", false),
      mount("/home/ivan/.config/mise", "/home/eng/.config/mise", true),
    ];
    let yaml = compose_yaml(
      &decoys(),
      "hodor",
      Path::new("/home/eng/github/hodor"),
      "/home/eng",
      &mounts,
      &[],
      &FnoxBinds::default(),
    );
    assert!(yaml.contains("name: hodor\nservices:"), "{yaml}");
    assert!(yaml.contains("working_dir: \"/home/eng/github/hodor\""), "{yaml}");
    assert!(yaml.contains("- /home/ivan/github/hodor:/home/eng/github/hodor:rw"), "{yaml}");
    assert!(yaml.contains("- /home/ivan/.config/mise:/home/eng/.config/mise:ro"), "{yaml}");
    assert!(yaml.contains("/home/eng/.config/hodor/proxy-entrypoint.sh:ro"), "{yaml}");
    assert!(yaml.contains("network_mode: \"service:hodor\""), "{yaml}");
    assert!(yaml.contains("- ${HODOR_CA:-~/.config/hodor/ca.pem}:/certs/ca.pem"), "{yaml}");
    assert!(!yaml.contains("/root/.config/fnox"), "no fnox mount without binds to mount: {yaml}");
    assert!(yaml.contains("init: true"), "{yaml}");
    assert!(
      yaml.contains("GITHUB_TOKEN: \"ghp_2641386f5e0c6b9ea7b79c738a1015a9bc3a9ae3\""),
      "{yaml}"
    );
  }

  #[test]
  fn workspace_slug_uses_path_segments() {
    assert_eq!(workspace_slug(Path::new("/home/ivan/github/hodor")), "home-ivan-github-hodor");
    assert_eq!(workspace_slug(Path::new("/srv/My_Project")), "srv-my-project");
  }

  #[test]
  fn the_example_workspace_loads_and_inherits_registry_hosts() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/agentic-devenv/.config/hodor.toml");
    let cli = crate::Cli {
      config: Some(example.clone()),
      command: None,
    };
    let (config, _) = crate::config::load(&cli).unwrap_or_else(|err| panic!("{} does not load: {err}", example.display()));
    assert_eq!(config.workspace.home.as_deref(), Some("/home/eng"));
    assert_eq!(config.workspace.shell.as_deref(), Some("bash"));
    let registry = generation_registry().unwrap();
    for (label, env) in [("anthropic", "ANTHROPIC_API_KEY"), ("github", "GH_TOKEN")] {
      let rule = config
        .rules
        .get(label)
        .unwrap_or_else(|| panic!("`{label}` missing from {}", example.display()));
      assert_eq!(rule.env, env);
      assert!(rule.value.is_none(), "`{label}` must resolve from fnox, not carry a value");
      assert!(!registry.hosts_for(rule).is_empty(), "`{label}` needs hosts from the registry");
    }
  }

  #[test]
  fn includes_that_are_not_there_are_rejected() {
    let host_home = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let sibling = root.path().join("sibling");
    std::fs::create_dir_all(&sibling).unwrap();

    let entries = include_entries(root.path(), &[PathBuf::from("sibling:ro")], Some(host_home.path())).unwrap();
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert!(entries.iter().any(|(path, ro)| path == &sibling && *ro), "{entries:?}");

    let err = include_entries(root.path(), &[PathBuf::from("missing")], Some(host_home.path())).unwrap_err();
    assert!(err.to_string().contains("does not exist"), "{err:?}");
    assert!(err.to_string().contains("missing"), "{err:?}");
  }

  #[test]
  fn fnox_binds_mount_only_what_exists_and_forward_present_credentials() {
    let home = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let fnox_dir = home.path().join(".config").join("fnox");
    std::fs::create_dir_all(&fnox_dir).unwrap();
    std::fs::write(fnox_dir.join("age.txt"), "AGE-SECRET-KEY-1\n").unwrap();
    std::fs::write(
      config_dir.path().join("fnox.toml"),
      "[secrets.X]\nprovider = \"plain\"\nvalue = \"x\"\n",
    )
    .unwrap();
    std::fs::write(config_dir.path().join("config.toml"), "[proxy]\n").unwrap();

    let binds = fnox_binds(Some(&fnox_dir), Some(config_dir.path()));
    let rendered: Vec<String> = binds
      .mounts
      .iter()
      .map(|entry| format!("{}:{}:ro", entry.host.display(), entry.container.display()))
      .collect();
    assert_eq!(
      rendered,
      vec![
        format!("{}:/root/.config/fnox:ro", fnox_dir.display()),
        format!("{}:/root/.config/hodor/fnox.toml:ro", config_dir.path().join("fnox.toml").display()),
      ],
      "the fnox config directory and hodor's own fnox level, and not the host's hodor config.toml"
    );

    let empty = tempfile::tempdir().unwrap();
    assert!(
      fnox_binds(Some(&empty.path().join("missing")), Some(empty.path()))
        .mounts
        .is_empty(),
      "a path that is not there is never mounted: docker would create a directory in its place"
    );

    // Credentials the shell has are forwarded by name, so no value lands in the file.
    let key = "BWS_ACCESS_TOKEN";
    let previous = std::env::var_os(key);
    set_env(key, "0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let binds = fnox_binds(None, None);
    assert!(binds.env.iter().any(|name| name == key), "{:?}", binds.env);
    let yaml = compose_yaml(&decoys(), "hodor", Path::new("/home/eng"), "/home/eng", &[], &[], &binds);
    assert!(yaml.contains(&format!("{key}: \"${{{key}}}\"")), "{yaml}");
    assert!(
      !yaml.contains("0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
      "the value must not be written"
    );
    match previous {
      Some(value) => set_env(key, value),
      None => unset_env(key),
    }
  }

  #[test]
  fn support_files_are_written_when_absent_and_never_overwritten() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let entrypoint = dir.path().join("proxy-entrypoint.sh");

    let files = ensure_support_files(dir.path()).unwrap();
    assert!(files.iter().all(|(_, created)| *created), "{files:?}");
    let pem = std::fs::read_to_string(dir.path().join("ca.pem")).unwrap();
    let crt = std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();
    let key = std::fs::read_to_string(dir.path().join("ca.key")).unwrap();
    assert!(dir.path().join("proxy-entrypoint.sh").is_file());
    assert!(dir.path().join("agent-containers").is_dir());
    // `ca.pem` is what hodor reads; `ca.crt` is the certificate alone, which is
    // what the agent gets. A clean system needs both.
    assert!(
      pem.contains("BEGIN CERTIFICATE") && pem.contains("PRIVATE KEY"),
      "ca.pem carries both halves"
    );
    assert!(
      crt.contains("BEGIN CERTIFICATE") && !crt.contains("PRIVATE KEY"),
      "ca.crt carries the certificate only"
    );
    assert!(
      key.contains("PRIVATE KEY") && !key.contains("CERTIFICATE"),
      "ca.key carries the key only"
    );
    let script = std::fs::read_to_string(&entrypoint).unwrap();
    assert!(
      script.contains("update-ca-certificates"),
      "the entrypoint installs the CA into the system store"
    );
    assert!(script.contains("exec \"$@\""), "the entrypoint hands off to the command");
    assert_ne!(
      std::fs::metadata(&entrypoint).unwrap().permissions().mode() & 0o111,
      0,
      "the agent runs the entrypoint directly, so it must be executable"
    );

    std::fs::write(&entrypoint, "#!/bin/sh\necho mine\n").unwrap();
    std::fs::remove_file(dir.path().join("ca.pem")).unwrap();
    let files = ensure_support_files(dir.path()).unwrap();
    let created: BTreeMap<&str, bool> = files
      .iter()
      .map(|(path, created)| (path.file_name().unwrap().to_str().unwrap(), *created))
      .collect();
    assert_eq!(created.get("proxy-entrypoint.sh"), Some(&false), "an edited entrypoint survives");
    assert_eq!(created.get("ca.pem"), Some(&true), "a deleted CA comes back");
    assert_eq!(std::fs::read_to_string(&entrypoint).unwrap(), "#!/bin/sh\necho mine\n");
  }

  #[test]
  fn generated_decoys_follow_the_rule_pattern() {
    let registry = crate::secrets::Registry::load(None).unwrap();
    let default = registry.decoy("ANTHROPIC_API_KEY", None);
    let rule: crate::config::RuleCfg =
      toml_edit::de::from_str("env = \"ANTHROPIC_API_KEY\"\npattern = \"sk-ant-api03-{hex:8}\"\n").unwrap();
    let rules = BTreeMap::from([("anthropic".to_string(), rule)]);

    let shaped = with_rule_patterns(
      vec![Decoy {
        env: "ANTHROPIC_API_KEY".to_string(),
        value: default.clone(),
      }],
      &registry,
      &rules,
    );

    assert_eq!(shaped[0].value, registry.decoy("ANTHROPIC_API_KEY", Some("sk-ant-api03-{hex:8}")));
    assert_ne!(shaped[0].value, default);
  }
}
