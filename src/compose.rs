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
fn generate_stack(root: &Path) -> eyre::Result<String> {
  let registry = generation_registry()?;
  let project = root.join(".config").join("hodor.toml");
  let cli = crate::Cli {
    config: project.is_file().then_some(project),
    command: None,
  };
  let (config, _) = crate::config::load(&cli)?;
  let home = config
    .workspace
    .home
    .clone()
    .ok_or_else(|| eyre::eyre!("[workspace] home is required for stack generation"))?;
  let host_home = dirs::home_dir();
  let mut entries = vec![(root.to_path_buf(), false)];
  for entry in &config.workspace.include {
    let (path, ro) = split_mode(entry);
    entries.push((expand(&path, root, host_home.as_deref()), ro));
  }
  // Parents first so a covering mount wins and covered paths drop out.
  entries.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
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
  let root_container = translate(root, host_home.as_deref(), &home);
  let project = config.workspace.name.clone().unwrap_or_else(|| workspace_slug(root));
  Ok(compose_yaml(&decoys, &project, &root_container, &home, &mounts, &agent_configs))
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
     \x20   cap_add:\n\
     \x20     - NET_ADMIN\n\
     \x20   stop_grace_period: 1s\n\
     \x20   volumes:\n",
    root = root_container.display()
  );
  for mount in mounts {
    let mode = if mount.ro { "ro" } else { "rw" };
    let _ = writeln!(out, "      - {}:{}:{mode}", mount.host.display(), mount.container.display());
  }
  let _ = write!(
    out,
    "      - ${{HODOR_CA:-~/.config/hodor/ca.pem}}:/certs/ca.pem\n\
     \x20     - ~/.config/fnox/age.txt:/root/.config/fnox/age.txt:ro\n\
     \n\
     \x20 agent:\n\
     \x20   image: ${{AGENT_IMAGE:-ghcr.io/casualjim/devenv:omp}}\n\
     \x20   # docker-init (tini) as pid 1: signal handling and child reaping\n\
     \x20   # for the long-running shells this container hosts\n\
     \x20   init: true\n\
     \x20   user: \"${{UID:-1000}}\"\n\
     \x20   working_dir: \"{root}\"\n\
     \x20   entrypoint: [\"{home}/.config/hodor/proxy-entrypoint.sh\"]\n\
     \x20   command: [\"sleep\", \"infinity\"]\n\
     \x20   environment:\n\
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
          let project = root.join(".config").join("hodor.toml");
          let cli = crate::Cli {
            config: project.is_file().then_some(project),
            command: None,
          };
          let (config, _) = crate::config::load(&cli)?;
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
        crate::ConfineAction::Up => command.arg("up").arg("-d").status(),
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

    let yaml = compose_yaml(&decoys(), "hodor", Path::new("/home/eng/github/hodor"), "/home/eng", &[], &mounts);
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
  fn compose_yaml_mounts_the_workspace_at_its_translated_path() {
    let mounts = vec![
      mount("/home/ivan/github/hodor", "/home/eng/github/hodor", false),
      mount("/home/ivan/.config/mise", "/home/eng/.config/mise", true),
    ];
    let yaml = compose_yaml(&decoys(), "hodor", Path::new("/home/eng/github/hodor"), "/home/eng", &mounts, &[]);
    assert!(yaml.contains("name: hodor\nservices:"), "{yaml}");
    assert!(yaml.contains("working_dir: \"/home/eng/github/hodor\""), "{yaml}");
    assert!(yaml.contains("- /home/ivan/github/hodor:/home/eng/github/hodor:rw"), "{yaml}");
    assert!(yaml.contains("- /home/ivan/.config/mise:/home/eng/.config/mise:ro"), "{yaml}");
    assert!(yaml.contains("/home/eng/.config/hodor/proxy-entrypoint.sh:ro"), "{yaml}");
    assert!(yaml.contains("network_mode: \"service:hodor\""), "{yaml}");
    assert!(yaml.contains("- ~/.config/fnox/age.txt:/root/.config/fnox/age.txt:ro"), "{yaml}");
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
