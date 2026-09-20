//! Compose stack generation: decoy selection, mount resolution, and YAML.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hodor_config::cli::ProxyBackend;
use hodor_config::config::AgentCfg;

use crate::paths::{Mount, covering, expand, translate};

/// One selected env var with its decoy value.
pub(crate) struct Decoy {
  /// Env var name as the rule declares it.
  pub env: String,
  /// Decoy value for the agent environment.
  pub value: String,
}

/// Select every fnox-declared name the registry knows, with its decoy.
pub(crate) fn select(fnox: Option<&hodor_fnox::FnoxSource>, registry: &hodor_config::registry::Registry) -> Vec<Decoy> {
  hodor_fnox::selected_envs(fnox, registry)
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
pub(crate) fn with_rule_patterns(
  decoys: Vec<Decoy>,
  registry: &hodor_config::registry::Registry,
  rules: &BTreeMap<String, hodor_config::config::RuleCfg>,
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
pub(crate) fn by_hosts(registry: &hodor_config::registry::Registry, decoys: Vec<Decoy>) -> (Vec<Decoy>, Vec<Decoy>) {
  decoys
    .into_iter()
    .partition(|decoy| registry.lookup(&decoy.env).is_some_and(|known| !known.hosts.is_empty()))
}

/// `hodor rules`: env-only rules for the secrets this workspace can get, plus
/// a note naming the fnox declarations no registry entry covers.
///
/// # Errors
///
/// Returns an error when the registry or the fnox source cannot be opened.
pub fn rules_command() -> eyre::Result<String> {
  let registry = generation_registry()?;
  let fnox = open_fnox()?;
  let (with_hosts, hostless) = by_hosts(&registry, select(fnox.as_ref(), &registry));
  let known = hodor_fnox::selected_envs(fnox.as_ref(), &registry);
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

/// Split a trailing `:ro` or `:rw` off an include entry; bare paths are rw.
pub(crate) fn split_mode(entry: &Path) -> (PathBuf, bool) {
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
/// hodor's own fnox level.
#[derive(Default)]
pub(crate) struct FnoxBinds {
  pub(crate) mounts: Vec<Mount>,
}

/// The fnox config directory fnox itself resolves: `FNOX_CONFIG_DIR`, else
/// `<config-dir>/fnox`.
pub(crate) fn fnox_config_dir(host_home: Option<&Path>) -> Option<PathBuf> {
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
pub(crate) fn fnox_binds(fnox_dir: Option<&Path>, config_dir: Option<&Path>) -> FnoxBinds {
  let mut binds = FnoxBinds { mounts: Vec::new() };
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
pub(crate) fn include_entries(root: &Path, includes: &[PathBuf], host_home: Option<&Path>) -> eyre::Result<Vec<(PathBuf, bool)>> {
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

pub(crate) fn generate_stack(root: &Path, backend: ProxyBackend) -> eyre::Result<String> {
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
  let agent_configs = agent_config_mounts(hodor_config::config::config_dir().as_deref(), &config.agents, &home)?;
  let fnox = fnox_binds(
    fnox_config_dir(host_home.as_deref()).as_deref(),
    hodor_config::config::config_dir().as_deref(),
  );
  let root_container = translate(root, host_home.as_deref(), &home);
  let project = config.workspace.name.clone().unwrap_or_else(|| workspace_slug(root));
  let storage = workspace_state_dir(root).join("containers");
  let uid = current_uid();
  Ok(
    Stack {
      backend,
      project,
      decoys,
      agent: AgentSpec {
        root: &root_container,
        home: &home,
        storage: &storage,
        uid,
      },
      mounts,
      agent_configs,
      fnox,
      init: config.workspace.init.clone(),
    }
    .render(),
  )
}

/// The process's user id, from the kernel: the same value `id -u` prints,
/// without the subprocess.
pub(crate) fn current_uid() -> u32 {
  // Safety: `getuid` takes no arguments, cannot fail, and touches no memory.
  unsafe { libc::getuid() }
}

/// `[rules.*]` TOML for the selection: env names only, values resolve from
/// fnox at serve time.
pub(crate) fn rules_toml(decoys: &[Decoy], hostless: &[Decoy], unregistered: &[String]) -> String {
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

/// What the generated agent service is built from: container-side paths and
/// the host directory mounted as the inner runtime's storage.
pub(crate) struct AgentSpec<'a> {
  /// Workspace root, translated into the agent container.
  pub(crate) root: &'a Path,
  /// The agent user's home directory in the container.
  pub(crate) home: &'a str,
  /// Host directory mounted at `{home}/.local/share/containers`.
  pub(crate) storage: &'a Path,
  /// Host uid baked as the agent user: mounts the agent writes must be its own.
  pub(crate) uid: u32,
}

/// What the hodor service runs for a capture backend, the extra capabilities
/// that needs, and the service keys that go with it.
fn backend_service(backend: ProxyBackend, project: &str) -> (String, &'static [&'static str], String) {
  match backend {
    ProxyBackend::Ebpf => (
      "[\"serve\", \"--proxy-backend\", \"ebpf\", \"--ebpf-cgroup\", \"enclosing\"]".to_string(),
      &["BPF", "PERFMON"],
      // Both services carry the same `cgroup_parent`, so docker creates that
      // cgroup as part of hodor's own start and hodor attaches to it by
      // resolving its parent from `/proc/self/cgroup`: the daemon resolves the
      // parent relative to its own cgroup root, which is why no host path is
      // written down here.
      format!("    cgroup: host\n    cgroup_parent: hodor-{project}.slice\n"),
    ),
    ProxyBackend::Tun => (
      "[\"serve\", \"--proxy-backend\", \"tun\"]".to_string(),
      &[],
      "    devices: [/dev/net/tun]\n".to_string(),
    ),
    ProxyBackend::Tproxy => ("[\"serve\", \"--proxy-backend\", \"tproxy\"]".to_string(), &[], String::new()),
    // `hodor init` rejects `none`; rendered anyway so this match is exhaustive.
    ProxyBackend::None => ("[\"serve\"]".to_string(), &[], String::new()),
  }
}

/// A stack to generate: every input compose rendering reads, as one value.
/// [`generate_stack`] fills it from a workspace; tests build it literally.
pub(crate) struct Stack<'a> {
  pub(crate) backend: ProxyBackend,
  pub(crate) project: String,
  pub(crate) decoys: Vec<Decoy>,
  pub(crate) agent: AgentSpec<'a>,
  pub(crate) mounts: Vec<Mount>,
  pub(crate) agent_configs: Vec<Mount>,
  pub(crate) fnox: FnoxBinds,
  pub(crate) init: Option<String>,
}

impl Stack<'_> {
  /// The compose file this stack renders to.
  pub(crate) fn render(&self) -> String {
    let (serve, extra_caps, service_extra) = backend_service(self.backend, &self.project);
    let mut out = String::new();
    let _ = write!(
      out,
      "# generated by `hodor init` — edit freely; regeneration only\n\
       # happens when this file is absent. hodor merges config like always\n\
       # (global layer plus this workspace's .config/hodor.toml, discovered\n\
       # from its working directory); the agent holds decoys only.\n\
       name: {project}\n\
       services:\n\
       \x20 hodor:\n\
       \x20   image: ghcr.io/casualjim/hodor:latest\n\
       \x20   working_dir: \"{root}\"\n\
       \x20   command: {serve}\n\
       {service_extra}\
       \x20   environment:\n\
       \x20     RUST_LOG: info\n\
       \x20     HODOR_CA_FILE: /certs/ca.pem\n",
      root = self.agent.root.display(),
      project = self.project
    );
    out.push_str(
      "    cap_add:\n\
       \x20     - NET_ADMIN\n",
    );
    for cap in extra_caps {
      let _ = writeln!(out, "      - {cap}");
    }
    out.push_str(
      "    stop_grace_period: 1s\n\
       \x20   volumes:\n",
    );
    for mount in &self.mounts {
      let mode = if mount.ro { "ro" } else { "rw" };
      let _ = writeln!(out, "      - {}:{}:{mode}", mount.host.display(), mount.container.display());
    }
    let _ = writeln!(
      out,
      "      - {}:/certs/ca.pem",
      hodor_config::config::config_dir()
        .unwrap_or_else(|| Path::new("~/.config/hodor").to_path_buf())
        .join("ca.pem")
        .display()
    );
    for mount in &self.fnox.mounts {
      let _ = writeln!(out, "      - {}:{}:ro", mount.host.display(), mount.container.display());
    }
    out.push_str(&self.agent_service());
    out
  }

  /// The agent service: it shares hodor's network namespace and holds decoys
  /// only, plus the backend's cgroup placement when the capture needs one. The
  /// hooks only capture processes inside the cgroup they attach to, so this
  /// service lands in it and hodor stays outside.
  fn agent_service(&self) -> String {
    let cgroup = match self.backend {
      ProxyBackend::Ebpf => format!(
        "    # Both services sit in this cgroup and hodor attaches to it: the hooks\n\
       \x20   # capture what is inside, and hodor's own sockets are skipped by\n\
       \x20   # the recorded proxy PID.\n\
       \x20   cgroup_parent: hodor-{}.slice\n",
        self.project
      ),
      ProxyBackend::Tun | ProxyBackend::Tproxy | ProxyBackend::None => String::new(),
    };
    let mut out = String::new();
    let _ = write!(
      out,
      "\n\
     \x20 agent:\n\
     \x20   image: ghcr.io/casualjim/devagent:26.04\n\
     \x20   # The agent runs containers of its own, which is what the widened\n\
     \x20   # privileges are for: inner containers mount, chroot and raise their\n\
     \x20   # own networking, so seccomp/systempaths/apparmor are unconfined and\n\
     \x20   # SYS_ADMIN is granted. apparmor=unconfined is what Ubuntu's default\n\
     \x20   # profile requires and is inert where AppArmor is not loaded.\n\
     \x20   # systempaths=unconfined is podman-only: drop it under docker.\n\
     \x20   security_opt: [seccomp=unconfined, systempaths=unconfined, apparmor=unconfined]\n\
     \x20   cap_add: [SYS_CHROOT, AUDIT_WRITE, NET_ADMIN, SETUID, SETGID, SYS_ADMIN]\n\
     \x20   devices: [/dev/net/tun]\n\
     {cgroup}\
     \x20   # docker-init (tini) as pid 1: signal handling and child reaping\n\
     \x20   # for the long-running shells this container hosts\n\
     \x20   init: true\n\
     \x20   user: \"{uid}\"\n\
     \x20   working_dir: \"{root}\"\n\
     \x20   entrypoint: [\"{home}/.config/hodor/agent-entrypoint.sh\"]\n\
     \x20   command: [\"sleep\", \"infinity\"]\n\
     \x20   environment:\n\
     \x20     # The entrypoint installs the CA into the system store. Node and\n\
     \x20     # Python's requests read their own bundle, so point them at it.\n\
     \x20     NODE_EXTRA_CA_CERTS: /etc/ssl/certs/ca-certificates.crt\n\
     \x20     REQUESTS_CA_BUNDLE: /etc/ssl/certs/ca-certificates.crt\n\
     \x20     # decoys — one per declared rule, swapped by hodor on grant match\n",
      root = self.agent.root.display(),
      home = self.agent.home,
      uid = self.agent.uid
    );
    if let Some(init) = &self.init {
      let _ = writeln!(out, "      HODOR_INIT: \"{init}\"");
    }
    for decoy in &self.decoys {
      let _ = writeln!(out, "      {}: \"{}\"", decoy.env, decoy.value);
    }
    out.push_str("    volumes:\n");
    for mount in self.mounts.iter().chain(&self.agent_configs) {
      let mode = if mount.ro { "ro" } else { "rw" };
      let _ = writeln!(out, "      - {}:{}:{mode}", mount.host.display(), mount.container.display());
    }
    let cfg_dir = hodor_config::config::config_dir();
    let entrypoint_host = cfg_dir
      .as_deref()
      .unwrap_or_else(|| Path::new("~/.config/hodor"))
      .join("agent-entrypoint.sh");
    let ca_crt_host = cfg_dir.as_deref().unwrap_or_else(|| Path::new("~/.config/hodor")).join("ca.crt");
    let _ = write!(
      out,
      "      - {}:{home}/.config/hodor/agent-entrypoint.sh:ro\n\
     \x20     - {}:/usr/local/share/ca-certificates/hodor-ca.crt:ro\n\
     \x20     # Inner container storage. Made at generation time under this\n\
     \x20     # workspace's state directory, owned by the user that runs the\n\
     \x20     # agent: a bind source the runtime creates itself is root-owned,\n\
     \x20     # and podman inside then dies without a word. A named volume needs\n\
     \x20     # the same ownership once, by hand.\n\
     \x20     - {storage}:{home}/.local/share/containers\n\
     \x20   network_mode: \"service:hodor\"\n",
      entrypoint_host.display(),
      ca_crt_host.display(),
      home = self.agent.home,
      storage = self.agent.storage.display()
    );
    out
  }
}

/// Container location each agent reads its config from by default, keyed by the
/// directory name under `<config-dir>/agents/`. `{home}` expands to
/// `[workspace] home`. `[agents.<name>] config_dir` overrides an entry or adds
/// one the table does not carry.
pub(crate) const AGENT_CONFIG_DIRS: &[(&str, &str)] = &[
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
pub(crate) fn agent_config_mounts(
  config_dir: Option<&Path>,
  configured: &BTreeMap<String, AgentCfg>,
  home: &str,
) -> eyre::Result<Vec<Mount>> {
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

/// Registry for the generation commands: bundled table plus global `rules.d`.
pub(crate) fn generation_registry() -> eyre::Result<hodor_config::registry::Registry> {
  hodor_config::registry::Registry::load(hodor_config::config::rules_dir().as_deref())
}

/// Open fnox via its own discovery; no hodor-specific env vars.
pub(crate) fn open_fnox() -> eyre::Result<Option<hodor_fnox::FnoxSource>> {
  hodor_fnox::FnoxSource::open()
}

/// The workspace's state directory: `<state-dir>/hodor/ws/<slug>`. The
/// generated stack lives here and the agent's inner-runtime storage sits
/// beside it.
pub(crate) fn workspace_state_dir(root: &Path) -> PathBuf {
  dirs::state_dir()
    .unwrap_or_else(|| PathBuf::from("."))
    .join("hodor")
    .join("ws")
    .join(workspace_slug(root))
}

/// The workspace's override file: `hodor.compose.yaml` first, then `.yml`.
pub(crate) fn workspace_file(root: &Path) -> PathBuf {
  let yaml = root.join(".config").join("hodor.compose.yaml");
  if yaml.is_file() {
    return yaml;
  }
  root.join(".config").join("hodor.compose.yml")
}

/// Stable directory slug for a workspace root: lowercase path segments
/// joined with dashes.
pub(crate) fn workspace_slug(root: &Path) -> String {
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
pub(crate) fn workspace_config(root: &Path) -> eyre::Result<hodor_config::config::AppConfig> {
  let project = root.join(".config").join("hodor.toml");
  let cli = hodor_config::cli::Cli {
    config: project.is_file().then_some(project),
    command: None,
  };
  Ok(hodor_config::config::load(&cli)?.0)
}
