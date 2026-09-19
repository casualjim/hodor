//! Config overlay: global + project files, env, CLI via confique.

use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use confique::{Config as _, Layer as _};
use eyre::WrapErr as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::cli::{Cli, Command};
use code_workspace::{Workspace, resolve_root};

/// Pattern used when neither the rule nor the registry supplies one.
pub const DEFAULT_PATTERN: &str = "{hex:32}";

/// Runtime config: listener settings, workspace mounts, plus rules by label.
#[derive(confique::Config, Debug, Clone, Serialize)]
pub struct AppConfig {
  /// Proxy listener settings.
  #[config(nested)]
  pub proxy: ProxyCfg,
  /// Workspace settings for generated compose output.
  #[config(nested)]
  pub workspace: WorkspaceCfg,
  /// Rules by label; merged per label across global + project files.
  #[config(default = {})]
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub rules: BTreeMap<String, RuleCfg>,
  /// WASM rewrite plugins by name; loaded at startup, fail closed.
  #[config(default = {})]
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub plugins: BTreeMap<String, crate::plugins::PluginCfg>,
  /// Agent config mounts by directory name; extends or overrides the built-in
  /// table.
  #[config(default = {})]
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub agents: BTreeMap<String, AgentCfg>,
}

/// One agent config mount: the directory of this name under
/// `<config-dir>/agents/` mounts at `config_dir` inside the agent container,
/// so the agent finds its own configuration where it looks by default.
#[derive(confique::Config, Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCfg {
  /// Container path the directory mounts at; `{home}` expands to
  /// `[workspace] home`.
  pub config_dir: String,
}

/// Extra host paths the generated agent service mounts, translated into the
/// container home; overlapping paths reuse the covering mount.
#[derive(confique::Config, Debug, Clone, Default, Serialize)]
pub struct WorkspaceCfg {
  /// Compose project name for the generated stack; defaults to the
  /// workspace slug.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub name: Option<String>,
  /// Shell invoked by `hodor confine shell`; defaults to sh.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub shell: Option<String>,
  /// Paths included in the generated compose; `~` expands, relative paths
  /// resolve against the workspace root.
  #[config(default = [])]
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub include: Vec<PathBuf>,
  /// `$HOME` inside the agent container; host paths under the host home
  /// translate into this prefix, others mount at their own path.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub home: Option<String>,
}
/// Proxy listener settings (CLI/env/file overlay).
#[derive(confique::Config, Clone, Debug, Serialize)]
#[config(layer_attr(derive(clap::Args, Clone, Debug, Default)))]
pub struct ProxyCfg {
  /// Explicit-proxy listen address.
  #[config(default = "127.0.0.1:8080", env = "HODOR_LISTEN")]
  #[config(layer_attr(arg(long = "listen", help = "explicit-proxy listen address")))]
  pub listen: SocketAddr,
  /// CA PEM path (default `<config-dir>/hodor/ca.pem`).
  #[config(env = "HODOR_CA_FILE")]
  #[config(layer_attr(arg(long = "ca-file", help = "CA PEM path (default <config-dir>/hodor/ca.pem)")))]
  #[serde(skip_serializing_if = "Option::is_none")]
  pub ca_file: Option<PathBuf>,
}

/// One rule: env name, allowed hosts, decoy shape, and value source.
#[derive(confique::Config, Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCfg {
  /// Env var name: decoy seed, registry key, and default fnox key.
  pub env: String,
  /// Inline real secret value (never serialized). Wins over fnox.
  #[serde(default, skip_serializing)]
  pub value: Option<SecretString>,
  /// fnox secret name; defaults to `env`.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub fnox_key: Option<String>,
  /// Raw `scheme://host[:port]` allow entries; unioned with registry hosts.
  #[serde(default)]
  pub allow: Vec<String>,
  /// Explicit fake pattern overriding the registry.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub pattern: Option<String>,
  /// Consult the host registry for this rule (default true).
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub registry: Option<bool>,
  /// What to do when the value or the hosts are missing.
  #[serde(default)]
  pub if_missing: IfMissing,
}

/// What to do when a rule cannot be fully resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IfMissing {
  /// Fail startup.
  #[default]
  Error,
  /// Log a warning and drop the rule's grant.
  Warn,
  /// Drop the rule's grant silently.
  Ignore,
}

/// Load config with precedence CLI > env > project > global.
/// Returns the config plus the discovered workspace (`None` when no
/// workspace marker was found and no explicit root was given).
///
/// # Errors
///
/// Returns an error when the working directory is unreadable, when a config
/// layer is malformed, or when an `allow` entry fails to resolve.
pub fn load(cli: &Cli) -> eyre::Result<(AppConfig, Option<Workspace>)> {
  let cwd = env::current_dir()?;
  let mut cli_layer = <AppConfig as confique::Config>::Layer::empty();
  if let Some(Command::Serve(args)) = &cli.command {
    cli_layer.proxy = args.proxy.clone();
  }

  let mut builder = AppConfig::builder().preloaded(cli_layer).env();
  let project = match &cli.config {
    Some(path) => Some(path.clone()),
    None => discover_project_config(&cwd),
  };
  if let Some(path) = &project
    && path.exists()
  {
    builder = builder.file(path);
  }
  let global = global_config_path().filter(|path| path.exists());
  if let Some(path) = &global {
    builder = builder.file(path);
  }

  let mut config: AppConfig = builder.load().map_err(eyre::Report::from)?;
  // confique merges the `rules` map wholesale per winning file, so re-merge
  // by label here: global entries first, project entries replace by label.
  // This second read of the same files is deliberate. confique's builder
  // produces the scalars and this pass produces the rule labels, so a file
  // edited between the two reads yields scalars from one parse and labels
  // from the other. Do not collapse it into a single read without accounting
  // for that.
  config.rules = load_merged_rules(project.as_deref(), global.as_deref())?;
  config.validate()?;

  let workspace = resolve_root(None, &cwd).ok().and_then(|root| Workspace::from_root(&root).ok());
  Ok((config, workspace))
}

/// Locate the project-layer file: resolve the workspace root upward from
/// `start`, then check `<root>/.config/hodor.toml`.
#[must_use]
pub fn discover_project_config(start: &Path) -> Option<PathBuf> {
  let root = resolve_root(None, start).ok()?;
  let path = root.join(".config").join("hodor.toml");
  path.exists().then_some(path)
}

/// Merge `[rules]` tables by label: global first, project wins wholesale
/// per label. Errors name the file + label.
fn load_merged_rules(project: Option<&Path>, global: Option<&Path>) -> eyre::Result<BTreeMap<String, RuleCfg>> {
  let mut merged = BTreeMap::new();
  for path in [global, project].into_iter().flatten() {
    let text = std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
    let doc: toml::Table = toml::from_str(&text).wrap_err_with(|| format!("parse {}", path.display()))?;
    let Some(rules) = doc.get("rules") else {
      continue;
    };
    let table = rules
      .as_table()
      .ok_or_else(|| eyre::eyre!("{}: `rules` must be a table", path.display()))?;
    for (label, entry) in table {
      let cfg = RuleCfg::deserialize(entry.clone()).wrap_err_with(|| format!("{}: rule `{label}`", path.display()))?;
      merged.insert(label.clone(), cfg);
    }
  }
  Ok(merged)
}

fn global_config_path() -> Option<PathBuf> {
  if let Ok(path) = env::var("HODOR_CONFIG") {
    return Some(PathBuf::from(path));
  }
  let standard = dirs::config_dir().map(|dir| dir.join("hodor").join("config.toml"));
  if let Some(path) = &standard
    && path.exists()
  {
    return Some(path.clone());
  }
  #[cfg(target_os = "macos")]
  {
    if let Some(home) = dirs::home_dir() {
      let path = home.join(".config").join("hodor").join("config.toml");
      if path.exists() {
        return Some(path);
      }
    }
  }
  standard
}

/// Directory holding the global config file, and `rules.d` beside it.
#[must_use]
pub fn config_dir() -> Option<PathBuf> {
  global_config_path().and_then(|path| path.parent().map(Path::to_path_buf))
}

/// Registry override directory: `rules.d` beside the global config file.
#[must_use]
pub fn rules_dir() -> Option<PathBuf> {
  config_dir().map(|dir| dir.join("rules.d"))
}

impl AppConfig {
  fn validate(&self) -> eyre::Result<()> {
    let mut env_names: BTreeMap<&str, &str> = BTreeMap::new();
    for (label, rule) in &self.rules {
      if let Some(previous) = env_names.insert(rule.env.as_str(), label.as_str()) {
        eyre::bail!("rules `{previous}` and `{label}` share env name `{}`", rule.env);
      }
      eyre::ensure!(!rule.env.is_empty(), "rule `{label}`: `env` must not be empty");
      if let Some(value) = &rule.value {
        eyre::ensure!(!value.expose_secret().is_empty(), "rule `{label}`: `value` must not be empty");
      }
      for entry in &rule.allow {
        let grant: crate::grants::UriGrant = entry
          .parse()
          .map_err(|err| eyre::eyre!("rule `{label}`: bad allow entry `{entry}`: {err}"))?;
        if matches!(grant.host, crate::grants::HostPat::Any) {
          tracing::warn!(label, entry, "grant matches any host; secret is exfil-risky");
        }
      }
      if let Some(pattern) = rule.pattern.as_deref().filter(|p| !p.is_empty()) {
        validate_pattern(pattern).map_err(|err| eyre::eyre!("rule `{label}`: bad pattern `{pattern}`: {err}"))?;
      }
    }
    Ok(())
  }
}

// ---------------------------------------------------------------------------
// format-valid deterministic fakes (port of substitute.py fake_for)
// ---------------------------------------------------------------------------

/// Deterministic format-valid fake for an env var name. Stable across
/// restarts, distinct per name. `pattern` wins; the registry supplies one
/// through `secrets::Registry::decoy`, and `DEFAULT_PATTERN` is the floor.
#[must_use]
pub fn fake_for(env_name: &str, pattern: Option<&str>) -> String {
  let template = pattern.filter(|pattern| !pattern.is_empty()).unwrap_or(DEFAULT_PATTERN);
  let seed = hex::encode(Sha256::digest(env_name.as_bytes()));
  render_template(template, &seed)
}
/// Validate an explicit `pattern` template: every `{...}` must be a known
/// verb (`hex`, `d`, `base62`) with a nonzero count. Rejects typos that
/// would otherwise render silently wrong (`{bogus:10}` → base62) or empty
/// (`{hex:0}` → skipped grant).
///
/// # Errors
///
/// Returns the offending verb or count as a message when a `{...}` segment is
/// not a known verb or carries a zero count.
pub fn validate_pattern(pattern: &str) -> Result<(), String> {
  let mut rest = pattern;
  while let Some(open) = rest.find('{') {
    let after = &rest[open + 1..];
    let Some(close) = after.find('}') else {
      return Err("unclosed `{`".to_string());
    };
    let body = &after[..close];
    let valid = match body.split_once(':') {
      Some((kind, count)) if matches!(kind, "hex" | "d" | "base62") && !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()) => {
        count.parse::<usize>().is_ok_and(|n| n > 0)
      }
      _ => false,
    };
    if !valid {
      return Err(format!(
        "bad verb `{{{body}}}`: expected {{hex:N}}, {{d:N}}, or {{base62:N}} with N > 0"
      ));
    }
    rest = &after[close + 1..];
  }
  Ok(())
}

/// A validated fake-template verb: only these three render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
  Hex,
  Decimal,
  Base62,
}

impl Verb {
  /// Parse a verb name; `None` for anything `validate_pattern` rejects.
  fn parse(kind: &str) -> Option<Self> {
    match kind {
      "hex" => Some(Verb::Hex),
      "d" => Some(Verb::Decimal),
      "base62" => Some(Verb::Base62),
      _ => None,
    }
  }

  /// Stable seed tag so each verb streams independently per index.
  fn tag(self) -> &'static str {
    match self {
      Verb::Hex => "hex",
      Verb::Decimal => "d",
      Verb::Base62 => "base62",
    }
  }
}

fn render_template(template: &str, seed: &str) -> String {
  let mut out = String::new();
  let mut rest = template;
  while let Some(open) = rest.find('{') {
    out.push_str(&rest[..open]);
    let after = &rest[open + 1..];
    let Some(close) = after.find('}') else {
      out.push_str(&rest[open..]);
      return out;
    };
    let body = &after[..close];
    // Unknown verbs and unparseable counts render literally: silently
    // emitting base62 (or nothing) would mint the wrong decoy shape.
    let literal = |out: &mut String| {
      out.push('{');
      out.push_str(body);
      out.push('}');
    };
    let validated = match body.split_once(':') {
      Some((kind, count_raw)) if !count_raw.is_empty() && count_raw.bytes().all(|b| b.is_ascii_digit()) => {
        match (Verb::parse(kind), count_raw.parse::<usize>()) {
          (Some(verb), Ok(count)) => Some((verb, count)),
          _ => None,
        }
      }
      _ => None,
    };
    match validated {
      Some((verb, count)) => out.push_str(&fill_verb(seed, verb, count)),
      None => literal(&mut out),
    }
    rest = &after[close + 1..];
  }
  out.push_str(rest);
  out
}

/// Render `count` chars of `verb` from `seed`. Every encoding is a library
/// call: `hex::encode`, `base62::encode`, or std `Display` for decimal.
fn fill_verb(seed: &str, verb: Verb, count: usize) -> String {
  let mut out = String::with_capacity(count);
  let mut index = 0;
  while out.len() < count {
    let digest = Sha256::digest(format!("{}:{}:{index}", seed, verb.tag()).as_bytes());
    match verb {
      Verb::Hex => out.push_str(&hex::encode(digest)),
      Verb::Decimal => {
        let word = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        out.push_str(&word.to_string());
      }
      Verb::Base62 => {
        let word: [u8; 16] = digest[0..16].try_into().expect("16 digest bytes");
        out.push_str(&base62::encode(u128::from_be_bytes(word)));
      }
    }
    index += 1;
  }
  out.truncate(count);
  out
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::Write as _;
  use std::sync::{Mutex, MutexGuard};

  use clap::Parser as _;

  static ENV_LOCK: Mutex<()> = Mutex::new(());

  fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
  }

  fn scrub_env() {
    for key in ["HODOR_CONFIG", "HODOR_LISTEN", "HODOR_CA_FILE"] {
      // SAFETY: test-only mutation, serialized by ENV_LOCK.
      unsafe { env::remove_var(key) };
    }
  }

  /// Test-only env write; callers hold `ENV_LOCK`.
  fn set_env(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    // SAFETY: test-only mutation, serialized by ENV_LOCK.
    unsafe { env::set_var(key, value) };
  }

  fn write_file(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).unwrap();
    }
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(body.as_bytes()).unwrap();
  }

  fn cli_for(argv: &[&str]) -> Cli {
    Cli::try_parse_from(argv).unwrap()
  }

  /// Enter `dir` as the process cwd, restoring the previous one on drop.
  struct CwdGuard(PathBuf);

  impl CwdGuard {
    fn enter(dir: &Path) -> Self {
      let previous = env::current_dir().unwrap();
      env::set_current_dir(dir).unwrap();
      Self(previous)
    }
  }

  impl Drop for CwdGuard {
    fn drop(&mut self) {
      env::set_current_dir(&self.0).unwrap();
    }
  }

  #[test]
  fn overlay_merges_proxy_scalar_and_rules_by_label() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    let project_root = dir.path().join("proj");
    let project = project_root.join(".config").join("hodor.toml");
    write_file(
      &global,
      r#"
[proxy]
listen = "127.0.0.1:1111"
[rules.a]
env = "A_TOKEN"
value = "global-a"
allow = ["https://a.example"]
[rules.b]
env = "B_TOKEN"
value = "global-b"
allow = ["https://b.example"]
"#,
    );
    write_file(
      &project,
      r#"
[proxy]
listen = "127.0.0.1:2222"
[rules.b]
env = "B_TOKEN"
value = "project-b"
allow = ["https://b.example"]
[rules.c]
env = "C_TOKEN"
value = "project-c"
allow = ["https://c.example"]
"#,
    );
    set_env("HODOR_CONFIG", &global);
    let nested = project_root.join("crates").join("inner");
    write_file(&project_root.join("Cargo.toml"), "[workspace]\n");
    std::fs::create_dir_all(&nested).unwrap();
    let _cwd = CwdGuard::enter(&nested);
    let cli = cli_for(&["hodor", "serve"]);
    let (config, _ws) = load(&cli).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:2222");
    assert_eq!(config.rules["a"].value.as_ref().unwrap().expose_secret(), "global-a");
    assert_eq!(config.rules["b"].value.as_ref().unwrap().expose_secret(), "project-b");
    assert_eq!(config.rules["c"].value.as_ref().unwrap().expose_secret(), "project-c");
    scrub_env();
  }

  #[test]
  fn precedence_cli_beats_env_beats_project_beats_global() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    let project_root = dir.path().join("proj");
    write_file(&global, "[proxy]\nlisten = \"127.0.0.1:1111\"\n");
    write_file(
      &project_root.join(".config").join("hodor.toml"),
      "[proxy]\nlisten = \"127.0.0.1:2222\"\n",
    );
    set_env("HODOR_CONFIG", &global);
    let nested = project_root.join("crates").join("inner");
    write_file(&project_root.join("Cargo.toml"), "[workspace]\n");
    std::fs::create_dir_all(&nested).unwrap();
    let _cwd = CwdGuard::enter(&nested);
    // project beats global
    let (config, _) = load(&cli_for(&["hodor", "serve"])).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:2222");
    // env beats project
    set_env("HODOR_LISTEN", "127.0.0.1:3333");
    let (config, _) = load(&cli_for(&["hodor", "serve"])).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:3333");
    // CLI beats env
    let (config, _) = load(&cli_for(&["hodor", "serve", "--listen", "127.0.0.1:4444"])).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:4444");
    scrub_env();
  }

  #[test]
  fn config_flag_replaces_project_layer() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    let override_file = dir.path().join("override.toml");
    write_file(&global, "[proxy]\nlisten = \"127.0.0.1:1111\"\n");
    write_file(&override_file, "[proxy]\nlisten = \"127.0.0.1:5555\"\n");
    set_env("HODOR_CONFIG", &global);
    let markerless = dir.path().join("markerless");
    std::fs::create_dir_all(&markerless).unwrap();
    let _cwd = CwdGuard::enter(&markerless);
    let cli = cli_for(&["hodor", "--config", override_file.to_str().unwrap(), "serve"]);
    let (config, _) = load(&cli).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:5555");
    scrub_env();
  }

  #[test]
  fn discovery_finds_workspace_root_from_nested_subdir() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("ws");
    let nested = root.join("crates").join("inner");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    write_file(&root.join("Cargo.toml"), "[workspace]\n");
    let project = root.join(".config").join("hodor.toml");
    write_file(&project, "[proxy]\n");
    assert_eq!(discover_project_config(&nested), Some(project));
    // same tree without the file: no project layer
    std::fs::remove_file(root.join(".config").join("hodor.toml")).unwrap();
    assert_eq!(discover_project_config(&nested), None);
  }

  #[test]
  fn discovery_bare_dir_yields_no_project_layer() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(discover_project_config(dir.path()), None);
  }

  #[test]
  fn rule_value_is_optional_and_defaults_absent() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(
      &global,
      r#"
[rules.gh]
env = "GITHUB_TOKEN"
"#,
    );
    set_env("HODOR_CONFIG", &global);
    let (config, _) = load(&cli_for(&["hodor", "serve"])).unwrap();
    let rule = &config.rules["gh"];
    assert!(rule.value.is_none());
    assert!(rule.allow.is_empty());
    assert_eq!(rule.if_missing, IfMissing::Error);
    assert_eq!(rule.registry, None);
    assert!(rule.fnox_key.is_none());
    scrub_env();
  }

  #[test]
  fn rule_parses_every_new_field() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(
      &global,
      r#"
[rules.gh]
env = "GITHUB_TOKEN"
value = "inline"
fnox_key = "GH_PAT"
allow = ["https://ghe.corp.example"]
pattern = "ghp_{hex:40}"
registry = false
if_missing = "warn"
"#,
    );
    set_env("HODOR_CONFIG", &global);
    let (config, _) = load(&cli_for(&["hodor", "serve"])).unwrap();
    let rule = &config.rules["gh"];
    assert_eq!(rule.fnox_key.as_deref(), Some("GH_PAT"));
    assert_eq!(rule.registry, Some(false));
    assert_eq!(rule.if_missing, IfMissing::Warn);
    scrub_env();
  }

  #[test]
  fn rules_dir_sits_beside_the_config_file() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    set_env("HODOR_CONFIG", &global);
    assert_eq!(rules_dir(), Some(dir.path().join("rules.d")));
    scrub_env();
  }

  #[test]
  fn fakes_are_format_valid_and_deterministic() {
    let first = fake_for("GH_TOKEN", Some("ghp_{hex:40}"));
    assert_eq!(first, fake_for("GH_TOKEN", Some("ghp_{hex:40}")));
    assert!(first.starts_with("ghp_"), "{first}");
    assert_eq!(first.len(), 44);

    let fallback = fake_for("SOME_RANDOM_THING", None);
    assert_eq!(fallback.len(), 32);
    assert!(fallback.bytes().all(|b| b.is_ascii_hexdigit()));

    let explicit = fake_for("GH_TOKEN", Some("sk_live_{base62:24}"));
    assert_eq!(explicit, fake_for("GH_TOKEN", Some("sk_live_{base62:24}")));
    assert!(explicit.starts_with("sk_live_"), "{explicit}");

    assert_ne!(fake_for("GH_TOKEN", None), fake_for("GH_OTHER", None));
  }

  #[test]
  fn validate_rejects_bad_entries() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(&global, "[rules.bad]\nenv = \"B\"\nvalue = \"v\"\nallow = [\"gopher://h\"]\n");
    set_env("HODOR_CONFIG", &global);
    let err = load(&cli_for(&["hodor", "serve"])).unwrap_err();
    assert!(err.to_string().contains("gopher://h"), "{err:?}");
    scrub_env();
  }

  #[test]
  fn validate_rejects_bad_patterns() {
    validate_pattern("sk_live_{base62:24}").unwrap();
    validate_pattern("prefix_{hex:8}").unwrap();
    validate_pattern("{hex:0}").unwrap_err();
    validate_pattern("{bogus:10}").unwrap_err();
    validate_pattern("unclosed_{hex:8").unwrap_err();
  }

  #[test]
  fn duplicate_env_names_rejected() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(
      &global,
      r#"
[rules.a]
env = "A_TOKEN"
value = "a"
allow = ["https://a.example"]
[rules.b]
env = "A_TOKEN"
value = "b"
allow = ["https://b.example"]
"#,
    );
    set_env("HODOR_CONFIG", &global);
    let err = load(&cli_for(&["hodor", "serve"])).unwrap_err();
    assert!(err.to_string().contains("share env name"), "{err:?}");
    scrub_env();
  }

  #[test]
  fn unknown_verb_renders_literally() {
    assert_eq!(render_template("{bogus:10}", "seed"), "{bogus:10}");
    assert_eq!(render_template("a{bogus:10}b", "seed"), "a{bogus:10}b");
    assert_eq!(fake_for("SOME_TOKEN", Some("{bogus:10}")), "{bogus:10}");
  }
}
