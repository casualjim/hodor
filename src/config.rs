//! Config overlay: global + project files, env, CLI via confique.

use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use confique::{Config as _, Layer as _};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{Cli, Command};
use code_workspace::{Workspace, resolve_root};

const PATTERNS: &[(&str, &str)] = &[
  ("gh_", "ghp_{hex:40}"),
  ("sk-ant-", "sk-ant-api03-{base62:64}"),
  ("sk-", "sk-{hex:48}"),
  ("anthropic", "sk-ant-api03-{base62:64}"),
  ("xox", "xoxb-{d:10}-{d:11}-{hex:24}"),
  ("slack", "xoxb-{d:10}-{d:11}-{hex:24}"),
];
const DEFAULT_PATTERN: &str = "{hex:32}";
const BASE62: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Runtime config: listener settings plus secrets by label.
#[derive(confique::Config, Debug, Clone, Serialize)]
pub struct AppConfig {
  /// Proxy listener settings.
  #[config(nested)]
  pub proxy: ProxyCfg,
  /// Secrets by label; merged per label across global + project files.
  #[config(default = {})]
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub secrets: BTreeMap<String, SecretCfg>,
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

/// One secret entry: env name, value, allow list, optional fake pattern.
#[derive(confique::Config, Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCfg {
  /// Env var name the deterministic fake derives from.
  pub env: String,
  /// Real secret value (never serialized).
  #[serde(skip_serializing)]
  pub value: SecretString,
  /// Raw `scheme://host[:port]` allow entries.
  pub allow: Vec<String>,
  /// Explicit fake pattern overriding prefix auto-detect.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub pattern: Option<String>,
}

/// Load config with precedence CLI > env > project > global.
/// Returns the config plus the discovered workspace (`None` when no
/// workspace marker was found and no explicit root was given).
pub fn load(cli: &Cli) -> eyre::Result<(AppConfig, Option<Workspace>)> {
  let cwd = env::current_dir()?;
  let mut cli_layer = <AppConfig as confique::Config>::Layer::empty();
  if let Some(Command::Serve(args)) = &cli.command {
    cli_layer.proxy = args.proxy.clone();
  }

  let explicit_root = env::var("HODOR_PROJECT_ROOT").ok().map(PathBuf::from);
  let mut builder = AppConfig::builder().preloaded(cli_layer).env();
  let project = match &cli.config {
    Some(path) => Some(path.clone()),
    None => discover_project_config(explicit_root.as_deref(), &cwd),
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
  // confique merges the `secrets` map wholesale per winning file, so re-merge
  // by label here: global entries first, project entries replace by label.
  config.secrets = load_merged_secrets(project.as_deref(), global.as_deref())?;
  config.validate()?;

  let workspace = match explicit_root {
    Some(root) => Some(Workspace::from_root(&root).map_err(|err| eyre::eyre!("bad HODOR_PROJECT_ROOT {}: {err}", root.display()))?),
    None => resolve_root(None, &cwd).ok().and_then(|root| Workspace::from_root(&root).ok()),
  };
  Ok((config, workspace))
}

/// Locate the project-layer file: explicit root wins without a walk,
/// otherwise resolve the workspace root upward from `start`.
pub fn discover_project_config(explicit: Option<&Path>, start: &Path) -> Option<PathBuf> {
  let root = match explicit {
    Some(root) => root.to_path_buf(),
    None => resolve_root(None, start).ok()?,
  };
  let path = root.join(".config").join("hodor.toml");
  path.exists().then_some(path)
}

/// Merge `[secrets]` tables by label: global first, project wins wholesale
/// per label. Errors name the file + label.
fn load_merged_secrets(project: Option<&Path>, global: Option<&Path>) -> eyre::Result<BTreeMap<String, SecretCfg>> {
  let mut merged = BTreeMap::new();
  for path in [global, project].into_iter().flatten() {
    let text = std::fs::read_to_string(path).map_err(|err| eyre::eyre!("read {}: {err}", path.display()))?;
    let doc: toml::Table = toml::from_str(&text).map_err(|err| eyre::eyre!("parse {}: {err}", path.display()))?;
    let Some(secrets) = doc.get("secrets") else {
      continue;
    };
    let table = secrets
      .as_table()
      .ok_or_else(|| eyre::eyre!("{}: `secrets` must be a table", path.display()))?;
    for (label, entry) in table {
      let cfg = SecretCfg::deserialize(entry.clone()).map_err(|err| eyre::eyre!("{}: secret `{label}`: {err}", path.display()))?;
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

impl AppConfig {
  fn validate(&self) -> eyre::Result<()> {
    let mut env_names = std::collections::BTreeMap::new();
    for (label, secret) in &self.secrets {
      if let Some(previous) = env_names.insert(secret.env.clone(), label.clone()) {
        eyre::bail!("secrets `{previous}` and `{label}` share env name `{}`", secret.env);
      }
      eyre::ensure!(!secret.env.is_empty(), "secret `{label}`: `env` must not be empty");
      eyre::ensure!(
        !secret.value.expose_secret().is_empty(),
        "secret `{label}`: `value` must not be empty"
      );
      for entry in &secret.allow {
        let grant: crate::grants::UriGrant = entry
          .parse()
          .map_err(|err| eyre::eyre!("secret `{label}`: bad allow entry `{entry}`: {err}"))?;
        if matches!(grant.host, crate::grants::HostPat::Any) {
          tracing::warn!(label, entry, "grant matches any host; secret is exfil-risky");
        }
      }
      if let Some(pattern) = secret.pattern.as_deref().filter(|p| !p.is_empty()) {
        validate_pattern(pattern).map_err(|err| eyre::eyre!("secret `{label}`: bad pattern `{pattern}`: {err}"))?;
      }
    }
    Ok(())
  }
}

// ---------------------------------------------------------------------------
// format-valid deterministic fakes (port of substitute.py fake_for + PATTERNS)
// ---------------------------------------------------------------------------

/// Deterministic format-valid fake for an env var name. Stable across
/// restarts, distinct per name. Explicit `pattern` wins over auto-detect.
pub fn fake_for(env_name: &str, pattern: Option<&str>) -> String {
  let template = pattern.filter(|p| !p.is_empty()).unwrap_or_else(|| {
    let lower = env_name.to_ascii_lowercase();
    PATTERNS
      .iter()
      .find(|(sub, _)| lower.contains(sub))
      .map_or(DEFAULT_PATTERN, |(_, template)| *template)
  });
  let seed = hex_string(&Sha256::digest(env_name.as_bytes()));
  render_template(template, &seed)
}
/// Validate an explicit `pattern` template: every `{...}` must be a known
/// verb (`hex`, `d`, `base62`) with a nonzero count. Rejects typos that
/// would otherwise render silently wrong (`{bogus:10}` → base62) or empty
/// (`{hex:0}` → skipped grant).
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

/// Render `count` chars of `verb` from `seed`. Only [`Verb`] reaches here,
/// so every arm is reachable and no fallback exists.
fn fill_verb(seed: &str, verb: Verb, count: usize) -> String {
  let mut out = String::with_capacity(count);
  for i in 0..count {
    let digest = Sha256::digest(format!("{}:{}:{i}", seed, verb.tag()).as_bytes());
    let word = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    match verb {
      Verb::Hex => out.push(char::from_digit(u32::from(digest[0] >> 4), 16).unwrap_or('0')),
      Verb::Decimal => out.push((b'0' + (word % 10) as u8) as char),
      Verb::Base62 => out.push(BASE62[(word % 62) as usize] as char),
    }
  }
  out
}
fn hex_string(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0xf) as usize] as char);
  }
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
    for key in ["HODOR_CONFIG", "HODOR_PROJECT_ROOT", "HODOR_LISTEN", "HODOR_CA_FILE"] {
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

  #[test]
  fn overlay_merges_proxy_scalar_and_secrets_by_label() {
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
[secrets.a]
env = "A_TOKEN"
value = "global-a"
allow = ["https://a.example"]
[secrets.b]
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
[secrets.b]
env = "B_TOKEN"
value = "project-b"
allow = ["https://b.example"]
[secrets.c]
env = "C_TOKEN"
value = "project-c"
allow = ["https://c.example"]
"#,
    );
    set_env("HODOR_CONFIG", &global);
    set_env("HODOR_PROJECT_ROOT", &project_root);
    let cli = cli_for(&["hodor", "serve"]);
    let (config, _ws) = load(&cli).unwrap();
    assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:2222");
    assert_eq!(config.secrets["a"].value.expose_secret(), "global-a");
    assert_eq!(config.secrets["b"].value.expose_secret(), "project-b");
    assert_eq!(config.secrets["c"].value.expose_secret(), "project-c");
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
    set_env("HODOR_PROJECT_ROOT", &project_root);
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
    set_env("HODOR_PROJECT_ROOT", dir.path().join("markerless"));
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
    assert_eq!(discover_project_config(None, &nested), Some(project));
    // same tree without the file: no project layer
    std::fs::remove_file(root.join(".config").join("hodor.toml")).unwrap();
    assert_eq!(discover_project_config(None, &nested), None);
  }

  #[test]
  fn discovery_bare_dir_yields_no_project_layer() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(discover_project_config(None, dir.path()), None);
  }

  #[test]
  fn discovery_explicit_root_skips_walk() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("markerless");
    let project = root.join(".config").join("hodor.toml");
    write_file(&project, "[proxy]\n");
    assert_eq!(discover_project_config(Some(&root), dir.path()), Some(project));
  }

  #[test]
  fn fakes_are_format_valid_and_deterministic() {
    let first = fake_for("GH_TOKEN", None);
    assert_eq!(first, fake_for("GH_TOKEN", None));
    assert!(first.starts_with("ghp_"), "{first}");
    assert_eq!(first.len(), 44);
    assert!(first[4..].bytes().all(|b| b.is_ascii_hexdigit()));

    let anthropic = fake_for("ANTHROPIC_API_KEY", None);
    assert!(anthropic.starts_with("sk-ant-api03-"), "{anthropic}");
    assert_eq!(anthropic.len(), "sk-ant-api03-".len() + 64);

    let slack = fake_for("SLACK_TOKEN", None);
    assert!(slack.starts_with("xoxb-"), "{slack}");

    let fallback = fake_for("SOME_RANDOM_THING", None);
    assert_eq!(fallback.len(), 32);
    assert!(fallback.bytes().all(|b| b.is_ascii_hexdigit()));

    let explicit = fake_for("GH_TOKEN", Some("sk_live_{base62:24}"));
    assert_eq!(explicit, fake_for("GH_TOKEN", Some("sk_live_{base62:24}")));
    assert!(explicit.starts_with("sk_live_"), "{explicit}");
    assert_eq!(explicit.len(), "sk_live_".len() + 24);

    assert_ne!(fake_for("GH_TOKEN", None), fake_for("GH_OTHER", None));
  }

  #[test]
  fn validate_rejects_bad_entries() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(&global, "[secrets.bad]\nenv = \"B\"\nvalue = \"v\"\nallow = [\"gopher://h\"]\n");
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
[secrets.a]
env = "A_TOKEN"
value = "a"
allow = ["https://a.example"]
[secrets.b]
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
