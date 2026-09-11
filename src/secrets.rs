//! Host registry and rule resolution: known hosts, decoy shapes, and
//! fnox-sourced values.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::config::RuleCfg;
use crate::grants::UriGrant;

/// Bundled registry: environment names, API hosts, and token shapes.
const BUNDLED: &str = include_str!("../rules/registry.toml");

/// What the registry knows about one environment name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHosts {
  /// Raw `scheme://host[:port]` entries, in declaration order.
  pub hosts: Vec<String>,
  /// Decoy template, if any entry supplies one.
  pub pattern: Option<String>,
}

/// Known hosts and decoy shapes: bundled table plus `rules.d` overrides.
#[derive(Debug, Clone, Default)]
pub struct Registry {
  /// Entry per uppercase environment name.
  names: BTreeMap<String, KnownHosts>,
  /// `(provider, lowercase substring, pattern)` in load order.
  contains: Vec<(String, String, String)>,
}

/// A registry file as written: `[providers.*]` and `[names.*]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
  /// Service-centric entries.
  #[serde(default)]
  providers: BTreeMap<String, ProviderEntry>,
  /// Exact environment-name entries.
  #[serde(default)]
  names: BTreeMap<String, NameEntry>,
}

/// One service entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderEntry {
  /// Environment names this provider claims.
  #[serde(default)]
  env: Vec<String>,
  /// Hosts every claimed name may reach.
  #[serde(default)]
  hosts: Vec<String>,
  /// Decoy template for every claimed name.
  #[serde(default)]
  pattern: Option<String>,
  /// Environment-name substrings that select `pattern` only.
  #[serde(default)]
  contains: Vec<String>,
  /// Discard earlier layers for the keys this entry covers.
  #[serde(default)]
  replace: bool,
}

/// One exact environment-name entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NameEntry {
  /// Hosts this name may reach.
  #[serde(default)]
  hosts: Vec<String>,
  /// Decoy template for this name.
  #[serde(default)]
  pattern: Option<String>,
  /// Discard earlier layers for this name.
  #[serde(default)]
  replace: bool,
}

impl Registry {
  /// Load the bundled table, then every `<rules_dir>/*.toml` in filename order.
  pub fn load(rules_dir: Option<&Path>) -> eyre::Result<Self> {
    let mut registry = Self::default();
    registry.apply(BUNDLED, Path::new("<bundled>"))?;
    let Some(dir) = rules_dir.filter(|dir| dir.is_dir()) else {
      return Ok(registry);
    };
    let mut files = std::fs::read_dir(dir)
      .map_err(|err| eyre::eyre!("read {}: {err}", dir.display()))?
      .map(|entry| {
        entry
          .map(|entry| entry.path())
          .map_err(|err| eyre::eyre!("read {}: {err}", dir.display()))
      })
      .collect::<eyre::Result<Vec<_>>>()?;
    files.retain(|path| path.extension().is_some_and(|ext| ext == "toml"));
    files.sort();
    for path in files {
      let text = std::fs::read_to_string(&path).map_err(|err| eyre::eyre!("read {}: {err}", path.display()))?;
      registry.apply(&text, &path)?;
    }
    Ok(registry)
  }

  /// Merge one registry file over what is already loaded.
  fn apply(&mut self, text: &str, source: &Path) -> eyre::Result<()> {
    let file: RegistryFile = toml::from_str(text).map_err(|err| eyre::eyre!("parse {}: {err}", source.display()))?;
    // One file claiming the same name twice is a data bug; a later file
    // overriding an earlier one is the intended mechanism.
    let mut claimed: BTreeMap<String, String> = BTreeMap::new();
    for (provider, entry) in &file.providers {
      for env in &entry.env {
        if let Some(previous) = claimed.insert(env.to_ascii_uppercase(), provider.clone()) {
          eyre::bail!("{}: providers `{previous}` and `{provider}` both claim `{env}`", source.display());
        }
      }
    }
    for (provider, entry) in &file.providers {
      self.apply_provider(provider, entry, source)?;
    }
    for (env, entry) in &file.names {
      self.apply_name(env, entry, source)?;
    }
    Ok(())
  }

  /// Apply one `[providers.<name>]` entry.
  fn apply_provider(&mut self, provider: &str, entry: &ProviderEntry, source: &Path) -> eyre::Result<()> {
    validate_hosts(&entry.hosts, source, &format!("provider `{provider}`"))?;
    validate_optional_pattern(entry.pattern.as_deref(), source, &format!("provider `{provider}`"))?;
    for env in &entry.env {
      let slot = self.names.entry(env.to_ascii_uppercase()).or_default();
      if entry.replace {
        slot.hosts.clear();
        slot.pattern = None;
      }
      for host in &entry.hosts {
        if !slot.hosts.contains(host) {
          slot.hosts.push(host.clone());
        }
      }
      if let Some(pattern) = &entry.pattern {
        slot.pattern = Some(pattern.clone());
      }
    }
    if entry.replace {
      self.contains.retain(|(name, _, _)| name != provider);
    }
    for needle in &entry.contains {
      let Some(pattern) = &entry.pattern else {
        eyre::bail!("{}: provider `{provider}`: `contains` needs a `pattern`", source.display());
      };
      self
        .contains
        .push((provider.to_string(), needle.to_ascii_lowercase(), pattern.clone()));
    }
    Ok(())
  }

  /// Apply one `[names.<ENV>]` entry.
  fn apply_name(&mut self, env: &str, entry: &NameEntry, source: &Path) -> eyre::Result<()> {
    validate_hosts(&entry.hosts, source, &format!("name `{env}`"))?;
    validate_optional_pattern(entry.pattern.as_deref(), source, &format!("name `{env}`"))?;
    let slot = self.names.entry(env.to_ascii_uppercase()).or_default();
    if entry.replace {
      slot.hosts.clear();
      slot.pattern = None;
    }
    for host in &entry.hosts {
      if !slot.hosts.contains(host) {
        slot.hosts.push(host.clone());
      }
    }
    if let Some(pattern) = &entry.pattern {
      slot.pattern = Some(pattern.clone());
    }
    Ok(())
  }

  /// Known hosts and pattern for one environment name.
  pub fn lookup(&self, env: &str) -> KnownHosts {
    self.names.get(&env.to_ascii_uppercase()).cloned().unwrap_or_default()
  }

  /// Decoy template for one environment name: explicit, then registry, then default.
  pub fn template(&self, env: &str, explicit: Option<&str>) -> String {
    if let Some(pattern) = explicit.filter(|pattern| !pattern.is_empty()) {
      return pattern.to_string();
    }
    if let Some(pattern) = self.names.get(&env.to_ascii_uppercase()).and_then(|entry| entry.pattern.clone()) {
      return pattern;
    }
    let lower = env.to_ascii_lowercase();
    if let Some((_, _, pattern)) = self.contains.iter().find(|(_, needle, _)| lower.contains(needle.as_str())) {
      return pattern.clone();
    }
    crate::config::DEFAULT_PATTERN.to_string()
  }

  /// Deterministic decoy for one environment name.
  pub fn decoy(&self, env: &str, explicit: Option<&str>) -> String {
    crate::config::fake_for(env, Some(&self.template(env, explicit)))
  }

  /// Registry hosts for one rule, honoring `registry = false`.
  #[expect(dead_code, reason = "consumed by secrets::resolve in the next task")]
  pub(crate) fn hosts_for(&self, rule: &RuleCfg) -> Vec<String> {
    if rule.registry == Some(false) {
      return Vec::new();
    }
    self.lookup(&rule.env).hosts
  }
}

/// Validate one host entry with the same grammar as `allow`.
fn validate_hosts(hosts: &[String], source: &Path, what: &str) -> eyre::Result<()> {
  for host in hosts {
    let _: UriGrant = host
      .parse()
      .map_err(|err| eyre::eyre!("{}: {what}: bad host `{host}`: {err}", source.display()))?;
  }
  Ok(())
}

/// Validate one decoy template when present.
fn validate_optional_pattern(pattern: Option<&str>, source: &Path, what: &str) -> eyre::Result<()> {
  if let Some(pattern) = pattern {
    crate::config::validate_pattern(pattern).map_err(|err| eyre::eyre!("{}: {what}: bad pattern `{pattern}`: {err}", source.display()))?;
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::PathBuf;

  use pretty_assertions::assert_eq;

  fn write_rules(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
  }

  #[test]
  fn bundled_table_loads_and_covers_github() {
    let registry = Registry::load(None).unwrap();
    let known = registry.lookup("GITHUB_TOKEN");
    assert_eq!(
      known.hosts,
      vec!["https://api.github.com", "https://github.com", "https://uploads.github.com"]
    );
    assert_eq!(known.pattern.as_deref(), Some("ghp_{hex:40}"));
  }

  #[test]
  fn lookup_is_case_insensitive() {
    let registry = Registry::load(None).unwrap();
    assert_eq!(registry.lookup("github_token"), registry.lookup("GITHUB_TOKEN"));
  }

  #[test]
  fn rules_d_unions_hosts_and_overrides_the_pattern() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-ghe.toml",
      r#"
[providers.github-ghe]
env = ["GITHUB_TOKEN"]
hosts = ["https://ghe.corp.example"]
pattern = "ghp_ghe_{hex:32}"
"#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("GITHUB_TOKEN");
    assert_eq!(
      known.hosts,
      vec![
        "https://api.github.com",
        "https://github.com",
        "https://uploads.github.com",
        "https://ghe.corp.example"
      ]
    );
    assert_eq!(known.pattern.as_deref(), Some("ghp_ghe_{hex:32}"));
  }

  #[test]
  fn replace_discards_the_bundled_entry() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-narrow.toml",
      r#"
[providers.github]
env = ["GITHUB_TOKEN"]
hosts = ["https://ghe.corp.example"]
replace = true
"#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("GITHUB_TOKEN");
    assert_eq!(known.hosts, vec!["https://ghe.corp.example"]);
    assert_eq!(known.pattern, None);
  }

  #[test]
  fn names_entry_overrides_a_provider_claim() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-name.toml",
      r#"
[names.GITHUB_TOKEN]
hosts = ["https://ghe.corp.example"]
pattern = "ghp_named_{hex:32}"
"#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("GITHUB_TOKEN");
    assert!(known.hosts.contains(&"https://api.github.com".to_string()));
    assert!(known.hosts.contains(&"https://ghe.corp.example".to_string()));
    assert_eq!(known.pattern.as_deref(), Some("ghp_named_{hex:32}"));
  }

  #[test]
  fn contains_tier_matches_a_substring_without_granting_hosts() {
    let registry = Registry::load(None).unwrap();
    assert_eq!(registry.template("ACME_ANTHROPIC_KEY", None), "sk-ant-api03-{base62:64}");
    assert!(registry.lookup("ACME_ANTHROPIC_KEY").hosts.is_empty());
  }

  #[test]
  fn explicit_pattern_beats_the_registry() {
    let registry = Registry::load(None).unwrap();
    assert_eq!(registry.template("GITHUB_TOKEN", Some("ghp_custom_{hex:8}")), "ghp_custom_{hex:8}");
  }

  #[test]
  fn unknown_env_name_falls_back_to_the_default_pattern() {
    let registry = Registry::load(None).unwrap();
    assert_eq!(registry.template("SOME_RANDOM_THING", None), crate::config::DEFAULT_PATTERN);
  }

  #[test]
  fn duplicate_claim_in_one_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-dup.toml",
      r#"
[providers.first]
env = ["SHARED_TOKEN"]
hosts = ["https://a.example"]

[providers.second]
env = ["SHARED_TOKEN"]
hosts = ["https://b.example"]
"#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("both claim"), "{err:?}");
  }

  #[test]
  fn contains_without_a_pattern_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-bad.toml",
      r#"
[providers.bad]
contains = ["bad"]
"#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("needs a `pattern`"), "{err:?}");
  }

  #[test]
  fn bad_host_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-bad.toml",
      r#"
[providers.bad]
env = ["BAD_TOKEN"]
hosts = ["https://api.example/path"]
"#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("bad host"), "{err:?}");
  }

  #[test]
  fn decoy_is_deterministic_and_registry_shaped() {
    let registry = Registry::load(None).unwrap();
    let decoy = registry.decoy("GITHUB_TOKEN", None);
    assert_eq!(decoy, registry.decoy("GITHUB_TOKEN", None));
    assert!(decoy.starts_with("ghp_"), "{decoy}");
    assert_eq!(decoy.len(), 44);
  }

  #[test]
  fn rules_d_files_load_in_filename_order() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-first.toml",
      "[names.ORDERED_TOKEN]\nhosts = [\"https://first.example\"]\n",
    );
    write_rules(dir.path(), "20-second.toml", "[names.ORDERED_TOKEN]\npattern = \"late_{hex:8}\"\n");
    let registry = Registry::load(Some(dir.path())).unwrap();
    let known = registry.lookup("ORDERED_TOKEN");
    assert_eq!(known.hosts, vec!["https://first.example"]);
    assert_eq!(known.pattern.as_deref(), Some("late_{hex:8}"));
  }

  #[test]
  fn missing_rules_dir_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::load(Some(&dir.path().join("absent"))).unwrap();
    assert!(!registry.lookup("GITHUB_TOKEN").hosts.is_empty());
  }
}
