//! Known-host registry: bundled host and decoy-shape table plus `rules.d`
//! overrides.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::Path;

use eyre::WrapErr as _;
use serde::Deserialize;

use crate::config::RuleCfg;
use crate::grants::UriGrant;

/// Bundled registry: environment names, API hosts, and token shapes.
const BUNDLED: &str = include_str!("../../../rules/registry.toml");

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
  /// `contains` rules in load order.
  contains: Vec<ContainsRule>,
}

/// One `[providers.*].contains` rule: which provider declared it, the
/// lowercase substring matched against an env name, and the pattern it picks.
#[derive(Debug, Clone)]
struct ContainsRule {
  /// Provider that declared it; `replace = true` clears that provider's rules.
  provider: String,
  /// Lowercase substring tested against the env name.
  needle: String,
  /// Decoy template selected when the needle matches.
  pattern: String,
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
  /// Load the bundled table, then one override directory.
  ///
  /// # Errors
  ///
  /// Returns an error when the bundled table is malformed, when the override
  /// directory cannot be read, or when an override does not parse.
  pub fn load(rules_dir: Option<&Path>) -> eyre::Result<Self> {
    let dirs = rules_dir.into_iter().collect::<Vec<_>>();
    let mut registry = Self::default();
    registry.apply(BUNDLED, Path::new("<bundled>"))?;
    for dir in dirs.iter().filter(|dir| dir.is_dir()) {
      let mut files = std::fs::read_dir(dir)
        .wrap_err_with(|| format!("read {}", dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()).wrap_err_with(|| format!("read {}", dir.display())))
        .collect::<eyre::Result<Vec<_>>>()?;
      files.retain(|path| path.extension().is_some_and(|ext| ext == "toml"));
      files.sort();
      for path in files {
        let text = std::fs::read_to_string(&path).wrap_err_with(|| format!("read {}", path.display()))?;
        registry.apply(&text, &path)?;
      }
    }
    Ok(registry)
  }

  /// Merge one registry file over what is already loaded.
  fn apply(&mut self, text: &str, source: &Path) -> eyre::Result<()> {
    let file: RegistryFile = toml::from_str(text).wrap_err_with(|| format!("parse {}", source.display()))?;
    // One file claiming the same name twice is a data bug; a later file
    // overriding an earlier one is the intended mechanism.
    let mut claimed: BTreeMap<String, &str> = BTreeMap::new();
    for (provider, entry) in &file.providers {
      for env in &entry.env {
        if let Some(previous) = claimed.insert(env.to_ascii_uppercase(), provider.as_str()) {
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
    validate_hosts(&entry.hosts, source, "provider", provider)?;
    let pattern = entry.pattern.as_deref().filter(|pattern| !pattern.is_empty());
    validate_optional_pattern(pattern, source, "provider", provider)?;
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
      if let Some(pattern) = pattern {
        slot.pattern = Some(pattern.to_string());
      }
    }
    if entry.replace {
      self.contains.retain(|rule| rule.provider != provider);
    }
    for needle in &entry.contains {
      eyre::ensure!(
        !needle.is_empty(),
        "{}: provider `{provider}`: `contains` entries must not be empty",
        source.display()
      );
      let Some(pattern) = pattern else {
        eyre::bail!("{}: provider `{provider}`: `contains` needs a `pattern`", source.display());
      };
      self.contains.push(ContainsRule {
        provider: provider.to_string(),
        needle: needle.to_ascii_lowercase(),
        pattern: pattern.to_string(),
      });
    }
    Ok(())
  }

  /// Apply one `[names.<ENV>]` entry.
  fn apply_name(&mut self, env: &str, entry: &NameEntry, source: &Path) -> eyre::Result<()> {
    validate_hosts(&entry.hosts, source, "name", env)?;
    let pattern = entry.pattern.as_deref().filter(|pattern| !pattern.is_empty());
    validate_optional_pattern(pattern, source, "name", env)?;
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
    if let Some(pattern) = pattern {
      slot.pattern = Some(pattern.to_string());
    }
    Ok(())
  }

  /// Known hosts and pattern for one environment name, `None` when absent.
  #[must_use]
  pub fn lookup(&self, env: &str) -> Option<&KnownHosts> {
    self.names.get(&env.to_ascii_uppercase())
  }

  /// Decoy template for one environment name: explicit, then registry, then default.
  #[must_use]
  pub fn template<'a>(&'a self, env: &str, explicit: Option<&'a str>) -> Cow<'a, str> {
    if let Some(pattern) = explicit.filter(|pattern| !pattern.is_empty()) {
      return Cow::Borrowed(pattern);
    }
    if let Some(pattern) = self.names.get(&env.to_ascii_uppercase()).and_then(|entry| entry.pattern.as_deref()) {
      return Cow::Borrowed(pattern);
    }
    let lower = env.to_ascii_lowercase();
    if let Some(rule) = self.contains.iter().find(|rule| lower.contains(rule.needle.as_str())) {
      return Cow::Borrowed(&rule.pattern);
    }
    Cow::Borrowed(crate::config::DEFAULT_PATTERN)
  }

  /// Deterministic decoy for one environment name.
  #[must_use]
  pub fn decoy(&self, env: &str, explicit: Option<&str>) -> String {
    crate::config::fake_for(env, Some(&self.template(env, explicit)))
  }

  /// Registry hosts for one rule, honoring `registry = false`.
  #[must_use]
  pub fn hosts_for(&self, rule: &RuleCfg) -> &[String] {
    if rule.registry == Some(false) {
      return &[];
    }
    self.lookup(&rule.env).map_or(&[], |known| known.hosts.as_slice())
  }
}

/// Validate one host entry with the same grammar as `allow`.
fn validate_hosts(hosts: &[String], source: &Path, kind: &str, name: &str) -> eyre::Result<()> {
  for host in hosts {
    let grant: UriGrant = host
      .parse()
      .map_err(|err| eyre::eyre!("{}: {kind} `{name}`: bad host `{host}`: {err}", source.display()))?;
    if matches!(grant.host, crate::grants::HostPat::Any) {
      let what = format!("{kind} `{name}`");
      tracing::warn!(file = %source.display(), entry = %host, what, "grant matches any host; secret is exfil-risky");
    }
  }
  Ok(())
}

/// Validate one decoy template when present.
fn validate_optional_pattern(pattern: Option<&str>, source: &Path, kind: &str, name: &str) -> eyre::Result<()> {
  if let Some(pattern) = pattern {
    crate::config::validate_pattern(pattern)
      .map_err(|err| eyre::eyre!("{}: {kind} `{name}`: bad pattern `{pattern}`: {err}", source.display()))?;
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
    let known = registry.lookup("GITHUB_TOKEN").expect("GITHUB_TOKEN in the bundled registry");
    assert_eq!(
      known.hosts,
      vec!["https://api.github.com", "https://github.com", "https://uploads.github.com"]
    );
    assert_eq!(known.pattern.as_deref(), Some("ghp_{hex:40}"));
  }

  #[test]
  fn bundled_table_covers_the_first_tranche() {
    let registry = Registry::load(None).unwrap();
    // Names follow the platforms' docs: Atlas documents `MONGODB_ATLAS_PRIVATE_API_KEY`
    // and Shopify's Admin API examples use `SHOP_TOKEN`.
    for env in [
      "GITHUB_TOKEN",
      "GITLAB_TOKEN",
      "ANTHROPIC_API_KEY",
      "OPENAI_API_KEY",
      "GEMINI_API_KEY",
      "AWS_ACCESS_KEY_ID",
      "AZURE_CLIENT_SECRET",
      "GOOGLE_APPLICATION_CREDENTIALS",
      "CLOUDFLARE_API_TOKEN",
      "DIGITALOCEAN_TOKEN",
      "HCLOUD_TOKEN",
      "FLY_API_TOKEN",
      "VERCEL_TOKEN",
      "NETLIFY_AUTH_TOKEN",
      "HEROKU_API_KEY",
      "STRIPE_SECRET_KEY",
      "SLACK_BOT_TOKEN",
      "TWILIO_AUTH_TOKEN",
      "SENDGRID_API_KEY",
      "POSTMARK_SERVER_TOKEN",
      "RESEND_API_KEY",
      "NPM_TOKEN",
      "PYPI_TOKEN",
      "HF_TOKEN",
      "DD_API_KEY",
      "SENTRY_AUTH_TOKEN",
      "GRAFANA_API_KEY",
      "MONGODB_ATLAS_PRIVATE_API_KEY",
      "SUPABASE_SERVICE_ROLE_KEY",
      "SHOP_TOKEN",
      "DEEPSEEK_API_KEY",
      "OPENROUTER_API_KEY",
      "TURSO_PLATFORM_TOKEN",
      "GITEA_TOKEN",
    ] {
      let known = registry
        .lookup(env)
        .unwrap_or_else(|| panic!("{env} missing from the bundled registry"));
      assert!(!known.hosts.is_empty(), "{env} has no hosts");
      assert!(known.pattern.is_some(), "{env} has no pattern");
    }
  }

  #[test]
  fn bundled_table_patterns_and_hosts_are_valid() {
    // `load` validates every entry, so a bad pattern or host fails here.
    let registry = Registry::load(None).unwrap();
    assert!(!registry.names.is_empty());
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
    let known = registry.lookup("GITHUB_TOKEN").expect("GITHUB_TOKEN in the loaded registry");
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
    let known = registry.lookup("GITHUB_TOKEN").expect("GITHUB_TOKEN in the bundled registry");
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
    let known = registry.lookup("GITHUB_TOKEN").expect("GITHUB_TOKEN in the loaded registry");
    assert!(known.hosts.contains(&"https://api.github.com".to_string()));
    assert!(known.hosts.contains(&"https://ghe.corp.example".to_string()));
    assert_eq!(known.pattern.as_deref(), Some("ghp_named_{hex:32}"));
  }

  #[test]
  fn contains_tier_matches_a_substring_without_granting_hosts() {
    let registry = Registry::load(None).unwrap();
    assert_eq!(registry.template("ACME_ANTHROPIC_KEY", None), "sk-ant-api03-{base62:64}");
    assert!(
      registry.lookup("ACME_ANTHROPIC_KEY").is_none(),
      "contains tier must not grant hosts"
    );
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
  fn empty_contains_needle_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-bad.toml",
      r#"
[providers.bad]
pattern = "bad_{hex:8}"
contains = [""]
"#,
    );
    let err = Registry::load(Some(dir.path())).unwrap_err();
    assert!(err.to_string().contains("must not be empty"), "{err:?}");
  }

  #[test]
  fn empty_registry_pattern_is_treated_as_absent() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-blank.toml",
      r#"
[providers.blank]
env = ["BLANK_TOKEN"]
hosts = ["https://blank.example"]
pattern = ""
"#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    assert_eq!(
      registry.lookup("BLANK_TOKEN").expect("BLANK_TOKEN in the loaded registry").pattern,
      None
    );
    assert_eq!(registry.template("BLANK_TOKEN", None), crate::config::DEFAULT_PATTERN);
  }

  #[test]
  fn any_host_entry_warns_but_loads() {
    let dir = tempfile::tempdir().unwrap();
    write_rules(
      dir.path(),
      "10-any.toml",
      r#"
[names.ANY_TOKEN]
hosts = ["https://*"]
"#,
    );
    let registry = Registry::load(Some(dir.path())).unwrap();
    assert_eq!(
      registry.lookup("ANY_TOKEN").expect("ANY_TOKEN in the loaded registry").hosts,
      vec!["https://*"]
    );
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
    let known = registry.lookup("ORDERED_TOKEN").expect("ORDERED_TOKEN in the loaded registry");
    assert_eq!(known.hosts, vec!["https://first.example"]);
    assert_eq!(known.pattern.as_deref(), Some("late_{hex:8}"));
  }

  #[test]
  fn missing_rules_dir_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Registry::load(Some(&dir.path().join("absent"))).unwrap();
    assert!(
      !registry
        .lookup("GITHUB_TOKEN")
        .expect("GITHUB_TOKEN in the bundled registry")
        .hosts
        .is_empty()
    );
  }
}
