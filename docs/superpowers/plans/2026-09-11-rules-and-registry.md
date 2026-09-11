# Rules and Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `hodor` rules state only an environment name: hosts and decoy shape come from a bundled, overridable registry of known services, and the real value comes from fnox.

**Architecture:** `config::load` stays a pure file overlay. A new `src/secrets.rs` owns two things — the host registry (bundled `rules/registry.toml` plus `rules.d/*.toml` overrides) and rule resolution, which unions registry hosts into each rule's `allow`, fills its decoy pattern, and fetches values from an embedded `fnox-core`. `grants::resolve` is untouched: it reads the same `RuleCfg` fields it reads today, now already populated.

**Tech Stack:** Rust 2024, `confique` (config overlay), `serde`/`toml`, `fnox-core` 1.33 (secret providers), `secrecy`, `tokio`, `cargo-nextest`.

**Spec:** `docs/superpowers/specs/2026-09-11-rules-and-registry-design.md`

## Global Constraints

- Toolchain: Rust stable 1.98.1 through mise. Never invoke `cargo` without the repo's mise environment; use `mise run format` and `cargo nextest run` as shown in each task.
- Format/lint gate: `mise run format` must be green. rustfmt `max_width = 140`, `tab_spaces = 2`, `merge_derives = false`. `cargo sort --grouped` owns `Cargo.toml` ordering.
- Lints: `missing_docs` is a warning-level gate for every `pub` item — document all new public items. The clippy gate is `clippy --all-targets --features tun -- -D warnings`; `#[allow]` must carry `reason=`.
- Errors: `eyre::Result` everywhere, `bail!`/`ensure!` with context that names the offending file, label, or key. Malformed client traffic still closes quietly — this plan touches startup only.
- Secrets: `secrecy::SecretString` for values. Never log a value; log label, `env`, host count, and source only.
- Tests: inline `#[cfg(test)] mod tests` per file, `snake_case` behavior-descriptive names with no `test_` prefix, `pretty_assertions` and `tempfile` are the only test deps, async tests use `#[tokio::test]`.
- **Commits:** the owner has not asked for commits. Each task ends with a conditional commit step — run it only if the owner has explicitly asked for commits in the session.
- Do not add `hodor secrets` or `hodor doctor`. Do not read fnox's `[[proxy.rules]]`. Do not add a project-layer `rules.d`.

---

### Task 1: Rename `[secrets]` to `[rules]` and open up the schema

**Files:**

- Modify: `src/config.rs`
- Modify: `src/grants.rs:186-197` (`cfg.secrets` → `cfg.rules`, `SecretCfg` → `RuleCfg`)
- Modify: `src/main.rs` (no logic change; verify it compiles)
- Modify: `integration/hodor.toml`
- Test: `src/config.rs` (`mod tests`)

**Interfaces:**

- Consumes: nothing.
- Produces:
  - `pub struct RuleCfg { pub env: String, pub value: Option<SecretString>, pub fnox_key: Option<String>, pub allow: Vec<String>, pub pattern: Option<String>, pub registry: Option<bool>, pub if_missing: IfMissing }`
  - `pub enum IfMissing { Error, Warn, Ignore }` (serde `lowercase`, `Default` = `Error`)
  - `pub struct FnoxCfg { pub config: Option<PathBuf>, pub profile: Option<String> }` (env `HODOR_FNOX_CONFIG`, `HODOR_FNOX_PROFILE`)
  - `AppConfig.rules: BTreeMap<String, RuleCfg>`, `AppConfig.fnox: FnoxCfg`
  - `pub fn config_dir() -> Option<PathBuf>`, `pub fn rules_dir() -> Option<PathBuf>`
  - `pub const DEFAULT_PATTERN: &str`

- [ ] **Step 1: Write the failing tests**

In `src/config.rs`'s `mod tests`, rename the existing `[secrets.*]` fixtures to `[rules.*]` and rename `overlay_merges_proxy_scalar_and_secrets_by_label` to `overlay_merges_proxy_scalar_and_rules_by_label`. Then replace `fakes_are_format_valid_and_deterministic`'s registry-dependent assertions with these new tests:

```rust
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
[fnox]
config = "/tmp/fnox.toml"
profile = "work,default"

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
    assert_eq!(config.fnox.config.as_deref(), Some(std::path::Path::new("/tmp/fnox.toml")));
    assert_eq!(config.fnox.profile.as_deref(), Some("work,default"));
    let rule = &config.rules["gh"];
    assert_eq!(rule.fnox_key.as_deref(), Some("GH_PAT"));
    assert_eq!(rule.registry, Some(false));
    assert_eq!(rule.if_missing, IfMissing::Warn);
    scrub_env();
  }

  #[test]
  fn fnox_env_vars_override_the_file() {
    let _guard = lock_env();
    scrub_env();
    let dir = tempfile::tempdir().unwrap();
    let global = dir.path().join("global.toml");
    write_file(&global, "[fnox]\nconfig = \"/tmp/file.toml\"\n");
    set_env("HODOR_CONFIG", &global);
    set_env("HODOR_FNOX_CONFIG", "/tmp/env.toml");
    let (config, _) = load(&cli_for(&["hodor", "serve"])).unwrap();
    assert_eq!(config.fnox.config.as_deref(), Some(std::path::Path::new("/tmp/env.toml")));
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
```

Add `HODOR_FNOX_CONFIG` and `HODOR_FNOX_PROFILE` to `scrub_env`'s key list, and import `IfMissing` in the tests module.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run config::`
Expected: compile failure — `RuleCfg` and `IfMissing` do not exist, `config.rules` is `config.secrets`.

- [ ] **Step 3: Rename the struct and table**

In `src/config.rs`, rename the struct and add the new fields:

```rust
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

/// fnox integration: config path and profile.
#[derive(confique::Config, Clone, Debug, Default, Serialize)]
pub struct FnoxCfg {
  /// Explicit fnox config path; default is fnox's own discovery.
  #[config(env = "HODOR_FNOX_CONFIG")]
  #[serde(skip_serializing_if = "Option::is_none")]
  pub config: Option<PathBuf>,
  /// fnox profile list, comma-separated; default is `FNOX_PROFILE`.
  #[config(env = "HODOR_FNOX_PROFILE")]
  #[serde(skip_serializing_if = "Option::is_none")]
  pub profile: Option<String>,
}
```

In `AppConfig`, replace the `secrets` field and add `fnox`:

```rust
  /// Proxy listener settings.
  #[config(nested)]
  pub proxy: ProxyCfg,
  /// fnox integration settings.
  #[config(nested)]
  pub fnox: FnoxCfg,
  /// Rules by label; merged per label across global + project files.
  #[config(default = {})]
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  pub rules: BTreeMap<String, RuleCfg>,
```

Rename `load_merged_secrets` to `load_merged_rules` and its `doc.get("secrets")` lookup to `doc.get("rules")`; update the call site in `load` to `config.rules = load_merged_rules(...)?`. Rename the error text `secret \`{label}\`` to `rule \`{label}\`` throughout.

- [ ] **Step 4: Update validation and add `DEFAULT_PATTERN`, `config_dir`, `rules_dir`**

Make `DEFAULT_PATTERN` public (it stays in use until Task 2):

```rust
/// Pattern used when neither the rule nor the registry supplies one.
pub const DEFAULT_PATTERN: &str = "{hex:32}";
```

Replace the loop body in `AppConfig::validate` so it iterates `&self.rules` and no longer requires a value:

```rust
    for (label, rule) in &self.rules {
      if let Some(previous) = env_names.insert(rule.env.clone(), label.clone()) {
        eyre::bail!("rules `{previous}` and `{label}` share env name `{}`", rule.env);
      }
      eyre::ensure!(!rule.env.is_empty(), "rule `{label}`: `env` must not be empty");
      if let Some(value) = &rule.value {
        eyre::ensure!(
          !value.expose_secret().is_empty(),
          "rule `{label}`: `value` must not be empty"
        );
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
```

Add below `global_config_path`:

```rust
/// Directory holding the global config file, and `rules.d` beside it.
pub fn config_dir() -> Option<PathBuf> {
  global_config_path().and_then(|path| path.parent().map(Path::to_path_buf))
}

/// Registry override directory: `rules.d` beside the global config file.
pub fn rules_dir() -> Option<PathBuf> {
  config_dir().map(|dir| dir.join("rules.d"))
}
```

- [ ] **Step 5: Update the remaining call sites**

`src/grants.rs::resolve` becomes, in full:

```rust
pub fn resolve(cfg: &AppConfig) -> eyre::Result<ResolvedConfig> {
  let mut grants = Vec::with_capacity(cfg.rules.len());
  for (label, rule) in &cfg.rules {
    let Some(value) = rule.value.clone() else {
      // `secrets::resolve` fills this before `serve`; a caller that skips
      // resolution gets no grant rather than a rule that swaps in nothing.
      tracing::warn!(label, env = %rule.env, "rule has no resolved value; no grant");
      continue;
    };
    let mut allow = Vec::with_capacity(rule.allow.len());
    for entry in &rule.allow {
      let uri: UriGrant = entry
        .parse()
        .map_err(|err| eyre::eyre!("rule `{label}`: bad allow entry `{entry}`: {err}"))?;
      allow.push(uri);
    }
    grants.push(Grant {
      label: label.clone(),
      fake: crate::config::fake_for(&rule.env, rule.pattern.as_deref()),
      value,
      allow,
    });
  }
  Ok(ResolvedConfig {
    proxy: cfg.proxy.clone(),
    grants,
  })
}
```

`src/main.rs` — `Command::Ca` no longer needs grants at all, only `ca_file`. Change `ca_path` to take the proxy settings and drop the `grants::resolve` call:

```rust
/// Resolve the CA file path: config `ca_file` if set, else the default
/// `<config-dir>/hodor/ca.pem`.
fn ca_path(proxy: &config::ProxyCfg) -> eyre::Result<PathBuf> {
  match proxy.ca_file.clone() {
    Some(path) => Ok(path),
    None => dirs::config_dir()
      .map(|dir: PathBuf| dir.join("hodor").join("ca.pem"))
      .ok_or_else(|| eyre::eyre!("unable to resolve user config directory")),
  }
}
```

and in the `Command::Ca` arm: `let (config, _) = config::load(&cli)?;` followed by `let ca = ca::load_or_generate(&ca_path(&config.proxy)?)?;`, with the `let resolved = grants::resolve(&config)?;` line removed. The `Command::Serve` arm still calls `grants::resolve(&config)?` exactly as today.

`integration/hodor.toml` — the table header becomes `[rules.demo]`, everything else unchanged.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo nextest run config:: grants::`
Expected: PASS.

- [ ] **Step 7: Format and lint**

Run: `mise run format`
Expected: green.

- [ ] **Step 8: Commit (only if the owner asked for commits)**

```bash
git add src/config.rs src/grants.rs src/main.rs integration/hodor.toml
git commit -m "refactor(config): rename [secrets] to [rules] and open the schema"
```

---

### Task 2: Registry module, bundled table, `rules.d`, and `hodor fake`

**Files:**

- Create: `src/secrets.rs`
- Create: `rules/registry.toml`
- Modify: `src/main.rs` (`mod secrets;`, `Command::Fake` body)
- Modify: `src/config.rs` (drop `PATTERNS`, simplify `fake_for`)
- Test: `src/secrets.rs` (`mod tests`)

**Interfaces:**

- Consumes: `RuleCfg`, `IfMissing`, `FnoxCfg`, `DEFAULT_PATTERN`, `rules_dir()` from Task 1.
- Produces:
  - `pub struct Registry` with `pub fn load(rules_dir: Option<&Path>) -> eyre::Result<Self>`, `pub fn lookup(&self, env: &str) -> KnownHosts`, `pub fn template(&self, env: &str, explicit: Option<&str>) -> String`, `pub fn decoy(&self, env: &str, explicit: Option<&str>) -> String`
  - `pub struct KnownHosts { pub hosts: Vec<String>, pub pattern: Option<String> }`
  - `config::fake_for(env: &str, pattern: Option<&str>) -> String` — now explicit-or-default only

- [ ] **Step 1: Write the failing tests**

Create `src/secrets.rs` with the module docs, the types from Step 3, and this test module:

```rust
#[cfg(test)]
mod tests {
  use super::*;
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
    assert_eq!(
      registry.template("ACME_ANTHROPIC_KEY", None),
      "sk-ant-api03-{base62:64}"
    );
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
    write_rules(
      dir.path(),
      "20-second.toml",
      "[names.ORDERED_TOKEN]\npattern = \"late_{hex:8}\"\n",
    );
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run secrets::`
Expected: compile failure — `src/secrets.rs` is not yet declared in `src/main.rs` and the types are not implemented.

- [ ] **Step 3: Implement the registry**

Create `src/secrets.rs` with this content above the test module:

```rust
//! Host registry and rule resolution: known hosts, decoy shapes, and
//! fnox-sourced values.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
      .map(|entry| entry.map(|entry| entry.path()).map_err(|err| eyre::eyre!("read {}: {err}", dir.display())))
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
          eyre::bail!(
            "{}: providers `{previous}` and `{provider}` both claim `{env}`",
            source.display()
          );
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
      self.contains
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
    if let Some(pattern) = self
      .names
      .get(&env.to_ascii_uppercase())
      .and_then(|entry| entry.pattern.clone())
    {
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
```

`PathBuf` is imported for the test helper; if the compiler flags it as unused in the non-test build, move `use std::path::PathBuf;` into the test module.

Create `rules/registry.toml`:

```toml
# Bundled registry: environment names, API hosts, and token shapes.
# Override any entry from <config-dir>/hodor/rules.d/*.toml; see README.

[providers.anthropic]
env = ["ANTHROPIC_API_KEY"]
hosts = ["https://api.anthropic.com"]
pattern = "sk-ant-api03-{base62:64}"
contains = ["anthropic", "sk-ant-"]
# source: https://docs.anthropic.com/en/api/getting-started

[providers.github]
env = ["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT"]
hosts = ["https://api.github.com", "https://github.com", "https://uploads.github.com"]
pattern = "ghp_{hex:40}"
contains = ["gh_"]
# source: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github

[providers.openai]
env = ["OPENAI_API_KEY"]
hosts = ["https://api.openai.com"]
pattern = "sk-{base62:48}"
contains = ["openai"]
# source: https://platform.openai.com/docs/api-reference/introduction

[providers.slack]
env = ["SLACK_TOKEN", "SLACK_BOT_TOKEN"]
hosts = ["https://slack.com", "https://api.slack.com"]
pattern = "xoxb-{d:10}-{d:11}-{hex:24}"
contains = ["slack", "xox"]
# source: https://api.slack.com/authentication/token-types
```

- [ ] **Step 4: Wire the module and simplify `fake_for`**

Add `mod secrets;` to `src/main.rs` in the existing alphabetical module list (between `proxy` and `sni`).

In `src/config.rs`, delete the `PATTERNS` const and shrink `fake_for` to explicit-or-default:

```rust
/// Deterministic format-valid fake for an env var name. Stable across
/// restarts, distinct per name. `pattern` wins; the registry supplies one
/// through `secrets::Registry::decoy`, and `DEFAULT_PATTERN` is the floor.
pub fn fake_for(env_name: &str, pattern: Option<&str>) -> String {
  let template = pattern.filter(|pattern| !pattern.is_empty()).unwrap_or(DEFAULT_PATTERN);
  let seed = hex_string(&Sha256::digest(env_name.as_bytes()));
  render_template(template, &seed)
}
```

Replace `fakes_are_format_valid_and_deterministic` in `src/config.rs` with a test of the reduced contract:

```rust
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
```

- [ ] **Step 5: Make `hodor fake` registry-aware**

In `src/main.rs`, replace the `Command::Fake` arm body:

```rust
    Command::Fake(args) => {
      if let Some(pattern) = args.pattern.as_deref() {
        config::validate_pattern(pattern).map_err(|err| eyre::eyre!("bad --pattern: {err}"))?;
      }
      let registry = secrets::Registry::load(config::rules_dir().as_deref())?;
      println!("{}", registry.decoy(&args.env, args.pattern.as_deref()));
      Ok(())
    }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo nextest run secrets:: config::`
Expected: PASS.

Then verify the CLI by hand:

```bash
cargo run --quiet -- fake GITHUB_TOKEN
cargo run --quiet -- fake ACME_ANTHROPIC_KEY
cargo run --quiet -- fake SOME_RANDOM_THING
```

Expected: three distinct decoys, `ghp_` + 40 hex, `sk-ant-api03-` + 64 base62, and 32 hex.

- [ ] **Step 7: Format and lint**

Run: `mise run format`
Expected: green.

- [ ] **Step 8: Commit (only if the owner asked for commits)**

```bash
git add src/secrets.rs src/config.rs src/main.rs rules/registry.toml
git commit -m "feat(secrets): add the bundled host registry and rules.d overrides"
```

---

### Task 3: Resolve hosts, patterns, and `if_missing` per rule

**Files:**

- Modify: `src/secrets.rs`
- Modify: `src/main.rs` (`Command::Serve`)
- Test: `src/secrets.rs` (`mod tests`)

**Interfaces:**

- Consumes: `Registry` from Task 2; `RuleCfg`, `IfMissing` from Task 1.
- Produces: `pub async fn resolve(config: &mut AppConfig, registry: &Registry) -> eyre::Result<()>` — unions registry hosts into each rule's `allow`, fills `pattern`, drops unresolved rules per `if_missing`. Task 4 adds fnox inside this same function without changing its signature.

- [ ] **Step 1: Write the failing tests**

Append to `src/secrets.rs`'s test module. The helpers build a `RuleCfg` directly so the tests do not depend on file loading:

```rust
  fn rule(env: &str) -> RuleCfg {
    RuleCfg {
      env: env.to_string(),
      value: Some(secrecy::SecretString::from("inline")),
      fnox_key: None,
      allow: Vec::new(),
      pattern: None,
      registry: None,
      if_missing: crate::config::IfMissing::Error,
    }
  }

  fn config_with(label: &str, rule: RuleCfg) -> crate::config::AppConfig {
    let mut config = crate::config::AppConfig {
      proxy: crate::config::ProxyCfg::default(),
      fnox: crate::config::FnoxCfg::default(),
      rules: BTreeMap::new(),
    };
    config.rules.insert(label.to_string(), rule);
    config
  }

  #[tokio::test]
  async fn resolve_unions_registry_hosts_with_explicit_allow() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("GITHUB_TOKEN");
    rule.allow = vec!["https://ghe.corp.example".to_string()];
    let mut config = config_with("gh", rule);
    resolve(&mut config, &registry).await.unwrap();
    let allow = &config.rules["gh"].allow;
    assert!(allow.contains(&"https://api.github.com".to_string()));
    assert!(allow.contains(&"https://ghe.corp.example".to_string()));
    assert_eq!(allow.len(), 4);
  }

  #[tokio::test]
  async fn resolve_registry_false_keeps_only_explicit_hosts() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("GITHUB_TOKEN");
    rule.registry = Some(false);
    rule.allow = vec!["https://ghe.corp.example".to_string()];
    let mut config = config_with("gh", rule);
    resolve(&mut config, &registry).await.unwrap();
    assert_eq!(config.rules["gh"].allow, vec!["https://ghe.corp.example".to_string()]);
  }

  #[tokio::test]
  async fn resolve_fills_the_pattern_from_the_registry() {
    let registry = Registry::load(None).unwrap();
    let mut config = config_with("gh", rule("GITHUB_TOKEN"));
    resolve(&mut config, &registry).await.unwrap();
    assert_eq!(config.rules["gh"].pattern.as_deref(), Some("ghp_{hex:40}"));
  }

  #[tokio::test]
  async fn resolve_keeps_an_explicit_pattern() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("GITHUB_TOKEN");
    rule.pattern = Some("ghp_custom_{hex:8}".to_string());
    let mut config = config_with("gh", rule);
    resolve(&mut config, &registry).await.unwrap();
    assert_eq!(config.rules["gh"].pattern.as_deref(), Some("ghp_custom_{hex:8}"));
  }

  #[tokio::test]
  async fn missing_hosts_error_by_default() {
    let registry = Registry::load(None).unwrap();
    let mut config = config_with("unknown", rule("NO_SUCH_SERVICE_TOKEN"));
    let err = resolve(&mut config, &registry).await.unwrap_err();
    assert!(err.to_string().contains("no hosts"), "{err:?}");
  }

  #[tokio::test]
  async fn missing_hosts_warn_drops_the_rule() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("NO_SUCH_SERVICE_TOKEN");
    rule.if_missing = crate::config::IfMissing::Warn;
    let mut config = config_with("unknown", rule);
    resolve(&mut config, &registry).await.unwrap();
    assert!(config.rules.is_empty());
  }

  #[tokio::test]
  async fn missing_hosts_ignore_drops_the_rule_silently() {
    let registry = Registry::load(None).unwrap();
    let mut rule = rule("NO_SUCH_SERVICE_TOKEN");
    rule.if_missing = crate::config::IfMissing::Ignore;
    let mut config = config_with("unknown", rule);
    resolve(&mut config, &registry).await.unwrap();
    assert!(config.rules.is_empty());
  }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run secrets::`
Expected: compile failure — `resolve` does not exist.

- [ ] **Step 3: Implement resolution**

Add to `src/secrets.rs`:

```rust
/// Resolve every rule in place: union registry hosts into `allow`, fill the
/// decoy pattern, and drop rules that `if_missing` lets go.
///
/// Values come from fnox in `resolve_values`; a rule with no value at all is
/// resolved by the owner of that field, not here.
pub async fn resolve(config: &mut crate::config::AppConfig, registry: &Registry) -> eyre::Result<()> {
  let mut dropped = Vec::new();
  for (label, rule) in &mut config.rules {
    let mut hosts = registry.hosts_for(rule);
    for entry in &rule.allow {
      if !hosts.contains(entry) {
        hosts.push(entry.clone());
      }
    }
    if hosts.is_empty() && skip(label, rule, "no hosts: registry has no entry and `allow` is empty")? {
      dropped.push(label.clone());
      continue;
    }
    // Unioned once here so `grants::resolve` sees the final list.
    rule.allow = hosts;
    if rule.pattern.is_none() {
      rule.pattern = Some(registry.template(&rule.env, None));
    }
    tracing::info!(
      label,
      env = %rule.env,
      hosts = rule.allow.len(),
      "rule resolved"
    );
  }
  for label in dropped {
    config.rules.remove(&label);
  }
  Ok(())
}

/// Apply one rule's `if_missing` policy. `Ok(true)` means drop the rule;
/// `Error` bails instead.
fn skip(label: &str, rule: &RuleCfg, what: &str) -> eyre::Result<bool> {
  match rule.if_missing {
    crate::config::IfMissing::Error => eyre::bail!("rule `{label}` (env {}): {what}", rule.env),
    crate::config::IfMissing::Warn => {
      tracing::warn!(label, env = %rule.env, reason = what, "dropping rule");
      Ok(true)
    }
    crate::config::IfMissing::Ignore => Ok(true),
  }
}
```

- [ ] **Step 4: Call resolution from `serve`**

In `src/main.rs`'s `Command::Serve` arm, after `config::load` and before `grants::resolve`:

```rust
      let (mut config, workspace) = config::load(&cli)?;
      let registry = secrets::Registry::load(config::rules_dir().as_deref())?;
      secrets::resolve(&mut config, &registry).await?;
      let resolved = grants::resolve(&config)?;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run secrets:: config:: grants::`
Expected: PASS.

- [ ] **Step 6: Format and lint**

Run: `mise run format`
Expected: green.

- [ ] **Step 7: Commit (only if the owner asked for commits)**

```bash
git add src/secrets.rs src/main.rs
git commit -m "feat(secrets): resolve rule hosts, patterns, and if_missing"
```

---

### Task 4: Resolve values from fnox

**Files:**

- Modify: `Cargo.toml`
- Modify: `src/secrets.rs`
- Test: `src/secrets.rs` (`mod tests`)

**Interfaces:**

- Consumes: `FnoxCfg` from Task 1, `resolve` from Task 3.
- Produces: fnox-backed values inside `resolve`; `FnoxSource::open(&FnoxCfg) -> eyre::Result<Option<FnoxSource>>` and `FnoxSource::value(&self, key: &str) -> eyre::Result<Option<String>>` (private to the module).

- [ ] **Step 1: Write the failing tests**

Append to `src/secrets.rs`'s test module:

```rust
  const FNOX_PLAIN: &str = r#"
[providers.plain]
type = "plain"

[secrets.GITHUB_TOKEN]
provider = "plain"
value = "real-github-token"

[secrets.OTHER_TOKEN]
provider = "plain"
value = "other-real-token"
"#;

  /// Config whose only rule pulls its value from the temp fnox file.
  fn config_with_fnox(label: &str, env: &str, fnox_path: &Path) -> crate::config::AppConfig {
    let mut rule = rule(env);
    rule.value = None;
    let mut config = config_with(label, rule);
    config.fnox.config = Some(fnox_path.to_path_buf());
    config
  }

  fn write_fnox(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("fnox.toml");
    std::fs::write(&path, body).unwrap();
    path
  }

  #[tokio::test]
  async fn fnox_supplies_the_value() {
    let registry = Registry::load(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let fnox_path = write_fnox(dir.path(), FNOX_PLAIN);
    let mut config = config_with_fnox("gh", "GITHUB_TOKEN", &fnox_path);
    resolve(&mut config, &registry).await.unwrap();
    let value = config.rules["gh"].value.as_ref().unwrap();
    assert_eq!(secrecy::ExposeSecret::expose_secret(value), "real-github-token");
  }

  #[tokio::test]
  async fn inline_value_wins_over_fnox() {
    let registry = Registry::load(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let fnox_path = write_fnox(dir.path(), FNOX_PLAIN);
    let mut config = config_with_fnox("gh", "GITHUB_TOKEN", &fnox_path);
    config.rules.get_mut("gh").unwrap().value = Some(secrecy::SecretString::from("inline-wins"));
    resolve(&mut config, &registry).await.unwrap();
    let value = config.rules["gh"].value.as_ref().unwrap();
    assert_eq!(secrecy::ExposeSecret::expose_secret(value), "inline-wins");
  }

  #[tokio::test]
  async fn fnox_key_overrides_the_env_name() {
    let registry = Registry::load(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let fnox_path = write_fnox(dir.path(), FNOX_PLAIN);
    let mut config = config_with_fnox("gh", "GITHUB_TOKEN", &fnox_path);
    config.rules.get_mut("gh").unwrap().fnox_key = Some("OTHER_TOKEN".to_string());
    resolve(&mut config, &registry).await.unwrap();
    let value = config.rules["gh"].value.as_ref().unwrap();
    assert_eq!(secrecy::ExposeSecret::expose_secret(value), "other-real-token");
  }

  #[tokio::test]
  async fn undeclared_fnox_key_follows_if_missing() {
    let registry = Registry::load(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let fnox_path = write_fnox(dir.path(), FNOX_PLAIN);
    let mut config = config_with_fnox("gh", "GITHUB_TOKEN", &fnox_path);
    config.rules.get_mut("gh").unwrap().fnox_key = Some("NOT_DECLARED".to_string());

    let mut strict = config.clone();
    let err = resolve(&mut strict, &registry).await.unwrap_err();
    assert!(err.to_string().contains("fnox does not declare"), "{err:?}");

    let mut lenient = config;
    lenient.rules.get_mut("gh").unwrap().if_missing = crate::config::IfMissing::Warn;
    resolve(&mut lenient, &registry).await.unwrap();
    assert!(lenient.rules.is_empty());
  }

  #[tokio::test]
  async fn declared_but_unreadable_fnox_config_is_an_error() {
    let registry = Registry::load(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with_fnox("gh", "GITHUB_TOKEN", &dir.path().join("absent.toml"));
    let err = resolve(&mut config, &registry).await.unwrap_err();
    assert!(err.to_string().contains("fnox"), "{err:?}");
  }

  #[tokio::test]
  async fn all_inline_values_never_open_fnox() {
    let registry = Registry::load(None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut config = config_with("gh", rule("GITHUB_TOKEN"));
    config.fnox.config = Some(dir.path().join("absent.toml"));
    resolve(&mut config, &registry).await.unwrap();
    assert!(config.rules["gh"].value.is_some());
  }

  #[test]
  fn config_not_found_during_discovery_is_not_an_error() {
    let err = fnox_core::FnoxError::ConfigNotFound {
      message: "no config".to_string(),
      help: "run fnox init".to_string(),
    };
    assert!(discovered_or_none(Err(err)).unwrap().is_none());
  }
```

`config.clone()` in the tests requires `AppConfig: Clone` (it derives `Clone`) and `RuleCfg: Clone` (it does).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run secrets::`
Expected: compile failure — `fnox_core` is not a dependency and `FnoxSource` does not exist.

- [ ] **Step 3: Add the dependency**

In `Cargo.toml`, insert into `[dependencies]` between `eyre` and `futures-sink`:

```toml
fnox-core = "1.33"
```

Run `cargo sort --grouped Cargo.toml` afterwards and confirm the file is unchanged apart from the new line.

- [ ] **Step 4: Implement `FnoxSource` and value resolution**

Add to `src/secrets.rs`:

```rust
/// Opened fnox handle plus the names it declares.
struct FnoxSource {
  fnox: fnox_core::Fnox,
  declared: BTreeSet<String>,
}

/// Map a discovery failure with no config found to `None`; other errors stay.
fn discovered_or_none(found: fnox_core::Result<fnox_core::Fnox>) -> eyre::Result<Option<fnox_core::Fnox>> {
  match found {
    Ok(fnox) => Ok(Some(fnox)),
    Err(fnox_core::FnoxError::ConfigNotFound { .. }) => Ok(None),
    Err(err) => Err(eyre::eyre!("fnox discovery failed: {err}")),
  }
}

impl FnoxSource {
  /// Open fnox, or `None` when discovery finds no config at all.
  async fn open(cfg: &crate::config::FnoxCfg) -> eyre::Result<Option<Self>> {
    let fnox = match &cfg.config {
      Some(path) => Some(
        fnox_core::Fnox::open(path).map_err(|err| eyre::eyre!("fnox config {}: {err}", path.display()))?,
      ),
      None => discovered_or_none(fnox_core::Fnox::discover())?,
    };
    let Some(fnox) = fnox else {
      return Ok(None);
    };
    let fnox = match cfg.profile.as_deref() {
      Some(profile) => {
        let profiles = profile
          .split(',')
          .map(str::trim)
          .filter(|profile| !profile.is_empty())
          .map(str::to_string)
          .collect::<Vec<_>>();
        fnox.with_profiles(profiles)
      }
      None => fnox,
    };
    let declared = fnox
      .list()
      .map_err(|err| eyre::eyre!("fnox: cannot list secrets: {err}"))?
      .into_iter()
      .collect();
    Ok(Some(Self { fnox, declared }))
  }

  /// Value for one key: `None` when fnox does not declare it, error when a
  /// declared key cannot be resolved.
  async fn value(&self, key: &str) -> eyre::Result<Option<String>> {
    if !self.declared.contains(key) {
      return Ok(None);
    }
    let value = self
      .fnox
      .get(key)
      .await
      .map_err(|err| eyre::eyre!("fnox secret `{key}`: {err}"))?;
    Ok(value.filter(|value| !value.is_empty()))
  }
}

/// fnox secret name for one rule: `fnox_key`, else `env`.
fn fnox_key(rule: &RuleCfg) -> String {
  rule.fnox_key.clone().unwrap_or_else(|| rule.env.clone())
}
```

Add `use std::collections::{BTreeMap, BTreeSet};` and `use secrecy::SecretString;` to the imports.

Replace `resolve` with the value-aware version:

```rust
/// Resolve every rule in place: fetch values from fnox when no inline value
/// is present, union registry hosts into `allow`, fill the decoy pattern, and
/// drop rules that `if_missing` lets go.
pub async fn resolve(config: &mut crate::config::AppConfig, registry: &Registry) -> eyre::Result<()> {
  let needs_fnox = config.rules.values().any(|rule| rule.value.is_none());
  let fnox = if needs_fnox {
    FnoxSource::open(&config.fnox).await?
  } else {
    None
  };

  // Values are fetched before the map is mutated, so rules stay borrowed
  // immutably while fnox is awaited.
  let keys = config
    .rules
    .iter()
    .filter(|(_, rule)| rule.value.is_none())
    .map(|(label, rule)| (label.clone(), fnox_key(rule)))
    .collect::<Vec<_>>();
  let mut values = BTreeMap::new();
  for (label, key) in keys {
    let value = match &fnox {
      Some(source) => source.value(&key).await?,
      None => None,
    };
    values.insert(label, value);
  }

  let mut dropped = Vec::new();
  for (label, rule) in &mut config.rules {
    if rule.value.is_none() {
      match values.remove(label).flatten() {
        Some(value) => rule.value = Some(SecretString::from(value)),
        None => {
          if skip(label, rule, "no inline value and fnox does not declare its key")? {
            dropped.push(label.clone());
            continue;
          }
        }
      }
    }
    let mut hosts = registry.hosts_for(rule);
    for entry in &rule.allow {
      if !hosts.contains(entry) {
        hosts.push(entry.clone());
      }
    }
    if hosts.is_empty() && skip(label, rule, "no hosts: registry has no entry and `allow` is empty")? {
      dropped.push(label.clone());
      continue;
    }
    // Unioned once here so `grants::resolve` sees the final list.
    rule.allow = hosts;
    if rule.pattern.is_none() {
      rule.pattern = Some(registry.template(&rule.env, None));
    }
    tracing::info!(
      label,
      env = %rule.env,
      hosts = rule.allow.len(),
      value = if rule.value.is_some() { "resolved" } else { "none" },
      "rule resolved"
    );
  }
  for label in dropped {
    config.rules.remove(&label);
  }
  Ok(())
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run secrets::`
Expected: PASS. The first `fnox-core` build is slow; allow several minutes.

- [ ] **Step 6: Verify end to end against the real fnox binary**

```bash
mkdir -p /tmp/hodor-fnox && cd /tmp/hodor-fnox
printf '[providers.plain]\ntype = "plain"\n\n[secrets.GITHUB_TOKEN]\nprovider = "plain"\nvalue = "real-github-token"\n' > fnox.toml
cd /home/ivan/github/casualjim/hodor
HODOR_CONFIG=/tmp/hodor-fnox/config.toml cargo run --quiet -- serve &
```

Expected: startup logs one `rule resolved` line per rule with `value: resolved`, or a clear error naming the rule and the missing half. Kill the server afterwards.

- [ ] **Step 7: Format and lint**

Run: `mise run format`
Expected: green.

- [ ] **Step 8: Commit (only if the owner asked for commits)**

```bash
git add Cargo.toml Cargo.lock src/secrets.rs
git commit -m "feat(secrets): resolve rule values from fnox"
```

---

### Task 5: Document the feature

**Files:**

- Modify: `README.md`
- Modify: `AGENTS.md`

**Interfaces:**

- Consumes: the finished behavior from Tasks 1-4.
- Produces: nothing code-facing.

- [ ] **Step 1: Rewrite the README config section**

Replace the `[secrets.demo]` example in Quickstart with a `[rules.demo]` block, and add three sections after Quickstart:

````markdown
## Rules

A rule wires an environment name to the hosts it may reach, the decoy shape
the client sees, and where the real value comes from.

```toml
[fnox]
config  = "fnox.toml"   # optional; default is fnox's own discovery
profile = "work"        # optional; default is FNOX_PROFILE

[rules.gh]
env        = "GITHUB_TOKEN"        # required: decoy seed, registry key, fnox key
value      = "..."                 # optional: inline real value
fnox_key   = "..."                 # optional: fnox secret name, default = env
allow      = ["https://ghe.corp"]  # optional: unions with registry hosts
pattern    = "..."                 # optional: overrides the registry pattern
registry   = false                 # optional: skip registry hosts
if_missing = "error"               # "error" (default) | "warn" | "ignore"
```

`env = "GITHUB_TOKEN"` alone is enough: the registry supplies the hosts and
the decoy shape.

## Known-host registry

hodor ships a table of known services in `rules/registry.toml`: the
environment names each one uses, its API hosts, and its token shape. Override
it from `<config-dir>/hodor/rules.d/*.toml`, loaded in filename order:

```toml
[providers.github]
env      = ["GITHUB_TOKEN"]
hosts    = ["https://api.github.com", "https://ghe.corp.example"]
pattern  = "ghp_ghe_{hex:32}"
contains = ["gh_"]
replace  = false

[names.GH_ENTERPRISE_TOKEN]
hosts = ["https://ghe.corp.example"]
```

`replace = true` discards what earlier layers declared for those names.
`contains` matches environment-name substrings and selects a decoy shape
only, never hosts. `hodor fake <ENV>` uses the same table, so a custom rule's
decoy can be previewed without running a proxy.

## Values from fnox

When a rule has no inline `value`, hodor resolves it through
[fnox](https://fnox.jdx.dev), which reaches age, 1Password, AWS Secrets
Manager, Vault, Bitwarden, the OS keychain, and the rest of its provider
catalog. hodor embeds `fnox-core`; no fnox binary is needed.

The fnox config is `[fnox].config`, else `HODOR_FNOX_CONFIG`, else whatever
fnox's own discovery finds: an upward `fnox.toml` walk layered over fnox's
global config. A key fnox does not declare follows the rule's `if_missing`; a
key it declares but cannot resolve is a startup error.
````

- [ ] **Step 2: Update `AGENTS.md`**

In the "Key Directories" `src/*.rs` list, add:

```markdown
- `src/secrets.rs` — host registry (`rules/registry.toml` + `<config-dir>/hodor/rules.d`), rule resolution, fnox value lookup
```

Add `rules/registry.toml` to the "Important Files" table with the role "bundled known-host and token-shape registry, overridable per entry". Update the `src/config.rs` line to say "confique overlay + rule schema + deterministic fake generator (`fake_for`)" and drop the `PATTERNS` mention. Update the "Grant-scoped MITM proxy" architecture paragraph's `config::load` step to mention `secrets::resolve` between config load and `grants::resolve`.

- [ ] **Step 3: Verify the documented commands work**

```bash
cargo run --quiet -- fake GITHUB_TOKEN
mkdir -p /tmp/hodor-doc-check/rules.d
printf '[names.GITHUB_TOKEN]\npattern = "ghp_doc_{hex:8}"\n' > /tmp/hodor-doc-check/rules.d/10-doc.toml
HODOR_CONFIG=/tmp/hodor-doc-check/config.toml cargo run --quiet -- fake GITHUB_TOKEN
```

Expected: the first prints `ghp_` + 40 hex; the second prints `ghp_doc_` + 8 hex, proving the `rules.d` override in the README works as written.

- [ ] **Step 4: Format and lint**

Run: `mise run format`
Expected: green.

- [ ] **Step 5: Commit (only if the owner asked for commits)**

```bash
git add README.md AGENTS.md
git commit -m "docs: document rules, the registry, and fnox values"
```

---

### Task 6: Seed the registry with the first tranche of providers

**Files:**

- Modify: `rules/registry.toml`
- Test: `src/secrets.rs` (`mod tests`)

**Interfaces:**

- Consumes: `Registry::load` from Task 2.
- Produces: data only; no signature changes.

- [ ] **Step 1: Write the failing coverage test**

Append to `src/secrets.rs`'s test module:

```rust
  #[test]
  fn bundled_table_covers_the_first_tranche() {
    let registry = Registry::load(None).unwrap();
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
      "MONGODB_ATLAS_PRIVATE_KEY",
      "SUPABASE_SERVICE_ROLE_KEY",
      "SHOPIFY_ACCESS_TOKEN",
    ] {
      let known = registry.lookup(env);
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo nextest run secrets::bundled_table_covers_the_first_tranche`
Expected: FAIL — the names missing from Task 2's starter table have no hosts.

- [ ] **Step 3: Research and fill each entry**

For every provider in the list, open the linked documentation page and record what it actually documents; do not guess. Each entry needs the environment names the platform's docs use, its API hosts, and its token shape.

Sources to consult, in order:

| Provider | Source |
| --- | --- |
| github | <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github> |
| gitlab | <https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html> |
| anthropic | <https://docs.anthropic.com/en/api/getting-started> |
| openai | <https://platform.openai.com/docs/api-reference/introduction> |
| gemini | <https://ai.google.dev/gemini-api/docs/api-key> |
| aws | <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html> and <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html> |
| azure | <https://learn.microsoft.com/en-us/azure/developer/intro/azure-developer-identity> |
| gcp | <https://cloud.google.com/docs/authentication/application-default-credentials> |
| cloudflare | <https://developers.cloudflare.com/fundamentals/api/get-started/create-token/> |
| digitalocean | <https://docs.digitalocean.com/reference/api/create-personal-access-token/> |
| hetzner | <https://docs.hetzner.cloud/#getting-started> |
| fly | <https://fly.io/docs/machines/api/working-with-machines-api/> |
| vercel | <https://vercel.com/docs/rest-api#creating-an-access-token> |
| netlify | <https://docs.netlify.com/api/get-started/> |
| heroku | <https://devcenter.heroku.com/articles/platform-api-quickstart> |
| stripe | <https://docs.stripe.com/keys> |
| slack | <https://api.slack.com/authentication/token-types> |
| twilio | <https://www.twilio.com/docs/iam/api/account> |
| sendgrid | <https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys> |
| postmark | <https://postmarkapp.com/developer/api/overview> |
| resend | <https://resend.com/docs/api-reference/introduction> |
| npm | <https://docs.npmjs.com/about-access-tokens> |
| pypi | <https://pypi.org/help/#apitoken> |
| huggingface | <https://huggingface.co/docs/hub/security-tokens> |
| datadog | <https://docs.datadoghq.com/account_management/api-app-keys/> |
| sentry | <https://docs.sentry.io/api/auth/> |
| grafana | <https://grafana.com/docs/grafana/latest/developers/http_api/> |
| mongodb-atlas | <https://www.mongodb.com/docs/atlas/configure-api-access/> |
| supabase | <https://supabase.com/docs/guides/api/api-keys> |
| shopify | <https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens> |

Write each entry with a `# source: <url>` comment naming the page the values came from, then add it to `rules/registry.toml`. Keep entries alphabetically ordered by provider name for readability, and keep the existing entries from Task 2 (corrected where the docs disagree).

Two rules while filling this in:

- Only stable API hosts. A service whose endpoint is per-tenant (`https://<tenant>.example.com`) gets its base host only if the docs document one.
- Token shapes only when the docs state a prefix or format. Where they do not, use a pattern that matches the platform's general shape (for example `{hex:32}`) rather than inventing a prefix.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run secrets::`
Expected: PASS, including the coverage test and the validation test.

- [ ] **Step 5: Format and lint**

Run: `mise run format`
Expected: green.

- [ ] **Step 6: Run the whole suite**

Run: `mise run test`
Expected: green for both the default and `--features tun` runs.

- [ ] **Step 7: Commit (only if the owner asked for commits)**

```bash
git add rules/registry.toml src/secrets.rs
git commit -m "feat(registry): seed known hosts for the first provider tranche"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
| --- | --- |
| `[rules]` rename, schema, `[fnox]`, `config_dir`/`rules_dir` | 1 |
| Registry schema, bundled file, `rules.d`, additivity, `replace`, `names`, `contains` | 2 |
| Host union, `registry = false`, pattern tiers, `if_missing`, rule dropping | 3 |
| fnox config selection, lazy open, declared vs unresolvable, `fnox_key` | 4 |
| `hodor fake` registry awareness | 2 |
| Observability logging | 3 (hosts) and 4 (value source) |
| Testing plan | every task, plus 6 for registry data |
| Research deliverable | 6 |
| README/AGENTS/docs | 5 |
| Costs (fnox-core dependency) | 4 Step 3 |

**Deviations from the spec, deliberate:**

- `grants.rs` needs no registry parameter: `secrets::resolve` writes the unioned hosts into `rule.allow` and the resolved template into `rule.pattern`, so `grants::resolve` reads exactly what it reads today. Its only changes are the `[rules]` rename and skipping a rule whose value is still `None` (a caller that skips `secrets::resolve` gets no grant instead of a rule that substitutes an empty value).
- `hodor ca` no longer calls `grants::resolve`; it only needs `ca_path`, which now takes `&ProxyCfg`.
- `contains` matching is deterministic by provider name order, not declaration order, because TOML tables deserialize into `BTreeMap`. The spec should be read that way.
- `PATTERNS` is deleted rather than ported wholesale: `gh_`, `sk-ant-`, `anthropic`, `xox`, and `slack` become registry `contains` entries, and the generic `sk-` substring rule is dropped in favor of explicit providers.

**Type consistency:** `Registry::load`, `Registry::lookup`, `Registry::template`, `Registry::decoy`, `Registry::hosts_for`, `KnownHosts`, `RuleCfg`, `IfMissing`, `FnoxCfg`, `DEFAULT_PATTERN`, `resolve`, `skip`, `FnoxSource::open`, `FnoxSource::value`, `fnox_key`, `discovered_or_none` are used with the same names and signatures in every task that mentions them.
