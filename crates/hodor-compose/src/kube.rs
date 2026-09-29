//! Kubeconfig adapter for `file_rewrite`: a kubectl config file is a
//! differently structured form of the same information a rule holds, so the
//! adapter derives the grant from the file instead of asking the operator to
//! state it twice. Only the `current-context` maps; the file is the secret
//! source, so a kube entry stating `envs` is an error rather than a second
//! source.
//!
//! Detection is structural: a YAML mapping with `kind: Config` and a
//! `clusters:` table takes the adapter path, everything else keeps the raw
//! byte-swap. The decoy twin keeps the server (transparent capture makes the
//! destination the identity) and swaps the trust and identity: hodor's CA,
//! the minted guest pair, and the decoy token.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
#[cfg(unix)]
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hodor_config::grants::{EndpointScope, Scheme, decoy_for_rule};
use hodor_pki::ca::{CertAuthority, load_or_generate_client_pair};
use serde::Deserialize;
use serde_yaml::{Mapping, from_str};

use crate::error::Error;

/// A kubeconfig rewrite mapped onto its grant fragment and decoy twin.
#[derive(Debug)]
pub(crate) struct KubeAdapted {
  /// Grant fragment TOML, holding the real credential.
  pub(crate) fragment: String,
  /// Decoy kubeconfig for the agent: same server, hodor CA, guest pair.
  pub(crate) decoy: String,
  /// Blobs to write beside the fragment: `(file name, bytes)`.
  pub(crate) materialized: Vec<(String, Vec<u8>)>,
}

/// A kubeconfig document; unknown fields ignored.
#[derive(Debug, Deserialize, Default)]
struct KubeDoc {
  /// Document kind: `Config` for kubeconfigs.
  #[serde(default)]
  kind: String,
  /// Active context name.
  #[serde(rename = "current-context", default)]
  current_context: String,
  /// Named context refs.
  #[serde(default)]
  contexts: Vec<KubeContextEntry>,
  /// Named clusters.
  #[serde(default)]
  clusters: Vec<KubeClusterEntry>,
  /// Named users.
  #[serde(default)]
  users: Vec<KubeUserEntry>,
}

/// One `contexts` entry: a name over a cluster/user pair.
#[derive(Debug, Deserialize, Default)]
struct KubeContextEntry {
  /// Entry name, matched against `current-context`.
  #[serde(default)]
  name: String,
  /// The referenced cluster and user.
  #[serde(default)]
  context: KubeContextRef,
}

/// The cluster/user a context points at.
#[derive(Debug, Deserialize, Default)]
struct KubeContextRef {
  /// Referenced cluster name.
  #[serde(default)]
  cluster: String,
  /// Referenced user name.
  #[serde(default)]
  user: String,
}

/// One `clusters` entry.
#[derive(Debug, Deserialize, Default)]
struct KubeClusterEntry {
  /// Entry name, matched against the context's `cluster`.
  #[serde(default)]
  name: String,
  /// The server and its trust anchor.
  #[serde(default)]
  cluster: KubeCluster,
}

/// A cluster's server and CA, inline or by file.
#[derive(Debug, Deserialize, Default)]
struct KubeCluster {
  /// API server URL.
  #[serde(default)]
  server: String,
  /// Inline base64 CA bundle.
  #[serde(rename = "certificate-authority-data", default)]
  ca_data: Option<String>,
  /// CA bundle file path: inline it first, the container cannot see it.
  #[serde(rename = "certificate-authority", default)]
  ca_file: Option<String>,
}

/// One `users` entry.
#[derive(Debug, Deserialize, Default)]
struct KubeUserEntry {
  /// Entry name, matched against the context's `user`.
  #[serde(default)]
  name: String,
  /// The credential.
  #[serde(default)]
  user: KubeUser,
}

/// A user's credential: bearer token and/or client pair, inline or by file.
#[derive(Debug, Deserialize, Default)]
struct KubeUser {
  /// Bearer token.
  #[serde(default)]
  token: Option<String>,
  /// Cloud auth-provider token.
  #[serde(rename = "auth-provider", default)]
  auth_provider: Option<KubeAuthProvider>,
  /// Exec credential plugin: unsupported, detected so it errors clearly.
  #[serde(default)]
  exec: Option<Mapping>,
  /// Inline base64 client certificate.
  #[serde(rename = "client-certificate-data", default)]
  cert_data: Option<String>,
  /// Client certificate file path: inline it first.
  #[serde(rename = "client-certificate", default)]
  cert_file: Option<String>,
  /// Inline base64 client key.
  #[serde(rename = "client-key-data", default)]
  key_data: Option<String>,
  /// Client key file path: inline it first.
  #[serde(rename = "client-key", default)]
  key_file: Option<String>,
}

/// A cloud auth provider block.
#[derive(Debug, Deserialize, Default)]
struct KubeAuthProvider {
  /// Provider config holding the token.
  #[serde(default)]
  config: KubeProviderConfig,
}

/// Auth provider config.
#[derive(Debug, Deserialize, Default)]
struct KubeProviderConfig {
  /// Bearer token.
  #[serde(rename = "access-token", default)]
  access_token: Option<String>,
}

/// Whether a rewrite source takes the adapter path without a stated format:
/// both markers are kubectl-specific, so anything carrying them is probed as
/// a kubeconfig. A stated `format` skips this probe.
#[must_use]
pub(crate) fn sniff(content: &[u8]) -> bool {
  let text = String::from_utf8_lossy(content);
  text.contains("current-context:") && text.contains("clusters:")
}

/// Map a kubeconfig onto its grant fragment and decoy twin. Returns `None`
/// when the document is not a kubeconfig after all, leaving the caller on
/// the raw path.
///
/// # Errors
///
/// Returns an error when the document does not parse, names no usable
/// current context, states a non-HTTPS server, or carries no substitutable
/// credential.
pub(crate) fn adapt(source: &Path, content: &[u8], ca: &CertAuthority, guests_dir: &Path) -> Result<Option<KubeAdapted>, Error> {
  let text = String::from_utf8_lossy(content);
  let doc: KubeDoc = from_str(&text).map_err(|err| Error::KubeYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  if doc.kind != "Config" {
    return Ok(None);
  }
  let file = || source.to_path_buf();
  let invalid = |detail: String| Error::KubeInvalid { file: file(), detail };
  if doc.current_context.is_empty() {
    return Err(invalid("missing `current-context`".to_string()));
  }
  let context = doc
    .contexts
    .iter()
    .find(|entry| entry.name == doc.current_context)
    .ok_or_else(|| invalid(format!("unknown context `{}`", doc.current_context)))?;
  if context.context.cluster.is_empty() || context.context.user.is_empty() {
    return Err(invalid(format!("context `{}` names no `cluster` or no `user`", context.name)));
  }
  let cluster = doc
    .clusters
    .iter()
    .find(|entry| entry.name == context.context.cluster)
    .ok_or_else(|| invalid(format!("unknown cluster `{}`", context.context.cluster)))?;
  if cluster.cluster.server.is_empty() {
    return Err(invalid(format!("cluster `{}` states no `server`", cluster.name)));
  }
  let scope: EndpointScope = cluster
    .cluster
    .server
    .parse()
    .map_err(|detail| invalid(format!("server `{}` is not an allow entry: {detail}", cluster.cluster.server)))?;
  if scope.scheme != Scheme::Https {
    return Err(invalid(format!(
      "server `{}` is plain HTTP: the API server is TLS-only",
      cluster.cluster.server
    )));
  }
  let user = doc
    .users
    .iter()
    .find(|entry| entry.name == context.context.user)
    .ok_or_else(|| invalid(format!("unknown user `{}`", context.context.user)))?;
  let token = user
    .user
    .token
    .as_deref()
    .or_else(|| {
      user
        .user
        .auth_provider
        .as_ref()
        .and_then(|provider| provider.config.access_token.as_deref())
    })
    .filter(|token| !token.is_empty());
  if user.user.cert_file.is_some() || user.user.key_file.is_some() || cluster.cluster.ca_file.is_some() {
    return Err(invalid(
      "uses file references; inline them first: `kubectl config view --flatten --minify`".to_string(),
    ));
  }
  if user.user.exec.is_some() && token.is_none() && user.user.cert_data.is_none() && user.user.key_data.is_none() {
    return Err(invalid("exec credential plugins are not supported".to_string()));
  }
  let cert = decode(source, user.user.cert_data.as_deref(), "client-certificate-data")?;
  let key = decode(source, user.user.key_data.as_deref(), "client-key-data")?;
  if cert.is_some() != key.is_some() {
    return Err(invalid(format!("user `{}` carries half of the client pair", user.name)));
  }
  if token.is_none() && cert.is_none() {
    return Err(invalid(format!(
      "user `{}` carries neither `token` nor a client pair: nothing to substitute",
      user.name
    )));
  }
  let ca_bundle = decode(source, cluster.cluster.ca_data.as_deref(), "certificate-authority-data")?;
  let label = kube_label(source, &doc.current_context)?;
  let env = label.to_uppercase().replace('-', "_");
  // Identity-only grants (cert auth, no bearer) still need a value to
  // resolve; the certificate never reaches the wire as application data, so
  // it can never match the swap.
  let value = token.map_or_else(
    || String::from_utf8_lossy(&cert.clone().unwrap_or_default()).into_owned(),
    str::to_string,
  );
  let (decoy_token, _) = decoy_for_rule(&env, None, &[scope], value.len());
  let (guest_cert_path, guest_key_path) = load_or_generate_client_pair(ca, guests_dir, &label)?;
  let guest_cert = fs::read(&guest_cert_path).map_err(|source| Error::ReadFile {
    path: guest_cert_path.clone(),
    source,
  })?;
  let guest_key = fs::read(&guest_key_path).map_err(|source| Error::ReadFile {
    path: guest_key_path.clone(),
    source,
  })?;
  let mut materialized = Vec::new();
  let mut tls = String::new();
  let _ = writeln!(tls, "[rules.{label}.tls.\"{}\"]", escaped(&cluster.cluster.server));
  if let (Some(cert), Some(key)) = (cert, key) {
    let cert_name = format!("{label}.client.crt");
    let key_name = format!("{label}.client.key");
    let _ = writeln!(
      tls,
      "client_cert = \"{KUBE_STATE_DIR}/rules.d/{cert_name}\"\nclient_key = \"{KUBE_STATE_DIR}/rules.d/{key_name}\"",
    );
    materialized.push((cert_name, cert));
    materialized.push((key_name, key));
  }
  if let Some(ca_bundle) = ca_bundle {
    let ca_name = format!("{label}.ca.crt");
    let _ = writeln!(tls, "root_cert = \"{KUBE_STATE_DIR}/rules.d/{ca_name}\"");
    materialized.push((ca_name, ca_bundle));
  }
  tls.push_str("guest_tls_mode = \"mtls\"\n");
  let fragment = format!(
    "# generated by `hodor init` from {} — do not edit or commit: it holds the REAL credential.\n# Regenerated when the workspace config changes.\n[rules.{label}]\nenv = \"{env}\"\nregistry = false\nallow = [\"{}\"]\nvalue = \"{}\"\n{tls}",
    source.display(),
    escaped(&cluster.cluster.server),
    escaped(&value),
  );
  let decoy = render_decoy(
    &doc.current_context,
    &cluster.name,
    &user.name,
    &cluster.cluster.server,
    &STANDARD.encode(ca.cert_pem()),
    token.map(|_| decoy_token.as_str()),
    &STANDARD.encode(&guest_cert),
    &STANDARD.encode(&guest_key),
  );
  Ok(Some(KubeAdapted {
    fragment,
    decoy,
    materialized,
  }))
}

/// Decode an optional base64 blob, erroring on invalid input.
fn decode(source: &Path, data: Option<&str>, field: &str) -> Result<Option<Vec<u8>>, Error> {
  data
    .filter(|data| !data.is_empty())
    .map(|data| {
      STANDARD.decode(data.trim()).map_err(|_| Error::KubeInvalid {
        file: source.to_path_buf(),
        detail: format!("field `{field}` is not valid base64"),
      })
    })
    .transpose()
}

/// Grant label from the source path and context: `{path-slug}-{context}`.
fn kube_label(source: &Path, context: &str) -> Result<String, Error> {
  let invalid = |detail: String| Error::KubeInvalid {
    file: source.to_path_buf(),
    detail,
  };
  let parent = source.parent().ok_or_else(|| invalid("has no parent directory".to_string()))?;
  let stem = source
    .file_stem()
    .map(|stem| stem.to_string_lossy())
    .ok_or_else(|| invalid("has no file name".to_string()))?;
  let path_slug = crate::stack::workspace_slug(parent);
  let slug = |text: &str| {
    let cleaned: String = text
      .to_lowercase()
      .chars()
      .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
      .collect();
    cleaned.trim_matches('-').to_string()
  };
  if path_slug.is_empty() || slug(&stem).is_empty() || slug(context).is_empty() {
    return Err(invalid("path or context sluggifies to nothing".to_string()));
  }
  Ok(format!("{}-{}-{}", path_slug, slug(&stem), slug(context)))
}

/// Render the agent's decoy kubeconfig: same server, hodor CA, guest pair,
/// and the decoy token when the real user carries one.
#[allow(clippy::too_many_arguments, reason = "one scalar per kubeconfig field the decoy renders")]
fn render_decoy(
  context: &str,
  cluster: &str,
  user: &str,
  server: &str,
  ca_b64: &str,
  token: Option<&str>,
  cert_b64: &str,
  key_b64: &str,
) -> String {
  let mut out = String::new();
  out.push_str("# generated by `hodor init` — decoys only, safe to inspect.\n");
  out.push_str(&format!(
    "apiVersion: v1\nkind: Config\ncurrent-context: {context}\ncontexts:\n- name: {context}\n  context: {{cluster: {cluster}, user: {user}}}\nclusters:\n- name: {cluster}\n  cluster: {{server: \"{}\", certificate-authority-data: {ca_b64}}}\nusers:\n- name: {user}\n  user: {{",
    escaped(server),
  ));
  if let Some(token) = token {
    out.push_str(&format!("token: \"{}\", ", escaped(token)));
  }
  out.push_str(&format!("client-certificate-data: {cert_b64}, client-key-data: {key_b64}}}\n"));
  out
}

/// Escape a string for a TOML basic string or a YAML double-quoted scalar.
fn escaped(text: &str) -> String {
  let mut out = String::with_capacity(text.len());
  for c in text.chars() {
    match c {
      '\\' => out.push_str("\\\\"),
      '"' => out.push_str("\\\""),
      '\n' => out.push_str("\\n"),
      '\r' => out.push_str("\\r"),
      '\t' => out.push_str("\\t"),
      c => out.push(c),
    }
  }
  out
}

/// Container path the kube grant layer mounts at in the hodor service. The
/// fragment names blobs under it; host and container serve resolve the same
/// entries because the state dir mounts there.
pub(crate) const KUBE_STATE_DIR: &str = "/hodor/kube";

/// Write the kube grant layer: the grant fragments concatenated into the
/// marker global config, plus the blobs under `rules.d`, pruning stale
/// `kube-*` files so a removed rewrite stops granting. The hodor service
/// points `HODOR_CONFIG` at the marker, adding this layer without touching
/// user config.
///
/// # Errors
///
/// Returns an error when the directory, the marker, or a blob cannot be
/// written, or when a stale file cannot be pruned.
pub(crate) fn write_state(state_dir: &Path, adapted: &[KubeAdapted]) -> Result<(), Error> {
  let marker = state_dir.join("hodor.toml");
  let rules_dir = state_dir.join("rules.d");
  if adapted.is_empty() && !marker.is_file() {
    return Ok(());
  }
  fs::create_dir_all(&rules_dir).map_err(|source| Error::CreateDir {
    path: rules_dir.clone(),
    source,
  })?;
  let mut toml = String::from("# generated by `hodor init`: kubeconfig grant layer. `HODOR_CONFIG` points here in the hodor service.\n");
  let mut current = BTreeSet::new();
  for grant in adapted {
    toml.push_str(&grant.fragment);
    for (name, bytes) in &grant.materialized {
      write_secret(&rules_dir.join(name), bytes)?;
      current.insert(name.clone());
    }
  }
  write_secret(&marker, toml.as_bytes())?;
  for entry in fs::read_dir(&rules_dir).map_err(|source| Error::ReadFile {
    path: rules_dir.clone(),
    source,
  })? {
    let path = entry
      .map_err(|source| Error::ReadFile {
        path: rules_dir.clone(),
        source,
      })?
      .path();
    if path.is_file()
      && path.file_name().is_some_and(|name| name.to_string_lossy().starts_with("kube-"))
      && !current.contains(&path.file_name().expect("checked above").to_string_lossy().into_owned())
    {
      fs::remove_file(&path).map_err(|source| Error::RemoveFile {
        path: path.clone(),
        source,
      })?;
    }
  }
  Ok(())
}

/// Write a secret file the agent must never see: owner-only on unix.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), Error> {
  fs::write(path, bytes).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  #[cfg(unix)]
  fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(|source| Error::WriteFile {
    path: path.to_path_buf(),
    source,
  })?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;

  use hodor_config::config::RuleCfg;
  use hodor_config::grants::GuestTlsMode;
  use serde::Deserialize;

  use super::*;

  const BEARER_DOC: &str = r"apiVersion: v1
kind: Config
current-context: k3s-local
contexts:
- name: k3s-local
  context: {cluster: k3s, user: admin}
clusters:
- name: k3s
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: admin
  user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
";

  const SOURCE: &str = "/home/ivan/.kube/k3s.yaml";

  fn test_ca() -> CertAuthority {
    CertAuthority::generate().unwrap()
  }

  fn adapt_doc(doc: &str) -> KubeAdapted {
    let dir = tempfile::tempdir().unwrap();
    adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path())
      .expect("adapt parses")
      .expect("bearer doc is a kubeconfig")
  }

  #[derive(Debug, Deserialize)]
  struct RulesDoc {
    rules: BTreeMap<String, RuleCfg>,
  }

  fn rules_from(fragment: &str) -> BTreeMap<String, RuleCfg> {
    toml_edit::de::from_str::<RulesDoc>(fragment).expect("fragment parses").rules
  }

  #[test]
  fn sniffing_spots_kubeconfigs() {
    let npmrc = "//registry.npmjs.org/:_authToken=real-secret-1\n";
    assert!(!sniff(npmrc.as_bytes()));
    assert!(sniff(BEARER_DOC.as_bytes()));
  }

  #[test]
  fn foreign_content_is_not_a_kubeconfig() {
    let dir = tempfile::tempdir().unwrap();
    let npmrc = "//registry.npmjs.org/:_authToken=real-secret-1\n";
    let err = adapt(Path::new(SOURCE), npmrc.as_bytes(), &test_ca(), dir.path()).expect_err("plain text fails closed");
    assert!(err.to_string().contains("does not parse as YAML"), "{err}");
  }

  #[test]
  fn label_slugs_the_source_path_and_context() {
    assert_eq!(kube_label(Path::new(SOURCE), "k3s-local").unwrap(), "home-ivan-kube-k3s-k3s-local");
    let adapted = adapt_doc(BEARER_DOC);
    assert!(
      adapted.fragment.contains("[rules.home-ivan-kube-k3s-k3s-local]"),
      "{}",
      adapted.fragment
    );
  }

  #[test]
  fn fragment_holds_the_grant_and_parses_as_a_rule() {
    let adapted = adapt_doc(BEARER_DOC);
    let rules = rules_from(&adapted.fragment);
    let rule = rules.get("home-ivan-kube-k3s-k3s-local").expect("rule present");
    assert_eq!(rule.env, "HOME_IVAN_KUBE_K3S_K3S_LOCAL");
    assert_eq!(rule.allow, vec!["https://10.0.0.1:6443".to_string()]);
    assert_eq!(rule.registry, Some(false));
    assert!(rule.value.is_some(), "bearer token is the inline real value");
    let tls = rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert!(
      tls
        .client_cert
        .as_ref()
        .is_some_and(|path| path.ends_with("home-ivan-kube-k3s-k3s-local.client.crt"))
    );
    assert!(
      tls
        .root_cert
        .as_ref()
        .is_some_and(|path| path.ends_with("home-ivan-kube-k3s-k3s-local.ca.crt"))
    );
    assert_eq!(tls.guest_tls_mode, GuestTlsMode::Mtls);
    assert_eq!(adapted.materialized.len(), 3, "pair plus CA materialize beside the fragment");
  }

  #[test]
  fn decoy_keeps_the_server_and_swaps_trust_identity_and_token() {
    let adapted = adapt_doc(BEARER_DOC);
    assert!(adapted.decoy.contains("server: \"https://10.0.0.1:6443\""), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("k3s-token"),
      "no real credential survives: {}",
      adapted.decoy
    );
    assert!(!adapted.decoy.contains("Q0E="), "no real CA survives: {}", adapted.decoy);
    assert!(!adapted.decoy.contains("Q0VSVA=="), "no real pair survives: {}", adapted.decoy);
    assert!(adapted.decoy.contains("token: \""), "decoy token present: {}", adapted.decoy);
    assert!(
      adapted.decoy.contains("client-certificate-data: "),
      "guest pair present: {}",
      adapted.decoy
    );
  }

  #[test]
  fn cert_only_user_maps_to_an_identity_grant() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
    );
    let adapted = adapt_doc(&doc);
    assert!(!adapted.decoy.contains("token:"), "no bearer, no token line: {}", adapted.decoy);
    let rules = rules_from(&adapted.fragment);
    assert!(
      rules["home-ivan-kube-k3s-k3s-local"].value.is_some(),
      "identity grant still resolves"
    );
  }

  #[test]
  fn file_refs_are_an_error() {
    let doc = BEARER_DOC.replace("certificate-authority-data: Q0E=", "certificate-authority: ca.crt");
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("file refs fail closed");
    assert!(err.to_string().contains("inline them first"), "{err}");
  }

  #[test]
  fn exec_plugins_are_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {exec: {command: aws-iam-authenticator}}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("exec fails closed");
    assert!(err.to_string().contains("exec credential plugins"), "{err}");
  }

  #[test]
  fn unknown_context_is_an_error() {
    let doc = BEARER_DOC.replace("current-context: k3s-local", "current-context: nope");
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("unknown context fails closed");
    assert!(err.to_string().contains("unknown context"), "{err}");
  }

  #[test]
  fn half_pair_is_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("half pair fails closed");
    assert!(err.to_string().contains("half of the client pair"), "{err}");
  }

  #[test]
  fn plain_http_server_is_an_error() {
    let doc = BEARER_DOC.replace("https://10.0.0.1:6443", "http://10.0.0.1:8080");
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("plain HTTP fails closed");
    assert!(err.to_string().contains("plain HTTP"), "{err}");
  }

  #[test]
  fn credentialless_user_is_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("nothing to swap fails closed");
    assert!(err.to_string().contains("nothing to substitute"), "{err}");
  }

  #[test]
  fn state_writes_and_stale_ones_prune() {
    let adapted = adapt_doc(BEARER_DOC);
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("kube");
    write_state(&state, &[adapted]).unwrap();
    let rules = state.join("rules.d");
    let marker = std::fs::read_to_string(state.join("hodor.toml")).unwrap();
    assert!(marker.contains("[rules.home-ivan-kube-k3s-k3s-local]"), "{marker}");
    assert!(rules.join("home-ivan-kube-k3s-k3s-local.client.crt").is_file());
    let stale = rules.join("kube-gone.crt");
    std::fs::write(&stale, "stale").unwrap();
    write_state(&state, &[]).unwrap();
    assert!(!stale.exists(), "removed rewrites stop granting");
  }
}
