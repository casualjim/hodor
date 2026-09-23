//! Grant model: a credential is one real secret, and a grant says what kind
//! of endpoints that secret may be presented at. A rule is one kind, inferred
//! from the URL schemes of its `allow` entries.

use std::path::PathBuf;
use std::str::FromStr;

use secrecy::{ExposeSecret as _, SecretString};

use crate::config::AppConfig;

/// Host pattern: exact, `*.`-wildcard (subdomains only), or any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPat {
  /// Exact hostname, ASCII case-insensitive.
  Exact(String),
  /// `*.`-prefixed suffix; matches subdomains only, never the apex.
  Wildcard(String),
  /// Any host (`*`).
  Any,
}

impl HostPat {
  /// Check if a hostname matches this pattern.
  ///
  /// Uses ASCII case-insensitive comparison to avoid `to_lowercase()`
  /// allocations (DNS hostnames are ASCII per RFC 4343). Wildcards match
  /// subdomains only: `*.example.com` matches `a.example.com` but never
  /// the apex `example.com`.
  #[must_use]
  pub fn matches(&self, hostname: &str) -> bool {
    match self {
      HostPat::Exact(h) => hostname.eq_ignore_ascii_case(h),
      HostPat::Wildcard(pattern) => {
        if let Some(suffix) = pattern.strip_prefix("*.") {
          hostname.len() > suffix.len() + 1
            && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.'
            && hostname[hostname.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        } else {
          hostname.eq_ignore_ascii_case(pattern)
        }
      }
      HostPat::Any => true,
    }
  }
}

/// One parsed `postgres://` connection string: the connection facts both
/// legs of a database rule share, plus the upstream TLS policy the string
/// may state.
#[derive(Debug)]
struct ParsedDbString {
  host: String,
  port: u16,
  user: Option<String>,
  password: SecretString,
  database: Option<String>,
  ssl: SslMode,
  negotiation: SslNegotiation,
  root_cert: Option<RootCert>,
  client_cert: Option<PathBuf>,
  client_key: Option<PathBuf>,
}

/// Parse one libpq connection string, honored exactly. The password is
/// required — a string with no credential maps nothing.
fn parse_db_string(entry: &str) -> Result<ParsedDbString, String> {
  if !entry.starts_with("postgres://") {
    return Err(format!("bad connection string `{entry}`: expected `postgres://`"));
  }
  let url = url::Url::parse(entry).map_err(|err| format!("bad connection string `{entry}`: {err}"))?;
  let host = url
    .host()
    .map(|host| host.to_string())
    .ok_or_else(|| format!("bad connection string `{entry}`: empty host"))?;
  let port = url.port().unwrap_or(5432);
  let user = (!url.username().is_empty()).then(|| url.username().to_string());
  let password = url
    .password()
    .filter(|password| !password.is_empty())
    .ok_or_else(|| format!("bad connection string `{entry}`: the password is required — a string with no credential maps nothing"))?;
  let password = SecretString::from(password.to_string());
  let mut ssl = SslMode::Prefer;
  let mut negotiation = SslNegotiation::Postgres;
  let mut root_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  for (key, value) in url.query_pairs() {
    match key.as_ref() {
      "sslmode" | "ssl" => {
        ssl = match value.as_ref() {
          "disable" => SslMode::Disable,
          "allow" => SslMode::Allow,
          "prefer" => SslMode::Prefer,
          "require" => SslMode::Require,
          "verify-ca" => SslMode::VerifyCa,
          "verify-full" => SslMode::VerifyFull,
          _ => {
            return Err(format!(
              "bad connection string `{entry}`: sslmode is disable, allow, prefer, require, verify-ca or verify-full"
            ));
          }
        };
      }
      "sslnegotiation" => {
        negotiation = match value.as_ref() {
          "postgres" => SslNegotiation::Postgres,
          "direct" => SslNegotiation::Direct,
          _ => return Err(format!("bad connection string `{entry}`: sslnegotiation is postgres or direct")),
        };
      }
      "sslrootcert" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslrootcert needs a path"));
        }
        root_cert = Some(if value == "system" {
          RootCert::System
        } else {
          RootCert::Path(PathBuf::from(value.as_ref()))
        });
      }
      "sslcert" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslcert needs a path"));
        }
        client_cert = Some(PathBuf::from(value.as_ref()));
      }
      "sslkey" => {
        if value.is_empty() {
          return Err(format!("bad connection string `{entry}`: sslkey needs a path"));
        }
        client_key = Some(PathBuf::from(value.as_ref()));
      }
      _ => return Err(format!("bad connection string `{entry}`: unknown query `{key}`")),
    }
  }
  if client_cert.is_some() != client_key.is_some() {
    return Err(format!("bad connection string `{entry}`: sslcert and sslkey come together"));
  }
  let database = match url.path() {
    "" | "/" => None,
    path => match path.strip_prefix('/').filter(|rest| !rest.contains('/')) {
      Some(name) if !name.is_empty() => Some(name.to_string()),
      _ => return Err(format!("bad connection string `{entry}`: database is one path segment")),
    },
  };
  Ok(ParsedDbString {
    host,
    port,
    user,
    password,
    database,
    ssl,
    negotiation,
    root_cert,
    client_cert,
    client_key,
  })
}

impl DatabaseScope {
  /// Both legs of a database rule from its two connection strings: the fake
  /// the rule states, the real the secret source resolved. The real
  /// string's TLS parameters state the upstream policy.
  ///
  /// # Errors
  /// Either string is not a `postgres://` connection string, or the real
  /// one names a verifying sslmode with no `sslrootcert` to verify against.
  pub fn from_strings(fake: &str, real: &str) -> Result<Self, String> {
    let fake = parse_db_string(fake)?;
    let real = parse_db_string(real)?;
    if matches!(real.ssl, SslMode::VerifyCa | SslMode::VerifyFull) && real.root_cert.is_none() {
      return Err("sslmode needs `sslrootcert=<path>` to verify against".to_string());
    }
    Ok(Self {
      downstream: DbLeg {
        host: fake.host,
        port: fake.port,
        user: fake.user,
        password: fake.password,
        database: fake.database,
      },
      upstream: DbLeg {
        host: real.host,
        port: real.port,
        user: real.user,
        password: real.password,
        database: real.database,
      },
      ssl: real.ssl,
      negotiation: real.negotiation,
      root_cert: real.root_cert,
      client_cert: real.client_cert,
      client_key: real.client_key,
      guest_tls: GuestTlsMode::default(),
    })
  }
}

/// Parse a user-facing host string: `*` is any host, `*.`-prefixed
/// strings are wildcards, everything else matches exactly. Infallible.
impl FromStr for HostPat {
  type Err = std::convert::Infallible;

  fn from_str(host: &str) -> Result<Self, Self::Err> {
    Ok(if host == "*" {
      HostPat::Any
    } else if host.starts_with("*.") {
      HostPat::Wildcard(host.to_string())
    } else {
      HostPat::Exact(host.to_string())
    })
  }
}

/// Grant scheme: the URL scheme names the protocol. No inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
  /// Plain HTTP.
  Http,
  /// TLS HTTP.
  Https,
  /// Raw TCP.
  Tcp,
  /// Postgres wire protocol. TLS comes from the `sslmode` query.
  Postgres,
}

/// Postgres TLS negotiation, read from the entry's `sslmode` query.
///
/// The values are libpq's, because the entry URL is the user's statement about
/// how this endpoint is reached, not a place for the proxy's own policy. The
/// mode governs the leg to the real server; the guest leg answers what the
/// guest asks for, the way a real server does.
///
/// A `require` verifies the chain only when the entry also names a
/// `sslrootcert`, which is what libpq does. `verify-ca` and `verify-full` need
/// one, because there is no other source of trust this proxy could use without
/// inventing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
  /// Never TLS.
  Disable,
  /// Cleartext first; TLS when the server refuses cleartext.
  Allow,
  /// TLS when the server accepts it, cleartext when it refuses.
  Prefer,
  /// TLS only; a server that refuses it fails the connection.
  Require,
  /// TLS only, verifying the server certificate chain.
  VerifyCa,
  /// TLS only, verifying the chain and the host name.
  VerifyFull,
}

/// How the entry asks a server for TLS, from its `sslnegotiation` query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslNegotiation {
  /// The 8-byte `SSLRequest`, then its one-byte answer. Every server since
  /// forever.
  Postgres,
  /// TLS straight away, with the `postgresql` ALPN identifier. PostgreSQL 17
  /// and later only.
  Direct,
}

/// One real secret and the decoy that stands in for it. Shared by every
/// grant kind, because substitution only ever needs these three.
#[derive(Debug, Clone)]
pub struct Credential {
  /// Secret label (log identifier, never the value).
  pub label: String,
  /// Deterministic format-valid decoy presented to clients.
  pub fake: String,
  /// Real secret value swapped upstream.
  pub value: SecretString,
}

/// How the guest leg treats client certificates. The mode is hodor's own
/// configuration, carried by the rule's `tls` table, never by an entry URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestTlsMode {
  /// Terminate TLS and never ask the guest for a client certificate.
  #[default]
  Tls,
  /// Request a client certificate and admit only ones hodor's own CA signs.
  Mtls,
}

/// Allow entry for a bearer-style credential: an endpoint, plus the upstream
/// client identity an https entry names for mTLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointScope {
  /// Entry scheme.
  pub scheme: Scheme,
  /// Entry host pattern.
  pub host: HostPat,
  /// Entry port.
  pub port: u16,
  /// PEM client certificate for upstream mTLS, when the entry names one.
  pub client_cert: Option<PathBuf>,
  /// PEM client key for upstream mTLS, when the entry names one.
  pub client_key: Option<PathBuf>,
  /// How the guest leg treats client certificates (rule table, not the URL).
  pub guest_tls: GuestTlsMode,
}

/// Upstream trust anchor an entry names with `sslrootcert`: a PEM path, or
/// libpq's `system` spelling for the platform trust store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RootCert {
  /// PEM trust anchors read from this path.
  Path(PathBuf),
  /// The platform trust store.
  System,
}

/// One leg of a database rule: the connection facts of one connection
/// string. The downstream leg comes from the rule's stated fake string; the
/// upstream leg comes from the resolved real connection string.
#[derive(Debug, Clone)]
pub struct DbLeg {
  /// Dial host.
  pub host: String,
  /// Dial port.
  pub port: u16,
  /// User this leg presents.
  pub user: Option<String>,
  /// Password this leg presents.
  pub password: SecretString,
  /// Database name, when the string names one.
  pub database: Option<String>,
}

/// A database rule's scope: both legs of its one connection-string mapping.
/// The real string states the upstream TLS policy; the rule's `tls` table
/// states the guest leg's mode, keyed by the rule's env name.
#[derive(Debug, Clone)]
pub struct DatabaseScope {
  /// The guest's leg, from the rule's stated fake connection string: the
  /// guest dials this host and port — the port is the rule's match key —
  /// and presents this user and password.
  pub downstream: DbLeg,
  /// The server's leg, from the resolved real connection string: hodor
  /// dials this host and port and presents this user and password.
  pub upstream: DbLeg,
  /// TLS mode for the leg to the real server.
  pub ssl: SslMode,
  /// How TLS is asked for, when the entry states it.
  pub negotiation: SslNegotiation,
  /// Trust anchor for server verification, when the entry names one: a PEM
  /// path, or the platform store via `sslrootcert=system`.
  pub root_cert: Option<RootCert>,
  /// PEM client certificate for upstream mTLS, when the entry names one.
  pub client_cert: Option<PathBuf>,
  /// PEM client key for upstream mTLS, when the entry names one.
  pub client_key: Option<PathBuf>,
  /// How the guest leg treats client certificates (rule table, not the URL).
  pub guest_tls: GuestTlsMode,
}

/// Parse one `allow` entry into typed parts. The `url` crate does the
/// work: every field is read off the parsed [`url::Url`]. The only special
/// case is the `*` host marker, which cannot survive URL parsing, so a
/// `w` placeholder stands in for one parse and the marker is restored from
/// the parsed host.
///
/// http/https/tcp stay authority-only (default ports 80/443; tcp needs an
/// explicit port). postgres is not an entry scheme: a database rule states
/// no allow entries — its connection string is the grant. Entries match,
/// secrets live in values.
impl FromStr for EndpointScope {
  type Err = String;

  fn from_str(entry: &str) -> Result<Self, Self::Err> {
    let Some((scheme_raw, rest)) = entry.split_once("://") else {
      return Err("missing `://`".to_string());
    };
    let wildcard = rest.starts_with('*');
    let probe = if wildcard {
      format!("{scheme_raw}://w{}", &rest[1..])
    } else {
      entry.to_string()
    };
    let url = url::Url::parse(&probe).map_err(|err| format!("bad allow entry `{entry}`: {err}"))?;
    let scheme = match url.scheme() {
      "http" => Scheme::Http,
      "https" => Scheme::Https,
      "tcp" => Scheme::Tcp,
      "postgres" => {
        return Err(format!(
          "bad allow entry `{entry}`: database rules state no allow entries — the connection string is the grant"
        ));
      }
      other => return Err(format!("unknown scheme `{other}`")),
    };
    if url.password().is_some() {
      return Err(format!(
        "bad allow entry `{entry}`: passwords live in values, never in match entries"
      ));
    }
    let parsed_host = match url.host() {
      Some(url::Host::Domain(domain)) => domain.to_string(),
      Some(url::Host::Ipv4(addr)) => addr.to_string(),
      Some(url::Host::Ipv6(addr)) => addr.to_string(),
      None => return Err(format!("bad allow entry `{entry}`: empty host")),
    };
    let host = if wildcard {
      let tail = parsed_host.strip_prefix('w').unwrap_or(&parsed_host);
      if tail.is_empty() {
        HostPat::Any
      } else if tail.starts_with('.') && tail.len() > 1 {
        HostPat::Wildcard(format!("*{tail}"))
      } else {
        return Err(format!("bad allow entry `{entry}`: `*` only leads `*` or `*.suffix`"));
      }
    } else {
      HostPat::Exact(parsed_host)
    };
    let port = match (url.port(), scheme) {
      (Some(port), _) => port,
      (None, Scheme::Http) => 80,
      (None, Scheme::Https) => 443,
      (None, Scheme::Tcp) => return Err("tcp grant requires an explicit port".to_string()),
      (None, Scheme::Postgres) => 5432,
    };
    reject_endpoint_query(entry, &url)?;
    Ok(EndpointScope {
      scheme,
      host,
      port,
      client_cert: None,
      client_key: None,
      guest_tls: GuestTlsMode::default(),
    })
  }
}

/// Endpoint entries are identity only. Every libpq query parameter is
/// rejected, and the rejection names the parameter exactly.
fn reject_endpoint_query(entry: &str, url: &url::Url) -> Result<(), String> {
  let mut negotiation = SslNegotiation::Postgres;
  let mut root_cert = None;
  let mut client_cert = None;
  let mut client_key = None;
  let mut ssl_seen = false;
  for (key, value) in url.query_pairs() {
    match key.as_ref() {
      "sslmode" | "ssl" => {
        match value.as_ref() {
          "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full" => {}
          _ => {
            return Err(format!(
              "bad allow entry `{entry}`: sslmode is disable, allow, prefer, require, verify-ca or verify-full"
            ));
          }
        }
        ssl_seen = true;
      }
      "sslnegotiation" => {
        negotiation = match value.as_ref() {
          "postgres" => SslNegotiation::Postgres,
          "direct" => SslNegotiation::Direct,
          _ => return Err(format!("bad allow entry `{entry}`: sslnegotiation is postgres or direct")),
        };
      }
      "sslrootcert" => {
        if value.is_empty() {
          return Err(format!("bad allow entry `{entry}`: sslrootcert needs a path"));
        }
        root_cert = Some(if value == "system" {
          RootCert::System
        } else {
          RootCert::Path(PathBuf::from(value.as_ref()))
        });
      }
      "sslcert" => {
        if value.is_empty() {
          return Err(format!("bad allow entry `{entry}`: sslcert needs a path"));
        }
        client_cert = Some(PathBuf::from(value.as_ref()));
      }
      "sslkey" => {
        if value.is_empty() {
          return Err(format!("bad allow entry `{entry}`: sslkey needs a path"));
        }
        client_key = Some(PathBuf::from(value.as_ref()));
      }
      _ => return Err(format!("bad allow entry `{entry}`: unknown query `{key}`")),
    }
  }
  if client_cert.is_some() != client_key.is_some() {
    return Err(format!("bad allow entry `{entry}`: sslcert and sslkey come together"));
  }
  if !url.username().is_empty() {
    return Err(format!("bad allow entry `{entry}`: userinfo is postgres-only"));
  }
  if let Some(path) = url.path().strip_prefix('/').filter(|path| !path.is_empty()) {
    return Err(format!("bad allow entry `{entry}`: paths are postgres-only, found `/{path}`"));
  }
  if ssl_seen {
    return Err(format!("bad allow entry `{entry}`: sslmode is postgres-only"));
  }
  if negotiation != SslNegotiation::Postgres {
    return Err(format!("bad allow entry `{entry}`: sslnegotiation is postgres-only"));
  }
  if root_cert.is_some() {
    return Err(format!("bad allow entry `{entry}`: sslrootcert is postgres-only"));
  }
  if client_cert.is_some() || client_key.is_some() {
    return Err(format!("bad allow entry `{entry}`: sslcert and sslkey are postgres-only"));
  }
  Ok(())
}

/// One secret and the endpoints it may be presented at. A rule is one kind,
/// so the variants carry only the fields their kind can use.
#[derive(Debug, Clone)]
pub enum Grant {
  /// Bearer-style secret for HTTP or raw TCP endpoints.
  Token {
    /// The real secret and its decoy.
    credential: Credential,
    /// Parsed endpoint entries.
    allow: Vec<EndpointScope>,
  },
  /// One connection-string mapping: fake connection string to real, 1:1.
  Database {
    /// The wire needles: the fake password and the real password.
    credential: Credential,
    /// The one scope this rule maps, carrying both legs' facts.
    scope: Box<DatabaseScope>,
  },
}

impl Grant {
  /// The secret this grant swaps.
  #[must_use]
  pub fn credential(&self) -> &Credential {
    match self {
      Grant::Token { credential, .. } | Grant::Database { credential, .. } => credential,
    }
  }

  /// Grant-level match for a concrete request: scheme + port + host.
  #[must_use]
  pub fn matches(&self, scheme: Scheme, host: &str, port: u16) -> bool {
    match self {
      Grant::Token { allow, .. } => allow.iter().any(|entry| endpoint_match(entry, scheme, host, port)),
      Grant::Database { scope, .. } => database_match(scope, scheme, host, port),
    }
  }

  /// Endpoint entry of `scheme` covering a destination. `host` None matches
  /// any host on the port, which is all a transparent capture knows before
  /// the identity is read.
  #[must_use]
  pub fn endpoint(&self, scheme: Scheme, host: Option<&str>, port: u16) -> Option<&EndpointScope> {
    let Grant::Token { allow, .. } = self else {
      return None;
    };
    allow
      .iter()
      .find(|entry| entry.scheme == scheme && entry.port == port && host.is_none_or(|host| entry.host.matches(host)))
  }

  /// The database scope whose downstream (guest-side) port and host cover a
  /// destination, `host` optional as above: transparent capture knows the
  /// port before it knows the host.
  #[must_use]
  pub fn database(&self, host: Option<&str>, port: u16) -> Option<&DatabaseScope> {
    let Grant::Database { scope, .. } = self else {
      return None;
    };
    (scope.downstream.port == port && host.is_none_or(|host| scope.downstream.host.eq_ignore_ascii_case(host))).then(|| scope.as_ref())
  }
}

fn endpoint_match(entry: &EndpointScope, scheme: Scheme, host: &str, port: u16) -> bool {
  entry.scheme == scheme && host_port_match(&entry.host, entry.port, host, port)
}

fn database_match(scope: &DatabaseScope, scheme: Scheme, host: &str, port: u16) -> bool {
  scheme == Scheme::Postgres && port == scope.downstream.port && scope.downstream.host.eq_ignore_ascii_case(host)
}

fn host_port_match(pat: &HostPat, entry_port: u16, host: &str, port: u16) -> bool {
  entry_port == port && pat.matches(host)
}

/// Resolved proxy config: listener settings plus parsed grants.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
  /// Proxy listener settings.
  pub proxy: crate::config::ProxyCfg,
  /// Parsed per-secret grants.
  pub grants: Vec<Grant>,
  /// Parsed plugin grants.
  pub plugins: Vec<crate::plugins::ResolvedPlugin>,
}

/// Parse every rule's `allow` entries into grants. A rule's entries must all
/// be one kind; the kind comes from their schemes, and the grant carries only
/// that kind's fields.
///
/// # Errors
///
/// Returns an error when an `allow` entry is not a valid URI grant, or when
/// one rule mixes endpoint and database entries.
///
/// # Panics
///
/// Panics when a database rule states no value; [`crate::config::Rule::is_database`]
/// guarantees one, so this is a programmer error, not a config error.
pub fn resolve(cfg: &AppConfig) -> eyre::Result<ResolvedConfig> {
  let mut grants = Vec::with_capacity(cfg.rules.len());
  for (label, rule) in &cfg.rules {
    if rule.is_database() {
      // Database rule: the rule states the fake connection string in
      // `value`; the real one resolved from the secret source into `real`.
      // No allow entries — the connection string is the grant.
      eyre::ensure!(
        rule.allow.is_empty(),
        "rule `{label}`: a database rule states no allow entries; the connection string is the grant"
      );
      let Some(real) = rule.real.clone() else {
        // The secret source did not resolve this name; no grant rather than
        // a rule that swaps in nothing.
        tracing::warn!(label, env = %rule.env, "rule has no resolved real connection string; no grant");
        continue;
      };
      let fake = rule.value.as_ref().expect("is_database checked a value").expose_secret();
      let mut scope = DatabaseScope::from_strings(fake, real.expose_secret()).map_err(|err| eyre::eyre!("rule `{label}`: {err}"))?;
      // The rule table states the guest leg only; the upstream identity
      // lives in the real string's libpq URL.
      for (key, tls) in &rule.tls {
        eyre::ensure!(
          key == &rule.env,
          "rule `{label}`: tls config names `{key}` but the rule's env is `{}`",
          rule.env
        );
        if tls.client_cert.is_some() || tls.client_key.is_some() {
          eyre::bail!(
            "rule `{label}`: postgres states the upstream identity in its libpq URL (`sslcert`/`sslkey`), never in the rule table"
          );
        }
        scope.guest_tls = tls.guest_tls_mode;
      }
      // The wire needles are the credentials: fake password in, real
      // password out; the legs' users swap when they differ (the wire
      // machine rewrites the startup's `user` parameter).
      let credential = Credential {
        label: label.clone(),
        fake: scope.downstream.password.expose_secret().to_string(),
        value: scope.upstream.password.clone(),
      };
      grants.push(Grant::Database {
        credential,
        scope: Box::new(scope),
      });
      continue;
    }
    // Endpoint rule: `value` is the real secret, `allow` names the hosts.
    let Some(value) = rule.value.clone() else {
      // `secrets::resolve` fills this before `serve`; a caller that skips
      // resolution gets no grant rather than a rule that swaps in nothing.
      tracing::warn!(label, env = %rule.env, "rule has no resolved value; no grant");
      continue;
    };
    let mut parsed = Vec::with_capacity(rule.allow.len());
    for entry in &rule.allow {
      let mut scope: EndpointScope = entry
        .parse()
        .map_err(|err| eyre::eyre!("rule `{label}`: bad allow entry `{entry}`: {err}"))?;
      // Identity comes from the entry; hodor's own TLS configuration comes
      // from the rule's `tls` table, keyed by the entry itself.
      if let Some(tls) = rule.tls.get(entry) {
        if tls.client_cert.is_some() != tls.client_key.is_some() {
          eyre::bail!("rule `{label}`: entry `{entry}`: client_cert and client_key come together");
        }
        scope.client_cert.clone_from(&tls.client_cert);
        scope.client_key.clone_from(&tls.client_key);
        scope.guest_tls = tls.guest_tls_mode;
      }
      parsed.push((entry, scope));
    }
    for key in rule.tls.keys() {
      if !rule.allow.iter().any(|entry| entry == key) {
        eyre::bail!("rule `{label}`: tls config names entry `{key}` the rule does not allow");
      }
    }
    if parsed.is_empty() {
      tracing::warn!(label, env = %rule.env, "rule has no allow entries; no grant");
      continue;
    }
    let allow = parsed.into_iter().map(|(_, scope)| scope).collect();
    let credential = Credential {
      label: label.clone(),
      fake: crate::config::fake_for(&rule.env, rule.pattern.as_deref()),
      value,
    };
    grants.push(Grant::Token { credential, allow });
  }
  let plugins = crate::plugins::resolve_plugins(cfg)?;
  Ok(ResolvedConfig {
    proxy: cfg.proxy.clone(),
    grants,
    plugins,
  })
}

/// Scheme + port + host all match, over raw parsed endpoint entries.
/// Plugins match this way.
#[must_use]
pub fn uri_match(allow: &[EndpointScope], scheme: Scheme, host: &str, port: u16) -> bool {
  allow.iter().any(|entry| endpoint_match(entry, scheme, host, port))
}

#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;

  use super::*;

  fn endpoint_grant(entries: &[&str]) -> Grant {
    Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: "fake".into(),
        value: SecretString::from("value"),
      },
      allow: entries.iter().map(|entry| endpoint_scope(entry)).collect(),
    }
  }

  fn endpoint_scope(entry: &str) -> EndpointScope {
    entry.parse().unwrap()
  }

  /// One database rule: the stated fake string plus the secret-source real
  /// string, exactly as serve loads it.
  fn cfg_with_db(fake: &str, real: &str) -> AppConfig {
    let mut rules = BTreeMap::new();
    rules.insert(
      "t".to_string(),
      crate::config::RuleCfg {
        env: "DATABASE_URL".into(),
        value: Some(SecretString::from(fake)),
        real: Some(SecretString::from(real)),
        fnox_key: None,
        allow: vec![],
        pattern: None,
        registry: None,
        tls: BTreeMap::new(),
        if_missing: crate::config::IfMissing::default(),
      },
    );
    AppConfig {
      proxy: crate::config::ProxyCfg {
        listen: "127.0.0.1:8080".parse().unwrap(),
        ca_file: None,
        handshake_timeout_secs: 10,
      },
      workspace: crate::config::WorkspaceCfg::default(),
      rules,
      plugins: BTreeMap::new(),
      agents: BTreeMap::new(),
    }
  }

  /// A resolved database scope, through [`resolve`] exactly as serve does.
  fn database_scope(fake: &str, real: &str) -> DatabaseScope {
    let resolved = resolve(&cfg_with_db(fake, real)).unwrap();
    let Some(Grant::Database { scope, .. }) = resolved.grants.first() else {
      panic!("a database rule resolves to a database grant");
    };
    (**scope).clone()
  }

  /// A resolved database grant.
  fn database_grant(fake: &str, real: &str) -> Grant {
    let resolved = resolve(&cfg_with_db(fake, real)).unwrap();
    resolved.grants.into_iter().next().unwrap()
  }

  fn cfg_with_rule(entries: &[&str]) -> AppConfig {
    cfg_with_tls(entries, BTreeMap::new())
  }

  /// [`cfg_with_rule`] plus per-entry TLS configuration.
  fn cfg_with_tls(entries: &[&str], tls: BTreeMap<String, crate::config::HostTlsCfg>) -> AppConfig {
    let mut rules = BTreeMap::new();
    rules.insert(
      "t".to_string(),
      crate::config::RuleCfg {
        env: "T".into(),
        value: Some(SecretString::from("value")),
        real: None,
        fnox_key: None,
        allow: entries.iter().map(|entry| (*entry).to_string()).collect(),
        pattern: None,
        registry: None,
        tls,
        if_missing: crate::config::IfMissing::default(),
      },
    );
    AppConfig {
      proxy: crate::config::ProxyCfg {
        listen: "127.0.0.1:8080".parse().unwrap(),
        ca_file: None,
        handshake_timeout_secs: 10,
      },
      workspace: crate::config::WorkspaceCfg::default(),
      rules,
      plugins: BTreeMap::new(),
      agents: BTreeMap::new(),
    }
  }

  #[test]
  fn uri_matching_covers_scheme_port_host() {
    let grant = endpoint_grant(&[
      "https://api.github.com",
      "https://*.githubusercontent.com",
      "tcp://10.0.0.8:5432",
      "https://*",
    ]);
    assert!(grant.matches(Scheme::Https, "api.github.com", 443));
    assert!(grant.matches(Scheme::Https, "API.GITHUB.COM", 443));
    assert!(!grant.matches(Scheme::Https, "api.github.com", 8443));
    assert!(!grant.matches(Scheme::Http, "api.github.com", 80));
    assert!(grant.matches(Scheme::Https, "x.githubusercontent.com", 443));
    // Apex matches here via the `https://*` entry; wildcard-apex exclusion
    // is covered by `wildcard_excludes_apex_but_matches_subdomains`.
    assert!(grant.matches(Scheme::Https, "githubusercontent.com", 443));
    assert!(grant.matches(Scheme::Tcp, "10.0.0.8", 5432));
    assert!(!grant.matches(Scheme::Tcp, "10.0.0.8", 5433));
    assert!(grant.matches(Scheme::Https, "anything.example", 443));
    assert!(!grant.matches(Scheme::Http, "anything.example", 80));
  }

  #[test]
  fn wildcard_excludes_apex_but_matches_subdomains() {
    let grant = endpoint_grant(&["https://*.example.com"]);
    assert!(!grant.matches(Scheme::Https, "example.com", 443));
    assert!(grant.matches(Scheme::Https, "a.example.com", 443));
    assert!(grant.matches(Scheme::Https, "A.EXAMPLE.COM", 443));
    assert!(
      grant.matches(Scheme::Https, "a.b.example.com", 443),
      "matches at any depth, e.g. api.v3.aave.com"
    );
    assert!(!grant.matches(Scheme::Https, "notexample.com", 443));
    assert!(!grant.matches(Scheme::Https, "example.com.evil.com", 443));
  }

  #[test]
  fn a_tcp_scope_is_not_an_https_scope() {
    // A tcp:// scope on a TLS port is not a TLS scope: the arm comes from the
    // scheme the config names.
    let grant = endpoint_grant(&["tcp://api.github.com:443"]);
    assert!(grant.endpoint(Scheme::Tcp, Some("api.github.com"), 443).is_some());
    assert!(grant.endpoint(Scheme::Https, Some("api.github.com"), 443).is_none());
    let grant = endpoint_grant(&["https://api.github.com"]);
    assert!(grant.endpoint(Scheme::Https, Some("api.github.com"), 443).is_some());
  }

  #[test]
  fn bad_entries_error() {
    "gopher://h".parse::<EndpointScope>().unwrap_err();
    "tcp://h".parse::<EndpointScope>().unwrap_err();
    "postgres://*:5432".parse::<EndpointScope>().unwrap_err();
    "https://".parse::<EndpointScope>().unwrap_err();
    "https://:443".parse::<EndpointScope>().unwrap_err();
    "https://h:abc".parse::<EndpointScope>().unwrap_err();
    "no-scheme".parse::<EndpointScope>().unwrap_err();
    "https://::1".parse::<EndpointScope>().unwrap_err();
    "https://::1:443".parse::<EndpointScope>().unwrap_err();
    "https://user@h".parse::<EndpointScope>().unwrap_err();
    "https://h/path".parse::<EndpointScope>().unwrap_err();
    "https://h?q=1".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432?sslmode=maybe".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432?sslnegotiation=maybe".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432?sslmode=verify-ca".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432?sslmode=verify-full".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432?sslmode=require&sslrootcert="
      .parse::<EndpointScope>()
      .unwrap_err();
    "https://h?sslnegotiation=direct".parse::<EndpointScope>().unwrap_err();
    "https://h?sslrootcert=/ca.pem".parse::<EndpointScope>().unwrap_err();
    "postgres://h:5432/a/b?sslmode=disable".parse::<EndpointScope>().unwrap_err();
    "https://h:443?sslcert=/c.pem&sslkey=/c.key".parse::<EndpointScope>().unwrap_err();
    "https://h?sslcert=/c.pem".parse::<EndpointScope>().unwrap_err();
    "https://h?sslkey=/c.key".parse::<EndpointScope>().unwrap_err();
    "https://h?sslcert=&sslkey=/c.key".parse::<EndpointScope>().unwrap_err();
    "tcp://h:443?sslcert=/c.pem&sslkey=/c.key".parse::<EndpointScope>().unwrap_err();
    "http://h?sslcert=/c.pem&sslkey=/c.key".parse::<EndpointScope>().unwrap_err();
  }

  #[test]
  fn client_identity_is_stated_by_the_real_string() {
    // libpq's own grammar carries the client identity on the real string —
    // the upstream leg's policy; endpoint URLs carry nothing of the kind.
    let pg = database_scope(
      "postgres://app:fake@db.internal:5432/main",
      "postgres://app:real@db.internal:5432/main?sslmode=require&sslcert=/c.pem&sslkey=/c.key",
    );
    assert_eq!(pg.client_cert, Some(PathBuf::from("/c.pem")));
    assert_eq!(pg.client_key, Some(PathBuf::from("/c.key")));
    let bare = endpoint_scope("https://api.internal");
    assert_eq!(bare.client_cert, None);
    assert_eq!(bare.client_key, None);
    assert_eq!(bare.guest_tls, GuestTlsMode::default());
  }

  #[test]
  fn rule_table_states_hodor_own_tls_configuration() {
    let mut tls = BTreeMap::new();
    tls.insert(
      "https://api.internal:443".to_string(),
      crate::config::HostTlsCfg {
        client_cert: Some(PathBuf::from("/c.pem")),
        client_key: Some(PathBuf::from("/c.key")),
        guest_tls_mode: GuestTlsMode::Mtls,
        guest_cert: Some(PathBuf::from("/in/cert.pem")),
        guest_key: Some(PathBuf::from("/in/key.pem")),
      },
    );
    let cfg = cfg_with_tls(&["https://api.internal:443"], tls);
    let resolved = resolve(&cfg).unwrap();
    let Grant::Token { allow, .. } = &resolved.grants[0] else {
      panic!("an endpoint rule");
    };
    assert_eq!(allow[0].client_cert, Some(PathBuf::from("/c.pem")));
    assert_eq!(allow[0].client_key, Some(PathBuf::from("/c.key")));
    assert_eq!(allow[0].guest_tls, GuestTlsMode::Mtls);
  }

  #[test]
  fn rule_table_for_a_database_rule_keys_by_its_env() {
    let mut cfg = cfg_with_db(
      "postgres://app:fake@db.internal:5432/main",
      "postgres://app:real@db.internal:5432/main?sslmode=require",
    );
    let entry = || crate::config::HostTlsCfg {
      client_cert: None,
      client_key: None,
      guest_tls_mode: GuestTlsMode::Mtls,
      guest_cert: Some(PathBuf::from("/in/cert.pem")),
      guest_key: Some(PathBuf::from("/in/key.pem")),
    };
    // A wrong key names nothing; the rule's env is the key.
    let mut tls = BTreeMap::new();
    tls.insert("PGPASSWORD".to_string(), entry());
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the rule's env is `DATABASE_URL`"), "{err}");
    // The table states the guest leg, never the upstream identity — libpq's
    // URL already owns that (`sslcert`/`sslkey`).
    let mut tls = BTreeMap::new();
    let mut e = entry();
    e.client_cert = Some(PathBuf::from("/c.pem"));
    e.client_key = Some(PathBuf::from("/c.key"));
    tls.insert("DATABASE_URL".to_string(), e);
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("never in the rule table"), "{err}");
    // Keyed correctly, the guest-leg mode lands on the scope.
    let mut tls = BTreeMap::new();
    tls.insert("DATABASE_URL".to_string(), entry());
    cfg.rules.get_mut("t").unwrap().tls = tls;
    let resolved = resolve(&cfg).unwrap();
    let Some(Grant::Database { scope, .. }) = resolved.grants.first() else {
      panic!("a database rule");
    };
    assert_eq!(scope.guest_tls, GuestTlsMode::Mtls);
  }

  #[test]
  fn rule_table_keys_must_name_allowed_entries() {
    let mut tls = BTreeMap::new();
    tls.insert(
      "https://other.internal:443".to_string(),
      crate::config::HostTlsCfg {
        client_cert: None,
        client_key: None,
        guest_tls_mode: GuestTlsMode::default(),
        guest_cert: None,
        guest_key: None,
      },
    );
    let cfg = cfg_with_tls(&["https://api.internal:443"], tls);
    assert!(resolve(&cfg).unwrap_err().to_string().contains("the rule does not allow"));
  }

  #[test]
  fn system_names_the_platform_trust_store() {
    let pg = database_scope(
      "postgres://app:fake@db.internal:5432/main",
      "postgres://app:real@h:5432?sslmode=verify-full&sslrootcert=system",
    );
    assert_eq!(pg.root_cert, Some(RootCert::System));
    let path = database_scope(
      "postgres://app:fake@db.internal:5432/main",
      "postgres://app:real@h:5432?sslmode=verify-full&sslrootcert=/ca.pem",
    );
    assert_eq!(path.root_cert, Some(RootCert::Path(PathBuf::from("/ca.pem"))));
  }

  #[test]
  fn bracketed_ipv6_matches_bare_ip() {
    let grant = endpoint_grant(&["tcp://[::1]:5432", "https://[2001:db8::1]"]);
    assert!(grant.matches(Scheme::Tcp, "::1", 5432));
    assert!(grant.matches(Scheme::Https, "2001:db8::1", 443));
  }

  #[test]
  fn scope_lookup_answers_by_scheme_and_by_port() {
    // A port-only lookup answers while the identity is still unknown, which is
    // all a transparent capture has to work with.
    let grant = endpoint_grant(&["https://api.github.com"]);
    assert!(grant.endpoint(Scheme::Https, Some("api.github.com"), 443).is_some());
    assert!(grant.endpoint(Scheme::Https, Some("api.github.com"), 80).is_none());
    assert!(grant.endpoint(Scheme::Https, Some("evil.example"), 443).is_none());
    assert!(grant.endpoint(Scheme::Https, None, 443).is_some());
  }

  #[test]
  fn a_database_rule_maps_two_connection_strings() {
    let scope = database_scope(
      "postgres://app:fake@fake.internal:5433/main",
      "postgres://app:real@db.internal:5432/main?sslmode=verify-full&sslrootcert=/ca.pem",
    );
    // The fake string states the guest's leg; its port is the match key.
    assert_eq!(scope.downstream.host, "fake.internal");
    assert_eq!(scope.downstream.port, 5433);
    assert_eq!(scope.downstream.user.as_deref(), Some("app"));
    assert_eq!(scope.downstream.password.expose_secret(), "fake");
    assert_eq!(scope.downstream.database.as_deref(), Some("main"));
    // The real string states the server's leg and the upstream policy.
    assert_eq!(scope.upstream.host, "db.internal");
    assert_eq!(scope.upstream.port, 5432);
    assert_eq!(scope.upstream.user.as_deref(), Some("app"));
    assert_eq!(scope.upstream.password.expose_secret(), "real");
    assert_eq!(scope.upstream.database.as_deref(), Some("main"));
    assert_eq!(scope.ssl, SslMode::VerifyFull);
    assert_eq!(scope.root_cert, Some(RootCert::Path(PathBuf::from("/ca.pem"))));
  }

  #[test]
  fn database_grant_answers_only_for_postgres() {
    let grant = database_grant(
      "postgres://app:fake@db.internal:5432/main",
      "postgres://app:real@db.internal:5432/main?sslmode=require",
    );
    assert!(grant.matches(Scheme::Postgres, "db.internal", 5432));
    assert!(!grant.matches(Scheme::Https, "db.internal", 5432));
    assert!(grant.database(Some("db.internal"), 5432).is_some());
    assert!(grant.database(None, 5432).is_some());
    assert!(grant.database(Some("db.internal"), 5433).is_none());
    // The wire needles are the two passwords: fake in, real out.
    let Grant::Database { credential, .. } = &grant else {
      panic!("a database grant");
    };
    assert_eq!(credential.fake, "fake");
    assert_eq!(credential.value.expose_secret(), "real");
  }

  #[test]
  fn the_kind_comes_from_the_stated_value() {
    let cfg = cfg_with_rule(&["https://api.github.com"]);
    let resolved = resolve(&cfg).unwrap();
    assert!(matches!(resolved.grants[0], Grant::Token { .. }));
    assert_eq!(resolved.grants[0].credential().label, "t");

    let cfg = cfg_with_db(
      "postgres://app:fake@db.internal:5432/main",
      "postgres://app:real@db.internal:5432/main?sslmode=disable",
    );
    let resolved = resolve(&cfg).unwrap();
    let Grant::Database { scope, .. } = &resolved.grants[0] else {
      panic!("database rule must resolve to a database grant");
    };
    // The real string states the upstream policy.
    assert_eq!(scope.ssl, SslMode::Disable);
    assert_eq!(scope.upstream.database.as_deref(), Some("main"));
  }

  #[test]
  fn a_database_rule_states_no_allow_entries() {
    let mut cfg = cfg_with_db(
      "postgres://app:fake@db.internal:5432/main",
      "postgres://app:real@db.internal:5432/main?sslmode=require",
    );
    cfg.rules.get_mut("t").unwrap().allow = vec!["https://api.github.com".to_string()];
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("no allow entries"), "{err}");
    assert!(err.contains("the connection string is the grant"), "{err}");
  }

  #[test]
  fn database_strings_need_their_credentials() {
    // Both strings carry a password: a string with no credential maps
    // nothing.
    let cfg = cfg_with_db("postgres://app@db.internal:5432/main", "postgres://app:real@db.internal:5432/main");
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the password is required"), "{err}");
    let cfg = cfg_with_db("postgres://app:fake@db.internal:5432/main", "postgres://app@db.internal:5432/main");
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("the password is required"), "{err}");
    // A schemed value that is not a connection string fails: the URL
    // mandate is enforced at parse. A bare token is a different kind of
    // rule, not a database rule at all.
    let cfg = cfg_with_db("postgres://app:fake@/main", "postgres://app:real@db.internal:5432/main");
    let err = resolve(&cfg).unwrap_err().to_string();
    assert!(err.contains("empty host"), "{err}");
    // Without the secret-source real string there is no grant at all.
    let mut cfg = cfg_with_db(
      "postgres://app:fake@db.internal:5432/main",
      "postgres://app:real@db.internal:5432/main",
    );
    cfg.rules.get_mut("t").unwrap().real = None;
    let resolved = resolve(&cfg).unwrap();
    assert!(resolved.grants.is_empty());
  }
}
