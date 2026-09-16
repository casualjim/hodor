//! URI grants: `scheme://host[:port]` allow entries + matching.

use std::str::FromStr;

use secrecy::SecretString;

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

/// Grant scheme: plain HTTP, TLS HTTP, or raw TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
  /// Plain HTTP.
  Http,
  /// TLS HTTP.
  Https,
  /// Raw TCP.
  Tcp,
}

/// One parsed `allow` entry: scheme + host pattern + port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriGrant {
  /// Entry scheme.
  pub scheme: Scheme,
  /// Entry host pattern.
  pub host: HostPat,
  /// Entry port.
  pub port: u16,
}

/// Parse one `allow` entry: `scheme://host[:port]`. Default ports http 80,
/// https 443; `tcp` requires an explicit port.
///
/// Structure comes from the `url` crate; only the `*` patterns are handled
/// here (`*` is not a valid URL host, so a placeholder is parsed and the
/// pattern restored after). Paths, queries, and userinfo are rejected:
/// entries are authority-only.
impl FromStr for UriGrant {
  type Err = String;

  fn from_str(entry: &str) -> Result<Self, Self::Err> {
    let (scheme_raw, rest) = entry.split_once("://").ok_or_else(|| "missing `://`".to_string())?;
    let scheme = match scheme_raw.to_ascii_lowercase().as_str() {
      "http" => Scheme::Http,
      "https" => Scheme::Https,
      "tcp" => Scheme::Tcp,
      other => return Err(format!("unknown scheme `{other}`")),
    };
    if rest.contains(['/', '?', '#', '@']) {
      return Err("allow entries are authority-only (no path, query, or userinfo)".to_string());
    }
    // `*` never survives URL parsing: swap the leading star for a placeholder
    // (same length, so `:port` suffix math on `rest` still holds).
    let probe = match rest.strip_prefix('*') {
      Some(tail) => format!("w{tail}"),
      None => rest.to_string(),
    };
    let url = url::Url::parse(&format!("{scheme_raw}://{probe}")).map_err(|err| format!("bad allow entry `{entry}`: {err}"))?;
    let port = match (url.port(), scheme) {
      (Some(port), _) => port,
      (None, Scheme::Http) => 80,
      (None, Scheme::Https) => 443,
      (None, Scheme::Tcp) => return Err("tcp grant requires an explicit port".to_string()),
    };
    if rest.starts_with('*') {
      // Original host is `*` or `*.suffix`, each optionally followed by the
      // explicit `:port` already validated above.
      let host_raw = match url.port() {
        Some(port) => rest
          .strip_suffix(&format!(":{port}"))
          .ok_or_else(|| format!("bad allow entry `{entry}`"))?,
        None => rest,
      };
      if host_raw == "*" {
        return Ok(UriGrant {
          scheme,
          host: HostPat::Any,
          port,
        });
      }
      if let Some(suffix) = host_raw.strip_prefix("*.") {
        if suffix.is_empty() {
          return Err(format!("bad allow entry `{entry}`: empty wildcard suffix"));
        }
        return Ok(UriGrant {
          scheme,
          host: HostPat::Wildcard(format!("*.{suffix}")),
          port,
        });
      }
      return Err(format!("bad allow entry `{entry}`: `*` only leads `*` or `*.suffix`"));
    }
    // `host_str` keeps IPv6 brackets; the `Host` enum normalizes to bare form.
    let host = match url.host() {
      Some(url::Host::Domain(domain)) => domain.to_string(),
      Some(url::Host::Ipv4(addr)) => addr.to_string(),
      Some(url::Host::Ipv6(addr)) => addr.to_string(),
      None => return Err(format!("bad allow entry `{entry}`: empty host")),
    };
    let host = HostPat::Exact(host);
    Ok(UriGrant { scheme, host, port })
  }
}

/// One secret plus its allow list: the unit of grant matching.
#[derive(Debug, Clone)]
pub struct Grant {
  /// Secret label (log identifier, never the value).
  pub label: String,
  /// Deterministic format-valid decoy presented to clients.
  pub fake: String,
  /// Real secret value swapped upstream.
  pub value: SecretString,
  /// Parsed allow entries.
  pub allow: Vec<UriGrant>,
}

impl Grant {
  /// Grant-level match for a concrete request: scheme + port + host.
  pub fn matches(&self, scheme: Scheme, host: &str, port: u16) -> bool {
    uri_match(&self.allow, scheme, host, port)
  }
}

/// Resolved proxy config: listener settings plus parsed grants.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
  /// Proxy listener settings.
  pub proxy: crate::config::ProxyCfg,
  /// Parsed per-secret grants.
  pub grants: Vec<Grant>,
}

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

/// Scheme + port + host all match.
pub fn uri_match(allow: &[UriGrant], scheme: Scheme, host: &str, port: u16) -> bool {
  allow
    .iter()
    .any(|grant| grant.scheme == scheme && grant.port == port && grant.host.matches(host))
}

/// Pre-TLS gate: host + port match with scheme ignored. Only candidate
/// connections are MITM'd; everything else splices passthrough.
pub fn intercept_candidate(grants: &[Grant], host: &str, port: u16) -> bool {
  grants
    .iter()
    .any(|grant| grant.allow.iter().any(|entry| entry.port == port && entry.host.matches(host)))
}

/// Scheme-aware TLS eligibility: at least one grant matches `https://host:port`.
/// The pre-TLS gate is scheme-blind, so a `tcp://host:443` grant alone must not
/// trigger TLS termination — MITM without substitution breaks byte-identity.
pub fn https_eligible(grants: &[Grant], host: &str, port: u16) -> bool {
  grants.iter().any(|grant| grant.matches(Scheme::Https, host, port))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn grants_for(entries: &[&str]) -> Vec<Grant> {
    vec![Grant {
      label: "t".into(),
      fake: "fake".into(),
      value: SecretString::from("value"),
      allow: entries.iter().map(|e| e.parse().unwrap()).collect(),
    }]
  }

  #[test]
  fn uri_matching_covers_scheme_port_host() {
    let grants = grants_for(&[
      "https://api.github.com",
      "https://*.githubusercontent.com",
      "tcp://10.0.0.8:5432",
      "https://*",
    ]);
    let allow = &grants[0].allow;
    assert!(uri_match(allow, Scheme::Https, "api.github.com", 443));
    assert!(uri_match(allow, Scheme::Https, "API.GITHUB.COM", 443));
    assert!(!uri_match(allow, Scheme::Https, "api.github.com", 8443));
    assert!(!uri_match(allow, Scheme::Http, "api.github.com", 80));
    assert!(uri_match(allow, Scheme::Https, "x.githubusercontent.com", 443));
    // Apex matches here via the `https://*` entry; wildcard-apex exclusion
    // is covered by `wildcard_excludes_apex_but_matches_subdomains`.
    assert!(uri_match(allow, Scheme::Https, "githubusercontent.com", 443));
    assert!(uri_match(allow, Scheme::Tcp, "10.0.0.8", 5432));
    assert!(!uri_match(allow, Scheme::Tcp, "10.0.0.8", 5433));
    assert!(uri_match(allow, Scheme::Https, "anything.example", 443));
    assert!(!uri_match(allow, Scheme::Http, "anything.example", 80));
  }

  #[test]
  fn wildcard_excludes_apex_but_matches_subdomains() {
    let grants = grants_for(&["https://*.example.com"]);
    let allow = &grants[0].allow;
    assert!(!uri_match(allow, Scheme::Https, "example.com", 443));
    assert!(uri_match(allow, Scheme::Https, "a.example.com", 443));
    assert!(uri_match(allow, Scheme::Https, "A.EXAMPLE.COM", 443));
    assert!(
      uri_match(allow, Scheme::Https, "a.b.example.com", 443),
      "matches at any depth, e.g. api.v3.aave.com"
    );
    assert!(!uri_match(allow, Scheme::Https, "notexample.com", 443));
    assert!(!uri_match(allow, Scheme::Https, "example.com.evil.com", 443));
  }

  #[test]
  fn https_eligible_rejects_tcp_only_grants() {
    let grants = grants_for(&["tcp://api.github.com:443"]);
    assert!(intercept_candidate(&grants, "api.github.com", 443));
    assert!(!https_eligible(&grants, "api.github.com", 443));
    let grants = grants_for(&["https://api.github.com"]);
    assert!(https_eligible(&grants, "api.github.com", 443));
  }

  #[test]
  fn bad_entries_error() {
    "gopher://h".parse::<UriGrant>().unwrap_err();
    "tcp://h".parse::<UriGrant>().unwrap_err();
    "https://".parse::<UriGrant>().unwrap_err();
    "https://:443".parse::<UriGrant>().unwrap_err();
    "https://h:abc".parse::<UriGrant>().unwrap_err();
    "no-scheme".parse::<UriGrant>().unwrap_err();
    "https://::1".parse::<UriGrant>().unwrap_err();
    "https://::1:443".parse::<UriGrant>().unwrap_err();
    "https://user@h".parse::<UriGrant>().unwrap_err();
    "https://h/path".parse::<UriGrant>().unwrap_err();
    "https://h?q=1".parse::<UriGrant>().unwrap_err();
  }

  #[test]
  fn bracketed_ipv6_matches_bare_ip() {
    let grants = grants_for(&["tcp://[::1]:5432", "https://[2001:db8::1]"]);
    let allow = &grants[0].allow;
    assert!(uri_match(allow, Scheme::Tcp, "::1", 5432));
    assert!(uri_match(allow, Scheme::Https, "2001:db8::1", 443));
  }

  #[test]
  fn intercept_candidate_ignores_scheme() {
    let grants = grants_for(&["https://api.github.com"]);
    assert!(intercept_candidate(&grants, "api.github.com", 443));
    assert!(!intercept_candidate(&grants, "api.github.com", 80));
    assert!(!intercept_candidate(&grants, "evil.example", 443));
  }
}
