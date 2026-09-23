//! What the config says a destination is, and how the peer names itself.
//!
//! The grant scopes covering a destination name the protocol, so the arm that
//! serves a connection comes from the config and never from the shape of its
//! bytes. Identity, the hostname those scopes are matched against, is read
//! from the opening bytes of the protocol the config named, because a
//! transparent capture destination is an IP.

use hodor_config::grants::{DatabaseScope, Grant, Scheme};
use rama::tls::client::{ClientHello, ClientHelloHandshakePrefix, parse_client_hello_handshake_prefix};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use std::time::Duration;

/// Hard cap for a single `ClientHello` (RFC 8446 §5.1: a record payload is at
/// most 2^14 bytes, plus the 5-byte record header).
const MAX_HELLO: usize = 16 * 1024 + 5;

/// How a destination is served, from the grant scopes that cover it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Expect<'a> {
  /// An `https://` scope: terminate TLS, then read the h1/h2 framing.
  Tls,
  /// An `http://` scope: a plaintext request head.
  Plain,
  /// A `tcp://` scope: opaque bytes, equal-length substitution, nothing read.
  Raw,
  /// A `postgres://` scope: pgwire framing, over whatever transport the entry
  /// states for the far side and the guest asks for on this side.
  Postgres(&'a DatabaseScope),
  /// No scope covers the destination: copy bytes unchanged.
  Splice,
}

/// Resolve the arm for a destination. `host` is the identity when the ingress
/// already knows it (a CONNECT authority), and None when only the captured
/// port is known (transparent capture), where identity is read afterwards and
/// the port alone shortlists the scopes.
///
/// One port carrying several protocol families is ambiguous without reading
/// bytes. The order below is the tie-break, and an arm whose framing does not
/// arrive closes rather than guessing a different one.
/// Unit arms compare by kind; a Postgres arm equals only itself — its scope
/// carries secrets, so there is no value comparison to build on.
impl PartialEq for Expect<'_> {
  fn eq(&self, other: &Self) -> bool {
    match (self, other) {
      (Expect::Postgres(a), Expect::Postgres(b)) => std::ptr::eq(*a, *b),
      (Expect::Tls, Expect::Tls) | (Expect::Plain, Expect::Plain) | (Expect::Raw, Expect::Raw) | (Expect::Splice, Expect::Splice) => true,
      _ => false,
    }
  }
}

impl Eq for Expect<'_> {}

#[must_use]
pub(crate) fn expect<'a>(grants: &'a [Grant], host: Option<&str>, port: u16) -> Expect<'a> {
  if let Some(scope) = grants.iter().find_map(|grant| grant.database(host, port)) {
    return Expect::Postgres(scope);
  }
  for (scheme, arm) in [
    (Scheme::Https, Expect::Tls),
    (Scheme::Http, Expect::Plain),
    (Scheme::Tcp, Expect::Raw),
  ] {
    if grants.iter().any(|grant| grant.endpoint(scheme, host, port).is_some()) {
      return arm;
    }
  }
  Expect::Splice
}

/// A complete TLS `ClientHello`, with the SNI when it carries one.
pub(crate) enum Hello {
  /// Complete hello naming its host.
  Named {
    /// Every byte read so far, replayed into the relay.
    buf: Vec<u8>,
    /// The server name the hello names.
    sni: String,
    /// The parsed hello, handed to the TLS terminator.
    hello: ClientHello,
  },
  /// A hello that yields no SNI. The ingress authority, when there is one, is
  /// the only identity available.
  Unnamed {
    /// Every byte read so far, replayed into the relay.
    buf: Vec<u8>,
  },
}

/// Read until a `ClientHello` completes. None when the bytes are not TLS, or
/// the hello never completes inside the pre-auth budget and the size cap.
///
/// # Errors
///
/// Returns an error when the guest stream fails to read.
pub(crate) async fn read_client_hello<G: AsyncRead + Unpin>(
  guest: &mut G,
  initial: &[u8],
  budget: Duration,
) -> eyre::Result<Option<Hello>> {
  let mut buf = initial.to_vec();
  let mut chunk = [0u8; 4096];
  // Total pre-auth budget: per-read timeouts re-arm, so a dripping client
  // could otherwise hold this task indefinitely one byte at a time.
  let deadline = tokio::time::Instant::now() + budget;
  loop {
    // SNI first: a hello completing exactly at the size cutoff still counts.
    if let Some((sni, hello)) = hello_sni(&buf) {
      return Ok(Some(Hello::Named { buf, sni, hello }));
    }
    let over_cap = buf.len() > MAX_HELLO;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if over_cap || remaining.is_zero() {
      // Bytes that opened as a TLS record but never completed: no SNI to
      // name the peer with, so the caller falls back to its authority.
      return Ok(buf.first().is_some_and(|byte| *byte == 0x16).then_some(Hello::Unnamed { buf }));
    }
    let read = tokio::time::timeout(remaining, guest.read(&mut chunk)).await;
    let Ok(n) = read else {
      return Ok(buf.first().is_some_and(|byte| *byte == 0x16).then_some(Hello::Unnamed { buf }));
    };
    let n = n?;
    if n == 0 {
      return Ok(buf.first().is_some_and(|byte| *byte == 0x16).then_some(Hello::Unnamed { buf }));
    }
    buf.extend_from_slice(&chunk[..n]);
    if buf.first() != Some(&0x16) {
      // Not a TLS record, so no ClientHello is coming.
      return Ok(None);
    }
  }
}

/// Read until the HTTP request head completes, and take the identity from its
/// `Host` field. None when no complete head arrives inside the pre-auth budget
/// and the head cap.
///
/// # Errors
///
/// Returns an error when the guest stream fails to read.
pub(crate) async fn read_http_head<G: AsyncRead + Unpin>(
  guest: &mut G,
  initial: &[u8],
  budget: Duration,
  default_port: u16,
) -> eyre::Result<Option<(Vec<u8>, String, u16)>> {
  let mut buf = initial.to_vec();
  let mut chunk = [0u8; 4096];
  let deadline = tokio::time::Instant::now() + budget;
  loop {
    if let Some((host, port)) = http_head_host(&buf, default_port) {
      return Ok(Some((buf, host, port)));
    }
    let over_cap = buf.len() > super::protocol::MAX_HEAD;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if over_cap || remaining.is_zero() {
      return Ok(None);
    }
    let read = tokio::time::timeout(remaining, guest.read(&mut chunk)).await;
    let Ok(n) = read else { return Ok(None) };
    let n = n?;
    if n == 0 {
      return Ok(None);
    }
    buf.extend_from_slice(&chunk[..n]);
  }
}

/// SNI plus hello of a complete `ClientHello` in `buf`, via rama's parser.
/// None while the hello is still incomplete, invalid, or carries no SNI, so
/// the caller keeps accumulating.
pub(crate) fn hello_sni(buf: &[u8]) -> Option<(String, ClientHello)> {
  match parse_client_hello_handshake_prefix(buf) {
    ClientHelloHandshakePrefix::Complete(hello) => {
      let sni = hello.ext_server_name().map(ToString::to_string)?;
      Some((sni, hello))
    }
    _ => None,
  }
}

/// Host header of a complete HTTP request head, port-defaulted to the dialed
/// port. None when the buffer is not a complete request head or the header is
/// missing or unparseable.
pub(crate) fn http_head_host(buf: &[u8], default_port: u16) -> Option<(String, u16)> {
  let mut headers = [httparse::EMPTY_HEADER; 32];
  let mut req = httparse::Request::new(&mut headers);
  if req.parse(buf).ok()? != httparse::Status::Complete(head_len(buf)?) {
    return None;
  }
  let host = req.headers.iter().find(|header| header.name.eq_ignore_ascii_case("host"))?;
  let value = std::str::from_utf8(host.value).ok()?;
  super::parse_authority(value, Some(default_port))
}

/// Offset just past the head boundary, when the buffer holds one.
fn head_len(head: &[u8]) -> Option<usize> {
  head.windows(4).position(|w| w == b"\r\n\r\n").map(|pos| pos + 4)
}

/// On-demand issuance burst guard: at most this many fresh MITM relays per
/// window. Bounds remote-triggered issuance (Any-host grants, SNI rotation).
const MINT_BURST: usize = 20;
const MINT_WINDOW_SECS: u64 = 10;

#[derive(Debug)]
pub(crate) struct MintBucket {
  mints: std::sync::Mutex<std::collections::VecDeque<std::time::Instant>>,
}

impl MintBucket {
  #[must_use]
  pub(crate) fn new() -> Self {
    Self {
      mints: std::sync::Mutex::new(std::collections::VecDeque::new()),
    }
  }

  pub(crate) fn allow(&self) -> bool {
    let mut mints = self.mints.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    // `None` means the monotonic clock has not yet run for a full window
    // (uptime under `MINT_WINDOW_SECS`), so no recorded relay can be older
    // than the cutoff and there is nothing to evict.
    if let Some(cutoff) = std::time::Instant::now().checked_sub(std::time::Duration::from_secs(MINT_WINDOW_SECS)) {
      while mints.front().is_some_and(|at| *at < cutoff) {
        mints.pop_front();
      }
    }
    mints.len() < MINT_BURST
  }

  pub(crate) fn record(&self) {
    let mut mints = self.mints.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    mints.push_back(std::time::Instant::now());
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use hodor_config::grants::{Credential, SslMode};
  use secrecy::SecretString;

  fn token_grant(entries: &[&str]) -> Vec<Grant> {
    vec![Grant::Token {
      credential: Credential {
        label: "t".into(),
        fake: "fake".into(),
        value: SecretString::from("value"),
      },
      allow: entries.iter().map(|entry| entry.parse().unwrap()).collect(),
    }]
  }

  fn database_grant(port: u16, ssl: SslMode) -> Vec<Grant> {
    vec![Grant::Database {
      credential: Credential {
        label: "pg".into(),
        fake: "fake".into(),
        value: SecretString::from("value"),
      },
      scope: Box::new(DatabaseScope {
        downstream: hodor_config::grants::DbLeg {
          host: "db.internal".to_string(),
          port,
          user: None,
          password: SecretString::from("fake"),
          database: None,
        },
        upstream: hodor_config::grants::DbLeg {
          host: "db.internal".to_string(),
          port,
          user: None,
          password: SecretString::from("value"),
          database: None,
        },
        ssl,
        negotiation: hodor_config::grants::SslNegotiation::Postgres,
        root_cert: None,
        client_cert: None,
        client_key: None,
        guest_tls: hodor_config::grants::GuestTlsMode::default(),
      }),
    }]
  }

  #[test]
  fn the_scope_scheme_names_the_arm() {
    // A tcp:// scope on a TLS port is not a TLS scope, and no byte decides
    // this: the config does.
    let grants = token_grant(&["tcp://api.github.com:443"]);
    assert_eq!(expect(&grants, Some("api.github.com"), 443), Expect::Raw);
    let grants = token_grant(&["https://api.github.com"]);
    assert_eq!(expect(&grants, Some("api.github.com"), 443), Expect::Tls);
    let grants = token_grant(&["http://api.github.com"]);
    assert_eq!(expect(&grants, Some("api.github.com"), 80), Expect::Plain);
  }

  #[test]
  fn an_uncovered_destination_splices_and_a_bare_port_shortlists() {
    let grants = token_grant(&["https://api.github.com"]);
    assert_eq!(expect(&grants, Some("elsewhere.example"), 443), Expect::Splice);
    // Transparent capture knows the port before it knows the host, so the arm
    // resolves with None and the identity is read afterwards.
    assert_eq!(expect(&grants, None, 443), Expect::Tls);
    assert_eq!(expect(&grants, None, 8443), Expect::Splice);
  }

  #[test]
  fn a_database_scope_carries_its_sslmode() {
    let grants = database_grant(5432, SslMode::Require);
    let Expect::Postgres(scope) = expect(&grants, Some("db.internal"), 5432) else {
      panic!("a database scope resolves to the postgres arm")
    };
    assert_eq!(scope.ssl, SslMode::Require);
    // Port alone is enough on the transparent path: no startup bytes are
    // inspected to reach this answer, and the entry that comes back is the
    // same one, so its sslmode and trust anchor travel with it.
    assert!(matches!(expect(&grants, None, 5432), Expect::Postgres(other) if std::ptr::eq(other, scope)));
  }
}
