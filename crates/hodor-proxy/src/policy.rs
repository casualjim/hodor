//! Pre-TLS policy: peek TLS vs plain, then route MITM / splice / machines.

use hodor_config::grants::{ResolvedConfig, Scheme, https_eligible, intercept_candidate};
use rama::tls::client::{ClientHello, ClientHelloHandshakePrefix, parse_client_hello_handshake_prefix};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use super::HANDSHAKE_TIMEOUT_SECS;

/// Hard cap for a single `ClientHello` (RFC 8446 §5.1: a record payload is at
/// most 2^14 bytes, plus the 5-byte record header).
const MAX_HELLO: usize = 16 * 1024 + 5;

pub(crate) enum Peeked {
  Tls { buf: Vec<u8>, sni: String, hello: ClientHello },
  TlsNoSni { buf: Vec<u8> },
  RawTcp { buf: Vec<u8> },
}

/// Buffer until a `ClientHello` with SNI arrives, or non-TLS bytes prove a
/// plain TCP stream. None on EOF/stall with no bytes, or oversize non-TLS.
/// TLS bytes that stall without yielding SNI come back as `TlsNoSni` so the
/// caller can MITM with the known authority (CONNECT) or splice (TUN).
///
/// # Errors
///
/// Returns an error when the guest stream fails to read.
pub(crate) async fn peek_stream<G: AsyncRead + Unpin>(guest: &mut G, initial: &[u8]) -> eyre::Result<Option<Peeked>> {
  let mut buf = initial.to_vec();
  let mut chunk = [0u8; 4096];
  // Total pre-auth budget: per-read timeouts re-arm, so a dripping client
  // could otherwise hold this task indefinitely one byte at a time.
  let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
  loop {
    // SNI first: a hello completing exactly at the size cutoff still counts.
    if let Some((sni, hello)) = hello_sni(&buf) {
      return Ok(Some(Peeked::Tls { buf, sni, hello }));
    }
    if buf.len() > MAX_HELLO {
      if buf.first() == Some(&0x16) {
        return Ok(Some(Peeked::TlsNoSni { buf }));
      }
      return Ok(None);
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
      if buf.first() == Some(&0x16) && !buf.is_empty() {
        return Ok(Some(Peeked::TlsNoSni { buf }));
      }
      return Ok(None);
    }
    let read = tokio::time::timeout(remaining, guest.read(&mut chunk)).await;
    let Ok(n) = read else {
      if buf.first() == Some(&0x16) && !buf.is_empty() {
        return Ok(Some(Peeked::TlsNoSni { buf }));
      }
      return Ok(None);
    };
    let n = n?;
    if n == 0 {
      if buf.first() == Some(&0x16) && !buf.is_empty() {
        return Ok(Some(Peeked::TlsNoSni { buf }));
      }
      return Ok(None);
    }
    buf.extend_from_slice(&chunk[..n]);
    if buf.first() != Some(&0x16) {
      return Ok(Some(Peeked::RawTcp { buf }));
    }
  }
}

/// SNI plus hello of a complete `ClientHello` in `buf`, via rama's parser.
/// None while the hello is still incomplete, invalid, or carries no SNI, so
/// the caller keeps accumulating.
fn hello_sni(buf: &[u8]) -> Option<(String, ClientHello)> {
  match parse_client_hello_handshake_prefix(buf) {
    ClientHelloHandshakePrefix::Complete(hello) => {
      let sni = hello.ext_server_name().map(ToString::to_string)?;
      Some((sni, hello))
    }
    _ => None,
  }
}

/// Routing decision for a peeked stream. `buf` is the replay prefix the arm
/// replays before pumping.
pub(crate) enum Route {
  /// Terminate TLS as `identity`, relay through substitution machines.
  /// `hello` is None on the CONNECT-without-SNI arm: the relay serves the
  /// bare bridge and derives egress identity from the connector target.
  MitmTls {
    identity: String,
    buf: Vec<u8>,
    hello: Option<ClientHello>,
  },
  Splice {
    buf: Vec<u8>,
  },
  RawTcpMachines {
    buf: Vec<u8>,
  },
  PlainHttpMachines {
    host: String,
    port: u16,
    buf: Vec<u8>,
  },
}

/// Pure arm table for a peeked stream. `enforce_host`: SNI must equal it
/// (CONNECT authority); None → the SNI itself is the identity (transparent).
/// None means close quietly (SNI mismatch, or nothing to serve).
#[must_use]
pub(crate) fn decide(snapshot: &ResolvedConfig, port: u16, enforce_host: Option<&str>, peeked: Peeked) -> Option<Route> {
  match peeked {
    Peeked::RawTcp { buf } => {
      // Transparent plain HTTP: the Host header is the http:// grant
      // identity (capture destination is an IP, no hostname). Non-HTTP bytes
      // stay on tcp:// raw machines.
      if let Some((host, hport)) = http_head_host(&buf, port)
        && snapshot.grants.iter().any(|grant| grant.matches(Scheme::Http, &host, hport))
      {
        Some(Route::PlainHttpMachines { host, port: hport, buf })
      } else {
        Some(Route::RawTcpMachines { buf })
      }
    }
    Peeked::Tls { buf, sni, hello } => {
      if let Some(authority) = enforce_host
        && !sni.eq_ignore_ascii_case(authority)
      {
        tracing::debug!(authority, sni, "CONNECT authority differs from SNI; closing");
        return None;
      }
      let identity = enforce_host.unwrap_or(&sni).to_string();
      if !intercept_candidate(&snapshot.grants, &identity, port) || !https_eligible(&snapshot.grants, &identity, port) {
        // No grant match, or only a non-HTTPS (e.g. tcp://) grant on this
        // port: splice the raw bytes instead of terminating TLS with no
        // substitution to perform.
        return Some(Route::Splice { buf });
      }
      Some(Route::MitmTls {
        identity,
        buf,
        hello: Some(hello),
      })
    }
    Peeked::TlsNoSni { buf } => {
      // No SNI: CONNECT path still knows the authority, so MITM with it;
      // transparent path has no identity to mint for, so splice with replay.
      if let Some(authority) = enforce_host {
        if !intercept_candidate(&snapshot.grants, authority, port) || !https_eligible(&snapshot.grants, authority, port) {
          return Some(Route::Splice { buf });
        }
        return Some(Route::MitmTls {
          identity: authority.to_string(),
          buf,
          hello: None,
        });
      }
      Some(Route::Splice { buf })
    }
  }
}

/// Host header of a complete HTTP request head, port-defaulted to the
/// dialed port. None when the buffer is not a complete request head or the
/// header is missing/unparseable.
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
