//! Explicit proxy core: CONNECT splice, TLS intercept relay.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::ca::{CertAuthority, CertCache, DomainCert};
use crate::grants::{Grant, HostPat, ResolvedConfig, Scheme, https_eligible, intercept_candidate};
use crate::sni::{MAX_HELLO, extract_sni};
use crate::substitute::{AnyMachine, Direction, H2_PREFACE, H2Machine, SecretsMachine, SubMachine};
use eyre::Context as _;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_HEAD: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Shared proxy state: live config snapshot, CA, and leaf-cert cache.
///
/// Config is write-once (no reload path), so a plain `Arc` — no lock, no
/// swap. The cert cache is a lock-free map; key generation stays on the
/// caller, never under a lock, so connections never block each other on it.
pub struct ProxyState {
  config: Arc<ResolvedConfig>,
  ca: Arc<CertAuthority>,
  certs: CertCache,
  connector: TlsConnector,
  fwmark: Option<u32>,
}

impl ProxyState {
  /// Build state from resolved config and the CA. Leaf certs for exact
  /// grant hosts — plus one wildcard leaf per `*.`-grant — are generated
  /// up front, so steady-state connections never pay keygen. `Any` hosts
  /// are unbounded and stay on on-demand generation.
  pub fn new(resolved: ResolvedConfig, ca: CertAuthority) -> Self {
    let connector = ca.connector();
    let ca = Arc::new(ca);
    let certs = CertCache::new();
    for host in exact_hosts(&resolved.grants) {
      match ca.generate_domain_cert(host) {
        Ok(fresh) => certs.insert(host, Arc::new(fresh)),
        Err(err) => tracing::warn!(%host, "pre-generated leaf failed, on-demand fallback: {err}"),
      }
    }
    for pattern in wildcard_hosts(&resolved.grants) {
      match ca.generate_domain_cert(pattern) {
        Ok(fresh) => certs.insert(pattern, Arc::new(fresh)),
        Err(err) => tracing::warn!(%pattern, "pre-generated wildcard leaf failed, on-demand fallback: {err}"),
      }
    }
    Self {
      config: Arc::new(resolved),
      ca,
      certs,
      connector,
      fwmark: None,
    }
  }

  #[cfg(feature = "tun")]
  /// Mark upstream sockets so TUN policy routing bypasses capture.
  pub fn with_fwmark(mut self, mark: u32) -> Self {
    self.fwmark = Some(mark);
    self
  }

  /// Load the current config snapshot.
  pub fn snapshot(&self) -> Arc<ResolvedConfig> {
    Arc::clone(&self.config)
  }
  #[cfg(feature = "tun")]
  /// `SO_MARK` for upstream sockets (`None` = unmarked).
  pub fn fwmark(&self) -> Option<u32> {
    self.fwmark
  }

  /// Leaf cert for `domain`: exact hit first, then the wildcard leaf when a
  /// `*.`-grant covers it, else mint per-domain (`Any` hosts land here).
  /// Expired entries rotate lazily via the cache. Concurrent misses for one
  /// domain may generate twice; last store wins, both valid.
  pub async fn leaf_cert(&self, domain: &str) -> eyre::Result<Arc<DomainCert>> {
    if let Some(hit) = self.certs.get(domain) {
      return Ok(hit);
    }
    if let Some(pattern) = wildcard_covering(&self.config.grants, domain) {
      if let Some(hit) = self.certs.get(&pattern) {
        return Ok(hit);
      }
      if !self.certs.mint_allowed() {
        eyre::bail!("leaf mint rate limit exceeded for {pattern}");
      }
      let ca = Arc::clone(&self.ca);
      let pattern_owned = pattern.clone();
      let joined = tokio::task::spawn_blocking({
        let pattern = pattern_owned.clone();
        move || ca.generate_domain_cert(&pattern)
      })
      .await
      .map_err(|err| eyre::eyre!("leaf mint task: {err}"))?;
      let fresh = Arc::new(joined?);
      self.certs.insert_minted(&pattern_owned, Arc::clone(&fresh));
      return Ok(fresh);
    }
    if !self.certs.mint_allowed() {
      eyre::bail!("leaf mint rate limit exceeded for {domain}");
    }
    let ca = Arc::clone(&self.ca);
    let domain_owned = domain.to_string();
    let joined = tokio::task::spawn_blocking({
      let domain = domain_owned.clone();
      move || ca.generate_domain_cert(&domain)
    })
    .await
    .map_err(|err| eyre::eyre!("leaf mint task: {err}"))?;
    let fresh = Arc::new(joined?);
    self.certs.insert_minted(&domain_owned, Arc::clone(&fresh));
    Ok(fresh)
  }
}

/// Exact hostnames across all grants, deduplicated. `Any` hosts stay on
/// on-demand generation; wildcards are covered by [`wildcard_hosts`].
fn exact_hosts(grants: &[Grant]) -> Vec<&str> {
  let mut hosts: Vec<&str> = grants
    .iter()
    .flat_map(|grant| grant.allow.iter())
    .filter_map(|uri| match &uri.host {
      HostPat::Exact(host) => Some(host.as_str()),
      _ => None,
    })
    .collect();
  hosts.sort_unstable();
  hosts.dedup();
  hosts
}

/// Deduplicated `*.`-patterns across all grants (e.g. `*.example.com`).
/// One leaf per pattern covers every subdomain, so wildcard subdomains
/// never pay per-host keygen.
fn wildcard_hosts(grants: &[Grant]) -> Vec<&str> {
  let mut hosts: Vec<&str> = grants
    .iter()
    .flat_map(|grant| grant.allow.iter())
    .filter_map(|uri| match &uri.host {
      HostPat::Wildcard(pattern) => Some(pattern.as_str()),
      _ => None,
    })
    .collect();
  hosts.sort_unstable();
  hosts.dedup();
  hosts
}

/// First `*.`-pattern covering `domain`, if any. Grant order wins on
/// overlap; grants derive from a `BTreeMap`, so the order is deterministic.
fn wildcard_covering(grants: &[Grant], domain: &str) -> Option<String> {
  grants.iter().flat_map(|grant| grant.allow.iter()).find_map(|uri| match &uri.host {
    HostPat::Wildcard(pattern) if uri.host.matches(domain) => Some(pattern.clone()),
    _ => None,
  })
}

/// Accept connections forever; returns only when the listener fails.
pub async fn serve(listener: TcpListener, state: Arc<ProxyState>) -> eyre::Result<()> {
  loop {
    let (stream, peer) = listener.accept().await?;
    let state = Arc::clone(&state);
    tokio::spawn(async move {
      if let Err(err) = handle_conn(stream, &state).await {
        tracing::debug!(%peer, ?err, "connection failed");
      }
    });
  }
}

async fn handle_conn(mut client: TcpStream, state: &ProxyState) -> eyre::Result<()> {
  let snapshot = state.snapshot();
  let head = read_head(&mut client).await?;
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut req = httparse::Request::new(&mut headers);
  let parsed = req.parse(&head)?;
  if !parsed.is_complete() {
    return Ok(()); // over cap without a full head: close, no response
  }
  let (Some(method), Some(target)) = (req.method, req.path) else {
    return Ok(()); // malformed request line: close, no response
  };
  if method.eq_ignore_ascii_case("connect") {
    handle_connect(client, target, state, &snapshot, &head).await
  } else {
    handle_forward(client, &head, target, state, &snapshot).await
  }
}

async fn handle_connect(
  mut client: TcpStream,
  target: &str,
  state: &ProxyState,
  snapshot: &ResolvedConfig,
  head: &[u8],
) -> eyre::Result<()> {
  let Some((host, port)) = parse_authority(target, None) else {
    return Ok(());
  };
  let tail = head_tail(head);
  if !intercept_candidate(&snapshot.grants, &host, port) {
    let mut upstream = dial_marked(&host, port, state.fwmark).await?;
    client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
    // Client bytes already read past the head (pipelined payloads) must not
    // be dropped: replay them upstream before splicing.
    if !tail.is_empty() {
      upstream.write_all(tail).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    return Ok(());
  }
  client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
  serve_candidate_stream(client, state, snapshot, &host, port, Some(&host), &host, tail).await
}
/// Bytes after the HTTP head boundary, if any (pipelined client data).
fn head_tail(head: &[u8]) -> &[u8] {
  head.windows(4).position(|w| w == b"\r\n\r\n").map_or(&[], |pos| &head[pos + 4..])
}

/// Host header of a complete HTTP request head, port-defaulted to the
/// dialed port. None when the buffer is not a complete request head or the
/// header is missing/unparseable.
fn http_head_host(buf: &[u8], default_port: u16) -> Option<(String, u16)> {
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut req = httparse::Request::new(&mut headers);
  let status = req.parse(buf).ok()?;
  if !status.is_complete() {
    return None;
  }
  let host = req.headers.iter().find(|h| h.name.eq_ignore_ascii_case("host"))?;
  let value = std::str::from_utf8(host.value).ok()?;
  parse_authority(value, Some(default_port))
}

/// Sniffed post-CONNECT / TUN stream: TLS with SNI, TLS without SNI, or plain TCP bytes.
pub(crate) enum Sniffed {
  Tls { buf: Vec<u8>, sni: String },
  TlsNoSni { buf: Vec<u8> },
  RawTcp { buf: Vec<u8> },
}

/// Buffer until a `ClientHello` with SNI arrives, or non-TLS bytes prove a
/// plain TCP stream. None on EOF/stall with no bytes, or oversize non-TLS.
/// TLS bytes that stall without yielding SNI come back as `TlsNoSni` so the
/// caller can MITM with the known authority (CONNECT) or splice (TUN).
pub(crate) async fn sniff_stream<G: AsyncRead + Unpin>(guest: &mut G, initial: &[u8]) -> eyre::Result<Option<Sniffed>> {
  let mut buf = initial.to_vec();
  let mut chunk = [0u8; 4096];
  // Total pre-auth budget: per-read timeouts re-arm, so a dripping client
  // could otherwise hold this task indefinitely one byte at a time.
  let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
  loop {
    // SNI first: a hello completing exactly at the size cutoff still counts.
    if let Some(sni) = extract_sni(&buf) {
      return Ok(Some(Sniffed::Tls { buf, sni }));
    }
    if buf.len() > MAX_HELLO {
      if buf.first() == Some(&0x16) {
        return Ok(Some(Sniffed::TlsNoSni { buf }));
      }
      return Ok(None);
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
      if buf.first() == Some(&0x16) && !buf.is_empty() {
        return Ok(Some(Sniffed::TlsNoSni { buf }));
      }
      return Ok(None);
    }
    let read = tokio::time::timeout(remaining, guest.read(&mut chunk)).await;
    let Ok(n) = read else {
      if buf.first() == Some(&0x16) && !buf.is_empty() {
        return Ok(Some(Sniffed::TlsNoSni { buf }));
      }
      return Ok(None);
    };
    let n = n?;
    if n == 0 {
      if buf.first() == Some(&0x16) && !buf.is_empty() {
        return Ok(Some(Sniffed::TlsNoSni { buf }));
      }
      return Ok(None);
    }
    buf.extend_from_slice(&chunk[..n]);
    if buf.first() != Some(&0x16) {
      return Ok(Some(Sniffed::RawTcp { buf }));
    }
  }
}

/// Serve a candidate stream (post-200 CONNECT, or TUN TCP): sniff TLS vs
/// plain TCP, then MITM / splice-with-replay / raw-machines as appropriate.
/// `enforce_host`: SNI must equal it (CONNECT authority); None → the SNI
/// itself is the identity (TUN). `dial_host` is the upstream TCP target,
/// `raw_host` the hostname for tcp:// grant matching.
#[allow(
  clippy::too_many_arguments,
  reason = "connection gating context: stream, state, targets, identity hint, replay buffer"
)]
pub(crate) async fn serve_candidate_stream<G>(
  mut guest: G,
  state: &ProxyState,
  snapshot: &ResolvedConfig,
  dial_host: &str,
  port: u16,
  enforce_host: Option<&str>,
  raw_host: &str,
  initial: &[u8],
) -> eyre::Result<()>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let Some(sniffed) = sniff_stream(&mut guest, initial).await? else {
    return Ok(());
  };
  match sniffed {
    Sniffed::RawTcp { buf } => {
      let upstream = dial_marked(dial_host, port, state.fwmark).await?;
      // Transparent plain HTTP: the Host header is the http:// grant
      // identity (TUN destination is an IP, no hostname). Non-HTTP bytes
      // stay on tcp:// raw machines.
      if let Some((host, hport)) = http_head_host(&buf, port)
        && snapshot.grants.iter().any(|grant| grant.matches(Scheme::Http, &host, hport))
      {
        let mut req = AnyMachine::Http1(SecretsMachine::new(
          &snapshot.grants,
          Scheme::Http,
          &host,
          hport,
          Direction::Request,
        ));
        let mut resp = AnyMachine::Http1(SecretsMachine::new(
          &snapshot.grants,
          Scheme::Http,
          &host,
          hport,
          Direction::Response,
        ));
        relay_guarded(guest, upstream, &mut req, &mut resp, &buf).await
      } else {
        let mut req = AnyMachine::Http1(SecretsMachine::new_raw(&snapshot.grants, raw_host, port, Direction::Request));
        let mut resp = AnyMachine::Http1(SecretsMachine::new_raw(&snapshot.grants, raw_host, port, Direction::Response));
        relay_guarded(guest, upstream, &mut req, &mut resp, &buf).await
      }
    }
    Sniffed::Tls { buf, sni } => {
      if let Some(authority) = enforce_host
        && !sni.eq_ignore_ascii_case(authority)
      {
        tracing::debug!(authority, sni, "CONNECT authority differs from SNI; closing");
        return Ok(());
      }
      let identity: &str = match enforce_host {
        Some(authority) => authority,
        None => &sni,
      };
      if !intercept_candidate(&snapshot.grants, identity, port) || !https_eligible(&snapshot.grants, identity, port) {
        // No grant match, or only a non-HTTPS (e.g. tcp://) grant on this
        // port: splice the raw bytes instead of terminating TLS with no
        // substitution to perform.
        let mut upstream = dial_marked(dial_host, port, state.fwmark).await?;
        upstream.write_all(&buf).await?;
        tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
        return Ok(());
      }
      mitm_tls_stream(guest, buf, identity, dial_host, port, state, snapshot).await
    }
    Sniffed::TlsNoSni { buf } => {
      // No SNI: CONNECT path still knows the authority, so MITM with it;
      // TUN path has no identity to mint for, so splice with replay.
      if let Some(authority) = enforce_host {
        if !intercept_candidate(&snapshot.grants, authority, port) || !https_eligible(&snapshot.grants, authority, port) {
          let mut upstream = dial_marked(dial_host, port, state.fwmark).await?;
          upstream.write_all(&buf).await?;
          tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
          return Ok(());
        }
        mitm_tls_stream(guest, buf, authority, dial_host, port, state, snapshot).await
      } else {
        let mut upstream = dial_marked(dial_host, port, state.fwmark).await?;
        upstream.write_all(&buf).await?;
        tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
        Ok(())
      }
    }
  }
}

/// Terminate guest TLS (`ClientHello` in `initial`), re-encrypt to
/// (`dial_host`, `port`) as `tls_host`, relay through machines.
async fn mitm_tls_stream<G>(
  guest: G,
  initial: Vec<u8>,
  tls_host: &str,
  dial_host: &str,
  port: u16,
  state: &ProxyState,
  snapshot: &ResolvedConfig,
) -> eyre::Result<()>
where
  G: AsyncRead + AsyncWrite + Unpin,
{
  let leaf = state.leaf_cert(tls_host).await?;
  let acceptor = TlsAcceptor::from(Arc::clone(&leaf.server_config));
  let prefixed = Prefixed::new(initial, guest);
  let mut guest_tls = tokio::time::timeout(std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), acceptor.accept(prefixed))
    .await
    .map_err(|_elapsed| eyre::eyre!("guest TLS handshake timed out"))?
    .map_err(|err| eyre::eyre!("guest TLS handshake: {err}"))?;

  let upstream = dial_marked(dial_host, port, state.fwmark).await?;
  let server_name = ServerName::try_from(tls_host.to_string()).map_err(|err| eyre::eyre!("bad SNI: {err}"))?;
  let server_tls = tokio::time::timeout(
    std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
    state.connector.connect(server_name, upstream),
  )
  .await
  .map_err(|_elapsed| eyre::eyre!("upstream TLS handshake timed out"))?
  .map_err(|err| eyre::eyre!("upstream TLS handshake: {err}"))?;

  let (peeked, mode) = peek_mode(&mut guest_tls).await?;
  let (mut req, mut resp): (AnyMachine, AnyMachine) = match mode {
    PlainMode::Http => (
      AnyMachine::Http1(SecretsMachine::new(
        &snapshot.grants,
        Scheme::Https,
        tls_host,
        port,
        Direction::Request,
      )),
      AnyMachine::Http1(SecretsMachine::new(
        &snapshot.grants,
        Scheme::Https,
        tls_host,
        port,
        Direction::Response,
      )),
    ),
    PlainMode::Raw => (
      AnyMachine::Http1(SecretsMachine::new_raw_tls(&snapshot.grants, tls_host, port, Direction::Request)),
      AnyMachine::Http1(SecretsMachine::new_raw_tls(&snapshot.grants, tls_host, port, Direction::Response)),
    ),
    PlainMode::H2 => (
      AnyMachine::H2(H2Machine::new(
        &snapshot.grants,
        Scheme::Https,
        tls_host,
        port,
        Direction::Request,
        true,
      )),
      AnyMachine::H2(H2Machine::new(
        &snapshot.grants,
        Scheme::Https,
        tls_host,
        port,
        Direction::Response,
        false,
      )),
    ),
  };
  relay_guarded(guest_tls, server_tls, &mut req, &mut resp, &peeked).await
}

/// Dial upstream, applying the fwmark when set (TUN self-exclusion).
/// Mark failures are fatal: silently unmarked dials would loop back into TUN.
pub(crate) async fn dial_marked(host: &str, port: u16, fwmark: Option<u32>) -> std::io::Result<TcpStream> {
  const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
  // One total budget across DNS + every address attempt: N blackholed
  // addresses must cost 10s total, not 10s each.
  let deadline = tokio::time::Instant::now() + DIAL_TIMEOUT;
  let mut last_err = std::io::Error::new(std::io::ErrorKind::NotFound, "DNS returned no addresses");
  let addrs = tokio::time::timeout(DIAL_TIMEOUT, tokio::net::lookup_host((host, port)))
    .await
    .map_err(|_elapsed| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS lookup timed out"))??;
  for addr in addrs {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
      last_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "dial budget exhausted");
      break;
    }
    match tokio::time::timeout(remaining, dial_one(addr, fwmark)).await {
      Ok(Ok(stream)) => return Ok(stream),
      Ok(Err(err)) => last_err = err,
      Err(_) => {
        last_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP dial timed out");
      }
    }
  }
  Err(last_err)
}

async fn dial_one(addr: SocketAddr, fwmark: Option<u32>) -> std::io::Result<TcpStream> {
  let Some(mark) = fwmark else {
    return TcpStream::connect(addr).await;
  };
  let domain = if addr.is_ipv4() {
    socket2::Domain::IPV4
  } else {
    socket2::Domain::IPV6
  };
  let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
  socket.set_mark(mark)?;
  socket.set_nonblocking(true)?;
  match socket.connect(&addr.into()) {
    Ok(()) => {}
    // In-flight nonblocking connect: WouldBlock (Windows/some Unixes) or
    // EINPROGRESS (Linux 115, macOS/BSD 36). `ErrorKind::InProgress` is
    // still unstable, so match the raw errno.
    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock || matches!(err.raw_os_error(), Some(115 | 36)) => {}
    Err(err) => return Err(err),
  }
  let stream = TcpStream::from_std(socket.into())?;
  stream.writable().await?;
  if let Some(err) = stream.take_error()? {
    return Err(err);
  }
  Ok(stream)
}

/// Plaintext protocol detected from the first client bytes.
enum PlainMode {
  Http,
  H2,
  Raw,
}

/// Read the first plaintext chunk and detect HTTP/1 vs H2 preface vs raw.
async fn peek_mode<G: AsyncRead + Unpin>(guest: &mut G) -> eyre::Result<(Vec<u8>, PlainMode)> {
  let mut peeked = Vec::new();
  let mut chunk = [0u8; 4096];
  // Total budget: same slow-drip concern as `sniff_stream`.
  let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
  loop {
    if peeked.len() >= H2_PREFACE.len() {
      if peeked.starts_with(H2_PREFACE) {
        return Ok((peeked, PlainMode::H2));
      }
      match try_parse_request(&peeked) {
        HeadPeek::Complete => return Ok((peeked, PlainMode::Http)),
        HeadPeek::NotHttp => return Ok((peeked, PlainMode::Raw)),
        HeadPeek::Partial if peeked.len() > MAX_HEAD => return Ok((peeked, PlainMode::Raw)),
        HeadPeek::Partial => {}
      }
    } else if !H2_PREFACE.starts_with(&peeked) {
      match try_parse_request(&peeked) {
        HeadPeek::Complete => return Ok((peeked, PlainMode::Http)),
        HeadPeek::NotHttp => return Ok((peeked, PlainMode::Raw)),
        HeadPeek::Partial => {}
      }
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
      return Ok(decide_partial(peeked));
    }
    let read = tokio::time::timeout(remaining, guest.read(&mut chunk)).await;
    let Ok(n) = read else {
      return Ok(decide_partial(peeked));
    };
    let n = n?;
    if n == 0 {
      return Ok(decide_partial(peeked));
    }
    peeked.extend_from_slice(&chunk[..n]);
  }
}

/// Outcome of trying to parse the peeked bytes as a request head.
enum HeadPeek {
  /// Complete request head: HTTP/1.
  Complete,
  /// Definitively not HTTP.
  NotHttp,
  /// Syntactically plausible so far: keep reading.
  Partial,
}

fn try_parse_request(data: &[u8]) -> HeadPeek {
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut req = httparse::Request::new(&mut headers);
  match req.parse(data) {
    Ok(status) if status.is_complete() => HeadPeek::Complete,
    Ok(_) => HeadPeek::Partial,
    Err(_) => HeadPeek::NotHttp,
  }
}

fn decide_partial(peeked: Vec<u8>) -> (Vec<u8>, PlainMode) {
  if peeked.len() >= H2_PREFACE.len() && peeked.starts_with(H2_PREFACE) {
    return (peeked, PlainMode::H2);
  }
  match try_parse_request(&peeked) {
    HeadPeek::Complete => (peeked, PlainMode::Http),
    HeadPeek::NotHttp | HeadPeek::Partial => (peeked, PlainMode::Raw),
  }
}

/// Bidirectional relay through per-direction machines. Guest FIN flushes the
/// request machine, then `close_notify` + upstream shutdown while still
/// draining server→guest; server close flushes the response machine and
/// ends the relay.
async fn relay_guarded<G, S>(
  mut guest: G,
  mut server: S,
  req: &mut (dyn SubMachine + Send),
  resp: &mut (dyn SubMachine + Send),
  first: &[u8],
) -> eyre::Result<()>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
{
  if !first.is_empty() {
    let (out, hits) = req.substitute(first);
    let pending = req.take_head_requests();
    if pending > 0 {
      resp.suppress_next_bodies(pending);
    }
    log_hits(&hits);
    if req.must_close() {
      return Ok(());
    }
    server.write_all(&out).await.context("relay request head to upstream")?;
  }
  let mut guest_buf = vec![0u8; 32 * 1024];
  let mut server_buf = vec![0u8; 32 * 1024];
  let mut guest_eof = false;
  loop {
    tokio::select! {
      result = guest.read(&mut guest_buf), if !guest_eof => {
        // rustls surfaces a peer FIN without close_notify as UnexpectedEof;
        // for a relay that is a normal end-of-stream, not an error.
        let result = match result {
          Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
          other => other,
        };
        match result {
          Ok(0) => {
            guest_eof = true;
            let (flushed, hits) = req.substitute(&[]);
            log_hits(&hits);
            server.write_all(&flushed).await.context("relay request flush to upstream")?;
            // Upstream may already have closed its write side; a failed
            // shutdown must not abort the relay — keep draining the
            // response direction.
            let _ = server.shutdown().await;
          }
          Ok(n) => {
            let (out, hits) = req.substitute(&guest_buf[..n]);
            let pending = req.take_head_requests();
            if pending > 0 {
              resp.suppress_next_bodies(pending);
            }
            log_hits(&hits);
            if req.must_close() {
              break;
            }
            server.write_all(&out).await.context("relay request chunk to upstream")?;
          }
          Err(err) => return Err(eyre::eyre!("guest read: {err}")),
        }
      }
      result = server.read(&mut server_buf) => {
        let result = match result {
          Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
          other => other,
        };
        match result {
          Ok(0) => {
            let (flushed, hits) = resp.substitute(&[]);
            log_hits(&hits);
            if resp.must_close() {
              break;
            }
            guest.write_all(&flushed).await.context("relay response flush to guest")?;
            break;
          }
          Ok(n) => {
            let (out, hits) = resp.substitute(&server_buf[..n]);
            log_hits(&hits);
            if resp.must_close() {
              // Scan-only path hit a needle it could not rewrite: drop the
              // chunk and the connection rather than leak the real value.
              break;
            }
            guest.write_all(&out).await.context("relay response chunk to guest")?;
            guest.flush().await.context("relay guest flush")?;
          }
          Err(err) => return Err(eyre::eyre!("upstream read: {err}")),
        }
      }
    }
  }
  guest.flush().await.context("relay final guest flush")?;
  let _ = guest.shutdown().await;
  Ok(())
}
fn log_hits(hits: &[crate::substitute::Hit]) {
  for hit in hits {
    tracing::debug!(label = %hit.label, location = ?hit.location, "substituted");
  }
}

async fn handle_forward(
  mut client: TcpStream,
  head: &[u8],
  target: &str,
  state: &ProxyState,
  snapshot: &ResolvedConfig,
) -> eyre::Result<()> {
  let remainder = target.get(..7).filter(|p| p.eq_ignore_ascii_case("http://")).map(|_| &target[7..]);
  let Some(remainder) = remainder else {
    return Ok(()); // origin-form / unknown scheme: close
  };
  let authority = remainder.split('/').next().unwrap_or("");
  let Some((host, port)) = parse_authority(authority, Some(80)) else {
    return Ok(());
  };
  let upstream = dial_marked(&host, port, state.fwmark).await?;
  if !snapshot.grants.iter().any(|grant| grant.matches(Scheme::Http, &host, port)) {
    // No http grant: splice byte-identical, streaming, no machine buffering.
    let mut upstream = upstream;
    upstream.write_all(head).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    return Ok(());
  }
  let mut req = AnyMachine::Http1(SecretsMachine::new(&snapshot.grants, Scheme::Http, &host, port, Direction::Request));
  let mut resp = AnyMachine::Http1(SecretsMachine::new(
    &snapshot.grants,
    Scheme::Http,
    &host,
    port,
    Direction::Response,
  ));
  relay_guarded(client, upstream, &mut req, &mut resp, head).await
}

/// Read until the end of the HTTP head (`\r\n\r\n`) or `MAX_HEAD` bytes.
/// Returns whatever was read; caller checks completeness. Bounded by the
/// handshake timeout: this runs pre-auth on unauthenticated client bytes.
async fn read_head(stream: &mut TcpStream) -> eyre::Result<Vec<u8>> {
  tokio::time::timeout(std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), read_head_inner(stream))
    .await
    .map_err(|_elapsed| eyre::eyre!("client head read timed out"))?
}

async fn read_head_inner(stream: &mut TcpStream) -> eyre::Result<Vec<u8>> {
  let mut buf = Vec::new();
  let mut chunk = [0u8; 8192];
  loop {
    let n = stream.read(&mut chunk).await?;
    if n == 0 {
      break;
    }
    buf.extend_from_slice(&chunk[..n]);
    if buf.len() > MAX_HEAD {
      break;
    }
    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
      break;
    }
  }
  Ok(buf)
}

/// Parse `host:port` authority via the `url` crate (dummy `http` scheme for
/// structure; the scheme itself is meaningless here). `default_port` fills
/// a missing port; without one the port is required. Returns `(host, port)`.
/// Unbracketed IPv6, userinfo, and paths are rejected — callers close
/// quietly on `None`.
fn parse_authority(authority: &str, default_port: Option<u16>) -> Option<(String, u16)> {
  if authority.contains(['/', '?', '#', '@']) {
    return None;
  }
  let url = url::Url::parse(&format!("http://{authority}")).ok()?;
  let host = match url.host()? {
    url::Host::Domain(domain) => domain.to_string(),
    url::Host::Ipv4(addr) => addr.to_string(),
    url::Host::Ipv6(addr) => addr.to_string(),
  };
  let port = url.port().or(default_port)?;
  Some((host, port))
}

/// A stream prefixed with already-read bytes (replays `initial_buf` first).
struct Prefixed<S> {
  prefix: Vec<u8>,
  pos: usize,
  inner: S,
}

impl<S> Prefixed<S> {
  fn new(prefix: Vec<u8>, inner: S) -> Self {
    Self { prefix, pos: 0, inner }
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    if self.pos < self.prefix.len() {
      let remaining = &self.prefix[self.pos..];
      let n = remaining.len().min(buf.remaining());
      buf.put_slice(&remaining[..n]);
      self.pos += n;
      return Poll::Ready(Ok(()));
    }
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
  fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

#[cfg(test)]
/// Test helper: bound address of a listener.
pub fn local_addr(listener: &TcpListener) -> SocketAddr {
  listener.local_addr().expect("listener has an address")
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  use crate::ca::install_crypto_provider;
  use crate::grants::UriGrant;

  #[test]
  fn parse_authority_bracketed_v6_default_port() {
    assert_eq!(parse_authority("[::1]:8080", None), Some(("::1".to_string(), 8080)));
    assert_eq!(parse_authority("[::1]", Some(80)), Some(("::1".to_string(), 80)));
    assert_eq!(parse_authority("[::1]", None), None);
    assert_eq!(parse_authority("[::1]extra", Some(80)), None);
    assert_eq!(parse_authority("example.com", Some(80)), Some(("example.com".to_string(), 80)));
    // Unbracketed IPv6 is never split: mirrors the grant parser rejection.
    assert_eq!(parse_authority("::1", Some(80)), None);
    assert_eq!(parse_authority("::1", None), None);
    assert_eq!(parse_authority("2001:db8::1:443", None), None);
    // Userinfo never authenticates upstream: reject, don't dial it.
    assert_eq!(parse_authority("user@example.com:80", None), None);
  }
  fn test_state() -> Arc<ProxyState> {
    test_state_with(Vec::new(), CertAuthority::generate().unwrap())
  }

  fn test_state_with(grants: Vec<Grant>, ca: CertAuthority) -> Arc<ProxyState> {
    Arc::new(ProxyState::new(
      ResolvedConfig {
        proxy: crate::config::ProxyCfg {
          listen: "127.0.0.1:0".parse().unwrap(),
          ca_file: None,
        },
        grants,
      },
      ca,
    ))
  }

  async fn run_proxy_with(state: Arc<ProxyState>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = local_addr(&listener);
    let handle = tokio::spawn(async move {
      let _ = serve(listener, state).await;
    });
    (addr, handle)
  }

  async fn run_proxy() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    run_proxy_with(test_state()).await
  }

  /// Read until the HTTP head is complete, then return all bytes read so far.
  async fn read_head_from<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
      let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      assert!(n > 0, "unexpected EOF waiting for head");
      buf.extend_from_slice(&chunk[..n]);
      if buf.windows(4).any(|w| w == b"\r\n\r\n") {
        return buf;
      }
    }
  }

  struct MitmFixture {
    proxy_addr: SocketAddr,
    proxy: tokio::task::JoinHandle<()>,
    stub: TcpListener,
    stub_port: u16,
    stub_acceptor: TlsAcceptor,
    connector: TlsConnector,
  }

  /// Proxy + TLS stub presenting a hodor-signed localhost cert; client
  /// connector trusts the hodor CA. Grants built with the stub port.
  async fn mitm_fixture(make_grants: impl Fn(u16) -> Vec<Grant>) -> MitmFixture {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let ca_der = ca.cert_der().clone();
    let stub_cert = ca.generate_domain_cert("localhost").unwrap();
    let stub_acceptor = TlsAcceptor::from(Arc::clone(&stub_cert.server_config));
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = local_addr(&stub).port();
    let grants = make_grants(stub_port);
    let (proxy_addr, proxy) = run_proxy_with(test_state_with(grants, ca)).await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let client_config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    }
  }

  fn localhost_grant(port: u16, fake: &str, value: &str) -> Vec<Grant> {
    vec![Grant {
      label: "t".into(),
      fake: fake.into(),
      value: secrecy::SecretString::from(value.to_string()),
      allow: vec![UriGrant {
        scheme: Scheme::Https,
        host: "localhost".parse().unwrap(),
        port,
      }],
    }]
  }

  /// CONNECT through the proxy and complete a client TLS handshake.
  async fn mitm_client_tls(proxy_addr: SocketAddr, stub_port: u16, connector: &TlsConnector) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
      .write_all(format!("CONNECT localhost:{stub_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = vec![0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    let server_name = ServerName::try_from("localhost".to_string()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client))
      .await
      .unwrap()
      .unwrap()
  }

  /// Read a full Content-Length body given head bytes already read.
  async fn read_body<S: AsyncRead + Unpin>(tls: &mut S, head_bytes: &[u8], len: usize) -> Vec<u8> {
    let head_end = head_bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let mut body = Vec::from(&head_bytes[head_end..]);
    while body.len() < len {
      let mut chunk = vec![0u8; len - body.len()];
      let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      assert!(n > 0, "unexpected EOF waiting for body");
      body.extend_from_slice(&chunk[..n]);
    }
    body
  }

  #[tokio::test]
  async fn connect_splices_bytes_verbatim() {
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = local_addr(&stub);
    let (proxy_addr, proxy) = run_proxy().await;

    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let mut buf = [0u8; 5];
      conn.read_exact(&mut buf).await.unwrap();
      assert_eq!(&buf, b"hello");
      conn.write_all(b"world").await.unwrap();
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
      .write_all(format!("CONNECT {stub_addr} HTTP/1.1\r\nHost: {stub_addr}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = vec![0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    client.write_all(b"hello").await.unwrap();
    let mut echo = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echo))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&echo, b"world");

    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn absolute_form_forwards_head_verbatim() {
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = local_addr(&stub);
    let (proxy_addr, proxy) = run_proxy().await;

    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let head = read_head_from(&mut conn).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(
        head_str.starts_with(&format!("GET http://{stub_addr}/x HTTP/1.1\r\n")),
        "{head_str}"
      );
      conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
      .write_all(format!("GET http://{stub_addr}/x HTTP/1.1\r\nHost: {stub_addr}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp))
      .await
      .unwrap()
      .unwrap();
    assert!(resp.starts_with(b"HTTP/1.1 200 OK"), "{}", resp.escape_ascii());

    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn malformed_request_closes_without_response() {
    let (proxy_addr, proxy) = run_proxy().await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(b"GARBAGE\r\n\r\n").await.unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp))
      .await
      .unwrap()
      .unwrap();
    assert!(resp.is_empty());
    proxy.abort();
  }

  #[tokio::test]
  async fn mitm_terminates_both_ends_verbatim() {
    let fx = mitm_fixture(|port| localhost_grant(port, "fake", "value")).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains("Authorization: Bearer hello\r\n"), "{head_str}");
      tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls
      .write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer hello\r\n\r\n")
      .await
      .unwrap();
    let resp = read_head_from(&mut tls).await;
    assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", resp.escape_ascii());
    assert_eq!(read_body(&mut tls, &resp, 2).await, b"hi");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn mitm_substitutes_request_and_redacts_response() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let fx = mitm_fixture(|port| localhost_grant(port, FAKE, VALUE)).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Authorization: Bearer {VALUE}\r\n")), "{head_str}");
      assert!(!head_str.contains(FAKE), "{head_str}");
      let body = format!("echo:{VALUE}");
      tls
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls
      .write_all(format!("GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let resp = read_head_from(&mut tls).await;
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(!resp_str.contains(VALUE), "{resp_str}");
    let expect_body = format!("echo:{FAKE}");
    assert_eq!(read_body(&mut tls, &resp, expect_body.len()).await, expect_body.as_bytes());
    stub_task.await.unwrap();
    proxy.abort();
  }

  fn localhost_tcp_grant(port: u16, fake: &str, value: &str) -> Vec<Grant> {
    vec![Grant {
      label: "t".into(),
      fake: fake.into(),
      value: secrecy::SecretString::from(value.to_string()),
      allow: vec![UriGrant {
        scheme: Scheme::Tcp,
        host: "localhost".parse().unwrap(),
        port,
      }],
    }]
  }

  #[tokio::test]
  async fn tcp_only_grant_splices_tls_verbatim() {
    // A tcp:// grant on the TLS port must not trigger MITM: the handshake
    // passes through to the stub, fakes stay fakes, values stay values.
    const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
    const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";
    let fx = mitm_fixture(|port| localhost_tcp_grant(port, FAKE, VALUE)).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Authorization: Bearer {FAKE}\r\n")), "{head_str}");
      assert!(!head_str.contains(VALUE), "{head_str}");
      let body = format!("echo:{VALUE}");
      tls
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls
      .write_all(format!("GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let resp = read_head_from(&mut tls).await;
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(resp_str.contains(VALUE), "{resp_str}");
    let expect_body = format!("echo:{VALUE}");
    assert_eq!(read_body(&mut tls, &resp, expect_body.len()).await, expect_body.as_bytes());
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn wildcard_grant_shares_one_leaf_across_subdomains() {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let grants = vec![Grant {
      label: "t".into(),
      fake: "fake".into(),
      value: secrecy::SecretString::from("value"),
      allow: vec![UriGrant {
        scheme: Scheme::Https,
        host: "*.example.com".parse().unwrap(),
        port: 443,
      }],
    }];
    let state = test_state_with(grants, ca);
    let a = state.leaf_cert("a.example.com").await.unwrap();
    let b = state.leaf_cert("other.example.com").await.unwrap();
    assert!(Arc::ptr_eq(&a, &b));
  }

  #[tokio::test]
  async fn non_candidate_splices_bytes_verbatim() {
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = local_addr(&stub);
    let (proxy_addr, proxy) = run_proxy().await; // no grants: splice path
    let blob: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
    let expect = blob.clone();
    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let mut got = vec![0u8; expect.len()];
      conn.read_exact(&mut got).await.unwrap();
      assert_eq!(got, expect);
    });
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
      .write_all(format!("CONNECT {stub_addr} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let mut head = vec![0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
      .await
      .unwrap()
      .unwrap();
    client.write_all(&blob).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), stub_task).await.unwrap().unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn tls_through_splice_leaves_fake_untouched() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let fx = mitm_fixture(|_| Vec::new()).await; // no grants: splice, full TLS through
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Bearer {FAKE}\r\n")), "{head_str}");
      tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls
      .write_all(format!("GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let resp = read_head_from(&mut tls).await;
    assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", resp.escape_ascii());
    assert_eq!(read_body(&mut tls, &resp, 2).await, b"hi");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  #[expect(clippy::cast_possible_truncation, reason = "test frame sized by construction, masked to bytes")]
  async fn mitm_h2_substitutes_headers() {
    use httlib_hpack::{Decoder, Encoder};

    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let fx = mitm_fixture(|port| localhost_grant(port, FAKE, VALUE)).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      stub_acceptor,
      connector,
    } = fx;

    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      // Raw preface + HEADERS arrive; upstream HPACK-decodes the value.
      let mut preface = [0u8; 24];
      tls.read_exact(&mut preface).await.unwrap();
      assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
      let mut hdr = [0u8; 9];
      tls.read_exact(&mut hdr).await.unwrap();
      assert_eq!(hdr[3], 0x1, "expected HEADERS");
      assert_eq!(u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff, 1);
      let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
      let mut block = vec![0u8; len];
      tls.read_exact(&mut block).await.unwrap();
      let mut decoder = Decoder::default();
      let mut headers = Vec::new();
      decoder.decode(&mut block, &mut headers).unwrap();
      let auth = headers.iter().find(|(name, _, _)| name == b"authorization").unwrap();
      assert_eq!(auth.1, format!("Bearer {VALUE}").as_bytes());
      tls.shutdown().await.unwrap();
    });

    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    let mut encoder = Encoder::default();
    let mut block = Vec::new();
    for (name, value) in [
      (":method", "GET"),
      (":scheme", "https"),
      (":path", "/"),
      (":authority", "localhost"),
      ("authorization", &format!("Bearer {FAKE}")),
    ] {
      encoder
        .encode(
          (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
          &mut block,
        )
        .unwrap();
    }
    let mut frame = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
    frame.push(((block.len() >> 16) & 0xff) as u8);
    frame.push(((block.len() >> 8) & 0xff) as u8);
    frame.push((block.len() & 0xff) as u8);
    frame.extend_from_slice(&[0x1, 0x4 | 0x1, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS|END_STREAM
    frame.extend_from_slice(&block);
    tls.write_all(&frame).await.unwrap();
    tls.flush().await.unwrap();
    // Stub shuts down after asserting; EOF ends the test race-free.
    let mut one = [0u8; 1];
    assert_eq!(tls.read(&mut one).await.unwrap(), 0);
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn absolute_form_ungranted_chunked_splices_byte_identical() {
    // No grants: chunked bodies must pass through byte-identical, never
    // re-encoded into a single chunk.
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = local_addr(&stub);
    let (proxy_addr, proxy) = run_proxy().await;
    let body = "3\r\naaa\r\n3\r\nbbb\r\n0\r\n\r\n";
    let request = format!("POST http://{stub_addr}/x HTTP/1.1\r\nHost: {stub_addr}\r\nTransfer-Encoding: chunked\r\n\r\n{body}");
    let expected = request.clone().into_bytes();
    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let mut buf = Vec::new();
      let mut chunk = [0u8; 4096];
      loop {
        let n = conn.read(&mut chunk).await.unwrap();
        if n == 0 {
          break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.ends_with(b"0\r\n\r\n") {
          break;
        }
      }
      assert_eq!(buf, expected, "ungranted chunked request must be byte-identical");
      conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
    });
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp))
      .await
      .unwrap()
      .unwrap();
    assert!(resp.starts_with(b"HTTP/1.1 200 OK"), "{}", resp.escape_ascii());
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn connect_pipelined_bytes_reach_upstream_verbatim() {
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_addr = local_addr(&stub);
    let (proxy_addr, proxy) = run_proxy().await; // no grants: splice path
    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let mut buf = [0u8; 5];
      conn.read_exact(&mut buf).await.unwrap();
      assert_eq!(&buf, b"early", "pipelined post-head bytes must survive");
      conn.write_all(b"ok").await.unwrap();
    });
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    // CONNECT head + payload in ONE write: the tail must be replayed.
    client
      .write_all(format!("CONNECT {stub_addr} HTTP/1.1\r\nHost: x\r\n\r\nearly").as_bytes())
      .await
      .unwrap();
    let mut head = vec![0u8; 19];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut head))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
    let mut reply = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(&reply, b"ok");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn transparent_plain_http_honors_http_grant() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = local_addr(&stub).port();
    let grants = vec![Grant {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
      allow: vec![UriGrant {
        scheme: Scheme::Http,
        host: "127.0.0.1".parse().unwrap(),
        port: stub_port,
      }],
    }];
    let state = test_state_with(grants, ca);
    let snapshot = state.snapshot();
    let stub_task = tokio::spawn(async move {
      let (mut conn, _) = stub.accept().await.unwrap();
      let head = read_head_from(&mut conn).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Authorization: Bearer {VALUE}")), "{head_str}");
      let body = format!("echo:{VALUE}");
      conn
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .unwrap();
    });
    let (guest, mut client_end) = tokio::io::duplex(64 * 1024);
    let serve = tokio::spawn({
      let state = Arc::clone(&state);
      let snapshot = Arc::clone(&snapshot);
      async move { serve_candidate_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, None, "127.0.0.1", &[]).await }
    });
    client_end
      .write_all(
        format!("GET /x HTTP/1.1\r\nHost: 127.0.0.1:{stub_port}\r\nAuthorization: Bearer {FAKE}\r\nConnection: close\r\n\r\n").as_bytes(),
      )
      .await
      .unwrap();
    let resp = read_head_from(&mut client_end).await;
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(!resp_str.contains(VALUE), "{resp_str}");
    let expect = format!("echo:{FAKE}");
    assert_eq!(read_body(&mut client_end, &resp, expect.len()).await, expect.as_bytes());
    stub_task.await.unwrap();
    serve.await.unwrap().unwrap();
  }

  #[tokio::test]
  async fn transparent_tls_mitm_substitutes_by_sni_identity() {
    const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
    const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";
    const SNI: &str = "testtun.invalid";
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let ca_der = ca.cert_der().clone();
    let stub_cert = ca.generate_domain_cert(SNI).unwrap();
    let stub_acceptor = TlsAcceptor::from(Arc::clone(&stub_cert.server_config));
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = local_addr(&stub).port();
    let grants = vec![Grant {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
      allow: vec![UriGrant {
        scheme: Scheme::Https,
        host: SNI.parse().unwrap(),
        port: stub_port,
      }],
    }];
    let state = test_state_with(grants, ca);
    let snapshot = state.snapshot();
    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let head = read_head_from(&mut tls).await;
      let head_str = String::from_utf8(head).unwrap();
      assert!(head_str.contains(&format!("Bearer {VALUE}")), "{head_str}");
      let body = format!("echo:{VALUE}");
      tls
        .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
        .await
        .unwrap();
    });
    let (guest, client_end) = tokio::io::duplex(64 * 1024);
    let serve = tokio::spawn({
      let state = Arc::clone(&state);
      let snapshot = Arc::clone(&snapshot);
      // TUN shape: dial target is an address, the SNI alone is the identity.
      async move { serve_candidate_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, None, "127.0.0.1", &[]).await }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let connector = TlsConnector::from(Arc::new(
      rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
    ));
    let server_name = ServerName::try_from(SNI.to_string()).unwrap();
    let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client_end))
      .await
      .unwrap()
      .unwrap();
    tls
      .write_all(format!("GET /x HTTP/1.1\r\nHost: {SNI}\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    stub_task.await.unwrap();
    let mut resp = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
      let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      resp.extend_from_slice(&chunk[..n]);
      if resp.windows(4).any(|w| w == b"\r\n\r\n") {
        break;
      }
    }
    let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let expect = format!("echo:{FAKE}");
    let mut body = Vec::from(&resp[head_end..]);
    while body.len() < expect.len() {
      let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      body.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(body, expect.as_bytes());
    serve.await.unwrap().unwrap();
  }
}
