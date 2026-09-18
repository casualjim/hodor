//! Explicit proxy core: CONNECT splice, TLS intercept relay.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rama::error::BoxError;
use rama::extensions::{Extensions, ExtensionsRef};
use rama::io::BridgeIo;
use rama::net::address::{Host, HostWithPort, SocketAddress};
use rama::net::client::ConnectorTarget;
use rama::net::socket::SocketOptions;
use rama::net::socket::opts::Domain;
use rama::rt::Executor;
use rama::tcp::client::TcpStreamConnector;
pub use rama::tcp::server::TcpListener as RamaTcpListener;
use rama::tcp::stream::TcpStream as RamaTcpStream;
use rama::tls::boring::TlsStream;
use rama::tls::boring::proxy::TlsMitmEgressServerAuth;
use rama::tls::boring::proxy::TlsMitmRelay;
use rama::tls::boring::proxy::TlsMitmRelayService;
use rama::tls::boring::proxy::cert_issuer::{CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer};
use rama::tls::client::ServerVerifyMode;
use rama::tls::server::InputWithClientHello;
use rama::{Service, crypto};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
#[cfg(test)]
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use crate::policy::{MintBucket, Route, decide, peek_stream};
use crate::substitute::{AnyMachine, Direction, H2_PREFACE, H2Machine, MachineMode, MachineParams, SecretsMachine};
use hodor_config::grants::{ResolvedConfig, Scheme, intercept_candidate};
use hodor_pki::ca::CertAuthority;
use hodor_plugin::Direction as HookDirection;

mod policy;
mod substitute;

mod relay;

pub(crate) use relay::relay_guarded;

const MAX_HEAD: usize = 64 * 1024;
pub(crate) const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Shared proxy state: live config snapshot, boring MITM relay, and the
/// issuance burst guard.
///
/// Config is write-once (no reload path), so a plain `Arc` — no lock, no
/// swap. Leaf issuance runs inside the boring relay's cached issuer, and the
/// [`MintBucket`] bounds remote-triggered issuance per MITM arm entry.
pub struct ProxyState {
  config: Arc<ResolvedConfig>,
  relay: TlsMitmRelay<CachedBoringMitmCertIssuer<InMemoryBoringMitmCertIssuer>>,
  mint: MintBucket,
  fwmark: Option<u32>,
  plugins: Arc<hodor_plugin::Registry>,
}

impl std::fmt::Debug for ProxyState {
  /// `ResolvedConfig` derives `Debug`, and `Grant`'s `value` is a
  /// `SecretString` that renders as `SecretBox<str>`, so real secrets never
  /// reach a log line through here.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ProxyState")
      .field("config", &self.config)
      .field("fwmark", &self.fwmark)
      .field("plugins", &self.plugins)
      .finish_non_exhaustive()
  }
}

impl ProxyState {
  /// Build state from resolved config and the CA. The boring pair comes from
  /// [`CertAuthority::boring_pair`]; egress trust is the system natives plus
  /// the hodor CA itself, so loopback stubs presenting hodor-signed certs
  /// verify on the production path. Verification is always on: this proxy
  /// swaps real secrets upstream, so a network attacker with an untrusted
  /// cert must fail closed.
  ///
  /// # Errors
  ///
  /// Returns an error when the CA pair fails to convert to boring types,
  /// when the egress trust policy rejects the hodor CA anchor, or when a
  /// configured plugin cannot be loaded.
  pub fn new(resolved: ResolvedConfig, ca: &CertAuthority) -> eyre::Result<Self> {
    let plugins = Arc::new(hodor_plugin::Registry::load(&resolved.plugins)?);
    let (crt, key) = ca.boring_pair()?;
    let anchor = crypto::pki_types::CertificateDer::from(ca.cert_der().to_vec());
    let egress = TlsMitmEgressServerAuth::new()
      .with_server_verify(ServerVerifyMode::Auto)
      .with_webpki_roots()
      .try_with_extra_server_trust_anchors([anchor])
      .map_err(|err| eyre::eyre!("egress trust anchors: {err}"))?;
    let relay = TlsMitmRelay::new_cached_in_memory(crt, key).with_egress_server_auth(egress);
    Ok(Self {
      config: Arc::new(resolved),
      relay,
      mint: MintBucket::new(),
      fwmark: None,
      plugins,
    })
  }

  #[cfg(target_os = "linux")]
  /// Mark upstream sockets so the capture backend's policy routing bypasses
  /// them (`tun` and `tproxy` alike).
  #[must_use]
  pub fn with_fwmark(mut self, mark: u32) -> Self {
    self.fwmark = Some(mark);
    self
  }

  /// Load the current config snapshot.
  #[must_use]
  pub fn snapshot(&self) -> Arc<ResolvedConfig> {
    Arc::clone(&self.config)
  }

  /// `SO_MARK` for upstream sockets (`None` = unmarked).
  #[must_use]
  pub fn fwmark(&self) -> Option<u32> {
    self.fwmark
  }
}

/// Guest-side adapter: any tokio stream plus a rama extension map. The relay
/// reads the [`ConnectorTarget`] identity from these extensions to derive
/// egress SNI and verification identity.
struct GuestIo<S> {
  inner: S,
  extensions: Extensions,
}

impl<S> GuestIo<S> {
  fn with_target(inner: S, identity: &str, port: u16) -> eyre::Result<Self> {
    let host: Host = identity.parse().map_err(|err| eyre::eyre!("bad MITM identity {identity}: {err}"))?;
    let extensions = Extensions::new();
    extensions.insert(ConnectorTarget(HostWithPort::new(host, port)));
    Ok(Self { inner, extensions })
  }

  fn bare(inner: S) -> Self {
    Self {
      inner,
      extensions: Extensions::new(),
    }
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for GuestIo<S> {
  fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GuestIo<S> {
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
impl<S> ExtensionsRef for GuestIo<S> {
  fn extensions(&self) -> &Extensions {
    &self.extensions
  }
}

/// Byte-pump service: the relay hands paired TLS streams here, and the
/// substitution machines pump them once plaintext detection has picked the
/// HTTP, H2, or raw arm. Decoded-request middleware is deliberately not used:
/// a `Request<Body>` round-trips through the HTTP codec and would break the
/// byte-identical guarantee the verbatim tests pin.
#[derive(Debug, Clone)]
struct PumpService {
  snapshot: Arc<ResolvedConfig>,
  identity: String,
  port: u16,
  plugins: Arc<hodor_plugin::Registry>,
}
impl<GI, GE> Service<BridgeIo<TlsStream<GI>, TlsStream<GE>>> for PumpService
where
  GI: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  GE: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  type Output = ();
  type Error = BoxError;

  async fn serve(&self, input: BridgeIo<TlsStream<GI>, TlsStream<GE>>) -> Result<Self::Output, Self::Error> {
    let BridgeIo(mut guest_tls, mut server_tls) = input;
    let (peeked, mode) = peek_mode(&mut guest_tls).await.map_err(|err| into_box_error(&err))?;
    let (mut req, mut resp): (AnyMachine, AnyMachine) = match mode {
      PlainMode::Http => (
        AnyMachine::Http1(SecretsMachine::new(
          MachineParams::new(
            &self.snapshot.grants,
            MachineMode::Https,
            &self.identity,
            self.port,
            Direction::Request,
          )
          .hook(
            self
              .plugins
              .select(Scheme::Https, &self.identity, self.port, HookDirection::Request),
          ),
        )),
        AnyMachine::Http1(SecretsMachine::new(
          MachineParams::new(
            &self.snapshot.grants,
            MachineMode::Https,
            &self.identity,
            self.port,
            Direction::Response,
          )
          .hook(
            self
              .plugins
              .select(Scheme::Https, &self.identity, self.port, HookDirection::Response),
          ),
        )),
      ),
      // Raw TLS has no HTTP structure to hook: machines only.
      PlainMode::Raw => (
        AnyMachine::Http1(SecretsMachine::new(MachineParams::new(
          &self.snapshot.grants,
          MachineMode::RawTls,
          &self.identity,
          self.port,
          Direction::Request,
        ))),
        AnyMachine::Http1(SecretsMachine::new(MachineParams::new(
          &self.snapshot.grants,
          MachineMode::RawTls,
          &self.identity,
          self.port,
          Direction::Response,
        ))),
      ),
      PlainMode::H2 => (
        AnyMachine::H2(H2Machine::new(
          MachineParams::new(
            &self.snapshot.grants,
            MachineMode::Https,
            &self.identity,
            self.port,
            Direction::Request,
          )
          .hook(
            self
              .plugins
              .select(Scheme::Https, &self.identity, self.port, HookDirection::Request),
          ),
        )),
        AnyMachine::H2(H2Machine::new(
          MachineParams::new(
            &self.snapshot.grants,
            MachineMode::Https,
            &self.identity,
            self.port,
            Direction::Response,
          )
          .hook(
            self
              .plugins
              .select(Scheme::Https, &self.identity, self.port, HookDirection::Response),
          ),
        )),
      ),
    };
    relay_guarded(&mut guest_tls, &mut server_tls, &mut req, &mut resp, &peeked)
      .await
      .map_err(|err| into_box_error(&err))
  }
}

/// Box an eyre report for a rama service error, preserving its debug chain.
fn into_box_error(err: &eyre::Report) -> BoxError {
  BoxError::from(format!("{err:?}"))
}
/// Serve the explicit listener until its executor shuts down. Accept errors
/// are logged by the listener loop and never end the process.
pub async fn serve(listener: RamaTcpListener, state: Arc<ProxyState>) {
  listener.serve(ExplicitService { state }).await;
}

/// Bind the explicit listener with rama socket options: plain TCP socket for
/// the configured address, bound and listening, ready to serve. Backlog
/// matches `std` (128).
///
/// # Errors
///
/// Returns an error when the socket cannot be built, bound, or marked
/// listening.
pub async fn bind_explicit(addr: SocketAddr) -> eyre::Result<RamaTcpListener> {
  let domain = if addr.is_ipv4() { Domain::IPv4 } else { Domain::IPv6 };
  let socket = SocketOptions {
    address: Some(SocketAddress::from(addr)),
    ..SocketOptions::default_tcp()
  }
  .try_build_socket(domain)
  .map_err(|err| eyre::eyre!("explicit listen socket: {err}"))?;
  socket.listen(128).map_err(|err| eyre::eyre!("explicit listen: {err}"))?;
  RamaTcpListener::bind_socket(socket, Executor::default())
    .await
    .map_err(|err| eyre::eyre!("explicit bind: {err}"))
}

/// Explicit ingress service: HTTP head dispatch (CONNECT vs forward).
/// Per-connection failures close quietly with a debug log.
#[derive(Debug, Clone)]
struct ExplicitService {
  state: Arc<ProxyState>,
}

impl Service<RamaTcpStream> for ExplicitService {
  type Output = ();
  type Error = std::convert::Infallible;

  async fn serve(&self, input: RamaTcpStream) -> Result<Self::Output, Self::Error> {
    let client = input.stream;
    let peer = client.peer_addr().ok();
    if let Err(err) = dispatch(client, &self.state).await {
      tracing::debug!(?peer, ?err, "connection failed");
    }
    Ok(())
  }
}

async fn dispatch(mut client: TcpStream, state: &ProxyState) -> eyre::Result<()> {
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
    let Some((host, port)) = parse_authority(target, None) else {
      return Ok(());
    };
    let tail = head_tail(&head).to_vec();
    if !intercept_candidate(&snapshot.grants, &host, port) {
      let mut upstream = dial_marked(&host, port, state.fwmark).await?;
      client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
      // Client bytes already read past the head (pipelined payloads) must not
      // be dropped: replay them upstream before splicing.
      if !tail.is_empty() {
        upstream.write_all(&tail).await?;
      }
      tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
      return Ok(());
    }
    client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
    serve_connect_stream(client, state, &snapshot, &host, port, &tail).await
  } else {
    forward_arm(client, &head, target, state, &snapshot).await
  }
}
/// Bytes after the HTTP head boundary, if any (pipelined client data).
fn head_tail(head: &[u8]) -> &[u8] {
  head.windows(4).position(|w| w == b"\r\n\r\n").map_or(&[], |pos| &head[pos + 4..])
}

/// Serve a post-200 CONNECT stream: peek TLS vs plain, route through the
/// policy table with the CONNECT authority enforced as SNI identity, then
/// MITM / splice / machines as appropriate. `initial` replays pipelined
/// bytes read past the CONNECT head.
///
/// # Errors
///
/// Returns an error when peeking fails, or when the upstream dial fails.
/// SNI mismatch and empty input close quietly (`Ok(())`), never errors.
pub async fn serve_connect_stream<G>(
  guest: G,
  state: &ProxyState,
  snapshot: &ResolvedConfig,
  host: &str,
  port: u16,
  initial: &[u8],
) -> eyre::Result<()>
where
  G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  drive_candidate_stream(guest, state, snapshot, host, port, Some(host), host, initial).await
}

/// Serve a transparently captured stream (TUN/TPROXY/eBPF leg): peek TLS vs
/// plain, route through the policy table with the SNI itself as identity,
/// then MITM / splice / machines as appropriate. `dial_host` is the upstream
/// TCP target, `raw_host` the hostname for tcp:// grant matching.
///
/// # Errors
///
/// Returns an error when peeking fails, or when the upstream dial fails.
/// Empty input closes quietly (`Ok(())`), never errors.
pub async fn serve_transparent_stream<G>(
  guest: G,
  state: &ProxyState,
  snapshot: &ResolvedConfig,
  dial_host: &str,
  port: u16,
  raw_host: &str,
) -> eyre::Result<()>
where
  G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  drive_candidate_stream(guest, state, snapshot, dial_host, port, None, raw_host, &[]).await
}

/// Shared candidate core behind the two entries above.
#[expect(
  clippy::too_many_arguments,
  reason = "connection gating context: stream, state, targets, identity hint, replay buffer"
)]
async fn drive_candidate_stream<G>(
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
  G: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let Some(peeked) = peek_stream(&mut guest, initial).await? else {
    return Ok(());
  };
  let Some(route) = decide(snapshot, port, enforce_host, peeked) else {
    return Ok(());
  };
  match route {
    Route::Splice { buf } => {
      let mut upstream = dial_marked(dial_host, port, state.fwmark).await?;
      upstream.write_all(&buf).await?;
      tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
      Ok(())
    }
    Route::RawTcpMachines { buf } => {
      let upstream = dial_marked(dial_host, port, state.fwmark).await?;
      // Raw TCP has no HTTP structure to hook: machines only.
      let mut req = AnyMachine::Http1(SecretsMachine::new(MachineParams::new(
        &snapshot.grants,
        MachineMode::RawTcp,
        raw_host,
        port,
        Direction::Request,
      )));
      let mut resp = AnyMachine::Http1(SecretsMachine::new(MachineParams::new(
        &snapshot.grants,
        MachineMode::RawTcp,
        raw_host,
        port,
        Direction::Response,
      )));
      relay_guarded(guest, upstream, &mut req, &mut resp, &buf).await
    }
    Route::PlainHttpMachines { host, port: hport, buf } => {
      let upstream = dial_marked(dial_host, port, state.fwmark).await?;
      let mut req = AnyMachine::Http1(SecretsMachine::new(
        MachineParams::new(&snapshot.grants, MachineMode::Http, &host, hport, Direction::Request).hook(state.plugins.select(
          Scheme::Http,
          &host,
          hport,
          HookDirection::Request,
        )),
      ));
      let mut resp = AnyMachine::Http1(SecretsMachine::new(
        MachineParams::new(&snapshot.grants, MachineMode::Http, &host, hport, Direction::Response).hook(state.plugins.select(
          Scheme::Http,
          &host,
          hport,
          HookDirection::Response,
        )),
      ));
      relay_guarded(guest, upstream, &mut req, &mut resp, &buf).await
    }
    Route::MitmTls { identity, buf, hello } => {
      if !state.mint.allow() {
        eyre::bail!("MITM issuance burst exceeded for {identity}");
      }
      state.mint.record();
      let upstream = dial_marked(dial_host, port, state.fwmark).await?;
      let guest_io = GuestIo::with_target(Prefixed::new(buf, guest), &identity, port)?;
      let bridge = BridgeIo(guest_io, GuestIo::bare(upstream));
      let pump = PumpService {
        snapshot: state.snapshot(),
        identity,
        port,
        plugins: Arc::clone(&state.plugins),
      };
      let relay = TlsMitmRelayService::new(state.relay.clone(), pump);
      match hello {
        Some(hello) => relay
          .serve(InputWithClientHello {
            input: bridge,
            client_hello: hello,
          })
          .await
          .map_err(|err| eyre::eyre!("MITM relay: {err}")),
        None => relay.serve(bridge).await.map_err(|err| eyre::eyre!("MITM relay: {err}")),
      }
    }
  }
}

/// Dial upstream, applying the fwmark when set (TUN self-exclusion).
/// Mark failures are fatal: silently unmarked dials would loop back into TUN.
///
/// # Errors
///
/// Returns an error when DNS resolution fails, when every resolved address
/// fails to connect within the overall budget, or when applying the fwmark
/// fails.
pub async fn dial_marked(host: &str, port: u16, fwmark: Option<u32>) -> std::io::Result<TcpStream> {
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
  if fwmark.is_none() {
    return TcpStream::connect(addr).await;
  }
  let opts = Arc::new(SocketOptions {
    mark: fwmark,
    ..SocketOptions::default_tcp()
  });
  // The mark lives on the fd, so the tokio stream unwraps losslessly.
  opts.connect(addr).await.map(|stream| stream.stream).map_err(std::io::Error::other)
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

async fn forward_arm(mut client: TcpStream, head: &[u8], target: &str, state: &ProxyState, snapshot: &ResolvedConfig) -> eyre::Result<()> {
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
  let mut req = AnyMachine::Http1(SecretsMachine::new(
    MachineParams::new(&snapshot.grants, MachineMode::Http, &host, port, Direction::Request).hook(state.plugins.select(
      Scheme::Http,
      &host,
      port,
      HookDirection::Request,
    )),
  ));
  let mut resp = AnyMachine::Http1(SecretsMachine::new(
    MachineParams::new(&snapshot.grants, MachineMode::Http, &host, port, Direction::Response).hook(state.plugins.select(
      Scheme::Http,
      &host,
      port,
      HookDirection::Response,
    )),
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
fn local_addr(listener: &TcpListener) -> SocketAddr {
  listener.local_addr().expect("listener has an address")
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  use hodor_config::grants::{Grant, UriGrant};
  use hodor_config::{PluginDirection, ResolvedPlugin};
  use hodor_pki::ca::install_crypto_provider;
  use rustls::pki_types::ServerName;
  use tokio_rustls::{TlsAcceptor, TlsConnector};

  use crate::substitute::SubMachine;

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
    test_state_with(Vec::new(), &CertAuthority::generate().unwrap())
  }

  fn test_state_with(grants: Vec<Grant>, ca: &CertAuthority) -> Arc<ProxyState> {
    test_state_with_plugins(grants, Vec::new(), ca)
  }

  fn test_state_with_plugins(grants: Vec<Grant>, plugins: Vec<ResolvedPlugin>, ca: &CertAuthority) -> Arc<ProxyState> {
    install_crypto_provider();
    Arc::new(
      ProxyState::new(
        ResolvedConfig {
          proxy: hodor_config::config::ProxyCfg {
            listen: "127.0.0.1:0".parse().unwrap(),
            ca_file: None,
          },
          grants,
          plugins,
        },
        ca,
      )
      .unwrap(),
    )
  }

  async fn run_proxy_with(state: Arc<ProxyState>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = bind_explicit("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
      serve(listener, state).await;
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
    mitm_fixture_with_plugins(make_grants, |_| Vec::new()).await
  }

  /// [`mitm_fixture`] plus plugin fixtures built with the stub port.
  async fn mitm_fixture_with_plugins(
    make_grants: impl Fn(u16) -> Vec<Grant>,
    make_plugins: impl Fn(u16) -> Vec<ResolvedPlugin>,
  ) -> MitmFixture {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let ca_der = ca.cert_der().clone();
    let stub_cert = ca.generate_domain_cert("localhost").unwrap();
    let stub_acceptor = TlsAcceptor::from(Arc::clone(&stub_cert.server_config));
    let stub = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = local_addr(&stub).port();
    let grants = make_grants(stub_port);
    let plugins = make_plugins(stub_port);
    let (proxy_addr, proxy) = run_proxy_with(test_state_with_plugins(grants, plugins, &ca)).await;
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
  async fn connect_authority_sni_mismatch_closes_without_dial() {
    let fx = mitm_fixture(|port| localhost_grant(port, "fake", "value")).await;
    let MitmFixture {
      proxy_addr,
      proxy,
      stub,
      stub_port,
      connector,
      ..
    } = fx;
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
    // Authority says localhost, SNI says otherwise: the relay must close
    // quietly instead of minting, so the handshake fails on EOF.
    let server_name = ServerName::try_from("other.test".to_string()).unwrap();
    let handshake = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, client)).await;
    let failed = match handshake {
      Err(_) | Ok(Err(_)) => true,
      Ok(Ok(_)) => false,
    };
    assert!(failed, "mismatched SNI must not complete a handshake");
    // No upstream dial happened: the stub accept still hangs.
    tokio::time::timeout(Duration::from_secs(2), stub.accept()).await.unwrap_err();
    proxy.abort();
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
    let len = u32::try_from(block.len()).unwrap();
    frame.extend_from_slice(&len.to_be_bytes()[1..]);
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
    let state = test_state_with(grants, &ca);
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
      async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
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
    let state = test_state_with(grants, &ca);
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
      async move { serve_transparent_stream(guest, &state, snapshot.as_ref(), "127.0.0.1", stub_port, "127.0.0.1").await }
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

  /// Hook that votes `Close` on every call.
  struct CloseHook;

  impl hodor_plugin::RewriteHook for CloseHook {
    fn rewrite_head<'a>(&'a mut self, _head: &'a mut hodor_plugin::Head) -> hodor_plugin::BoxFuture<'a, hodor_plugin::Verdict> {
      Box::pin(async move { hodor_plugin::Verdict::Close })
    }

    fn rewrite_trailers<'a>(
      &'a mut self,
      _headers: &'a mut Vec<hodor_plugin::Header>,
    ) -> hodor_plugin::BoxFuture<'a, hodor_plugin::Verdict> {
      Box::pin(async move { hodor_plugin::Verdict::Close })
    }

    fn rewrite_chunk<'a>(&'a mut self, _data: &'a mut Vec<u8>, _eof: bool) -> hodor_plugin::BoxFuture<'a, hodor_plugin::Verdict> {
      Box::pin(async move { hodor_plugin::Verdict::Close })
    }
  }

  #[tokio::test]
  async fn plugin_e2e_close_verdict_drops_connection() {
    let (guest_end, mut client_end) = tokio::io::duplex(64 * 1024);
    let (server_end, mut stub_end) = tokio::io::duplex(64 * 1024);
    let mut req =
      SecretsMachine::new(MachineParams::new(&[], MachineMode::Http, "x", 80, Direction::Request).hook(Some(Box::new(CloseHook))));
    let mut resp = SecretsMachine::new(MachineParams::new(&[], MachineMode::Http, "x", 80, Direction::Response));
    let (relay_out, ()) = tokio::join!(relay_guarded(guest_end, server_end, &mut req, &mut resp, b""), async {
      client_end.write_all(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
    });
    relay_out.unwrap();
    assert!(req.must_close());
    // The latched head never reached the wire: upstream sees nothing.
    // The relay already returned, dropping its server half, so the read
    // resolves as EOF — zero bytes means `Ok(0)`, a leak would be `Ok(n)`.
    let mut buf = [0u8; 64];
    let n = stub_end.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "upstream must receive zero bytes");
  }

  /// Fixture component path, or `None` when `HODOR_PLUGIN_FIXTURES` is unset
  /// or the fixture was not built (`mise run build:plugins` first).
  fn plugin_fixture(name: &str) -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(std::env::var_os("HODOR_PLUGIN_FIXTURES")?).join(format!("{name}.wasm"));
    path.is_file().then_some(path)
  }

  /// Plugin allow list mirroring [`localhost_grant`]: the MITM leg selects
  /// hooks with the same identity the machine receives.
  fn plugin_allow(port: u16) -> Vec<UriGrant> {
    vec![UriGrant {
      scheme: Scheme::Https,
      host: "localhost".parse().unwrap(),
      port,
    }]
  }

  fn plugin_entry(name: &str, port: u16, fixture: std::path::PathBuf) -> ResolvedPlugin {
    ResolvedPlugin {
      name: name.to_string(),
      path: fixture,
      allow: plugin_allow(port),
      direction: PluginDirection::Both,
    }
  }

  #[tokio::test]
  async fn plugin_e2e_request_head_chunk_and_trailers() {
    const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let Some(fixture) = plugin_fixture("marker-request") else {
      println!("skip: HODOR_PLUGIN_FIXTURES missing marker-request.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins(
      |port| localhost_grant(port, FAKE, VALUE),
      |port| vec![plugin_entry("marker-request", port, fixture.clone())],
    )
    .await;
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
      // Stage 1 plugin head effect.
      assert!(head_str.contains("x-hodor-plugin: marker\r\n"), "{head_str}");
      // Chunked rest: the head read may have swallowed the whole message
      // (client sent it in one block); only read more when the chunked
      // terminator is not in hand yet.
      let mut message = head_str;
      while !message.contains("x-trailer-plugin: marker\r\n\r\n") {
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
          .await
          .unwrap()
          .unwrap();
        assert!(n > 0, "unexpected EOF waiting for chunked body");
        message.push_str(&String::from_utf8_lossy(&chunk[..n]));
      }
      assert!(message.contains("C\r\nhello-marked\r\n0\r\n"), "{message}");
      assert!(message.contains("x-client-trailer: yes\r\n"), "{message}");
      assert!(message.contains("x-trailer-plugin: marker\r\n"), "{message}");
      tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls
      .write_all(
        format!(
          "POST /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {FAKE}\r\nTransfer-Encoding: chunked\r\nTrailer: x-client-trailer\r\n\r\n5\r\nhello\r\n0\r\nx-client-trailer: yes\r\n\r\n"
        )
        .as_bytes(),
      )
      .await
      .unwrap();
    let resp = read_head_from(&mut tls).await;
    assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", resp.escape_ascii());
    assert_eq!(read_body(&mut tls, &resp, 2).await, b"hi");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn plugin_e2e_response_head_and_chunk() {
    let Some(fixture) = plugin_fixture("marker-response") else {
      println!("skip: HODOR_PLUGIN_FIXTURES missing marker-response.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins(
      |port| localhost_grant(port, "fake", "value"),
      |port| vec![plugin_entry("marker-response", port, fixture.clone())],
    )
    .await;
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
      assert!(
        !String::from_utf8(head).unwrap().contains("x-hodor-response-plugin"),
        "response-only world leaves the request leg alone"
      );
      tls
        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        .await
        .unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let resp = read_head_from(&mut tls).await;
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(resp_str.contains("x-hodor-response-plugin: marker\r\n"), "{resp_str}");
    // The chunk hook grew the body; chunked framing carries the new size.
    let mut message = resp;
    while !message.ends_with(b"0\r\n\r\n") {
      let mut chunk = [0u8; 4096];
      let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      assert!(n > 0, "unexpected EOF waiting for chunked body");
      message.extend_from_slice(&chunk[..n]);
    }
    let message = String::from_utf8_lossy(&message);
    assert!(message.contains("C\r\nhello-marked\r\n0\r\n\r\n"), "{message}");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn plugin_e2e_h2_chunk_hook_per_frame() {
    use httlib_hpack::{Decoder, Encoder};

    fn data_frame(flags: u8, payload: &[u8]) -> Vec<u8> {
      let mut frame = Vec::new();
      frame.push(((payload.len() >> 16) & 0xff) as u8);
      frame.push(((payload.len() >> 8) & 0xff) as u8);
      frame.push((payload.len() & 0xff) as u8);
      frame.extend_from_slice(&[0x0, flags, 0, 0, 0, 1]);
      frame.extend_from_slice(payload);
      frame
    }

    let Some(fixture) = plugin_fixture("marker-request") else {
      println!("skip: HODOR_PLUGIN_FIXTURES missing marker-request.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins(
      |port| localhost_grant(port, "fake", "value"),
      |port| vec![plugin_entry("marker-request", port, fixture.clone())],
    )
    .await;
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
      let mut preface = [0u8; 24];
      tls.read_exact(&mut preface).await.unwrap();
      assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
      let mut hdr = [0u8; 9];
      tls.read_exact(&mut hdr).await.unwrap();
      assert_eq!(hdr[3], 0x1, "expected HEADERS");
      let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
      let mut block = vec![0u8; len];
      tls.read_exact(&mut block).await.unwrap();
      let mut decoder = Decoder::default();
      let mut headers = Vec::new();
      decoder.decode(&mut block, &mut headers).unwrap();
      assert!(
        headers
          .iter()
          .any(|(name, value, _)| name == b"x-hodor-plugin" && value == b"marker"),
        "head hook marker upstream"
      );
      // Three DATA frames, END_STREAM only on the last.
      let mut bodies = Vec::new();
      for (i, end_stream) in [false, false, true].iter().enumerate() {
        let mut hdr = [0u8; 9];
        tls.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[3], 0x0, "expected DATA frame {i}");
        assert_eq!(hdr[4] & 0x1, u8::from(*end_stream), "END_STREAM on frame {i}");
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let mut payload = vec![0u8; len];
        tls.read_exact(&mut payload).await.unwrap();
        bodies.push(payload);
      }
      // One marker per DATA frame: the hook ran per frame (streaming),
      // not once over a buffered body (which would mark at most once).
      let joined = String::from_utf8(bodies.concat()).unwrap();
      assert_eq!(joined.matches("-marked").count(), 3, "{joined}");
      assert_eq!(joined.replace("-marked", ""), "AAAAAAAABBBBBBBBC");
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    let mut encoder = Encoder::default();
    let mut block = Vec::new();
    for (name, value) in [
      (":method", "POST"),
      (":scheme", "https"),
      (":path", "/x"),
      (":authority", "localhost"),
    ] {
      encoder
        .encode(
          (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
          &mut block,
        )
        .unwrap();
    }
    let mut req = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
    req.push(((block.len() >> 16) & 0xff) as u8);
    req.push(((block.len() >> 8) & 0xff) as u8);
    req.push((block.len() & 0xff) as u8);
    req.extend_from_slice(&[0x1, 0x4, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS
    req.extend_from_slice(&block);
    req.extend_from_slice(&data_frame(0x0, b"AAAAAAAA"));
    req.extend_from_slice(&data_frame(0x0, b"BBBBBBBB"));
    req.extend_from_slice(&data_frame(0x1, b"C"));
    tls.write_all(&req).await.unwrap();
    tls.flush().await.unwrap();
    let mut one = [0u8; 1];
    assert_eq!(tls.read(&mut one).await.unwrap(), 0);
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn plugin_e2e_h2_trailers_hook() {
    use httlib_hpack::{Decoder, Encoder};

    let Some(fixture) = plugin_fixture("marker-request") else {
      println!("skip: HODOR_PLUGIN_FIXTURES missing marker-request.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins(
      |port| localhost_grant(port, "fake", "value"),
      |port| vec![plugin_entry("marker-request", port, fixture.clone())],
    )
    .await;
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
      let mut preface = [0u8; 24];
      tls.read_exact(&mut preface).await.unwrap();
      // Skip the request HEADERS; the second HEADERS block is trailers.
      for _ in 0..2 {
        let mut hdr = [0u8; 9];
        tls.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[3], 0x1, "expected HEADERS");
        let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
        let mut block = vec![0u8; len];
        tls.read_exact(&mut block).await.unwrap();
        if hdr[4] & 0x1 == 0x1 {
          let mut decoder = Decoder::default();
          let mut headers = Vec::new();
          decoder.decode(&mut block, &mut headers).unwrap();
          assert!(headers.iter().any(|(name, value, _)| name == b"x-t" && value == b"abc"));
          assert!(
            headers
              .iter()
              .any(|(name, value, _)| name == b"x-trailer-plugin" && value == b"marker"),
            "trailer hook marker upstream"
          );
        }
      }
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    let mut encoder = Encoder::default();
    let mut head_block = Vec::new();
    for (name, value) in [
      (":method", "POST"),
      (":scheme", "https"),
      (":path", "/x"),
      (":authority", "localhost"),
    ] {
      encoder
        .encode(
          (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
          &mut head_block,
        )
        .unwrap();
    }
    let mut trailer_block = Vec::new();
    encoder
      .encode(
        ("x-t".as_bytes().to_vec(), "abc".as_bytes().to_vec(), Encoder::NEVER_INDEXED),
        &mut trailer_block,
      )
      .unwrap();
    let mut req = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
    req.push(((head_block.len() >> 16) & 0xff) as u8);
    req.push(((head_block.len() >> 8) & 0xff) as u8);
    req.push((head_block.len() & 0xff) as u8);
    req.extend_from_slice(&[0x1, 0x4, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS
    req.extend_from_slice(&head_block);
    req.push(((trailer_block.len() >> 16) & 0xff) as u8);
    req.push(((trailer_block.len() >> 8) & 0xff) as u8);
    req.push((trailer_block.len() & 0xff) as u8);
    req.extend_from_slice(&[0x1, 0x4 | 0x1, 0, 0, 0, 1]); // HEADERS stream 1 END_HEADERS|END_STREAM
    req.extend_from_slice(&trailer_block);
    tls.write_all(&req).await.unwrap();
    tls.flush().await.unwrap();
    let mut one = [0u8; 1];
    assert_eq!(tls.read(&mut one).await.unwrap(), 0);
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn plugin_e2e_grant_mismatch_not_invoked() {
    let Some(fixture) = plugin_fixture("marker-request") else {
      println!("skip: HODOR_PLUGIN_FIXTURES missing marker-request.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins(
      |port| localhost_grant(port, "fake", "value"),
      |port| {
        vec![ResolvedPlugin {
          name: "marker-request".to_string(),
          path: fixture.clone(),
          allow: vec![UriGrant {
            scheme: Scheme::Https,
            host: "other.invalid".parse().unwrap(),
            port,
          }],
          direction: PluginDirection::Both,
        }]
      },
    )
    .await;
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
      assert!(
        !String::from_utf8(head).unwrap().contains("x-hodor-plugin"),
        "ungranted plugin stays out of the head"
      );
      tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await.unwrap();
      tls.shutdown().await.unwrap();
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let resp = read_head_from(&mut tls).await;
    assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"), "{}", resp.escape_ascii());
    assert_eq!(read_body(&mut tls, &resp, 2).await, b"hi");
    stub_task.await.unwrap();
    proxy.abort();
  }

  #[tokio::test]
  async fn plugin_e2e_trap_fails_closed() {
    let Some(fixture) = plugin_fixture("trap-request") else {
      println!("skip: HODOR_PLUGIN_FIXTURES missing trap-request.wasm");
      return;
    };
    let fx = mitm_fixture_with_plugins(
      |port| localhost_grant(port, "fake", "value"),
      |port| vec![plugin_entry("trap-request", port, fixture.clone())],
    )
    .await;
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
      // The proxy already completed the upstream TLS handshake before the
      // guest trapped on the request head: application bytes must be zero.
      let mut buf = [0u8; 64];
      let res = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await.unwrap();
      assert!(
        matches!(res, Ok(0)) || res.is_err(),
        "upstream must receive zero bytes, got {res:?}"
      );
    });
    let mut tls = mitm_client_tls(proxy_addr, stub_port, &connector).await;
    tls.write_all(b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let mut one = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut one)).await.unwrap();
    assert!(matches!(res, Ok(0)) || res.is_err(), "guest connection must drop, got {res:?}");
    stub_task.await.unwrap();
    proxy.abort();
  }
}
