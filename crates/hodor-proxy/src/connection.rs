//! Connection layer: guest adapters, the terminated-TLS pump, dialing.
//! Knows bytes and TLS; nothing of wire formats.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use rama::Service;
use rama::error::BoxError;
use rama::extensions::{Extensions, ExtensionsRef};
use rama::io::BridgeIo;
use rama::net::address::{Host, HostWithPort};
use rama::net::client::ConnectorTarget;
use rama::net::socket::SocketOptions;
use rama::tcp::client::TcpStreamConnector;
use rama::tls::boring::TlsStream;
use rama::tls::client::{ClientAuth, ClientAuthData, NegotiatedTlsParameters, TlsClientAuth};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use hodor_config::grants::{DatabaseScope, GuestTlsMode, ResolvedConfig, RootCert, SslMode, SslNegotiation};
use hodor_pki::ca::CertAuthority;

use crate::into_box_error;
use crate::protocol::{PairCtx, https_framing};
use crate::relay::relay_guarded;

/// Guest-side adapter: any tokio stream plus a rama extension map. The relay
/// reads the [`ConnectorTarget`] identity from these extensions to derive
/// egress SNI and verification identity.
pub(crate) struct GuestIo<S> {
  inner: S,
  extensions: Extensions,
}

impl<S> GuestIo<S> {
  pub(crate) fn with_target(inner: S, identity: &str, port: u16) -> eyre::Result<Self> {
    let host: Host = identity.parse().map_err(|err| eyre::eyre!("bad MITM identity {identity}: {err}"))?;
    let extensions = Extensions::new();
    extensions.insert(ConnectorTarget(HostWithPort::new(host, port)));
    Ok(Self { inner, extensions })
  }

  pub(crate) fn bare(inner: S) -> Self {
    Self {
      inner,
      extensions: Extensions::new(),
    }
  }

  /// Record the upstream client identity (mTLS) the relay presents on egress.
  pub(crate) fn with_egress_client_auth(self, auth: TlsClientAuth) -> Self {
    self.extensions.insert(auth);
    self
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

/// Load an upstream client identity (mTLS) from the entry's PEM paths: the
/// certificate chain and its key, ready for the relay's egress. Only the
/// entry names this identity; nothing invents one.
pub(crate) fn client_identity(cert: &Path, key: &Path) -> eyre::Result<TlsClientAuth> {
  let cert_bytes = std::fs::read(cert).map_err(|err| eyre::eyre!("read `{}`: {err}", cert.display()))?;
  let key_bytes = std::fs::read(key).map_err(|err| eyre::eyre!("read `{}`: {err}", key.display()))?;
  let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|err| eyre::eyre!("certificate `{}`: {err}", cert.display()))?;
  eyre::ensure!(!chain.is_empty(), "`{}` holds no certificates", cert.display());
  let private = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|err| eyre::eyre!("key `{}`: {err}", key.display()))?;
  Ok(TlsClientAuth(ClientAuth::Single(ClientAuthData {
    cert_chain: chain,
    private_key: private,
  })))
}

/// Byte-pump service: the relay hands paired TLS streams here, and the
/// substitution machines pump them. Decoded-request middleware is deliberately
/// not used: a `Request<Body>` round-trips through the HTTP codec and would
/// break the byte-identical guarantee the verbatim tests pin.
#[derive(Debug, Clone)]
pub(crate) struct PumpService {
  pub(crate) snapshot: Arc<ResolvedConfig>,
  pub(crate) identity: String,
  pub(crate) port: u16,
  pub(crate) plugins: Arc<hodor_plugin::Registry>,
  pub(crate) mint: Option<crate::mint::MintHandle>,
}
impl<GI, GE> Service<BridgeIo<TlsStream<GI>, TlsStream<GE>>> for PumpService
where
  GI: AsyncRead + AsyncWrite + Unpin + Send + 'static + ExtensionsRef,
  GE: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  type Output = ();
  type Error = BoxError;

  async fn serve(&self, input: BridgeIo<TlsStream<GI>, TlsStream<GE>>) -> Result<Self::Output, Self::Error> {
    let BridgeIo(mut guest_tls, mut server_tls) = input;
    // The scope that matched selected TLS termination; framing picks the legs.
    // Schemes below are grant scopes (authorization), never selection.
    let ctx = PairCtx {
      grants: &self.snapshot.grants,
      host: &self.identity,
      port: self.port,
      plugins: &self.plugins,
      mint: self.mint.clone(),
    };
    // The relay handshook the upstream leg before the guest's, and answered
    // the guest with what that leg agreed, so this one fact frames both
    // directions. Nothing here reads a plaintext byte.
    let negotiated = guest_tls
      .extensions()
      .get_ref::<NegotiatedTlsParameters>()
      .and_then(|params| params.application_layer_protocol.as_ref());
    let (mut downstream_machine, mut upstream_machine) = https_framing(&ctx, negotiated);
    relay_guarded(&mut guest_tls, &mut server_tls, &mut downstream_machine, &mut upstream_machine, &[])
      .await
      .map_err(|err| into_box_error(&err))
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

/// A stream prefixed with already-read bytes (replays `initial_buf` first).
pub(crate) struct Prefixed<S> {
  prefix: Vec<u8>,
  pos: usize,
  inner: S,
}

impl<S> Prefixed<S> {
  pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
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

/// Postgres transport halves.
///
/// The guest's transport is the guest's choice, so this half answers what the
/// guest asked for with a leaf minted for the name it asked for. The server's
/// transport is the entry URL's statement, so that half negotiates, offers and
/// verifies exactly what the URL says, and nothing this proxy would prefer.
#[derive(Debug)]
pub(crate) struct PgTransport {
  ca: CertAuthority,
  provider: Arc<rustls::crypto::CryptoProvider>,
  leaves: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
  roots: Mutex<HashMap<RootCert, Arc<RootCertStore>>>,
}

impl PgTransport {
  /// Build both halves over the CA that signs guest-facing leaves.
  ///
  /// # Errors
  ///
  /// Returns an error when the CA cannot be read back from its own PEM.
  pub(crate) fn new(ca: &CertAuthority) -> eyre::Result<Self> {
    Ok(Self {
      // An own handle on the same CA: minting needs its signing key, and the
      // caller's borrow ends with this call.
      ca: CertAuthority::load(&ca.cert_pem(), &ca.key_pem())?,
      provider: rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())),
      leaves: Mutex::new(HashMap::new()),
      roots: Mutex::new(HashMap::new()),
    })
  }

  /// Accept the guest's TLS, minting the leaf for `sni` on first use.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the handshake fails.
  pub(crate) async fn accept_guest<G>(
    &self,
    sni: &str,
    guest: G,
    guest_tls: GuestTlsMode,
  ) -> eyre::Result<tokio_rustls::server::TlsStream<G>>
  where
    G: AsyncRead + AsyncWrite + Unpin,
  {
    let config = match guest_tls {
      GuestTlsMode::Tls => self.leaf(sni)?,
      // `mtls` asks the guest for a client certificate and admits only ones
      // this hodor's own CA signs — the same anchor that mints the leaves.
      GuestTlsMode::Mtls => self.leaf_mtls(sni)?,
    };
    TlsAcceptor::from(config)
      .accept(guest)
      .await
      .map_err(|err| eyre::eyre!("guest postgres TLS: {err}"))
  }

  /// Handshake the server, verifying only what the entry asked to verify.
  ///
  /// # Errors
  ///
  /// Returns an error when the named trust anchor cannot be read, when the
  /// server name is unusable, or when the handshake fails.
  pub(crate) async fn connect_server<S>(
    &self,
    scope: &DatabaseScope,
    server_name: &str,
    server: S,
  ) -> eyre::Result<tokio_rustls::client::TlsStream<S>>
  where
    S: AsyncRead + AsyncWrite + Unpin,
  {
    let roots = match &scope.root_cert {
      Some(root) => Some(self.roots_for(root)?),
      None => None,
    };
    let verifier = PgCertVerifier {
      roots,
      check_name: scope.ssl == SslMode::VerifyFull,
      provider: Arc::clone(&self.provider),
    };
    let builder = rustls::ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(verifier));
    let mut config = match (&scope.client_cert, &scope.client_key) {
      // The entry names the proxy's client identity, so the upstream leg
      // presents it; nothing else invents one.
      (Some(cert), Some(key)) => {
        let TlsClientAuth(ClientAuth::Single(data)) = client_identity(cert, key)? else {
          eyre::bail!("client identity `{}` is empty", cert.display());
        };
        builder
          .with_client_auth_cert(data.cert_chain.clone(), data.private_key.clone_key())
          .map_err(|err| eyre::eyre!("client identity `{}`: {err}", cert.display()))?
      }
      _ => builder.with_no_client_auth(),
    };
    if scope.negotiation == SslNegotiation::Direct {
      // Direct TLS is defined by this identifier, on both ends (RFC 9113 does
      // the same for `h2`). A negotiated-shape client offers nothing.
      config.alpn_protocols = vec![POSTGRESQL_ALPN.to_vec()];
    }
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| eyre::eyre!("postgres server name: {err}"))?;
    TlsConnector::from(Arc::new(config))
      .connect(name, server)
      .await
      .map_err(|err| eyre::eyre!("server postgres TLS: {err}"))
  }

  /// Leaf for one name, cached. Minted outside the lock so two guests naming
  /// the same host keygen at most twice and never while a lock is held.
  fn leaf(&self, sni: &str) -> eyre::Result<Arc<rustls::ServerConfig>> {
    if let Some(config) = self.lock_leaves().get(sni) {
      return Ok(Arc::clone(config));
    }
    let mut config = (*self.ca.generate_domain_cert(sni)?.server_config).clone();
    // A real server offers this identifier, and a direct-TLS client looks for
    // it (PostgreSQL 17). Classic clients offer no ALPN and see none.
    config.alpn_protocols = vec![POSTGRESQL_ALPN.to_vec()];
    let config = Arc::new(config);
    self.lock_leaves().insert(sni.to_string(), Arc::clone(&config));
    Ok(config)
  }

  /// `mtls` variant of [`Self::leaf`]: the same leaf shape, presented by a
  /// config that demands a client certificate this hodor's CA can verify.
  ///
  /// # Errors
  ///
  /// Returns an error when the leaf cannot be minted or the verifier cannot
  /// be built.
  fn leaf_mtls(&self, sni: &str) -> eyre::Result<Arc<rustls::ServerConfig>> {
    let cache_key = format!("{sni}|mtls");
    if let Some(config) = self.lock_leaves().get(&cache_key) {
      return Ok(Arc::clone(config));
    }
    let (chain, key_der) = hodor_pki::ca::generate_domain_pair(&self.ca, sni)?;
    let mut roots = RootCertStore::empty();
    roots
      .add(self.ca.cert_der().clone())
      .map_err(|err| eyre::eyre!("mtls guest roots: {err}"))?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
      .build()
      .map_err(|err| eyre::eyre!("mtls guest verifier: {err}"))?;
    let mut config = rustls::ServerConfig::builder()
      .with_client_cert_verifier(verifier)
      .with_single_cert(chain, key_der)
      .map_err(|err| eyre::eyre!("mtls leaf: {err}"))?;
    config.alpn_protocols = vec![POSTGRESQL_ALPN.to_vec()];
    let config = Arc::new(config);
    self.lock_leaves().insert(cache_key, Arc::clone(&config));
    Ok(config)
  }

  /// Trust anchors from the entry's `sslrootcert`, read once per path.
  fn roots_for(&self, root: &RootCert) -> eyre::Result<Arc<RootCertStore>> {
    if let Some(store) = self.lock_roots().get(root) {
      return Ok(Arc::clone(store));
    }
    let store = match root {
      RootCert::Path(path) => {
        let pem = std::fs::read(path).map_err(|err| eyre::eyre!("sslrootcert {}: {err}", path.display()))?;
        let mut store = RootCertStore::empty();
        let mut anchors = 0usize;
        for cert in CertificateDer::pem_slice_iter(&pem) {
          let cert = cert.map_err(|err| eyre::eyre!("sslrootcert {}: {err}", path.display()))?;
          store
            .add(cert)
            .map_err(|err| eyre::eyre!("sslrootcert {}: {err}", path.display()))?;
          anchors += 1;
        }
        eyre::ensure!(anchors > 0, "sslrootcert {}: no certificate in file", path.display());
        store
      }
      // `system` names the platform trust store exactly; an unreadable or
      // empty store fails closed rather than silently verifying nothing.
      RootCert::System => {
        let native = rustls_native_certs::load_native_certs();
        if let Some(err) = native.errors.first() {
          eyre::bail!("sslrootcert system store: {err}");
        }
        let mut store = RootCertStore::empty();
        for cert in native.certs {
          store.add(cert).map_err(|err| eyre::eyre!("sslrootcert system store: {err}"))?;
        }
        eyre::ensure!(!store.is_empty(), "sslrootcert system store holds no certificates");
        store
      }
    };
    let store = Arc::new(store);
    self.lock_roots().insert(root.clone(), Arc::clone(&store));
    Ok(store)
  }

  fn lock_leaves(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<rustls::ServerConfig>>> {
    self.leaves.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
  }

  fn lock_roots(&self) -> std::sync::MutexGuard<'_, HashMap<RootCert, Arc<RootCertStore>>> {
    self.roots.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
  }
}

/// ALPN identifier for direct Postgres TLS.
const POSTGRESQL_ALPN: &[u8] = b"postgresql";

/// Server verification shaped by the entry URL rather than by this proxy.
///
/// libpq verifies nothing when no trust anchor is named, which is what makes
/// `require` usable against a private server; it verifies the chain once one
/// is; and it checks the host name only for `verify-full`. Inventing an anchor
/// here would fail the servers those modes exist to reach.
#[derive(Debug)]
struct PgCertVerifier {
  roots: Option<Arc<RootCertStore>>,
  check_name: bool,
  provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PgCertVerifier {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    _ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, RustlsError> {
    let Some(roots) = self.roots.as_ref() else {
      return Ok(ServerCertVerified::assertion());
    };
    let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
    rustls::client::verify_server_cert_signed_by_trust_anchor(
      &cert,
      roots,
      intermediates,
      now,
      self.provider.signature_verification_algorithms.all,
    )?;
    if self.check_name {
      rustls::client::verify_server_name(&cert, server_name)?;
    }
    Ok(ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.provider.signature_verification_algorithms.supported_schemes()
  }
}
