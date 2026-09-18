//! Live capture tests: these need root (`bpf(2)` plus cgroup writes) and are
//! run explicitly through `mise run test:ebpf`.
//!
//! They exercise the real kernel path — programs loaded and attached to a
//! cgroup the test creates — so they are the only tests that can catch a wrong
//! map layout, a wrong byte order, or an attach type the kernel rejects.
//!
//! Two things make them work as ordinary in-process tests rather than needing a
//! separate client process:
//!
//! - `SelfExclusion::Nothing` disables the PID check. With the real PID, this
//!   process's own client sockets would be "hodor's own" and never captured.
//! - the stub upstream sits on loopback, which the programs never rewrite. So
//!   hodor's own dials cannot be captured even with the PID check disabled:
//!   there is no loop for them to fall into.
//!
//! Every connect target is TEST-NET-2 (`198.51.100.0/24`), not loopback: the
//! programs deliberately skip loopback destinations, so a loopback client would
//! prove nothing about capture.

#![cfg(test)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hodor_config::config::ProxyCfg;
use hodor_config::grants::{Grant, ResolvedConfig, Scheme, UriGrant};
use hodor_proxy::ProxyState;

use crate::{Options, SelfExclusion, run_ebpf_with};

/// Serializes the live tests: each one creates a host-wide cgroup.
static LIVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A cgroup for one live test, removed on drop.
///
/// The programs are attached here, so only processes the test places in it are
/// captured. That is the whole point of the eBPF backend, and it keeps the test
/// from disturbing the machine it runs on.
struct TestCgroup(std::path::PathBuf);

impl TestCgroup {
  /// Create `/sys/fs/cgroup/hodor-test-<pid>-<suffix>`.
  fn create(suffix: &str) -> Self {
    let path = std::path::PathBuf::from(format!("/sys/fs/cgroup/hodor-test-{}-{suffix}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap_or_else(|err| panic!("create cgroup {}: {err}", path.display()));
    Self(path)
  }

  fn path(&self) -> &std::path::Path {
    &self.0
  }

  /// Move `pid` into this cgroup, so its sockets get captured.
  fn admit(&self, pid: u32) {
    std::fs::write(self.0.join("cgroup.procs"), pid.to_string())
      .unwrap_or_else(|err| panic!("move pid {pid} into {}: {err}", self.0.display()));
  }
}

impl Drop for TestCgroup {
  fn drop(&mut self) {
    // Best-effort: a leftover empty cgroup is untidy but harmless.
    let _ = std::fs::remove_dir(&self.0);
  }
}

/// A `ProxyState` with the given grants.
fn state_with(grants: Vec<Grant>, ca: &hodor_pki::ca::CertAuthority) -> Arc<ProxyState> {
  Arc::new(
    ProxyState::new(
      ResolvedConfig {
        proxy: ProxyCfg {
          listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
          ca_file: None,
        },
        grants,
        plugins: Vec::new(),
      },
      ca,
    )
    .unwrap(),
  )
}

/// Start capture, move this process into its cgroup, and fail loudly if the
/// attach never came up.
async fn start_capture(
  cgroup: &TestCgroup,
  state: Arc<ProxyState>,
  upstream_override: Option<SocketAddr>,
) -> tokio::task::JoinHandle<eyre::Result<()>> {
  let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
  let capture = tokio::spawn(run_ebpf_with(
    Options {
      cgroup: Some(cgroup.path().to_path_buf()),
      upstream_override,
      self_exclusion: SelfExclusion::Nothing,
      ready: Some(ready_tx),
      ..Options::default()
    },
    state,
  ));
  // Surface attach errors here rather than at connect time. The three outcomes
  // are distinct and all matter: signalled means attached and accepting; a
  // dropped sender means the task died before it was ready; a timeout means it
  // is still not ready. Without telling the last two apart, a load or attach
  // failure shows up as an unrelated connect timeout — and a test asserting
  // that traffic is *not* captured would pass vacuously.
  match tokio::time::timeout(Duration::from_secs(5), ready_rx).await {
    Ok(Ok(())) => {}
    Ok(Err(_)) => {
      let result = capture.await.expect("capture task");
      panic!("capture task died before it was ready: {result:?}");
    }
    Err(_) => {
      let result = capture.await.expect("capture task");
      panic!("capture task not ready after 5s: {result:?}");
    }
  }
  cgroup.admit(std::process::id());
  capture
}

/// The TCP point of the backend: a captured connection is MITM'd, with
/// fake→real on the request and real→fake on the response.
///
/// The eBPF twin of `tproxy_live_tcp_mitm_substitutes`. The guest targets
/// TEST-NET-2 so the kernel capture path is real, while `upstream_override`
/// remaps hodor's own dial to a loopback stub.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes)"]
async fn ebpf_live_tcp_mitm_substitutes() {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const SNI: &str = "testebpf.invalid";
  const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

  let _live = LIVE_LOCK.lock().await;

  hodor_pki::ca::install_crypto_provider();
  let ca = hodor_pki::ca::CertAuthority::generate().unwrap();
  let ca_der = ca.cert_der().clone();
  let stub_cert = hodor_pki::ca::generate_domain_cert(SNI, &ca).unwrap();
  let stub_acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&stub_cert.server_config));
  let stub = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  let stub_port = stub.local_addr().unwrap().port();

  let state = state_with(
    vec![Grant {
      label: "t".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
      allow: vec![UriGrant {
        scheme: Scheme::Https,
        host: SNI.parse().unwrap(),
        port: stub_port,
      }],
    }],
    &ca,
  );

  let cgroup = TestCgroup::create("tcp");
  let capture = start_capture(&cgroup, state, Some(SocketAddr::from((Ipv4Addr::LOCALHOST, stub_port)))).await;

  let stub_task = tokio::spawn(async move {
    let (conn, _) = stub.accept().await.unwrap();
    let mut tls = stub_acceptor.accept(conn).await.unwrap();
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
      let n = tls.read(&mut chunk).await.unwrap();
      head.extend_from_slice(&chunk[..n]);
    }
    let head_str = String::from_utf8(head).unwrap();
    // The upstream sees the real value: substitution happened in flight.
    assert!(head_str.contains(&format!("Bearer {VALUE}")), "{head_str}");
    let body = format!("echo:{VALUE}");
    tls
      .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
      .await
      .unwrap();
    tls.shutdown().await.unwrap();
  });

  let mut roots = rustls::RootCertStore::empty();
  roots.add(ca_der).unwrap();
  let connector = tokio_rustls::TlsConnector::from(Arc::new(
    rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
  ));

  let tcp = match tokio::time::timeout(
    Duration::from_secs(10),
    tokio::net::TcpStream::connect(SocketAddr::from((DST, stub_port))),
  )
  .await
  {
    Ok(Ok(tcp)) => tcp,
    state => {
      let result = capture.await.expect("capture task");
      panic!("guest connect failed ({state:?}); capture task result: {result:?}");
    }
  };
  let server_name = rustls::pki_types::ServerName::try_from(SNI.to_string()).unwrap();
  let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
    .await
    .unwrap()
    .unwrap();
  tls
    .write_all(format!("GET /x HTTP/1.1\r\nHost: {SNI}\r\nAuthorization: Bearer {FAKE}\r\n\r\n").as_bytes())
    .await
    .unwrap();

  let mut resp = Vec::new();
  let mut chunk = [0u8; 4096];
  while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
      .await
      .unwrap()
      .unwrap();
    resp.extend_from_slice(&chunk[..n]);
  }
  let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
  let mut body = Vec::from(&resp[head_end..]);
  let expect = format!("echo:{FAKE}");
  while body.len() < expect.len() {
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
      .await
      .unwrap()
      .unwrap();
    body.extend_from_slice(&chunk[..n]);
  }
  // The response came back redacted: the guest never sees the real value.
  assert_eq!(body, expect.as_bytes());
  stub_task.await.unwrap();
  capture.abort();
}

/// Connected UDP is relayed both ways, and the reply the client observes must
/// carry the *original* destination as its source.
///
/// That last part is the `recvmsg4` hook, and it is load-bearing: the reply
/// physically arrives from hodor's loopback listener, while the client's socket
/// is connected to TEST-NET-2, so without the rewrite the kernel would filter
/// it as a source mismatch and the receive below would time out.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes)"]
async fn ebpf_live_udp_relay_roundtrip() {
  const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);

  let _live = LIVE_LOCK.lock().await;

  hodor_pki::ca::install_crypto_provider();
  let ca = hodor_pki::ca::CertAuthority::generate().unwrap();
  // No grants: the UDP leg is a relay, and substitution plays no part in it.
  let state = state_with(Vec::new(), &ca);

  let stub = tokio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  let stub_addr = stub.local_addr().unwrap();
  let stub_port = stub_addr.port();
  tokio::spawn(async move {
    let mut buf = [0u8; 2048];
    loop {
      let Ok((n, from)) = stub.recv_from(&mut buf).await else {
        return;
      };
      let mut reply = b"echo:".to_vec();
      reply.extend_from_slice(&buf[..n]);
      let _ = stub.send_to(&reply, from).await;
    }
  });

  let cgroup = TestCgroup::create("udp");
  let capture = start_capture(&cgroup, state, Some(stub_addr)).await;

  // Connected socket: only `connect()`ed UDP is captured at all, so this is the
  // shape the backend supports. An unconnected `sendto` would never be
  // redirected, which is why DNS is documented as untouched.
  let client = tokio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  client.connect(SocketAddr::from((DST, stub_port))).await.unwrap();

  client.send(b"probe").await.unwrap();
  let mut reply = [0u8; 2048];
  let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut reply))
    .await
    .expect("relay reply within 5s; a timeout here usually means recvmsg4 did not restore the source")
    .unwrap();
  assert_eq!(&reply[..n], b"echo:probe");
  capture.abort();
}

/// A captured connection with no matching grant is spliced byte-for-byte.
///
/// The property that keeps everything else on the network working: capture
/// must redirect, but it must not touch the bytes when no rule applies. Also
/// proves the capture path itself is live — the guest reaches a TEST-NET-2
/// address with no route, so the only way the sentinel arrives is that
/// `connect4` redirected it to hodor's listener.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes)"]
async fn ebpf_live_ungranted_tcp_splices_byte_identical() {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);
  const SENTINEL: &[u8] = b"plain-splice-sentinel";

  let _live = LIVE_LOCK.lock().await;

  hodor_pki::ca::install_crypto_provider();
  let ca = hodor_pki::ca::CertAuthority::generate().unwrap();
  // No grants at all, so nothing can match and the splice path is forced.
  let state = state_with(Vec::new(), &ca);

  let stub = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  let stub_port = stub.local_addr().unwrap().port();
  let stub_task = tokio::spawn(async move {
    let (mut conn, _) = stub.accept().await.unwrap();
    let mut buf = [0u8; 128];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], SENTINEL);
    // Echo back: the client must see the identical bytes.
    conn.write_all(&buf[..n]).await.unwrap();
    conn.shutdown().await.unwrap();
  });

  let cgroup = TestCgroup::create("splice");
  let capture = start_capture(&cgroup, state, Some(SocketAddr::from((Ipv4Addr::LOCALHOST, stub_port)))).await;

  let mut conn = tokio::time::timeout(
    Duration::from_secs(10),
    tokio::net::TcpStream::connect(SocketAddr::from((DST, stub_port))),
  )
  .await
  .expect("captured connect within 10s")
  .expect("connect4 must have redirected this to hodor's listener");
  conn.write_all(SENTINEL).await.unwrap();
  let mut echoed = vec![0u8; SENTINEL.len()];
  let _ = tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut echoed))
    .await
    .expect("spliced reply within 10s")
    .unwrap();
  assert_eq!(echoed, SENTINEL, "splice must be byte-identical");
  stub_task.await.unwrap();
  capture.abort();
}

/// Unconnected `sendto` UDP — the shape every DNS resolver uses — is never
/// captured or relayed.
///
/// Capture is entered at `connect()`, so a socket that never connects has no
/// `ORIG_DST` entry: `capture_egress` records nothing for it and hodor never
/// learns of the flow. The observable is the reply's *source* — a `sendto` the
/// backend had relayed would come back from hodor's listener, not from the
/// stub; receiving it from the stub's own address proves nothing sat in the
/// middle.
#[tokio::test]
#[ignore = "needs root (bpf syscall, cgroup writes)"]
async fn ebpf_live_unconnected_udp_passes_through() {
  const SENTINEL: &[u8] = b"dns-shaped-sentinel";

  let _live = LIVE_LOCK.lock().await;

  hodor_pki::ca::install_crypto_provider();
  let ca = hodor_pki::ca::CertAuthority::generate().unwrap();
  let state = state_with(Vec::new(), &ca);

  // Loopback, and reached without `connect()`: the programs skip loopback
  // destinations, so nothing here can be rewritten — the point is that the
  // datagram still flows end to end with its own addressing intact.
  let stub = tokio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  let stub_addr = stub.local_addr().unwrap();
  let stub_task = tokio::spawn(async move {
    let mut buf = [0u8; 2048];
    let (n, from) = stub.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], SENTINEL, "the stub must receive the untouched datagram");
    let _ = stub.send_to(b"dns-shaped-reply", from).await;
  });

  let cgroup = TestCgroup::create("udp-passthrough");
  let capture = start_capture(&cgroup, state, None).await;

  // No `connect()` anywhere: this socket must reach the stub directly.
  let client = tokio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    .await
    .unwrap();
  client.send_to(SENTINEL, stub_addr).await.unwrap();
  let mut reply = [0u8; 2048];
  let (n, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut reply))
    .await
    .expect("direct reply within 5s; a timeout means the datagram was captured instead")
    .unwrap();
  assert_eq!(&reply[..n], b"dns-shaped-reply");
  assert_eq!(
    from, stub_addr,
    "reply must come from the stub itself: a relayed datagram would arrive from hodor's listener"
  );
  stub_task.await.unwrap();
  capture.abort();
}
