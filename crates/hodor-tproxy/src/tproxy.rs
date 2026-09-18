//! TPROXY capture: a kernel-transparent listener plus netlink-installed
//! rules (`nft.rs`, `route.rs`). The kernel terminates TCP; hodor sees
//! plain accepted streams with the original destination recoverable from
//! `local_addr()`. Non-matching traffic splices through the same
//! `serve_candidate_stream` machinery as explicit CONNECT.
//!
//! Privileges: `CAP_NET_ADMIN` (nft table, fib rules, `IP_TRANSPARENT`).

use crate::nft;
use crate::route;

use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd as _;
use std::path::Path;
use std::sync::Arc;

use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::none::ControlMessage;
use netlink_packet_netfilter::{NetfilterHeader, NetfilterMessage, NetfilterProtoFamily};
use netlink_sys::Socket;
use netlink_sys::SocketAddr as NetlinkSocketAddr;
use netlink_sys::constants::NETLINK_NETFILTER;
use rama::net::address::SocketAddress;
use rama::net::socket::SocketOptions;
use rama::net::socket::opts::Domain;
use tokio::net::TcpStream;

use hodor_config::grants::ResolvedConfig;
use hodor_proxy::{ProxyState, serve_candidate_stream};

/// Capture mark: the nft OUTPUT rule sets it on intercepted TCP, the fib
/// rule routes marked packets to the local-delivery table, and the
/// prerouting rule hands them to the transparent listener.
pub const FWMARK: u32 = 0x88;
/// Mark for hodor's own upstream dials. Deliberately different from
/// [`FWMARK`]: no fib rule matches it, so hodor's egress keeps normal
/// routing, and the nft OUTPUT rule skips it instead of re-marking it into
/// the capture table (which would blackhole the dial).
pub const EGRESS_MARK: u32 = 0x89;
const ROUTE_TABLE: u8 = 100;
const NFT_TABLE: &str = "hodor_tproxy";
const LISTEN_PORT: u16 = 15000;

/// Install rules + routes, then accept captured connections forever.
///
/// # Errors
///
/// Returns an error when the capture rules cannot be installed or the
/// listener cannot be bound.
pub async fn run_tproxy(state: Arc<ProxyState>, allow_root_netns: bool) -> eyre::Result<()> {
  run_tproxy_with(
    Options {
      allow_root_netns,
      ..Options::default()
    },
    state,
  )
  .await
}

/// Test seams over [`run_tproxy`].
#[derive(Debug, Default)]
pub(crate) struct Options {
  /// Restrict the OUTPUT mark rule to one exact destination address, so
  /// live tests leave the host untouched.
  pub scope: Option<Ipv4Addr>,
  /// Transparent listener port (tests avoid collisions).
  pub port: Option<u16>,
  /// Dial this address instead of the captured destination (stub upstream).
  pub upstream_override: Option<SocketAddr>,
  /// Signalled once rules are installed and the listener is accepting.
  pub ready: Option<tokio::sync::oneshot::Sender<()>>,
  /// Explicit acknowledgment that unscoped capture in this network
  /// namespace is intended (VM, container, disposable host).
  pub allow_root_netns: bool,
}

/// Pure refusal decision for unscoped capture.
///
/// Unscoped rules mark and reroute every outbound TCP packet in the
/// enclosing network namespace. In a machine someone is using, that is an
/// outage waiting for an unclean exit: between install and guard teardown a
/// SIGKILL leaves the rules installed, and the machine loses all TCP egress
/// until an operator removes them by hand. Scoped rules cannot do that, so
/// they stand on their own; unscoped rules need an isolated netns or
/// explicit acknowledgment.
fn unscoped_capture_refused(has_scope: bool, isolated_netns: bool, allow_root_netns: bool) -> bool {
  !has_scope && !isolated_netns && !allow_root_netns
}

fn netns_inode(path: &str) -> eyre::Result<u64> {
  use std::os::unix::fs::MetadataExt as _;
  std::fs::metadata(path)
    .map(|meta| meta.ino())
    .map_err(|err| eyre::eyre!("stat {path}: {err}"))
}

/// True when our network namespace differs from PID 1's: `ip netns`,
/// bubblewrap `--unshare-net`, or a VM. The root netns of a bare host reads
/// false, which is the point.
fn netns_isolated() -> eyre::Result<bool> {
  Ok(netns_inode("/proc/self/ns/net")? != netns_inode("/proc/1/ns/net")? || in_container())
}

/// Container runtimes leave marker files; a container's default network is
/// its own namespace, so unscoped capture stays inside it. `network_mode:
/// host` opts out of that isolation explicitly and must not rely on markers.
fn in_container() -> bool {
  Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

fn assert_unscoped_capture_allowed(options: &Options) -> eyre::Result<()> {
  if options.allow_root_netns {
    tracing::warn!(
      "installing unscoped TPROXY capture rules by explicit request; cleanup if this process is SIGKILLed: \
       nft delete table inet hodor_tproxy; ip rule del pref 200 fwmark 0x88 table 100"
    );
    return Ok(());
  }
  let isolated = netns_isolated()?;
  if unscoped_capture_refused(options.scope.is_some(), isolated, false) {
    eyre::bail!(
      "refusing to install unscoped TPROXY capture rules in the host network namespace: every outbound TCP \
       packet would be rerouted into hodor until the process exits cleanly. Run inside a network namespace \
       (bubblewrap / ip netns / VM) or pass --tproxy-allow-root-netns (env HODOR_TPROXY_ALLOW_ROOT_NETNS=1) \
       if this machine is disposable"
    );
  }
  Ok(())
}

pub(crate) async fn run_tproxy_with(options: Options, state: Arc<ProxyState>) -> eyre::Result<()> {
  assert_unscoped_capture_allowed(&options)?;
  let listener = transparent_listener(options.port.unwrap_or(LISTEN_PORT))?;
  let listen_port = listener.local_addr()?.port();
  let handle = route::netlink()?;
  let lo = route::link_index(&handle, "lo").await?;
  for plan in route::proxy_rules(ROUTE_TABLE) {
    route::add_rule(&handle, &plan).await?;
  }
  route::add_local_route(&handle, ROUTE_TABLE, lo).await?;
  let _routes = route::RouteGuard::new(route::proxy_undos(ROUTE_TABLE));

  let capture = crate::nft::CaptureConfig {
    listen_port,
    fwmark: FWMARK,
    egress_mark: EGRESS_MARK,
    scope: options.scope,
    table: NFT_TABLE.into(),
  };
  // Self-heal first: a SIGKILLed previous run skips the Drop guards and
  // leaves the table installed, and the exclusive create below would then
  // fail with EEXIST. Best-effort delete, errors ignored (ENOENT on a
  // clean host is expected).
  let stale_table = vec![capture.teardown_message()];
  let _ = tokio::task::spawn_blocking(move || send_batch(stale_table)).await;
  let install_messages = capture.install_messages();
  tokio::task::spawn_blocking(move || send_batch(install_messages))
    .await
    .map_err(|err| eyre::eyre!("nft install task: {err}"))??;
  let _nft = NftGuard {
    teardown: Some(capture.teardown_message()),
  };
  if let Some(ready) = options.ready {
    let _ = ready.send(());
  }
  tracing::info!(listen_port, fwmark = FWMARK, table = ROUTE_TABLE, "tproxy capturing");
  // No signal handlers here: tokio's ctrl_c()/signal() replace the
  // process-wide SIGINT/SIGTERM dispositions, which would make the host
  // process (and the live test) unkillable with ctrl-c. Teardown runs via
  // the Drop guards when this task is dropped; SIGKILL is uncatchable and
  // the install log names the manual cleanup commands for that case.
  loop {
    let (stream, _peer) = listener.accept().await?;
    // On a transparent socket the local address IS the original destination.
    let Ok(dst) = stream.local_addr() else {
      continue;
    };
    let state = Arc::clone(&state);
    let override_addr = options.upstream_override;
    tokio::spawn(async move {
      if let Err(err) = tproxy_conn_task(stream, dst, override_addr, state).await {
        tracing::debug!(%dst, ?err, "tproxy connection failed");
      }
    });
  }
}

/// One captured TCP connection: the SNI itself is the identity, exactly the
/// TUN shape (no 200, no authority enforcement).
async fn tproxy_conn_task(
  stream: TcpStream,
  dst: SocketAddr,
  upstream_override: Option<SocketAddr>,
  state: Arc<ProxyState>,
) -> eyre::Result<()> {
  let dial = upstream_override.unwrap_or(dst);
  let dial_host = dial.ip().to_string();
  let snapshot: Arc<ResolvedConfig> = state.snapshot();
  let snapshot = &*snapshot;
  serve_candidate_stream(stream, &state, snapshot, &dial_host, dial.port(), None, &dial_host, &[]).await
}

/// `IP_TRANSPARENT` listener on `0.0.0.0:port`.
fn transparent_listener(port: u16) -> eyre::Result<tokio::net::TcpListener> {
  let socket = SocketOptions {
    address: Some(SocketAddress::default_ipv4(port)),
    ip_transparent: Some(true),
    freebind: Some(true),
    reuse_address: Some(true),
    ..SocketOptions::default_tcp()
  }
  .try_build_socket(Domain::IPv4)?;
  socket.set_nonblocking(true)?;
  socket.listen(1024)?;
  Ok(tokio::net::TcpListener::from_std(socket.into())?)
}

/// Sends a prepared nftables batch over a fresh netfilter netlink socket
/// and checks the batch ACK. nftables requires batch context (a point
/// NEWTABLE is rejected with EINVAL — verified against the kernel), and a
/// batch is atomic, which is what we want anyway. Sync netlink is
/// startup/teardown-only, so it runs in `spawn_blocking` / a throwaway
/// thread.
fn send_batch(messages: Vec<NetlinkMessage<NetfilterMessage>>) -> eyre::Result<()> {
  let mut socket = Socket::new(NETLINK_NETFILTER)?;
  // A missing kernel ACK must fail, not hang: without this, a stalled
  // batch blocks the Drop-guard threads (which join()) and the process
  // never exits while still holding the capture rules.
  let timeout = libc::timeval { tv_sec: 5, tv_usec: 0 };
  #[expect(
    clippy::cast_possible_truncation,
    reason = "socklen_t is u32; sizeof timeval is 16 and always fits"
  )]
  let optlen = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
  // SAFETY: setsockopt with a valid fd, a constant option, and a timeval
  // of the exact size the kernel expects for SO_RCVTIMEO.
  let rc = unsafe {
    libc::setsockopt(
      socket.as_raw_fd(),
      libc::SOL_SOCKET,
      libc::SO_RCVTIMEO,
      (&raw const timeout).cast::<libc::c_void>(),
      optlen,
    )
  };
  eyre::ensure!(rc == 0, "SO_RCVTIMEO on nft socket: {}", std::io::Error::last_os_error());
  socket.bind(&NetlinkSocketAddr::new(0, 0))?;

  // NFNL_MSG_BATCH_BEGIN / NFNL_MSG_BATCH_END, nfgen payload matching the
  // nft CLI: family UNSPEC, version 0, res_id htons(NFNL_SUBSYS_NFTABLES).
  // Entries carry res_id 0. Only the END carries NLM_F_ACK: the kernel
  // processes the batch atomically and acks it once (or reports the
  // offending entry's offset).
  let batch_msg = |message_type: u16, flags: u16, seq: u32, res_id: u16| {
    let mut msg = NetlinkMessage::new(
      NetlinkHeader::default(),
      NetlinkPayload::InnerMessage(NetfilterMessage::new(
        NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, res_id),
        ControlMessage::Other {
          // batch message types are the fixed kernel constants 16 and 17
          #[expect(clippy::cast_possible_truncation, reason = "batch types are the fixed kernel constants 16 and 17")]
          message_type: message_type as u8,
          attributes: vec![],
        },
      )),
    );
    msg.header.message_type = message_type;
    msg.header.flags = flags;
    msg.header.sequence_number = seq;
    msg.finalize();
    msg
  };
  let mut entries = messages;
  for (seq, entry) in entries.iter_mut().enumerate() {
    entry.header.sequence_number = u32::try_from(seq + 1).unwrap_or(u32::MAX);
    entry.finalize();
  }

  let mut wire = Vec::new();
  let begin = batch_msg((nft::SUBSYS_NFTABLES << 8) | 0x10, NLM_F_REQUEST, 0, nft::SUBSYS_NFTABLES);
  wire.extend_from_slice(&{
    let mut buf = vec![0u8; begin.buffer_len()];
    begin.serialize(&mut buf);
    buf
  });
  for entry in &entries {
    let mut buf = vec![0u8; entry.buffer_len()];
    entry.serialize(&mut buf);
    wire.extend_from_slice(&buf);
  }
  let end_seq = u32::try_from(entries.len() + 1).unwrap_or(u32::MAX);
  let end = batch_msg(
    (nft::SUBSYS_NFTABLES << 8) | 0x11,
    NLM_F_REQUEST | NLM_F_ACK,
    end_seq,
    nft::SUBSYS_NFTABLES,
  );
  wire.extend_from_slice(&{
    let mut buf = vec![0u8; end.buffer_len()];
    end.serialize(&mut buf);
    buf
  });

  socket.send(&wire, 0)?;
  let (reply, _) = socket.recv_from_full()?;
  let parsed = NetlinkMessage::<NetfilterMessage>::deserialize(&reply)
    .map_err(|err| eyre::eyre!("{err} (raw {} bytes: {})", reply.len(), hex_prefix(&reply)))?;
  match parsed.payload {
    NetlinkPayload::Error(err) => eyre::ensure!(err.code.is_none(), "nft batch failed: {err}"),
    other => eyre::bail!("unexpected nft batch reply: {other:?}"),
  }
  Ok(())
}

/// First bytes of a rejected reply, hex, for error context.
fn hex_prefix(bytes: &[u8]) -> String {
  use std::fmt::Write as _;
  bytes.iter().take(64).fold(String::new(), |mut acc, byte| {
    let _ = write!(acc, "{byte:02x}");
    acc
  })
}

/// Flushes the capture table on drop (best-effort): rules and chains go
/// with it. A stale TPROXY redirect would blackhole traffic after exit, so
/// cleanup is load-bearing.
struct NftGuard {
  teardown: Option<NetlinkMessage<NetfilterMessage>>,
}

impl Drop for NftGuard {
  fn drop(&mut self) {
    if let Some(msg) = self.teardown.take() {
      let _ = std::thread::spawn(move || {
        let _ = send_batch(vec![msg]);
      })
      .join();
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  use hodor_config::grants::{Grant, Scheme, UriGrant};

  /// Main table: the live test's scoped dst route lands here.
  const TABLE_MAIN: u8 = 254;

  static LIVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

  #[test]
  fn options_default_captures_everything() {
    let options = Options::default();
    assert!(options.scope.is_none());
    assert!(options.port.is_none());
    assert!(options.upstream_override.is_none());
    assert!(!options.allow_root_netns);
  }

  #[test]
  fn unscoped_capture_refusal_matrix() {
    // Scoped: allowed, cannot blackhole more than the scoped destination.
    assert!(!unscoped_capture_refused(true, false, false));
    // Isolated netns: allowed, the netns is the blast radius.
    assert!(!unscoped_capture_refused(false, true, false));
    // Explicit acknowledgment: allowed (VM / disposable host).
    assert!(!unscoped_capture_refused(false, false, true));
    // Root netns, no scope, no acknowledgment: refused.
    assert!(unscoped_capture_refused(false, false, false));
  }

  #[tokio::test]
  #[ignore = "needs root (mutates host nft rules and routes)"]
  #[expect(clippy::too_many_lines, reason = "linear live-test script, split would obscure the flow")]
  async fn tproxy_live_tcp_mitm_substitutes() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const FAKE: &str = "$$CREDENTIAL_DODSZYJGK2D0:L$$";
    const VALUE: &str = "$$CREDENTIAL_C1YI2U4SC3JE:L$$";
    const SNI: &str = "testtproxy.invalid";
    const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

    let _live = LIVE_LOCK.lock().await;

    hodor_pki::ca::install_crypto_provider();
    let ca = hodor_pki::ca::CertAuthority::generate().unwrap();
    let ca_der = ca.cert_der().clone();
    let stub_cert = hodor_pki::ca::generate_domain_cert(SNI, &ca).unwrap();
    let stub_acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&stub_cert.server_config));
    // Stub on loopback: upstream_override remaps hodor's dial there. The
    // guest still targets TEST-NET-2 so the kernel capture path is real.
    let stub = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub_port = stub.local_addr().unwrap().port();

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
    let state = Arc::new(
      ProxyState::new(
        ResolvedConfig {
          proxy: hodor_config::config::ProxyCfg {
            listen: "127.0.0.1:0".parse().unwrap(),
            ca_file: None,
          },
          grants,
        },
        ca,
      )
      .with_fwmark(EGRESS_MARK),
    );

    // The guest needs SOME route for its initial lookup of the scoped dst
    // before the OUTPUT mark reroutes it into the capture table; a plain
    // dev-lo route suffices and is undone on drop.
    let route_handle = route::netlink().unwrap();
    let lo = route::link_index(&route_handle, "lo").await.unwrap();
    let dst_route = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
      .destination_prefix(DST, 32)
      .output_interface(lo)
      .table_id(u32::from(TABLE_MAIN))
      .build();
    tokio::time::timeout(Duration::from_secs(5), route_handle.route().add(dst_route).replace().execute())
      .await
      .expect("scoped dst route add within 5s")
      .unwrap();
    let _dst_route_guard = DstRouteGuard;

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let capture = tokio::spawn(run_tproxy_with(
      Options {
        scope: Some(DST),
        port: None,
        upstream_override: Some(SocketAddr::from(([127, 0, 0, 1], stub_port))),
        ready: Some(ready_tx),
        allow_root_netns: false,
      },
      state,
    ));
    // Surface install errors immediately instead of failing at connect time:
    // the signal arrives once rules + listener are up; a dropped sender means
    // the task died during install, so join it for the real error.
    if tokio::time::timeout(Duration::from_secs(2), ready_rx).await.is_err() {
      let result = capture.await.expect("capture task");
      panic!("capture task not ready after 2s: {result:?}");
    }

    let stub_task = tokio::spawn(async move {
      let (conn, _) = stub.accept().await.unwrap();
      let mut tls = stub_acceptor.accept(conn).await.unwrap();
      let mut head = Vec::new();
      let mut chunk = [0u8; 4096];
      loop {
        let n = tls.read(&mut chunk).await.unwrap();
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
          break;
        }
      }
      let head_str = String::from_utf8(head).unwrap();
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
    let mut body = Vec::from(&resp[head_end..]);
    let expect = format!("echo:{FAKE}");
    while body.len() < expect.len() {
      let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut chunk))
        .await
        .unwrap()
        .unwrap();
      body.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(body, expect.as_bytes());
    stub_task.await.unwrap();
    capture.abort();
  }

  /// Removes the scoped dev-lo test route on drop (best-effort).
  struct DstRouteGuard;

  impl Drop for DstRouteGuard {
    fn drop(&mut self) {
      let _ = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
          let Ok(handle) = route::netlink() else {
            return;
          };
          let Ok(lo) = route::link_index(&handle, "lo").await else {
            return;
          };
          let message = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::new(198, 51, 100, 7), 32)
            .output_interface(lo)
            .table_id(u32::from(TABLE_MAIN))
            .build();
          let _ = handle.route().del(message).execute().await;
        });
      })
      .join();
    }
  }
}
