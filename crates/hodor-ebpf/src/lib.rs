//! eBPF capture backend: userspace half.
//!
//! Kernel-side programs (`hodor-ebpf-programs`) rewrite outbound connection
//! destinations to this crate's loopback listeners and stash the original
//! destination in BPF maps. This crate reads those maps and feeds the accepted
//! streams into the same substitution machinery every other backend uses.
//!
//! Nothing here touches netfilter or the routing table: the exclusion mechanism
//! is the cgroup a program is attached to, plus the recorded proxy PID.

use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aya::{
  Ebpf,
  maps::{Array, MapData},
  programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSockAddr},
};
use eyre::Context as _;
use hodor_proxy::ProxyState;

mod flow;
mod tcp;
mod udp;

/// Loopback port the TCP leg listens on. Also written into the BPF `CONFIG`
/// map, which is what actually sends connections here.
pub const TCP_LISTEN_PORT: u16 = 15000;
/// Loopback port the UDP relay listens on.
pub const UDP_LISTEN_PORT: u16 = 15001;

/// The `--ebpf-cgroup` value meaning "the cgroup this process's own cgroup
/// lives under", resolved at startup. A compose stack that gives both services
/// one `cgroup_parent` names no host path and uses this instead: the docker
/// daemon resolves that parent relative to its own cgroup root, so an absolute
/// path baked at generation time is wrong wherever the daemon is nested.
pub const ENCLOSING: &str = "enclosing";

/// Where cgroup v2 is mounted; the mount point the resolved path is built on.
const CGROUP2_MOUNT: &str = "/sys/fs/cgroup";

/// Resolve the cgroup enclosing this process: the parent of its own cgroup.
///
/// `/proc/self/cgroup` holds this process's path inside the cgroup v2 tree
/// (`0::<path>`), relative to the mount. The parent directory is the cgroup
/// shared with sibling containers, which is what a stack that sets one
/// `cgroup_parent` on both services wants attached. hodor is a member of the
/// attached subtree here, so the recorded proxy PID is what keeps its own
/// sockets out of the capture loop.
fn enclosing_cgroup() -> eyre::Result<PathBuf> {
  let content = std::fs::read_to_string("/proc/self/cgroup").wrap_err("read /proc/self/cgroup")?;
  let own = own_cgroup_path(&content).ok_or_else(|| eyre::eyre!("no `0::<path>` line in /proc/self/cgroup: not a cgroup v2 process"))?;
  enclosing_from(&own).ok_or_else(|| {
    eyre::eyre!(
      "no cgroup encloses {}: it is the cgroup root, where attaching would capture every process on the machine; pass an explicit --ebpf-cgroup path",
      own.display()
    )
  })
}

/// This process's own path in the cgroup v2 tree, from the `0::<path>` line.
fn own_cgroup_path(content: &str) -> Option<PathBuf> {
  content.lines().find_map(|line| line.strip_prefix("0::")).map(PathBuf::from)
}

/// The cgroup directory enclosing `own`, mounted at [`CGROUP2_MOUNT`]. `None`
/// when there is nothing worth attaching to: the cgroup root itself, or one of
/// its direct children, where the parent is that root.
fn enclosing_from(own: &Path) -> Option<PathBuf> {
  let parent = own.parent()?;
  if parent == Path::new("/") {
    return None;
  }
  // `join` with an absolute path would replace the mount instead of extending
  // it, so the leading slash comes off first.
  Some(Path::new(CGROUP2_MOUNT).join(parent.strip_prefix("/").ok()?))
}

/// The compiled programs, embedded at build time by `build.rs`.
static PROGRAMS: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/hodor-ebpf-programs"));

/// Test seams over [`run_ebpf`], mirroring `tproxy::Options`.
#[derive(Debug, Default)]
pub(crate) struct Options {
  /// cgroup directory to attach the programs to. Required in production: a
  /// default would capture every process on the machine.
  pub cgroup: Option<PathBuf>,
  /// Dial this address instead of the captured destination (stub upstream).
  pub upstream_override: Option<SocketAddr>,
  /// TCP listener port (tests avoid collisions).
  pub tcp_port: Option<u16>,
  /// UDP listener port (tests avoid collisions).
  pub udp_port: Option<u16>,
  /// Signalled once the programs are attached and the listeners are accepting.
  pub ready: Option<tokio::sync::oneshot::Sender<()>>,
  /// Which process the programs skip, so hodor's own upstream dials are never
  /// re-captured.
  pub self_exclusion: SelfExclusion,
}

/// Which process the programs skip.
///
/// The programs compare this against `bpf_get_current_pid_tgid() >> 32` and
/// let a match through unredirected. Production has exactly one state, so a
/// load that excludes nothing cannot be asked for by accident — an earlier
/// `Option<u32>` spelled "skip nothing" as `Some(0)`, which then tripped a
/// validation rule that separately rejected zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum SelfExclusion {
  /// Skip this process. What every production run uses.
  #[default]
  Proxy,
  /// Skip nothing, so even this process's own sockets are captured.
  ///
  /// Sound only when hodor's own dials cannot be re-captured: the live tests
  /// dial a loopback stub, and the programs never rewrite a loopback
  /// destination, so there is no loop to fall into. In a production run this
  /// would capture hodor's own upstream connections and recurse — which is why
  /// it exists only for tests, and why production code cannot name it.
  #[cfg(test)]
  Nothing,
}

impl SelfExclusion {
  /// The value written to the programs' `CONFIG` map.
  ///
  /// "Skip nothing" is 0 because no real process has tgid 0: the idle task
  /// never issues socket calls, so the comparison can never match. Inside a
  /// PID namespace this pid never matches what the kernel reports either —
  /// the cgroup id in [`Config`] is the guard that carries that case.
  fn pid(self) -> u32 {
    match self {
      Self::Proxy => std::process::id(),
      #[cfg(test)]
      Self::Nothing => 0,
    }
  }
}

/// The id of this process's own cgroup, as `bpf_get_current_cgroup_id`
/// reports it: the kernfs inode of the cgroup directory. A PID namespace
/// translates ids, so a containerized hodor never matches the pid guard —
/// the cgroup id has no namespace of its own. `0` means it could not be
/// determined, leaving the pid as the only guard.
fn own_cgroup_id() -> u64 {
  use std::os::unix::fs::MetadataExt as _;
  let Ok(content) = std::fs::read_to_string("/proc/self/cgroup") else {
    return 0;
  };
  let Some(own) = own_cgroup_path(&content) else {
    return 0;
  };
  // `join` with an absolute path would replace the mount instead of extending
  // it, so the leading slash comes off first.
  let Ok(relative) = own.strip_prefix("/") else {
    return 0;
  };
  std::fs::metadata(Path::new(CGROUP2_MOUNT).join(relative)).map_or(0, |meta| meta.ino())
}

/// Attach the capture programs and serve captured traffic forever.
///
/// `cgroup` is the directory whose member processes get captured. hodor itself
/// must live outside it, or its own upstream dials would be redirected back
/// into it; the recorded proxy PID is a second guard against that.
///
/// # Errors
///
/// Fails when the embedded object cannot be loaded, the `CONFIG` map cannot be
/// written, the cgroup cannot be opened or attached to, or either listener
/// cannot be bound. Every one of these is fatal for capture, so they surface
/// rather than degrade: a silent failure here would leave traffic flowing
/// unproxied while the operator believes it is captured.
pub async fn run_ebpf(state: Arc<ProxyState>, cgroup: PathBuf) -> eyre::Result<()> {
  run_ebpf_with(
    Options {
      cgroup: Some(cgroup),
      ..Options::default()
    },
    state,
  )
  .await
}

pub(crate) async fn run_ebpf_with(options: Options, state: Arc<ProxyState>) -> eyre::Result<()> {
  let cgroup = match options.cgroup.as_deref() {
    Some(path) if path == Path::new(ENCLOSING) => enclosing_cgroup()?,
    Some(path) => path.to_path_buf(),
    None => eyre::bail!("ebpf capture needs a cgroup directory to attach to, or `--ebpf-cgroup {ENCLOSING}`"),
  };
  let tcp_port = options.tcp_port.unwrap_or(TCP_LISTEN_PORT);
  let udp_port = options.udp_port.unwrap_or(UDP_LISTEN_PORT);

  let mut bpf = Ebpf::load(PROGRAMS).wrap_err("load eBPF programs")?;
  configure(&mut bpf, tcp_port, udp_port, options.self_exclusion).wrap_err("write eBPF CONFIG map")?;

  // `bpf` is held on the stack for as long as this task lives, so the programs
  // stay attached: dropping `Ebpf` detaches them and unloads them, which means
  // there is no kernel residue and nothing to clean up on exit.
  attach(&mut bpf, &cgroup).wrap_err_with(|| format!("attach to cgroup {}", cgroup.display()))?;

  let flow = flow::FlowTables::from_bpf(&mut bpf)?;
  if let Some(ready) = options.ready {
    let _ = ready.send(());
  }
  tracing::info!(tcp_port, udp_port, cgroup = %cgroup.display(), "ebpf capturing");

  // Both legs run for the life of the process; whichever fails first fails the
  // backend, and `main` treats that as fatal because capture was requested.
  tokio::select! {
    result = tcp::serve(tcp_port, flow.clone(), state, options.upstream_override) => result,
    result = udp::serve(udp_port, flow, options.upstream_override) => result,
  }
}

/// Write the loader-side configuration the programs read at runtime.
fn configure(bpf: &mut Ebpf, tcp_port: u16, udp_port: u16, self_exclusion: SelfExclusion) -> eyre::Result<()> {
  let config = Config {
    proxy_pid: self_exclusion.pid(),
    _pad: [0; 4],
    proxy_cgroup: own_cgroup_id(),
    tcp_port: u32::from(tcp_port),
    udp_port: u32::from(udp_port),
  };
  config
    .validate()
    .map_err(|err| eyre::eyre!("refusing to write an unusable CONFIG: {err}"))?;
  let map = bpf
    .map_mut("CONFIG")
    .ok_or_else(|| eyre::eyre!("CONFIG map missing from the eBPF object"))?;
  let mut map: Array<&mut MapData, Config> = map.try_into().map_err(|err| eyre::eyre!("CONFIG has an unexpected type: {err}"))?;
  map.set(0, config, 0).map_err(|err| eyre::eyre!("write CONFIG: {err}"))
}

/// Configuration map layout; must match `hodor-ebpf-programs::Config`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Config {
  /// PID of this process, so the programs can skip its own dials. Only
  /// meaningful outside a PID namespace: inside one the pid the kernel-side
  /// guard compares is not the pid this process sees.
  pub proxy_pid: u32,
  /// Explicit padding: the layout is an ABI with `hodor-ebpf-programs`, and
  /// no byte may be left to the compiler.
  pub _pad: [u8; 4],
  /// Id of this process's own cgroup, or 0 when unknown: the guard a
  /// namespace cannot translate, which is what carries the container case.
  pub proxy_cgroup: u64,
  /// Port `connect4` rewrites TCP destinations to.
  pub tcp_port: u32,
  /// Port `connect4` rewrites UDP destinations to.
  pub udp_port: u32,
}

impl Config {
  /// Reject a configuration the programs could not use meaningfully.
  ///
  /// `proxy_pid` is not checked: [`SelfExclusion`] is the only way to set it,
  /// and its production variant is this process's PID, which is never zero.
  fn validate(self) -> Result<(), String> {
    if self.tcp_port == 0 || self.udp_port == 0 {
      return Err("listen ports must be non-zero".into());
    }
    Ok(())
  }
}

// SAFETY: `Config` is `repr(C)` and contains only integers, so any bit pattern
// is a valid value and it can cross the map boundary as bytes.
unsafe impl aya::Pod for Config {}

/// Address encoding the kernel uses in `bpf_sock_addr.user_ip4` and in
/// `sock_common.skc_rcv_saddr`: the address bytes sit in memory in network
/// order, so the value read as a native `u32` is byte-reversed from the
/// numeric address. Both conversions below are that reversal, spelled out so
/// the two directions cannot drift apart.
pub(crate) fn decode_addr(raw: u32) -> Ipv4Addr {
  Ipv4Addr::from(u32::from_be(raw))
}

/// Inverse of [`decode_addr`].
pub(crate) fn encode_addr(addr: Ipv4Addr) -> u32 {
  u32::from(addr).to_be()
}

/// Port encoding the kernel uses in `bpf_sock_addr.user_port`, which holds the
/// port in network byte order in its low 16 bits.
pub(crate) fn decode_port(raw: u32) -> u16 {
  // The kernel writes this field with a 2-byte store, so the upper half is
  // always zero: masking then converting cannot fail, and the `expect` states
  // that invariant rather than silently truncating a malformed value.
  let low = raw & u32::from(u16::MAX);
  u16::from_be(u16::try_from(low).expect("masked to the low 16 bits"))
}

/// Inverse of [`decode_port`].
///
/// The programs do this conversion themselves, so nothing on the loader path
/// needs it; it exists so the round-trip tests can assert both directions
/// against one encoding.
#[cfg(test)]
pub(crate) fn encode_port(port: u16) -> u32 {
  u32::from(u16::to_be(port))
}

/// Original destination recorded by `connect4` before it rewrote the address.
///
/// Every byte is spelled out, including padding, so the layout is identical on
/// both sides of the map regardless of how either compiler would pad the
/// struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct OrigDst {
  /// Destination address, in the kernel's `user_ip4` encoding.
  pub ip: u32,
  /// Destination port, in the kernel's `user_port` encoding.
  pub port: u32,
  /// `IPPROTO_TCP` (6) or `IPPROTO_UDP` (17).
  pub proto: u8,
  /// Padding, mirroring `hodor-ebpf-programs::OrigDst`.
  pub _pad: [u8; 3],
}

// SAFETY: `repr(C)`, integer fields only.
unsafe impl aya::Pod for OrigDst {}

impl OrigDst {
  /// The destination as a socket address.
  pub(crate) fn socket_addr(&self) -> SocketAddr {
    SocketAddr::from((decode_addr(self.ip), decode_port(self.port)))
  }
}

/// Key indexing a redirected flow by the client's local 4-tuple, which is the
/// peer address hodor's listener observes. Must match
/// `hodor-ebpf-programs::FlowKey`, byte for byte: the kernel compares map keys
/// as raw bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FlowKey {
  /// Local address, in the kernel's `skc_rcv_saddr` encoding.
  pub ip: u32,
  /// Local port, host byte order: the kernel stores `skc_num` unswapped.
  pub port: u16,
  /// Padding, always zero. Explicit so the lookup key cannot differ from the
  /// inserted one in bytes the kernel compares but Rust never writes.
  pub _pad: [u8; 2],
}

// SAFETY: `repr(C)`, integer fields only.
unsafe impl aya::Pod for FlowKey {}

impl FlowKey {
  /// Key for a connection whose peer address is `peer`, as reported by
  /// `accept()` or `recv_from()`. The hook records the client's local 4-tuple,
  /// and for a loopback redirect that is exactly the address the server leg
  /// sees as its peer.
  pub(crate) fn from_peer(peer: SocketAddr) -> Option<Self> {
    let std::net::IpAddr::V4(ip) = peer.ip() else {
      return None;
    };
    Some(Self {
      ip: encode_addr(ip),
      port: peer.port(),
      _pad: [0; 2],
    })
  }
}

/// Attach every capture program to `cgroup`.
///
/// The links live inside the loaded object, so keeping `bpf` alive keeps the
/// programs attached; there are no handles to hold here.
fn attach(bpf: &mut Ebpf, cgroup: &std::path::Path) -> eyre::Result<()> {
  let file = File::open(cgroup).wrap_err_with(|| format!("open cgroup {}", cgroup.display()))?;
  let mode = CgroupAttachMode::Single;
  attach_sock_addr(bpf, "connect4", &file, mode)?;
  attach_sock_addr(bpf, "recvmsg4", &file, mode)?;
  let program: &mut CgroupSkb = bpf
    .program_mut("capture_egress")
    .ok_or_else(|| eyre::eyre!("capture_egress program missing from the eBPF object"))?
    .try_into()
    .map_err(|err| eyre::eyre!("capture_egress has an unexpected type: {err}"))?;
  program.load().map_err(|err| eyre::eyre!("load capture_egress: {err}"))?;
  program
    .attach(&file, CgroupSkbAttachType::Egress, mode)
    .map_err(|err| eyre::eyre!("attach capture_egress: {err}"))?;
  Ok(())
}

/// Load and attach one `cgroup_sock_addr` program.
///
/// The attach type comes from the program's own section name, which `load`
/// reads, so nothing about it needs passing here.
fn attach_sock_addr(bpf: &mut Ebpf, name: &str, cgroup: &File, mode: CgroupAttachMode) -> eyre::Result<()> {
  let program: &mut CgroupSockAddr = bpf
    .program_mut(name)
    .ok_or_else(|| eyre::eyre!("{name} program missing from the eBPF object"))?
    .try_into()
    .map_err(|err| eyre::eyre!("{name} has an unexpected type: {err}"))?;
  program.load().map_err(|err| eyre::eyre!("load {name}: {err}"))?;
  program.attach(cgroup, mode).map_err(|err| eyre::eyre!("attach {name}: {err}"))?;
  Ok(())
}

#[cfg(test)]
mod live;

#[cfg(test)]
mod tests {
  use super::*;

  /// The stack hands hodor `--ebpf-cgroup enclosing` instead of a host path:
  /// the docker daemon resolves `cgroup_parent` relative to its own cgroup
  /// root, so the slice's fs path depends on where the daemon is nested. The
  /// resolution below has to land on the cgroup both containers share.
  #[test]
  fn the_own_cgroup_path_is_parsed_from_the_v2_line() {
    let own = own_cgroup_path("0::/hodor.slice/hodor-x.slice/docker-abc.scope\n").unwrap();
    assert_eq!(own, PathBuf::from("/hodor.slice/hodor-x.slice/docker-abc.scope"));
    assert!(own_cgroup_path("2:cpu:/\n1:name=systemd:/\n").is_none());
    assert!(own_cgroup_path("").is_none());
  }

  #[test]
  fn the_enclosing_cgroup_is_the_parent_of_this_processes_own_cgroup() {
    let own = own_cgroup_path("0::/hodor.slice/hodor-x.slice/docker-abc.scope\n").unwrap();
    assert_eq!(own, PathBuf::from("/hodor.slice/hodor-x.slice/docker-abc.scope"));
    assert_eq!(
      enclosing_from(&own).unwrap(),
      PathBuf::from("/sys/fs/cgroup/hodor.slice/hodor-x.slice"),
      "hodor's own scope is one level under the slice both services share"
    );

    // Nothing to attach to without capturing the machine: the cgroup root and
    // its direct children have the root as their parent.
    assert!(enclosing_from(Path::new("/")).is_none());
    assert!(enclosing_from(Path::new("/docker-abc.scope")).is_none());

    // A cgroup v1 layout has no `0::` line, and neither does an empty file.
    assert!(own_cgroup_path("2:cpu:/\n1:name=systemd:/\n").is_none());
    assert!(own_cgroup_path("").is_none());
  }

  /// `user_ip4` carries the address bytes in network order, so a raw read is
  /// byte-reversed from the numeric address. Getting this backwards silently
  /// routes every captured connection to the wrong host.
  #[test]
  fn addr_encoding_round_trips_through_the_kernel_layout() {
    for addr in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(93, 184, 216, 34), Ipv4Addr::new(198, 51, 100, 7)] {
      assert_eq!(decode_addr(encode_addr(addr)), addr);
    }
    // Spelled out for one address so a regression in either direction fails
    // with an obvious value rather than an opaque round-trip mismatch: the
    // bytes of 127.0.0.1 in memory, read as a little-endian native integer.
    assert_eq!(encode_addr(Ipv4Addr::LOCALHOST).to_le_bytes(), [127, 0, 0, 1]);
    assert_eq!(decode_addr(u32::from_le_bytes([127, 0, 0, 1])), Ipv4Addr::LOCALHOST);
  }

  /// `user_port` holds the port in network order in its low 16 bits.
  #[test]
  fn port_encoding_round_trips_through_the_kernel_layout() {
    for port in [1u16, 53, 443, TCP_LISTEN_PORT, UDP_LISTEN_PORT, u16::MAX] {
      assert_eq!(decode_port(encode_port(port)), port);
    }
    assert_eq!(encode_port(TCP_LISTEN_PORT), u32::from(TCP_LISTEN_PORT.to_be()));
  }

  /// The listener's own address must decode back to the loopback address the
  /// programs rewrite destinations to.
  #[test]
  fn rewritten_destination_decodes_to_loopback() {
    let orig = OrigDst {
      ip: encode_addr(Ipv4Addr::LOCALHOST),
      port: encode_port(TCP_LISTEN_PORT),
      proto: 6,
      _pad: [0; 3],
    };
    assert_eq!(orig.socket_addr(), SocketAddr::from(([127, 0, 0, 1], TCP_LISTEN_PORT)));
  }

  /// A flow key built from an accepted connection's peer must decode back to
  /// that peer: the hook records the same tuple the listener later reads.
  #[test]
  fn flow_key_matches_the_peer_address() {
    let peer = SocketAddr::from(([93, 184, 216, 34], 54321));
    let key = FlowKey::from_peer(peer).expect("v4 peer");
    assert_eq!(decode_addr(key.ip), Ipv4Addr::new(93, 184, 216, 34));
    assert_eq!(key.port, 54321);
  }

  /// An IPv6 peer must be reported as unkeyable rather than silently keyed on
  /// a truncated address: the capture hooks are `connect4`/`recvmsg4` only, so
  /// no IPv6 flow ever carries an `OrigDst` to look up.
  #[test]
  fn flow_key_rejects_ipv6() {
    let peer = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 443));
    assert!(FlowKey::from_peer(peer).is_none());
  }

  /// The map keys and values cross the kernel boundary as raw bytes, so their
  /// sizes and offsets are an ABI with `hodor-ebpf-programs`. These assertions
  /// are what turns a silent layout drift into a build failure.
  #[test]
  fn map_layouts_are_fully_specified() {
    use std::mem::{align_of, offset_of, size_of};

    // 4 + 2 + 2 explicit padding: no room left for compiler-inserted bytes.
    assert_eq!(size_of::<FlowKey>(), 8);
    assert_eq!(align_of::<FlowKey>(), 4);
    assert_eq!(offset_of!(FlowKey, ip), 0);
    assert_eq!(offset_of!(FlowKey, port), 4);
    assert_eq!(offset_of!(FlowKey, _pad), 6);

    assert_eq!(size_of::<OrigDst>(), 12);
    assert_eq!(offset_of!(OrigDst, ip), 0);
    assert_eq!(offset_of!(OrigDst, port), 4);
    assert_eq!(offset_of!(OrigDst, proto), 8);
    assert_eq!(offset_of!(OrigDst, _pad), 9);

    assert_eq!(size_of::<Config>(), 24);
    assert_eq!(align_of::<Config>(), 8);
    assert_eq!(offset_of!(Config, proxy_pid), 0);
    assert_eq!(offset_of!(Config, _pad), 4);
    assert_eq!(offset_of!(Config, proxy_cgroup), 8);
    assert_eq!(offset_of!(Config, tcp_port), 16);
    assert_eq!(offset_of!(Config, udp_port), 20);
  }

  /// A configuration the programs cannot act on must be refused before it is
  /// written: a zero port would have `connect4` rewrite every destination to
  /// port 0, where nothing is listening.
  #[test]
  fn config_validation_rejects_zero_ports() {
    let base = Config {
      proxy_pid: SelfExclusion::Proxy.pid(),
      _pad: [0; 4],
      proxy_cgroup: own_cgroup_id(),
      tcp_port: u32::from(TCP_LISTEN_PORT),
      udp_port: u32::from(UDP_LISTEN_PORT),
    };
    base.validate().expect("a fully populated config is valid");
    assert!(Config { tcp_port: 0, ..base }.validate().is_err());
    assert!(Config { udp_port: 0, ..base }.validate().is_err());
  }

  /// Production must always exclude its own process: without it, hodor's
  /// upstream dials are captured and fed back into its own listener, forever.
  #[test]
  fn production_excludes_its_own_process() {
    let pid = SelfExclusion::Proxy.pid();
    assert_ne!(pid, 0, "tgid 0 is the idle task, which never issues socket calls");
    assert_eq!(pid, std::process::id());
    // The escape hatch is a distinct, deliberately-spelled value.
    assert_eq!(SelfExclusion::Nothing.pid(), 0);
    assert_ne!(SelfExclusion::Proxy, SelfExclusion::Nothing);
  }

  /// The embedded object must survive aya's own call relocation.
  ///
  /// This is the first thing `Ebpf::load` does after reading the ELF, and it
  /// needs no privileges — so it is the one part of the load path that can be
  /// checked in a normal `cargo test`. It catches the failure mode where a
  /// kernel helper is called through a hand-written `extern` block instead of
  /// aya's generated wrapper: the call keeps a `R_BPF_64_32` relocation that
  /// aya then tries to resolve as a *pc-relative internal call*, failing with
  /// `UnknownFunction` for the instruction's own address. The real thing then
  /// only surfaces as a confusing connect timeout inside a root-only live
  /// test.
  #[test]
  fn programs_relocate_their_calls() {
    let mut obj = aya_obj::Object::parse(PROGRAMS).expect("embedded object parses as ELF");
    let text_sections = obj.functions.keys().map(|(section_index, _)| *section_index).collect();
    obj
      .relocate_calls(&text_sections)
      .expect("every call must resolve; an unresolved helper extern is the usual cause");

    // All three attachment points must be present: a rename that drifted from
    // `attach()` would otherwise only fail on a root-only run.
    for name in ["connect4", "recvmsg4", "capture_egress"] {
      assert!(obj.programs.contains_key(name), "program `{name}` missing from the object");
    }
  }
}
