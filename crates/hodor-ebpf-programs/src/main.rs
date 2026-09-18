//! Hodor's eBPF capture programs: cgroup hooks that redirect outbound
//! connections to hodor's loopback listeners, stashing the original
//! destination in maps the userspace loader reads back.
//!
//! Mechanism, per connection:
//!
//! 1. `connect4` fires on `connect()`. When the destination is not hodor's own
//!    and not already loopback, the real destination is recorded under the
//!    socket cookie and the destination rewritten to `127.0.0.1:<listener>`.
//! 2. `capture_egress` fires as the redirected packet leaves the machine and
//!    indexes the socket cookie by the client's local 4-tuple, which is what
//!    hodor's listener later sees as its peer address.
//! 3. `recvmsg4` rewrites the *source* address a connected UDP socket observes,
//!    so replies that physically come from hodor's listener still look like
//!    they came from the address the client connected to.
//!
//! No netfilter, no policy routes, no `IP_TRANSPARENT`: the kernel's own socket
//! address rewrite is the whole mechanism.
//!
//! Indexing lives in `capture_egress` rather than a `sock_ops` program because
//! `bpf_sock_ops` has no UDP opcode — the kernel's `BPF_SOCK_OPS_*` enum
//! contains only TCP callbacks, so connected UDP would never be indexed. Egress
//! sees every protocol, and runs after the socket's source port has been
//! autobound, which is exactly when the 4-tuple is final.

#![no_std]
#![no_main]

use aya_ebpf::{
  EbpfContext as _,
  helpers::{bpf_get_current_pid_tgid, bpf_get_socket_cookie},
  macros::{cgroup_skb, cgroup_sock_addr, map},
  maps::{Array, LruHashMap},
  programs::{SkBuffContext, SockAddrContext},
};

/// Loader-provided configuration: map key 0.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
  /// PID of the hodor process, so its own dials are never captured.
  pub proxy_pid: u32,
  /// Loopback port `connect4` rewrites TCP destinations to.
  pub tcp_port: u32,
  /// Loopback port `connect4` rewrites UDP destinations to.
  pub udp_port: u32,
}

/// Original destination recorded before the rewrite. Both fields keep the
/// kernel's own encodings — `user_ip4` and `user_port` are network byte order —
/// so `recvmsg4` can write them straight back into the context.
///
/// `proto` is followed by explicit padding rather than `repr(C)`'s implicit
/// padding, so the bytes userspace reads are the bytes the kernel wrote.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OrigDst {
  /// Destination address, in the kernel's `user_ip4` encoding.
  pub ip: u32,
  /// Destination port, network byte order in the low 16 bits.
  pub port: u32,
  /// `IPPROTO_TCP` or `IPPROTO_UDP`. Kept so userspace can reject a flow whose
  /// socket has been reused for the other protocol.
  pub proto: u8,
  /// Padding, always zero.
  pub _pad: [u8; 3],
}

/// Flow key: the client's local 4-tuple, which is the peer address hodor's
/// listener observes.
///
/// Deliberately no protocol field: an egress hook sees the IP header's protocol
/// byte only via packet data, and deriving it would cost a bounds-checked load
/// plus CAP_BPF-scoped data access. Two redirected sockets would have to share
/// the same local port across TCP and UDP to collide, and userspace rejects
/// that by checking the recorded [`OrigDst::proto`] — failing closed.
///
/// The trailing padding is an explicit field, not `repr(C)`'s implicit padding:
/// this is a map *key*, compared byte for byte by the kernel, so every byte has
/// to be written deterministically on both sides. Implicit padding would be
/// left uninitialized by the struct literals, and a difference in those bytes
/// between the insert and the lookup would make the lookup miss.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
  /// Local address, in the kernel's `skc_rcv_saddr` encoding.
  pub ip: u32,
  /// Local port, host byte order (the kernel reports it unswapped).
  pub port: u16,
  /// Padding, always zero.
  pub _pad: [u8; 2],
}

/// `IPPROTO_TCP`.
const IPPROTO_TCP: u32 = 6;
/// `IPPROTO_UDP`.
const IPPROTO_UDP: u32 = 17;
/// `AF_INET`.
const AF_INET: u32 = 2;

/// How many concurrent redirected sockets to remember.
const MAX_ENTRIES: u32 = 16_384;

#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

/// cookie → original destination.
#[map]
static ORIG_DST: LruHashMap<u64, OrigDst> = LruHashMap::with_max_entries(MAX_ENTRIES, 0);

/// client's local 4-tuple → cookie.
#[map]
static FLOW: LruHashMap<FlowKey, u64> = LruHashMap::with_max_entries(MAX_ENTRIES, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
  loop {}
}

/// True when this process is hodor itself, or the config has not been written
/// yet (map key 0 absent). Failing closed keeps hodor's own upstream dials out
/// of the capture loop, which would otherwise recurse.
///
/// The check is per *thread group*, not per thread: aya's `tgid()` is the
/// process id, which is what the loader writes into `CONFIG`.
#[inline(always)]
fn is_proxy() -> bool {
  let Some(config) = CONFIG.get(0) else {
    return true;
  };
  bpf_get_current_pid_tgid().wrapping_shr(32) as u32 == config.proxy_pid
}

/// `127.0.0.1` in the kernel's address encoding (`user_ip4` / `skc_rcv_saddr`).
#[inline(always)]
fn loopback_addr() -> u32 {
  // The kernel stores addresses byte-reversed from host integers, so the host
  // value is swapped on the way in and out.
  u32::from_be(0x7F00_0001)
}

/// True when `addr` is any `127.0.0.0/8` address, in the kernel's encoding.
#[inline(always)]
fn is_loopback(addr: u32) -> bool {
  u32::from_be(addr) & 0xFF00_0000 == 0x7F00_0000
}

#[inline(always)]
fn tcp_port() -> Option<u32> {
  CONFIG.get(0).map(|config| config.tcp_port)
}

#[inline(always)]
fn udp_port() -> Option<u32> {
  CONFIG.get(0).map(|config| config.udp_port)
}

/// Rewrite one `connect()` to hodor's loopback listener, remembering where the
/// client actually meant to go.
///
/// Returns 1 on every path: 1 is allow, 0 is deny, and this backend never
/// denies — anything not redirected proceeds to its real destination.
fn redirect(ctx: &SockAddrContext, listener_port: u32) -> i32 {
  let addr = ctx.sock_addr;
  // SAFETY: the kernel passes a valid, live `bpf_sock_addr` for this hook.
  let (family, protocol, ip, port) = unsafe { ((*addr).user_family, (*addr).protocol, (*addr).user_ip4, (*addr).user_port) };
  if family != AF_INET {
    return 1; // IPv6 hook (`connect6`) not implemented; leave it alone.
  }
  // Loopback already means either an explicit local service or a previous
  // rewrite; never redirect those, or hodor would capture its own listeners.
  if is_loopback(ip) {
    return 1;
  }
  // SAFETY: `ctx.as_ptr()` is the context the kernel supplied to this hook.
  let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
  if cookie == 0 {
    return 1;
  }
  let orig = OrigDst {
    ip,
    port,
    proto: protocol as u8,
    _pad: [0; 3],
  };
  if ORIG_DST.insert(cookie, orig, 0).is_err() {
    return 1;
  }
  // SAFETY: as above; only the destination being rewritten.
  unsafe {
    (*addr).user_ip4 = loopback_addr();
    (*addr).user_port = u16::to_be(listener_port as u16) as u32;
  }
  1
}

/// `connect4`: redirect a client's `connect()` into hodor.
///
/// This is where TLS, plain HTTP and connected UDP all get captured, because
/// every one of them reaches the network through `connect()`. Non-TCP/UDP
/// protocols are allowed through untouched.
#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
  if is_proxy() {
    return 1;
  }
  // SAFETY: the kernel supplies a live `bpf_sock_addr` for this hook.
  let protocol = unsafe { (*ctx.sock_addr).protocol };
  let listener = match protocol {
    IPPROTO_TCP => tcp_port(),
    IPPROTO_UDP => udp_port(),
    _ => None,
  };
  match listener {
    Some(port) => redirect(&ctx, port),
    None => 1,
  }
}

/// `recvmsg4`: make replies that hodor relays look like they came from the
/// address the socket is connected to.
///
/// Without this a connected UDP client would drop every reply: the datagram
/// physically arrives from `127.0.0.1:<relay port>` while the socket is
/// connected to the real server, and the kernel would filter it as a
/// mismatched source.
#[cgroup_sock_addr(recvmsg4)]
pub fn recvmsg4(ctx: SockAddrContext) -> i32 {
  let addr = ctx.sock_addr;
  // SAFETY: the kernel supplies a live `bpf_sock_addr` for this hook.
  let (family, ip) = unsafe { ((*addr).user_family, (*addr).user_ip4) };
  // Only replies that physically came from our own loopback listener need
  // rewriting; anything else already carries its true source.
  if family != AF_INET || !is_loopback(ip) {
    return 1;
  }
  // SAFETY: `ctx.as_ptr()` is the context the kernel supplied to this hook.
  let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
  if cookie == 0 {
    return 1;
  }
  // SAFETY: the map is not shared mutably with userspace while a datagram is
  // being received, and the value is copied out before use.
  let Some(orig) = (unsafe { ORIG_DST.get(cookie) }) else {
    return 1;
  };
  // SAFETY: as above; only the reported source is being restored.
  unsafe {
    (*addr).user_ip4 = orig.ip;
    (*addr).user_port = orig.port;
  }
  1
}

/// `capture_egress`: index the redirected flow by the client's local 4-tuple,
/// so userspace can resolve an accepted connection back to its original
/// destination.
///
/// Only flows that `connect4` actually redirected are recorded — hence the
/// `ORIG_DST` presence check — so unconnected UDP (typical DNS) keeps its own
/// addressing and is never touched.
#[cgroup_skb(egress)]
pub fn capture_egress(ctx: SkBuffContext) -> i32 {
  if is_proxy() {
    return 1;
  }
  if ctx.skb.family() != AF_INET {
    return 1;
  }
  // SAFETY: `ctx.as_ptr()` is the context the kernel supplied to this hook.
  let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
  if cookie == 0 {
    return 1;
  }
  // SAFETY: the presence check only reads the entry; the cookie is not
  // dereferenced and no mutable borrow escapes.
  let redirected = unsafe { ORIG_DST.get(cookie) }.is_some();
  if !redirected {
    return 1;
  }
  let key = FlowKey {
    ip: ctx.skb.local_ipv4(),
    port: ctx.skb.local_port() as u16,
    _pad: [0; 2],
  };
  let _ = FLOW.insert(key, cookie, 0);
  1
}
