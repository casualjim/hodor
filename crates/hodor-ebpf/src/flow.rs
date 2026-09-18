//! Map access: turning a captured flow's local 4-tuple back into the original
//! destination the client asked for.

use std::net::SocketAddr;
use std::sync::Arc;

use aya::{
  Ebpf,
  maps::{HashMap, MapData},
};
use eyre::Context as _;

use crate::{FlowKey, OrigDst};

/// `IPPROTO_TCP`, matching the programs.
pub(crate) const PROTO_TCP: u8 = 6;
/// `IPPROTO_UDP`, matching the programs.
pub(crate) const PROTO_UDP: u8 = 17;

/// Read-only views of the two capture maps.
///
/// `MapData` is reference-counted, so cloning the tables shares the same maps
/// rather than copying anything; the TCP and UDP legs each hold one.
///
/// The programs declare these maps as `LRU_HASH`, but aya exposes LRU and plain
/// hash maps through the same userspace type: the distinction only affects
/// kernel-side eviction.
#[derive(Clone)]
pub(crate) struct FlowTables {
  flows: Arc<HashMap<MapData, FlowKey, u64>>,
  orig: Arc<HashMap<MapData, u64, OrigDst>>,
}

impl FlowTables {
  /// Take ownership of the `FLOW` and `ORIG_DST` maps out of a loaded object.
  pub(crate) fn from_bpf(bpf: &mut Ebpf) -> eyre::Result<Self> {
    let flows = bpf
      .take_map("FLOW")
      .ok_or_else(|| eyre::eyre!("FLOW map missing from the eBPF object"))?;
    let orig = bpf
      .take_map("ORIG_DST")
      .ok_or_else(|| eyre::eyre!("ORIG_DST map missing from the eBPF object"))?;
    Ok(Self {
      flows: Arc::new(flows.try_into().map_err(|err| eyre::eyre!("FLOW has an unexpected type: {err}"))?),
      orig: Arc::new(
        orig
          .try_into()
          .map_err(|err| eyre::eyre!("ORIG_DST has an unexpected type: {err}"))?,
      ),
    })
  }

  /// Original destination for a captured flow whose peer address is `peer`,
  /// which must have been captured for `proto`.
  ///
  /// The client's socket was rewritten to connect to our loopback listener, so
  /// the server leg sees that loopback address as its peer — exactly the key
  /// the egress hook recorded. `None` means the flow was never redirected (or
  /// the LRU entry aged out); callers close quietly rather than guess.
  ///
  /// The `proto` check matters because the hook's key carries no protocol:
  /// were a TCP and a UDP socket to share a local port, the lookup could land
  /// on the other protocol's entry, and dialing that destination would
  /// misroute the connection.
  pub(crate) fn original(&self, peer: SocketAddr, proto: u8) -> eyre::Result<Option<SocketAddr>> {
    let Some(key) = FlowKey::from_peer(peer) else {
      return Ok(None);
    };
    let cookie = match self.flows.get(&key, 0) {
      Ok(cookie) => cookie,
      // A missing key is the ordinary "not captured" case, not an error.
      Err(aya::maps::MapError::KeyNotFound) => return Ok(None),
      Err(err) => return Err(err).wrap_err("read FLOW"),
    };
    match self.orig.get(&cookie, 0) {
      Ok(orig) if orig.proto == proto => Ok(Some(orig.socket_addr())),
      // Either the entry aged out of the LRU, or the local port has been
      // reused by the other protocol: both mean "not this flow".
      Ok(_) | Err(aya::maps::MapError::KeyNotFound) => Ok(None),
      Err(err) => Err(err).wrap_err("read ORIG_DST"),
    }
  }
}
