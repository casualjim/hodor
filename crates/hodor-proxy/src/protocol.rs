//! Wire selection: the scope the destination matched picks the wire
//! constructors, and inside an HTTPS scope the TLS layer names the version.

use rama::net::tls::ApplicationProtocol;

use hodor_config::grants::{Grant, Scheme};
use hodor_plugin::Direction as HookDirection;

use crate::wire::{AnyWire, Direction, H2, Http, Postgres, Raw};

/// Borrowed construction context: grants authorize, plugins hook, and the
/// connection identity scopes both.
pub(crate) struct PairCtx<'a> {
  /// Grant source for eligible pairs.
  pub(crate) grants: &'a [Grant],
  /// Connection endpoint host.
  pub(crate) host: &'a str,
  /// Connection endpoint port.
  pub(crate) port: u16,
  /// Per-connection plugin registry.
  pub(crate) plugins: &'a hodor_plugin::Registry,
  /// Runtime token-mint handle; `None` keeps value-swap-only behavior.
  pub(crate) mint: Option<crate::mint::MintHandle>,
}

/// Both directions for a cleartext HTTP connection.
pub(crate) fn http_pair(ctx: &PairCtx<'_>) -> (AnyWire, AnyWire) {
  (
    AnyWire::Http(Http::new(
      ctx.grants,
      Scheme::Http,
      ctx.host,
      ctx.port,
      Direction::Downstream,
      ctx.plugins.select(Scheme::Http, ctx.host, ctx.port, HookDirection::Request),
      ctx.mint.clone(),
    )),
    AnyWire::Http(Http::new(
      ctx.grants,
      Scheme::Http,
      ctx.host,
      ctx.port,
      Direction::Upstream,
      ctx.plugins.select(Scheme::Http, ctx.host, ctx.port, HookDirection::Response),
      ctx.mint.clone(),
    )),
  )
}

/// Both directions behind terminated TLS, HTTP/1 framing.
pub(crate) fn https_pair(ctx: &PairCtx<'_>) -> (AnyWire, AnyWire) {
  (
    AnyWire::Http(Http::new(
      ctx.grants,
      Scheme::Https,
      ctx.host,
      ctx.port,
      Direction::Downstream,
      ctx.plugins.select(Scheme::Https, ctx.host, ctx.port, HookDirection::Request),
      ctx.mint.clone(),
    )),
    AnyWire::Http(Http::new(
      ctx.grants,
      Scheme::Https,
      ctx.host,
      ctx.port,
      Direction::Upstream,
      ctx.plugins.select(Scheme::Https, ctx.host, ctx.port, HookDirection::Response),
      ctx.mint.clone(),
    )),
  )
}

/// Both directions behind terminated TLS, HTTP/2 framing.
pub(crate) fn https_h2_pair(ctx: &PairCtx<'_>) -> (AnyWire, AnyWire) {
  (
    AnyWire::H2(H2::new(
      ctx.grants,
      Scheme::Https,
      ctx.host,
      ctx.port,
      Direction::Downstream,
      ctx.plugins.select(Scheme::Https, ctx.host, ctx.port, HookDirection::Request),
      ctx.mint.clone(),
    )),
    AnyWire::H2(H2::new(
      ctx.grants,
      Scheme::Https,
      ctx.host,
      ctx.port,
      Direction::Upstream,
      ctx.plugins.select(Scheme::Https, ctx.host, ctx.port, HookDirection::Response),
      ctx.mint.clone(),
    )),
  )
}

/// Terminated TLS without HTTP structure: raw equal-length swap on https
/// grants.
pub(crate) fn raw_tls_pair(ctx: &PairCtx<'_>) -> (AnyWire, AnyWire) {
  (
    AnyWire::Raw(Raw::new(ctx.grants, Scheme::Https, ctx.host, ctx.port, Direction::Downstream)),
    AnyWire::Raw(Raw::new(ctx.grants, Scheme::Https, ctx.host, ctx.port, Direction::Upstream)),
  )
}

/// Cleartext Postgres: pgwire greeting, then raw relay on postgres grants.
pub(crate) fn postgres_pair(ctx: &PairCtx<'_>) -> (AnyWire, AnyWire) {
  (
    AnyWire::Postgres(Postgres::new(ctx.grants, ctx.host, ctx.port, Direction::Downstream)),
    AnyWire::Postgres(Postgres::new(ctx.grants, ctx.host, ctx.port, Direction::Upstream)),
  )
}

/// Cleartext non-HTTP bytes: raw equal-length swap on tcp grants.
pub(crate) fn raw_tcp_pair(ctx: &PairCtx<'_>) -> (AnyWire, AnyWire) {
  (
    AnyWire::Raw(Raw::new(ctx.grants, Scheme::Tcp, ctx.host, ctx.port, Direction::Downstream)),
    AnyWire::Raw(Raw::new(ctx.grants, Scheme::Tcp, ctx.host, ctx.port, Direction::Upstream)),
  )
}

/// Both directions for an HTTPS scope, framed as TLS agreed to frame them.
///
/// The relay opens the upstream leg first and answers the guest with that leg's
/// ALPN choice, so one negotiated protocol describes both directions. That
/// choice is the only thing that proves the plaintext is HTTP: a flow that
/// agreed neither `h2` nor `http/1.1` relays raw, where the equal-length grants
/// for this scope still swap and no framing is invented for bytes nobody
/// claimed.
///
/// HTTP/2 over TLS is defined by its ALPN identifier (RFC 9113 §3.1), so an
/// unnegotiated connection is never HTTP/2, and any other value - including
/// some other protocol's own identifier - is not a framing this layer knows.
pub(crate) fn https_framing(ctx: &PairCtx<'_>, negotiated: Option<&ApplicationProtocol>) -> (AnyWire, AnyWire) {
  match negotiated {
    Some(proto) if proto.as_bytes() == ApplicationProtocol::HTTP_2.as_bytes() => https_h2_pair(ctx),
    Some(proto) if proto.as_bytes() == ApplicationProtocol::HTTP_11.as_bytes() => https_pair(ctx),
    _ => raw_tls_pair(ctx),
  }
}

/// Cap for one client head: over this without a complete head, the bytes are
/// not a request head, so the reader stops instead of buffering an unbounded
/// drip.
pub(crate) const MAX_HEAD: usize = 64 * 1024;
