//! Bidirectional pump through two wire directions.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::Error;
use crate::wire::{Rewritten, Wire};

/// Bidirectional relay through the two directions' wire formats. Guest FIN
/// flushes the downstream direction, then `close_notify` plus upstream
/// shutdown while still draining upstream→guest; upstream close flushes the
/// upstream direction and ends the relay.
///
/// Buffers live outside the `select!` so a cancelled branch never drops
/// partial bytes.
pub(crate) async fn relay_guarded<G, S, M>(
  mut guest: G,
  mut server: S,
  downstream: &mut M,
  upstream: &mut M,
  first: &[u8],
) -> Result<(), Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  let eof: &[u8] = &[];
  if !first.is_empty() && !feed_first(&mut guest, &mut server, downstream, upstream, first).await? {
    return Ok(());
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
            let (rewritten, hits) = downstream.feed(eof).await;
            drain_reply(&mut guest, downstream).await?;
            log_hits(&hits);
            if let Rewritten::Emit(flushed) = rewritten {
              server.write_all(&flushed).await.map_err(|err| Error::RequestFlushToUpstream { source: err })?;
            }
            // Upstream may already have closed its write side; a failed
            // shutdown must not abort the relay — keep draining the
            // response direction.
            let _ = server.shutdown().await;
          }
          Ok(n) => {
            let (rewritten, hits) = downstream.feed(&guest_buf[..n]).await;
            drain_reply(&mut guest, downstream).await?;
            let pending = downstream.take_peer_note();
            if pending > 0 {
              upstream.apply_peer_note(pending);
            }
            log_hits(&hits);
            match rewritten {
              Rewritten::Close => break,
              Rewritten::Hold => {}
              Rewritten::Emit(out) => {
                server.write_all(&out).await.map_err(|err| Error::RequestChunkToUpstream { source: err })?;
              }
            }
          }
          Err(err) => return Err(Error::GuestRead { source: err }),
        }
      }
      result = server.read(&mut server_buf) => {
        let result = match result {
          Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
          other => other,
        };
        match result {
          Ok(0) => {
            let (rewritten, hits) = upstream.feed(eof).await;
            log_hits(&hits);
            match rewritten {
              Rewritten::Close | Rewritten::Hold => break,
              Rewritten::Emit(flushed) => {
                guest.write_all(&flushed).await.map_err(|err| Error::ResponseFlushToGuest { source: err })?;
                break;
              }
            }
          }
          Ok(n) => {
            let (rewritten, hits) = upstream.feed(&server_buf[..n]).await;
            log_hits(&hits);
            match rewritten {
              Rewritten::Close => {
                // Scan-only path hit a needle it could not rewrite: drop the
                // chunk and the connection rather than leak the real value.
                break;
              }
              Rewritten::Hold => {}
              Rewritten::Emit(out) => {
                guest.write_all(&out).await.map_err(|err| Error::ResponseChunkToGuest { source: err })?;
                guest.flush().await.map_err(|err| Error::GuestFlush { source: err })?;
              }
            }
          }
          Err(err) => return Err(Error::UpstreamRead { source: err }),
        }
      }
    }
  }
  guest.flush().await.map_err(|err| Error::FinalGuestFlush { source: err })?;
  let _ = guest.shutdown().await;
  Ok(())
}

/// Feed the replayed first bytes downstream, flush the first protocol reply,
/// and carry the first chunk upstream. Returns `false` when the downstream
/// direction already ended the relay.
async fn feed_first<G, S, M>(guest: &mut G, server: &mut S, downstream: &mut M, upstream: &mut M, first: &[u8]) -> Result<bool, Error>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  let (rewritten, hits) = downstream.feed(first).await;
  drain_reply(guest, downstream).await?;
  let pending = downstream.take_peer_note();
  if pending > 0 {
    upstream.apply_peer_note(pending);
  }
  log_hits(&hits);
  match rewritten {
    Rewritten::Close => return Ok(false),
    Rewritten::Hold => {}
    Rewritten::Emit(out) => {
      server
        .write_all(&out)
        .await
        .map_err(|err| Error::RequestHeadToUpstream { source: err })?;
      server.flush().await.map_err(|err| Error::RequestHeadFlush { source: err })?;
    }
  }
  Ok(true)
}

/// Flush one queued guest-bound protocol reply, if the last chunk queued
/// one (Postgres negotiation refusals). Only the downstream direction ever
/// queues.
async fn drain_reply<G: AsyncWrite + Unpin, M: Wire>(guest: &mut G, wire: &mut M) -> Result<(), Error> {
  if let Some(reply) = wire.take_reply() {
    guest
      .write_all(&reply)
      .await
      .map_err(|err| Error::ProtocolReplyToGuest { source: err })?;
    guest.flush().await.map_err(|err| Error::ProtocolReplyFlush { source: err })?;
  }
  Ok(())
}
pub(crate) fn log_hits(hits: &[crate::wire::Hit]) {
  for hit in hits {
    tracing::debug!(label = %hit.label, location = ?hit.location, "substituted");
  }
}
