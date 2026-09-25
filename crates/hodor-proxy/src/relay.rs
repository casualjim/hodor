//! Bidirectional pump through two wire directions.

use eyre::WrapErr as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

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
) -> eyre::Result<()>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: Wire,
{
  let eof: &[u8] = &[];
  if !first.is_empty() {
    let (rewritten, hits) = downstream.feed(first).await;
    drain_reply(&mut guest, downstream).await?;
    let pending = downstream.take_peer_note();
    if pending > 0 {
      upstream.apply_peer_note(pending);
    }
    log_hits(&hits);
    match rewritten {
      Rewritten::Close => return Ok(()),
      Rewritten::Hold => {}
      Rewritten::Emit(out) => {
        server.write_all(&out).await.context("relay request head to upstream")?;
        server.flush().await.context("relay request head flush")?;
      }
    }
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
              server.write_all(&flushed).await.context("relay request flush to upstream")?;
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
                server.write_all(&out).await.context("relay request chunk to upstream")?;
              }
            }
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
            let (rewritten, hits) = upstream.feed(eof).await;
            log_hits(&hits);
            match rewritten {
              Rewritten::Close | Rewritten::Hold => break,
              Rewritten::Emit(flushed) => {
                guest.write_all(&flushed).await.context("relay response flush to guest")?;
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
                guest.write_all(&out).await.context("relay response chunk to guest")?;
                guest.flush().await.context("relay guest flush")?;
              }
            }
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

/// Flush one queued guest-bound protocol reply, if the last chunk queued
/// one (Postgres negotiation refusals). Only the downstream direction ever
/// queues.
async fn drain_reply<G: AsyncWrite + Unpin, M: Wire>(guest: &mut G, wire: &mut M) -> eyre::Result<()> {
  if let Some(reply) = wire.take_reply() {
    guest.write_all(&reply).await.context("relay protocol reply to guest")?;
    guest.flush().await.context("relay protocol reply flush")?;
  }
  Ok(())
}
pub(crate) fn log_hits(hits: &[crate::wire::Hit]) {
  for hit in hits {
    tracing::debug!(label = %hit.label, location = ?hit.location, "substituted");
  }
}
