//! Bidirectional relay through per-direction substitution machines.

use eyre::WrapErr as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::substitute::SubMachine;

/// Bidirectional relay through per-direction machines. Guest FIN flushes the
/// request machine, then `close_notify` + upstream shutdown while still
/// draining server→guest; server close flushes the response machine and
/// ends the relay.
pub(crate) async fn relay_guarded<G, S, M>(mut guest: G, mut server: S, req: &mut M, resp: &mut M, first: &[u8]) -> eyre::Result<()>
where
  G: AsyncRead + AsyncWrite + Unpin,
  S: AsyncRead + AsyncWrite + Unpin,
  M: SubMachine + Send,
{
  let eof: &[u8] = &[];
  if !first.is_empty() {
    let (out, hits) = req.substitute(first).await;
    let pending = req.take_head_requests();
    if pending > 0 {
      resp.suppress_next_bodies(pending);
    }
    log_hits(&hits);
    if req.must_close() {
      return Ok(());
    }
    server.write_all(&out).await.context("relay request head to upstream")?;
    server.flush().await.context("relay request head flush")?;
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
            let (flushed, hits) = req.substitute(eof).await;
            log_hits(&hits);
            server.write_all(&flushed).await.context("relay request flush to upstream")?;
            // Upstream may already have closed its write side; a failed
            // shutdown must not abort the relay — keep draining the
            // response direction.
            let _ = server.shutdown().await;
          }
          Ok(n) => {
            let (out, hits) = req.substitute(&guest_buf[..n]).await;
            let pending = req.take_head_requests();
            if pending > 0 {
              resp.suppress_next_bodies(pending);
            }
            log_hits(&hits);
            if req.must_close() {
              break;
            }
            server.write_all(&out).await.context("relay request chunk to upstream")?;
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
            let (flushed, hits) = resp.substitute(eof).await;
            log_hits(&hits);
            if resp.must_close() {
              break;
            }
            guest.write_all(&flushed).await.context("relay response flush to guest")?;
            break;
          }
          Ok(n) => {
            let (out, hits) = resp.substitute(&server_buf[..n]).await;
            log_hits(&hits);
            if resp.must_close() {
              // Scan-only path hit a needle it could not rewrite: drop the
              // chunk and the connection rather than leak the real value.
              break;
            }
            guest.write_all(&out).await.context("relay response chunk to guest")?;
            guest.flush().await.context("relay guest flush")?;
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
pub(crate) fn log_hits(hits: &[crate::substitute::Hit]) {
  for hit in hits {
    tracing::debug!(label = %hit.label, location = ?hit.location, "substituted");
  }
}
