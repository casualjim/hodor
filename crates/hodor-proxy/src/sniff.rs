//! Stream sniffing: TLS-with-SNI, TLS-without-SNI, or plain TCP bytes.

use tokio::io::{AsyncRead, AsyncReadExt as _};

use hodor_pki::sni::{MAX_HELLO, extract_sni};

use super::HANDSHAKE_TIMEOUT_SECS;

/// Sniffed post-CONNECT / TUN stream: TLS with SNI, TLS without SNI, or plain TCP bytes.
pub enum Sniffed {
  Tls { buf: Vec<u8>, sni: String },
  TlsNoSni { buf: Vec<u8> },
  RawTcp { buf: Vec<u8> },
}

/// Buffer until a `ClientHello` with SNI arrives, or non-TLS bytes prove a
/// plain TCP stream. None on EOF/stall with no bytes, or oversize non-TLS.
/// TLS bytes that stall without yielding SNI come back as `TlsNoSni` so the
/// caller can MITM with the known authority (CONNECT) or splice (TUN).
///
/// # Errors
///
/// Returns an error when the guest stream fails to read.
pub async fn sniff_stream<G: AsyncRead + Unpin>(guest: &mut G, initial: &[u8]) -> eyre::Result<Option<Sniffed>> {
  let mut buf = initial.to_vec();
  let mut chunk = [0u8; 4096];
  // Total pre-auth budget: per-read timeouts re-arm, so a dripping client
  // could otherwise hold this task indefinitely one byte at a time.
  let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
  loop {
    // SNI first: a hello completing exactly at the size cutoff still counts.
    if let Some(sni) = extract_sni(&buf) {
      return Ok(Some(Sniffed::Tls { buf, sni }));
    }
    if buf.len() > MAX_HELLO {
      if buf.first() == Some(&0x16) {
        return Ok(Some(Sniffed::TlsNoSni { buf }));
      }
      return Ok(None);
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
      if buf.first() == Some(&0x16) && !buf.is_empty() {
        return Ok(Some(Sniffed::TlsNoSni { buf }));
      }
      return Ok(None);
    }
    let read = tokio::time::timeout(remaining, guest.read(&mut chunk)).await;
    let Ok(n) = read else {
      if buf.first() == Some(&0x16) && !buf.is_empty() {
        return Ok(Some(Sniffed::TlsNoSni { buf }));
      }
      return Ok(None);
    };
    let n = n?;
    if n == 0 {
      if buf.first() == Some(&0x16) && !buf.is_empty() {
        return Ok(Some(Sniffed::TlsNoSni { buf }));
      }
      return Ok(None);
    }
    buf.extend_from_slice(&chunk[..n]);
    if buf.first() != Some(&0x16) {
      return Ok(Some(Sniffed::RawTcp { buf }));
    }
  }
}
