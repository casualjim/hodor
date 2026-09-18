//! HTTP/1-family substitution machine (plain HTTP, TLS, raw TCP).

use std::borrow::Cow;
use std::fmt::Write as _;

use base64::Engine as _;

use hodor_config::grants::{Grant, Scheme};

use super::SubMachine;

use super::{
  Direction, Hit, Location, Pair, eligible_pairs, find_crossing, find_new_match, max_tail_size, replace_bytes, replace_in,
  response_has_no_body, scan_with_tail,
};

/// Max buffered header block before degrading to opaque scan-only.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Max buffered fixed-length or chunked body before scan-only fallback.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Max header fields per head block for httparse scratch space.
const MAX_HEADERS: usize = 128;
/// Per-state data lives in struct fields so the dispatch loop can match
/// by value and mutate freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
  /// Accumulating a header block.
  Head,
  /// Accumulating a fixed-length body; head held for a possible CL rewrite.
  Fixed,
  /// Accumulating a chunked body (raw bytes); head already emitted.
  Chunked,
  /// Forwarding a known-length body unchanged, scanning for hits.
  Scan,
  /// Oversize head: forward + scan until the head boundary, then opaque.
  Drain,
  /// Forward + scan forever; framing unknowable.
  Opaque,
  /// Close-delimited response body: buffered for substitution at EOF.
  CloseDelimited,
  /// Non-HTTP TCP: equal-length replace with held-back tail.
  Raw,
}

/// Incremental chunked-framing parse phase (resumes across arrivals).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkPhase {
  /// Reading a chunk-size line.
  SizeLine,
  /// Inside chunk data, `remaining` bytes left (then CRLF).
  Data { remaining: usize },
  /// Reading trailer lines until the empty line.
  Trailers,
}

/// One state step's outcome: remaining borrowed input, or spilled owned
/// bytes to re-loop on (message remainder following a completed message).
enum Step<'r> {
  Rest(&'r [u8]),
  Spill(Vec<u8>),
}

/// Per-connection, per-direction substitution machine.
///
/// Request direction substitutes eligible fakes→values; response direction
/// substitutes values→fakes for the same eligible set (redaction). Anything
/// unframable is forwarded unchanged with hits logged — never blocked.
/// Call [`SecretsMachine::substitute`] with an empty chunk at stream EOF to
/// flush held bytes.
#[expect(
  clippy::struct_excessive_bools,
  reason = "framing state machine: each bool is one independent latch"
)]
pub(crate) struct SecretsMachine {
  pairs: Vec<Pair>,
  dir: Direction,
  state: State,
  head_buf: Vec<u8>,
  body_buf: Vec<u8>,
  chunk_raw: Vec<u8>,
  /// Incremental chunked framing: parse phase, validated prefix, violation.
  chunk_phase: ChunkPhase,
  chunk_scan: usize,
  chunk_broken: bool,
  raw_held: Vec<u8>,
  scan_tail: Vec<u8>,
  tail_size: usize,
  fixed_held: Option<Vec<u8>>,
  fixed_remaining: usize,
  fixed_allowed: bool,
  chunk_allowed: bool,
  scan_remaining: usize,
  /// Request side: HEAD heads seen, pending pickup by the relay.
  head_requests: usize,
  /// Response side: next N responses carry no body (HEAD requests).
  suppress_body: usize,
  /// Fail-closed latch: a scan-only path hit a needle it could not rewrite
  /// (compressed/oversize/opaque). The relay drops the connection.
  must_close: bool,
}

impl SecretsMachine {
  /// HTTP machine: eligible set precomputed via `Grant::matches`.
  #[must_use]
  pub fn new(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction) -> Self {
    Self::build(grants, scheme, host, port, dir, State::Head, false)
  }

  /// Raw TCP machine: only equal-length pairs (framing safety).
  #[must_use]
  pub fn new_raw(grants: &[Grant], host: &str, port: u16, dir: Direction) -> Self {
    Self::build(grants, Scheme::Tcp, host, port, dir, State::Raw, true)
  }

  /// Raw machine behind terminated TLS (`PlainMode::Raw`): the endpoint's
  /// identity is the `https://` grant, not `tcp://`.
  #[must_use]
  pub fn new_raw_tls(grants: &[Grant], host: &str, port: u16, dir: Direction) -> Self {
    Self::build(grants, Scheme::Https, host, port, dir, State::Raw, true)
  }

  /// Opaque machine: scan-only, forward unchanged (framing unknowable).
  #[cfg(test)]
  #[must_use]
  pub fn new_opaque(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction) -> Self {
    Self::build(grants, scheme, host, port, dir, State::Opaque, false)
  }

  fn build(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction, state: State, equal_len_only: bool) -> Self {
    let pairs = eligible_pairs(grants, scheme, host, port, dir, equal_len_only);
    let tail_size = max_tail_size(&pairs);
    Self {
      pairs,
      dir,
      state,
      head_buf: Vec::new(),
      body_buf: Vec::new(),
      chunk_raw: Vec::new(),
      chunk_phase: ChunkPhase::SizeLine,
      chunk_scan: 0,
      chunk_broken: false,
      raw_held: Vec::new(),
      scan_tail: Vec::new(),
      tail_size,
      fixed_held: None,
      fixed_remaining: 0,
      fixed_allowed: true,
      chunk_allowed: true,
      scan_remaining: 0,
      head_requests: 0,
      suppress_body: 0,
      must_close: false,
    }
  }

  /// Process one chunk. Returns the bytes to forward (borrowed when the
  /// chunk passes through byte-identical) plus any hits. Empty input
  /// flushes held bytes (call at stream EOF).
  pub fn substitute<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    if chunk.is_empty() {
      let (flushed, hits) = self.flush_held();
      return (Cow::Owned(flushed), hits);
    }
    // Opaque is pure passthrough: scan + forward unchanged, zero-copy.
    // Most close-delimited response bodies live here for their whole life.
    if self.state == State::Opaque {
      let hits = self.scan_chunk(chunk, Location::Body);
      if self.dir == Direction::Response && !hits.is_empty() {
        self.must_close = true;
      }
      return (Cow::Borrowed(chunk), hits);
    }
    let mut out = Vec::with_capacity(chunk.len());
    let mut hits = Vec::new();
    // Owned spillover for head/body leftovers: re-loop, never recurse —
    // pipelined messages per chunk are attacker-controlled.
    let mut owned: Vec<u8>;
    let mut rest = chunk;
    while !rest.is_empty() {
      let step = match self.state {
        State::Head => self.step_head(rest, &mut out, &mut hits),
        State::Fixed => self.step_fixed(rest, &mut out, &mut hits),
        State::Chunked => self.step_chunked(rest, &mut out, &mut hits),
        State::Scan => self.step_scan(rest, &mut out, &mut hits),
        State::Drain => self.step_drain(rest, &mut out, &mut hits),
        State::Opaque => {
          let scan_hits = self.scan_chunk(rest, Location::Body);
          if self.dir == Direction::Response && !scan_hits.is_empty() {
            self.must_close = true;
          }
          hits.extend(scan_hits);
          out.extend_from_slice(rest);
          Step::Rest(&[])
        }
        State::CloseDelimited => self.step_close(rest, &mut out, &mut hits),
        State::Raw => self.step_raw(rest, &mut out, &mut hits),
      };
      match step {
        Step::Rest(remaining) => rest = remaining,
        Step::Spill(spill) => {
          if spill.is_empty() {
            break;
          }
          owned = spill;
          rest = &owned;
        }
      }
    }
    if out.as_slice() == chunk {
      (Cow::Borrowed(chunk), hits)
    } else {
      (Cow::Owned(out), hits)
    }
  }

  /// Head state: buffer until the `\r\n\r\n` boundary, then hand the head
  /// to `process_head` and re-loop on the remainder.
  fn step_head<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let need = MAX_HEAD_BYTES.saturating_add(4).saturating_sub(self.head_buf.len());
    let take = need.min(rest.len());
    self.head_buf.extend_from_slice(&rest[..take]);
    let rest = &rest[take..];
    if let Some(end) = find_header_boundary(&self.head_buf) {
      let mut owned = std::mem::take(&mut self.head_buf);
      let mut combined = owned.split_off(end);
      let (head_out, head_hits) = self.process_head(owned);
      out.extend_from_slice(&head_out);
      hits.extend(head_hits);
      combined.extend_from_slice(rest);
      return Step::Spill(combined);
    }
    if self.head_buf.len() > MAX_HEAD_BYTES {
      // Oversize head: emit buffered bytes unchanged, drain to boundary.
      let buffered = std::mem::take(&mut self.head_buf);
      hits.extend(self.scan_chunk(&buffered, Location::Header));
      out.extend_from_slice(&buffered);
      self.state = State::Drain;
    }
    Step::Rest(rest)
  }

  /// Fixed-length body state: substitute when the declared length arrives.
  fn step_fixed<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let take = self.fixed_remaining.min(rest.len());
    self.body_buf.extend_from_slice(&rest[..take]);
    let rest = &rest[take..];
    self.fixed_remaining -= take;
    if self.fixed_remaining == 0 {
      let body = std::mem::take(&mut self.body_buf);
      let saved = self.fixed_held.take();
      let allowed = self.fixed_allowed;
      self.state = State::Head;
      if allowed {
        let (new_body, mut body_hits) = replace_in(&body, &self.pairs, Location::Body);
        hits.append(&mut body_hits);
        let mut head = saved.unwrap_or_default();
        if new_body.len() != body.len() {
          head = update_content_length(&head, new_body.len());
        }
        out.extend_from_slice(&head);
        out.extend_from_slice(&new_body);
      } else {
        if let Some(head) = saved {
          out.extend_from_slice(&head);
        }
        let scan_hits = self.scan_chunk(&body, Location::Body);
        if self.dir == Direction::Response && !scan_hits.is_empty() {
          self.must_close = true;
        }
        hits.extend(scan_hits);
        out.extend_from_slice(&body);
      }
    }
    Step::Rest(rest)
  }

  /// Chunked body state: buffer until the terminal chunk, then re-encode.
  fn step_chunked<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let need = MAX_BODY_BYTES.saturating_add(MAX_HEAD_BYTES).saturating_sub(self.chunk_raw.len());
    let take = need.min(rest.len());
    self.chunk_raw.extend_from_slice(&rest[..take]);
    let rest = &rest[take..];
    if let Some(end) = self.chunked_progress() {
      let mut owned = std::mem::take(&mut self.chunk_raw);
      let raw = owned[..end].to_vec();
      let mut combined = owned.split_off(end);
      self.chunk_reset();
      self.state = State::Head;
      if self.chunk_allowed {
        let (body_out, mut body_hits) = reencode_chunked(&raw, &self.pairs);
        hits.append(&mut body_hits);
        out.extend_from_slice(&body_out);
      } else {
        let scan_hits = self.scan_chunk(&raw, Location::Body);
        if self.dir == Direction::Response && !scan_hits.is_empty() {
          self.must_close = true;
        }
        hits.extend(scan_hits);
        out.extend_from_slice(&raw);
      }
      combined.extend_from_slice(rest);
      return Step::Spill(combined);
    }
    if self.chunk_raw.len() >= MAX_BODY_BYTES + MAX_HEAD_BYTES || self.chunk_broken {
      let raw = std::mem::take(&mut self.chunk_raw);
      self.chunk_reset();
      let scan_hits = self.scan_chunk(&raw, Location::Body);
      if self.dir == Direction::Response && !scan_hits.is_empty() {
        self.must_close = true;
      }
      hits.extend(scan_hits);
      out.extend_from_slice(&raw);
      self.state = State::Opaque;
    }
    Step::Rest(rest)
  }

  /// Reset the incremental chunked parser for the next message.
  fn chunk_reset(&mut self) {
    self.chunk_scan = 0;
    self.chunk_broken = false;
    self.chunk_phase = ChunkPhase::SizeLine;
  }

  /// Incrementally parse `chunk_raw` from `chunk_scan`, resuming where the
  /// last arrival left off (no quadratic rescans on drip-fed bodies).
  /// Returns `Some(end)` past the terminal CRLF when the body completes.
  /// Definite violations latch `chunk_broken`.
  fn chunked_progress(&mut self) -> Option<usize> {
    loop {
      match self.chunk_phase {
        ChunkPhase::SizeLine | ChunkPhase::Trailers => {
          let line_start = self.chunk_scan;
          // Resume the CRLF scan one byte back so a CRLF straddling the
          // previous arrival is still found.
          let from = line_start.saturating_sub(1);
          let Some(rel) = find_crlf(&self.chunk_raw[from..]) else {
            if self.chunk_raw.len() - line_start > MAX_HEAD_BYTES {
              self.chunk_broken = true;
            }
            return None;
          };
          let line_end = from + rel;
          let line = &self.chunk_raw[line_start..line_end];
          self.chunk_scan = line_end + 2;
          match self.chunk_phase {
            ChunkPhase::SizeLine => match parse_chunk_size(line) {
              Some(0) => self.chunk_phase = ChunkPhase::Trailers,
              Some(size) => self.chunk_phase = ChunkPhase::Data { remaining: size },
              None => {
                self.chunk_broken = true;
                return None;
              }
            },
            ChunkPhase::Trailers => {
              if line.is_empty() {
                return Some(self.chunk_scan);
              }
            }
            ChunkPhase::Data { .. } => unreachable!("phase checked above"),
          }
        }
        ChunkPhase::Data { remaining } => {
          let need = remaining + 2;
          if self.chunk_raw.len() - self.chunk_scan < need {
            return None;
          }
          if self.chunk_raw[self.chunk_scan + remaining..self.chunk_scan + remaining + 2] != b"\r\n"[..] {
            self.chunk_broken = true;
            return None;
          }
          self.chunk_scan += need;
          self.chunk_phase = ChunkPhase::SizeLine;
        }
      }
    }
  }

  /// Scan state: forward an oversize body unchanged, counting remaining bytes.
  fn step_scan<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let take = self.scan_remaining.min(rest.len());
    let (data, rest) = rest.split_at(take);
    let scan_hits = self.scan_chunk(data, Location::Body);
    if self.dir == Direction::Response && !scan_hits.is_empty() {
      self.must_close = true;
    }
    hits.extend(scan_hits);
    out.extend_from_slice(data);
    self.scan_remaining -= take;
    if self.scan_remaining == 0 {
      self.state = State::Head;
    }
    Step::Rest(rest)
  }

  /// Drain state: resync at the next boundary instead of swallowing opaque.
  fn step_drain<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let Some(end) = find_header_boundary(rest) else {
      let scan_hits = self.scan_chunk(rest, Location::Header);
      if self.dir == Direction::Response && !scan_hits.is_empty() {
        self.must_close = true;
      }
      hits.extend(scan_hits);
      out.extend_from_slice(rest);
      self.state = State::Opaque;
      return Step::Rest(&[]);
    };
    let (head, tail) = rest.split_at(end);
    let scan_hits = self.scan_chunk(head, Location::Header);
    if self.dir == Direction::Response && !scan_hits.is_empty() {
      self.must_close = true;
    }
    hits.extend(scan_hits);
    out.extend_from_slice(head);
    self.state = State::Head;
    if tail.is_empty() {
      Step::Rest(&[])
    } else {
      // `tail` is a suffix of the borrowed chunk — return it borrowed
      // instead of copying through an owned spill.
      Step::Rest(tail)
    }
  }

  /// Close-delimited response body: buffer up to the cap, substitute at EOF.
  /// Over the cap, degrade to scan-only forward and fail closed on a hit.
  fn step_close<'r>(&mut self, rest: &'r [u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'r> {
    let need = MAX_BODY_BYTES.saturating_sub(self.body_buf.len());
    let take = need.min(rest.len());
    self.body_buf.extend_from_slice(&rest[..take]);
    let rest = &rest[take..];
    if self.body_buf.len() >= MAX_BODY_BYTES {
      let body = std::mem::take(&mut self.body_buf);
      let scan_hits = self.scan_chunk(&body, Location::Body);
      if self.dir == Direction::Response && !scan_hits.is_empty() {
        self.must_close = true;
      }
      hits.extend(scan_hits);
      out.extend_from_slice(&body);
      self.state = State::Opaque;
    }
    Step::Rest(rest)
  }

  /// Raw state: equal-length substitution with a cross-chunk hold-back window.
  fn step_raw(&mut self, rest: &[u8], out: &mut Vec<u8>, hits: &mut Vec<Hit>) -> Step<'static> {
    // Probe for a hit without copying the whole chunk: fully-inside matches
    // scan rest in place; boundary matches scan a tiny tail window. On a
    // hit, fall back to the full held+rest replace. Hold back only a suffix
    // that can still grow into a needle: a fixed window would stall
    // lockstep protocols (send a line, wait for the reply).
    let hit = self.pairs.iter().any(|pair| {
      find_new_match(rest, &pair.needle, 0)
        || (!self.raw_held.is_empty() && {
          let old_len = self.raw_held.len();
          let bound = self.tail_size.min(rest.len());
          let mut window = self.raw_held.clone();
          window.extend_from_slice(&rest[..bound]);
          find_crossing(&window, &pair.needle, old_len)
        })
    });
    if !hit {
      let hold = if self.raw_held.is_empty() {
        needle_prefix_suffix_len(rest, &self.pairs, self.tail_size)
      } else {
        let bound = self.tail_size.min(rest.len());
        let mut window = std::mem::take(&mut self.raw_held);
        window.extend_from_slice(&rest[..bound]);
        needle_prefix_suffix_len(&window, &self.pairs, self.tail_size)
      };
      let emit_len = rest.len().saturating_sub(hold);
      out.extend_from_slice(&rest[..emit_len]);
      if hold > 0 {
        self.raw_held = rest[emit_len..].to_vec();
      }
      return Step::Rest(&[]);
    }
    let mut combined = std::mem::take(&mut self.raw_held);
    combined.extend_from_slice(rest);
    let hold = needle_prefix_suffix_len(&combined, &self.pairs, self.tail_size);
    let emit_len = combined.len() - hold;
    let (new_emit, mut emit_hits) = replace_in(&combined[..emit_len], &self.pairs, Location::Body);
    hits.append(&mut emit_hits);
    out.extend_from_slice(&new_emit);
    self.raw_held = combined[emit_len..].to_vec();
    Step::Rest(&[])
  }

  /// Substitute a complete head block (ending exactly at the boundary) and
  /// set the body state. Returns the head bytes to emit plus hits.
  fn process_head(&mut self, head: Vec<u8>) -> (Vec<u8>, Vec<Hit>) {
    let Ok(head_str) = std::str::from_utf8(&head) else {
      let hits = self.scan_chunk(&head, Location::Header);
      self.state = State::Opaque;
      return (head, hits);
    };
    let Ok(ParsedHead { headers, status, method }) = parse_head_fields(&head, self.dir) else {
      // Unparseable head: still substitute header lines (fully buffered),
      // then opaque — the body boundary is unknowable.
      let (new_head, hits) = substitute_head(head_str, &self.pairs);
      self.state = State::Opaque;
      return (new_head, hits);
    };
    // Framing classification, computed once.
    let framing = parse_framing(&headers);
    // HEAD is counted only on framable messages so the response side never
    // suppresses wrongly; the response no-body handling likewise runs only
    // on framable messages (Broken substitutes headers then goes opaque).
    let framable = !matches!(framing, Framing::Broken);
    if framable && self.dir == Direction::Request && method.is_some_and(|m| m.eq_ignore_ascii_case("head")) {
      self.head_requests += 1;
    }
    if framable && self.dir == Direction::Response {
      // 1xx/204/304 never carry a body, whatever the framing claims.
      // HEAD responses never carry a body either (signalled per-request).
      let interim = matches!(status, Some(100..200));
      if response_has_no_body(status) {
        // Interim 1xx keeps a pending HEAD suppression for the final response.
        if !interim && self.suppress_body > 0 {
          self.suppress_body -= 1;
        }
        let (new_head, hits) = substitute_head(head_str, &self.pairs);
        self.state = State::Head;
        return (new_head, hits);
      }
      if self.suppress_body > 0 {
        self.suppress_body -= 1;
        let (new_head, hits) = substitute_head(head_str, &self.pairs);
        self.state = State::Head;
        return (new_head, hits);
      }
    }
    match framing {
      Framing::Broken => {
        let (new_head, hits) = substitute_head(head_str, &self.pairs);
        self.state = State::Opaque;
        (new_head, hits)
      }
      Framing::Chunked => {
        let (new_head, hits) = substitute_head(head_str, &self.pairs);
        self.chunk_allowed = !has_non_identity_content_encoding(&headers);
        self.chunk_reset();
        self.state = State::Chunked;
        (new_head, hits)
      }
      Framing::Fixed { len } => {
        if len == 0 {
          // Empty body: emit head now, nothing left to wait for.
          let (new_head, hits) = substitute_head(head_str, &self.pairs);
          self.state = State::Head;
          (new_head, hits)
        } else if len > MAX_BODY_BYTES {
          // Oversize: scan-only, head emitted unchanged.
          let hits = self.scan_chunk(&head, Location::Header);
          self.scan_remaining = len;
          self.state = State::Scan;
          (head, hits)
        } else {
          let (new_head, hits) = substitute_head(head_str, &self.pairs);
          let allowed = !has_non_identity_content_encoding(&headers);
          self.fixed_remaining = len;
          self.fixed_allowed = allowed;
          self.state = State::Fixed;
          if allowed {
            self.fixed_held = Some(new_head);
            (Vec::new(), hits)
          } else {
            (new_head, hits)
          }
        }
      }
      Framing::None => {
        let (new_head, hits) = substitute_head(head_str, &self.pairs);
        if self.dir == Direction::Response && !response_has_no_body(status) {
          // Close-delimited response body: framing unknowable. With pairs,
          // buffer for substitution at EOF (fail closed over the cap);
          // without pairs, zero-copy opaque passthrough stays byte-identical.
          if self.pairs.is_empty() {
            self.state = State::Opaque;
          } else {
            self.body_buf.clear();
            self.state = State::CloseDelimited;
          }
        } else {
          self.state = State::Head;
        }
        (new_head, hits)
      }
    }
  }

  /// Emit everything held (partial message) unchanged. The raw tail is
  /// substituted: at EOF the data is complete.
  fn flush_held(&mut self) -> (Vec<u8>, Vec<Hit>) {
    let mut out = Vec::new();

    let mut hits = Vec::new();
    out.extend_from_slice(std::mem::take(&mut self.head_buf).as_slice());
    match self.state {
      State::Fixed => {
        if let Some(head) = self.fixed_held.take() {
          out.extend_from_slice(&head);
        }
        out.extend_from_slice(std::mem::take(&mut self.body_buf).as_slice());
      }
      State::Chunked => {
        out.extend_from_slice(std::mem::take(&mut self.chunk_raw).as_slice());
      }
      State::Raw => {
        let held = std::mem::take(&mut self.raw_held);
        let (new_held, mut held_hits) = replace_in(&held, &self.pairs, Location::Body);
        hits.append(&mut held_hits);
        out.extend_from_slice(&new_held);
      }
      State::CloseDelimited => {
        let body = std::mem::take(&mut self.body_buf);
        let (new_body, mut body_hits) = replace_in(&body, &self.pairs, Location::Body);
        hits.append(&mut body_hits);
        out.extend_from_slice(&new_body);
      }
      _ => {}
    }
    self.state = State::Opaque;
    (out, hits)
  }

  /// Scan `data` (plus overlap tail) for needles; updates the tail.
  fn scan_chunk(&mut self, data: &[u8], location: Location) -> Vec<Hit> {
    scan_with_tail(&self.pairs, &mut self.scan_tail, self.tail_size, data, location)
  }
}

enum Framing {
  Broken,
  Chunked,
  Fixed { len: usize },
  None,
}
/// A parsed head block: fields plus direction-specific extras.
struct ParsedHead<'h> {
  headers: Vec<httparse::Header<'h>>,
  /// Response status code (`None` for requests).
  status: Option<u16>,
  /// Request method (`None` for responses).
  method: Option<&'h str>,
}

/// Parse a complete head block with httparse (request or response per `dir`).
/// Err on any parse failure or header overflow — the caller degrades to
/// opaque scan-only forwarding.
fn parse_head_fields(head: &[u8], dir: Direction) -> Result<ParsedHead<'_>, ()> {
  let mut scratch = [httparse::EMPTY_HEADER; MAX_HEADERS];
  match dir {
    Direction::Request => {
      let mut req = httparse::Request::new(&mut scratch);
      match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => Ok(ParsedHead {
          headers: req.headers.to_vec(),
          status: None,
          method: req.method,
        }),
        _ => Err(()),
      }
    }
    Direction::Response => {
      let mut resp = httparse::Response::new(&mut scratch);
      match resp.parse(head) {
        Ok(httparse::Status::Complete(_)) => Ok(ParsedHead {
          headers: resp.headers.to_vec(),
          status: resp.code,
          method: None,
        }),
        _ => Err(()),
      }
    }
  }
}

/// Framing classification from parsed header fields.
fn parse_framing(headers: &[httparse::Header<'_>]) -> Framing {
  match (parse_transfer_encoding(headers), parse_content_length(headers)) {
    (Err(()), _) | (_, Err(())) | (Ok(true), Ok(Some(_))) => Framing::Broken, // TE + CL: ambiguous
    (Ok(true), Ok(None)) => Framing::Chunked,
    (Ok(false), Ok(Some(len))) => Framing::Fixed { len },
    (Ok(false), Ok(None)) => Framing::None,
  }
}

/// Read `Transfer-Encoding` fields: Ok(true) = chunked, Ok(false) = absent.
/// Err on any other coding or a repeated chunked.
fn parse_transfer_encoding(headers: &[httparse::Header<'_>]) -> Result<bool, ()> {
  let mut saw_chunked = false;
  for header in headers {
    if !header.name.eq_ignore_ascii_case("transfer-encoding") {
      continue;
    }
    let Ok(value) = std::str::from_utf8(header.value) else {
      return Err(());
    };
    for coding in value.split(',') {
      let coding = coding.trim();
      let coding_name = coding.split_once(';').map_or(coding, |(name, _)| name).trim();
      if coding_name.is_empty() || !coding_name.eq_ignore_ascii_case("chunked") {
        return Err(());
      }
      if saw_chunked {
        return Err(());
      }
      saw_chunked = true;
    }
  }
  Ok(saw_chunked)
}

/// Read `Content-Length` fields: Err on malformed or conflicting values.
fn parse_content_length(headers: &[httparse::Header<'_>]) -> Result<Option<usize>, ()> {
  let mut content_length = None;
  for header in headers {
    if !header.name.eq_ignore_ascii_case("content-length") {
      continue;
    }
    let Ok(value) = std::str::from_utf8(header.value) else {
      return Err(());
    };
    let Ok(parsed) = value.trim().parse::<usize>() else {
      return Err(());
    };
    if content_length.is_some_and(|existing| existing != parsed) {
      return Err(());
    }
    content_length = Some(parsed);
  }
  Ok(content_length)
}

fn has_non_identity_content_encoding(headers: &[httparse::Header<'_>]) -> bool {
  headers
    .iter()
    .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
    .any(|header| {
      let Ok(value) = std::str::from_utf8(header.value) else {
        return true;
      };
      value.split(',').any(|encoding| !encoding.trim().eq_ignore_ascii_case("identity"))
    })
}

/// Substitute all pairs in a head block: Basic-auth lines first (decoded),
/// then raw byte replace on every line except `Host` (routing safety,
/// mirroring the H2 `:authority` skip). Returns the new head + hits.
fn substitute_head(head_str: &str, pairs: &[Pair]) -> (Vec<u8>, Vec<Hit>) {
  let mut current = head_str.to_string();
  let mut hits = Vec::new();
  for pair in pairs {
    let Ok(needle) = std::str::from_utf8(&pair.needle) else {
      continue;
    };
    let Ok(replacement) = std::str::from_utf8(&pair.replacement) else {
      continue;
    };
    if substitute_basic_lines(&mut current, needle, replacement) {
      hits.push(Hit {
        label: pair.label.clone(),
        location: Location::BasicAuth,
      });
    }
  }
  // `current` derives from `&str`, so per-line buffers stay UTF-8: needles
  // and replacements are config strings, never arbitrary bytes.
  let mut replaced = vec![false; pairs.len()];
  let mut out = String::with_capacity(current.len());
  for (i, line) in current.split("\r\n").enumerate() {
    if i > 0 {
      out.push_str("\r\n");
    }
    if line.split_once(':').is_some_and(|(name, _)| name.eq_ignore_ascii_case("host")) {
      out.push_str(line);
      continue;
    }
    let mut buf = line.as_bytes().to_vec();
    for (pi, pair) in pairs.iter().enumerate() {
      if let Some(next) = replace_bytes(&buf, &pair.needle, &pair.replacement) {
        buf = next;
        replaced[pi] = true;
      }
    }
    out.push_str(&String::from_utf8_lossy(&buf));
  }
  for (pi, pair) in pairs.iter().enumerate() {
    if replaced[pi] {
      hits.push(Hit {
        label: pair.label.clone(),
        location: Location::Header,
      });
    }
  }
  (out.into_bytes(), hits)
}

/// Substitute inside `Authorization: Basic` lines (decode → replace →
/// re-encode). Returns true when any line changed.
fn substitute_basic_lines(head: &mut String, needle: &str, replacement: &str) -> bool {
  let mut changed = false;
  let mut out = String::with_capacity(head.len());
  for (i, line) in head.split("\r\n").enumerate() {
    if i > 0 {
      out.push_str("\r\n");
    }
    let Some((name, value)) = line.split_once(':') else {
      out.push_str(line);
      continue;
    };
    if !name.eq_ignore_ascii_case("authorization") {
      out.push_str(line);
      continue;
    }
    let value = value.trim_start();
    let Some(split_at) = value.find(char::is_whitespace) else {
      out.push_str(line);
      continue;
    };
    let (scheme, encoded) = value.split_at(split_at);
    if !scheme.eq_ignore_ascii_case("basic") {
      out.push_str(line);
      continue;
    }
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
      out.push_str(line);
      continue;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
      out.push_str(line);
      continue;
    };
    if !decoded.contains(needle) {
      out.push_str(line);
      continue;
    }
    let replaced = decoded.replace(needle, replacement);
    out.push_str(name);
    out.push_str(": Basic ");
    out.push_str(&base64::engine::general_purpose::STANDARD.encode(replaced.as_bytes()));
    changed = true;
  }
  *head = out;
  changed
}

fn find_header_boundary(data: &[u8]) -> Option<usize> {
  data.windows(4).position(|w| w == b"\r\n\r\n").map(|pos| pos + 4)
}

/// Rewrite the `Content-Length` line(s) to `new_len` (case-insensitive).
fn update_content_length(head: &[u8], new_len: usize) -> Vec<u8> {
  let head_str = String::from_utf8_lossy(head);
  let mut result = String::with_capacity(head_str.len());
  for (i, line) in head_str.split("\r\n").enumerate() {
    if i > 0 {
      result.push_str("\r\n");
    }
    if line
      .as_bytes()
      .get(..15)
      .is_some_and(|b| b.eq_ignore_ascii_case(b"content-length:"))
    {
      let _ = write!(result, "Content-Length: {new_len}");
    } else {
      result.push_str(line);
    }
  }
  result.into_bytes()
}

/// Offset of the first `\r\n` in `data`, if present.
fn find_crlf(data: &[u8]) -> Option<usize> {
  if data.len() < 2 {
    return None;
  }
  data.windows(2).position(|w| w == b"\r\n")
}

fn parse_chunk_size(line: &[u8]) -> Option<usize> {
  let size = line.split(|byte| *byte == b';').next().unwrap_or_default();
  let size = size.trim_ascii();
  if size.is_empty() {
    return None;
  }
  let size = std::str::from_utf8(size).ok()?;
  let size = usize::from_str_radix(size, 16).ok()?;
  // Sizes above the buffering bound are definitionally oversize; a hostile
  // `usize`-max value must never reach downstream cursor arithmetic.
  (size <= MAX_BODY_BYTES).then_some(size)
}

/// Decode a complete chunked body, substitute payloads, re-encode as a
/// single chunk with fresh sizes; trailers forwarded verbatim.
fn reencode_chunked(raw: &[u8], pairs: &[Pair]) -> (Vec<u8>, Vec<Hit>) {
  let mut payload = Vec::new();
  let mut cursor = 0;
  let trailers_start = loop {
    let line_end = raw[cursor..]
      .windows(2)
      .position(|w| w == b"\r\n")
      .map_or(raw.len(), |rel| rel + cursor);
    let size = parse_chunk_size(&raw[cursor..line_end]).unwrap_or(0);
    cursor = (line_end + 2).min(raw.len());
    if size == 0 {
      break cursor;
    }
    let end = (cursor + size).min(raw.len());
    payload.extend_from_slice(&raw[cursor..end]);
    cursor = (end + 2).min(raw.len());
  };
  let (new_payload, mut hits) = replace_in(&payload, pairs, Location::Body);
  let (new_trailers, trailer_hits) = replace_in(&raw[trailers_start..], pairs, Location::Body);
  hits.extend(trailer_hits);
  let mut out = Vec::with_capacity(raw.len() + 16);
  if !new_payload.is_empty() {
    out.extend_from_slice(format!("{:X}\r\n", new_payload.len()).as_bytes());
    out.extend_from_slice(&new_payload);
    out.extend_from_slice(b"\r\n");
  }
  out.extend_from_slice(b"0\r\n");
  out.extend_from_slice(&new_trailers);
  (out, hits)
}

impl SubMachine for SecretsMachine {
  fn substitute<'b>(&mut self, chunk: &'b [u8]) -> (Cow<'b, [u8]>, Vec<Hit>) {
    SecretsMachine::substitute(self, chunk)
  }
  fn take_head_requests(&mut self) -> usize {
    std::mem::take(&mut self.head_requests)
  }
  fn suppress_next_bodies(&mut self, n: usize) {
    self.suppress_body += n;
  }
  fn must_close(&self) -> bool {
    self.must_close
  }
}

/// Longest suffix of `data` (bounded by `bound`) that is a proper prefix of
/// some needle: exactly the bytes that might still grow into a match.
fn needle_prefix_suffix_len(data: &[u8], pairs: &[Pair], bound: usize) -> usize {
  let max = bound.min(data.len());
  for keep in (1..=max).rev() {
    let suffix = &data[data.len() - keep..];
    if pairs.iter().any(|pair| pair.needle.len() > keep && pair.needle.starts_with(suffix)) {
      return keep;
    }
  }
  0
}

#[cfg(test)]
mod tests {
  use super::*;

  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  fn grants() -> Vec<Grant> {
    vec![Grant {
      label: "github".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
      allow: vec!["https://api.github.com".parse::<hodor_config::grants::UriGrant>().unwrap()],
    }]
  }

  fn req_machine() -> SecretsMachine {
    SecretsMachine::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Request)
  }

  fn resp_machine() -> SecretsMachine {
    SecretsMachine::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Response)
  }

  #[test]
  fn request_header_substituted_and_response_redacted() {
    let mut req = req_machine();
    let input = format!("GET /x HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {FAKE}\r\n\r\n");
    let (out, hits) = req.substitute(input.as_bytes());
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains(VALUE), "{out}");
    assert!(!out.contains(FAKE), "{out}");
    assert_eq!(
      hits,
      vec![Hit {
        label: "github".into(),
        location: Location::Header
      }]
    );

    let mut resp = resp_machine();
    let body = format!("token={VALUE}");
    let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (out, hits) = resp.substitute(input.as_bytes());
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains(FAKE), "{out}");
    assert!(!out.contains(VALUE), "{out}");
    assert_eq!(
      hits,
      vec![Hit {
        label: "github".into(),
        location: Location::Body
      }]
    );
  }

  #[test]
  fn host_header_preserved_while_other_headers_substituted() {
    let mut req = req_machine();
    let input = format!("GET /x HTTP/1.1\r\nHost: {FAKE}\r\nX-Token: {FAKE}\r\n\r\n");
    let (out, hits) = req.substitute(input.as_bytes());
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains(&format!("Host: {FAKE}\r\n")), "{out}");
    assert!(out.contains(&format!("X-Token: {VALUE}\r\n")), "{out}");
    assert_eq!(
      hits,
      vec![Hit {
        label: "github".into(),
        location: Location::Header
      }]
    );
  }

  #[test]
  fn basic_auth_decoded_substituted_reencoded() {
    let creds = base64::engine::general_purpose::STANDARD.encode(format!("user:{FAKE}"));
    let mut req = req_machine();
    let input = format!("GET /x HTTP/1.1\r\nAuthorization: Basic {creds}\r\n\r\n");
    let (out, hits) = req.substitute(input.as_bytes());
    let out = String::from_utf8(out.into_owned()).unwrap();
    let encoded = out.split("Authorization: Basic ").nth(1).unwrap().split("\r\n").next().unwrap();
    let decoded = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded.trim()).unwrap()).unwrap();
    assert_eq!(decoded, format!("user:{VALUE}"));
    assert!(hits.iter().any(|hit| hit.location == Location::BasicAuth));
  }

  #[test]
  fn content_length_rewritten_only_on_size_change() {
    // Same length: header untouched.
    let mut req = req_machine();
    let body = format!("x={FAKE}");
    let input = format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (out, _) = req.substitute(input.as_bytes());
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains(&format!("Content-Length: {}\r\n", body.len())), "{out}");
    assert!(out.contains(VALUE), "{out}");

    // Shrinking substitution: header rewritten.
    let short_value_grants = vec![Grant {
      label: "g".into(),
      fake: "LONGFAKEVALUE".into(),
      value: secrecy::SecretString::from("short"),
      allow: vec!["https://api.github.com".parse::<hodor_config::grants::UriGrant>().unwrap()],
    }];
    let mut machine = SecretsMachine::new(&short_value_grants, Scheme::Https, "api.github.com", 443, Direction::Request);
    let body = "x=LONGFAKEVALUE";
    let input = format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let (out, _) = machine.substitute(input.as_bytes());
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(out.contains("Content-Length: 7\r\n"), "{out}");
    assert!(out.ends_with("x=short"), "{out}");
  }

  #[test]
  fn chunked_split_across_writes_reencoded_valid() {
    // Two chunks: "xx" + FAKE(44 = 0x2c bytes).
    let head = "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    let chunk_a = "2\r\nxx\r\n";
    let (fake_first, fake_rest) = FAKE.split_at(20);
    let part1 = format!("{head}{chunk_a}2c\r\n{fake_first}");
    let part2 = format!("{fake_rest}\r\n0\r\n\r\n");
    let mut req = req_machine();
    // Split the first part mid-head to exercise buffering too.
    let mid = head.len() - 10;
    let (out1, _) = req.substitute(&part1.as_bytes()[..mid]);
    let out1 = out1.into_owned();
    assert!(out1.is_empty());
    let (out2, _) = req.substitute(&part1.as_bytes()[mid..]);
    let out2 = out2.into_owned();
    let (out3, hits) = req.substitute(part2.as_bytes());
    let out3 = out3.into_owned();
    let mut full = out1;
    full.extend_from_slice(&out2);
    full.extend_from_slice(&out3);
    let full_str = String::from_utf8(full).unwrap();
    assert!(full_str.contains(VALUE), "{full_str}");
    assert!(!full_str.contains(FAKE), "{full_str}");
    assert!(hits.iter().any(|hit| hit.location == Location::Body));
    // Valid chunked framing: single data chunk + terminator.
    let body_start = full_str.find("\r\n\r\n").unwrap() + 4;
    let body = &full_str[body_start..];
    assert!(body.ends_with("0\r\n\r\n"), "{body}");
    let first_line_end = body.find("\r\n").unwrap();
    let size = usize::from_str_radix(&body[..first_line_end], 16).unwrap();
    assert_eq!(size, 2 + VALUE.len());
    assert_eq!(&body[first_line_end + 2..first_line_end + 2 + size], &format!("xx{VALUE}"));
  }

  #[test]
  fn te_plus_cl_forwarded_unchanged_with_hit() {
    let mut req = req_machine();
    let input = format!("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n{FAKE}");
    let (out, hits) = req.substitute(input.as_bytes());
    assert_eq!(out.as_ref(), input.as_bytes());
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].location, Location::Body);
  }

  #[test]
  fn oversize_body_scan_only_with_hits() {
    let mut req = req_machine();
    let head = format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY_BYTES + 1);
    let (out, hits) = req.substitute(head.as_bytes());
    assert_eq!(out.as_ref(), head.as_bytes());
    assert!(hits.is_empty());
    let scan_input = format!("prefix-{FAKE}-suffix");
    let (out, hits) = req.substitute(scan_input.as_bytes());
    assert_eq!(out.as_ref(), scan_input.as_bytes());
    assert_eq!(
      hits,
      vec![Hit {
        label: "github".into(),
        location: Location::Body
      }]
    );
  }

  #[test]
  fn cross_write_fake_matches_in_scan_mode() {
    let mut opaque = SecretsMachine::new_opaque(&grants(), Scheme::Https, "api.github.com", 443, Direction::Request);
    let (first, second) = FAKE.split_at(20);
    let (_, hits1) = opaque.substitute(first.as_bytes());
    assert!(hits1.is_empty());
    let (out2, hits2) = opaque.substitute(second.as_bytes());
    assert_eq!(out2.as_ref(), second.as_bytes());
    assert_eq!(hits2.len(), 1);
  }

  #[test]
  fn raw_mode_replaces_equal_length_across_writes() {
    let grants = vec![Grant {
      label: "db".into(),
      fake: "FAKE1234".into(),
      value: secrecy::SecretString::from("REAL5678"),
      allow: vec!["tcp://10.0.0.8:5432".parse::<hodor_config::grants::UriGrant>().unwrap()],
    }];
    let mut raw = SecretsMachine::new_raw(&grants, "10.0.0.8", 5432, Direction::Request);
    let (out1, _) = raw.substitute(b"xxFAKE");
    let out1 = out1.into_owned();
    let (out2, _) = raw.substitute(b"1234yy");
    let out2 = out2.into_owned();
    let (flush, _) = raw.substitute(&[]);
    let flush = flush.into_owned();
    let mut full = out1;
    full.extend_from_slice(&out2);
    full.extend_from_slice(&flush);
    assert_eq!(full, b"xxREAL5678yy");
  }

  #[test]
  fn raw_mode_skips_unequal_length() {
    let grants = vec![Grant {
      label: "u".into(),
      fake: "SHORT".into(),
      value: secrecy::SecretString::from("A-MUCH-LONGER-VALUE"),
      allow: vec!["tcp://10.0.0.8:5432".parse::<hodor_config::grants::UriGrant>().unwrap()],
    }];
    let mut raw = SecretsMachine::new_raw(&grants, "10.0.0.8", 5432, Direction::Request);
    let (out, hits) = raw.substitute(b"xxSHORTyy");
    let out = out.into_owned();
    let (flush, _) = raw.substitute(&[]);
    let flush = flush.into_owned();
    let mut full = out;
    full.extend_from_slice(&flush);
    assert_eq!(full, b"xxSHORTyy");
    assert!(hits.is_empty());
  }

  #[test]
  fn raw_mode_flushes_complete_line_without_more_input() {
    // Lockstep protocols send one line and wait for the reply: the fully
    // substituted line must leave the machine before any further chunk.
    let grants = vec![Grant {
      label: "db".into(),
      fake: "FAKE1234".into(),
      value: secrecy::SecretString::from("REAL5678"),
      allow: vec!["tcp://10.0.0.8:5432".parse::<hodor_config::grants::UriGrant>().unwrap()],
    }];
    let mut raw = SecretsMachine::new_raw(&grants, "10.0.0.8", 5432, Direction::Request);
    let (out, hits) = raw.substitute(b"auth FAKE1234\n");
    assert_eq!(out.as_ref(), b"auth REAL5678\n");
    assert_eq!(hits.len(), 1);
  }

  #[test]
  fn raw_tls_mode_matches_https_grants() {
    // PlainMode::Raw behind terminated TLS: the endpoint identity is an
    // `https://` grant, so the raw machine must match it, not `tcp://`.
    let grants = vec![Grant {
      label: "api".into(),
      fake: "FAKE1234".into(),
      value: secrecy::SecretString::from("REAL5678"),
      allow: vec!["https://api:9443".parse::<hodor_config::grants::UriGrant>().unwrap()],
    }];
    let mut req = SecretsMachine::new_raw_tls(&grants, "api", 9443, Direction::Request);
    let (out, hits) = req.substitute(b"auth FAKE1234\n");
    assert_eq!(out.as_ref(), b"auth REAL5678\n");
    assert_eq!(hits.len(), 1);
    let mut resp = SecretsMachine::new_raw_tls(&grants, "api", 9443, Direction::Response);
    let (out, hits) = resp.substitute(b"ok REAL5678\n");
    assert_eq!(out.as_ref(), b"ok FAKE1234\n");
    assert_eq!(hits.len(), 1);
  }

  #[test]
  fn pipelined_requests_both_substituted() {
    let mut req = req_machine();
    let input = format!("GET /a HTTP/1.1\r\nAuthorization: Bearer {FAKE}\r\n\r\nGET /b HTTP/1.1\r\nAuthorization: Bearer {FAKE}\r\n\r\n");
    let (out, hits) = req.substitute(input.as_bytes());
    let out = String::from_utf8(out.into_owned()).unwrap();
    assert!(!out.contains(FAKE), "{out}");
    assert_eq!(out.matches(VALUE).count(), 2);
    assert_eq!(hits.len(), 2);
  }

  #[test]
  fn non_utf8_head_goes_opaque_unchanged() {
    let mut req = req_machine();
    let mut input = b"GET /x HTTP/1.1\r\nX-Bin: \xff\xfe\r\n\r\n".to_vec();
    input.extend_from_slice(FAKE.as_bytes());
    let (out, _) = req.substitute(&input);
    assert_eq!(out.as_ref(), input.as_slice());
  }

  #[test]
  fn flush_emits_partial_head_unchanged() {
    let mut req = req_machine();
    let (out, _) = req.substitute(b"GET /x HTTP/1.1\r\nAuthorization: Bearer ");
    assert!(out.is_empty());
    let (flush, _) = req.substitute(&[]);
    assert_eq!(flush.as_ref(), b"GET /x HTTP/1.1\r\nAuthorization: Bearer ");
  }

  #[test]
  fn unchanged_chunk_borrows_zero_copy() {
    let mut req = req_machine();
    let input = b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n";
    let (out, hits) = req.substitute(input);
    assert!(matches!(out, Cow::Borrowed(_)));
    assert!(hits.is_empty());
  }

  #[test]
  fn empty_content_length_emits_head_immediately() {
    let mut resp = resp_machine();
    let (out, _) = resp.substitute(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(out.as_ref(), b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  }

  #[test]
  fn no_body_status_ignores_framing() {
    let mut resp = resp_machine();
    let (out, _) = resp.substitute(b"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n");
    assert_eq!(out.as_ref(), b"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n");
    // Next bytes are a new response head, not a swallowed body.
    let (out, _) = resp.substitute(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(out.as_ref(), b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  }

  #[test]
  fn head_response_carries_no_body() {
    let mut req = req_machine();
    let mut resp = resp_machine();
    let (out, _) = req.substitute(b"HEAD /x HTTP/1.1\r\nHost: a\r\n\r\n");
    assert!(!out.is_empty());
    resp.suppress_next_bodies(req.take_head_requests());
    let body = format!("token={VALUE}");
    let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    let (out, _) = resp.substitute(input.as_bytes());
    assert_eq!(out.as_ref(), input.as_bytes());
  }

  #[test]
  fn hostile_oversize_chunk_size_degrades_not_panics() {
    // usize::MAX-ish size: must fall to scan-only, never panic on
    // cursor arithmetic.
    let mut req = req_machine();
    let input = b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff;\r\n";
    let (out, _) = req.substitute(input);
    assert_eq!(out.as_ref(), input);
  }

  #[test]
  fn chunked_drip_fed_byte_by_byte_reencoded() {
    // One byte per substitute() call: exercises the incremental chunk
    // parser's resume logic (CRLF straddling arrivals, partial sizes).
    let mut req = req_machine();
    let fake_first = &FAKE[..3];
    let fake_rest = &FAKE[3..];
    let input = format!(
      "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nxx{fake_first}\r\n{:X}\r\n",
      fake_rest.len()
    );
    let tail = format!("{fake_rest}\r\n0\r\n\r\n");
    let full = format!("{input}{tail}");
    let mut collected = Vec::new();
    for byte in full.as_bytes() {
      let (out, _) = req.substitute(std::slice::from_ref(byte));
      collected.extend_from_slice(&out);
    }
    let (flush, _) = req.substitute(&[]);
    collected.extend_from_slice(&flush);
    let text = String::from_utf8(collected).unwrap();
    assert!(text.contains(VALUE), "{text}");
    assert!(!text.contains(FAKE), "{text}");
    // Valid re-encoded framing: single chunk holding the full payload.
    let body_start = text.find("\r\n\r\n").unwrap() + 4;
    let body = &text[body_start..];
    let size_line_end = body.find("\r\n").unwrap();
    let size = usize::from_str_radix(&body[..size_line_end], 16).unwrap();
    assert_eq!(size, 2 + VALUE.len());
  }

  #[test]
  fn opaque_state_passes_through_borrowed() {
    let mut req = req_machine();
    // Close-delimited response head → Opaque body streaming.
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    let _ = req.substitute(head);
    let body = b"plain body bytes without secrets";
    let (out, hits) = req.substitute(body);
    assert!(matches!(out, Cow::Borrowed(_)));
    assert!(matches!(req.state, State::Opaque));
    assert!(hits.is_empty());
  }

  #[test]
  fn close_delimited_response_redacts_at_eof() {
    let mut resp = resp_machine();
    let (head_out, _) = resp.substitute(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
    let head_out = head_out.into_owned();
    assert!(head_out.starts_with(b"HTTP/1.1 200 OK"));
    assert!(matches!(resp.state, State::CloseDelimited), "{:?}", resp.state);
    let body = format!("tok-{VALUE}-end");
    let (body_out, hits) = resp.substitute(body.as_bytes());
    let body_out = body_out.into_owned();
    assert!(body_out.is_empty(), "close-delimited bodies buffer until EOF");
    assert!(hits.is_empty());
    let (flush, flush_hits) = resp.substitute(&[]);
    let flush = flush.into_owned();
    let flush_str = String::from_utf8_lossy(&flush);
    assert!(flush_str.contains(FAKE), "{flush_str}");
    assert!(!flush_str.contains(VALUE), "{flush_str}");
    assert_eq!(flush_hits.len(), 1);
    assert!(!resp.must_close());
  }

  #[test]
  fn close_delimited_without_pairs_streams_zero_copy() {
    let mut resp = SecretsMachine::new(&[], Scheme::Https, "api.github.com", 443, Direction::Response);
    let _ = resp.substitute(b"HTTP/1.1 200 OK\r\n\r\n");
    assert!(matches!(resp.state, State::Opaque), "{:?}", resp.state);
    let (out, hits) = resp.substitute(b"body-bytes");
    assert!(matches!(out, Cow::Borrowed(_)));
    assert!(hits.is_empty());
  }

  #[test]
  fn compressed_response_hit_fails_closed() {
    let mut resp = resp_machine();
    let body = format!("blob-{VALUE}-blob");
    let head = format!(
      "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
      body.len()
    );
    let (out, hits) = resp.substitute(head.as_bytes());
    let out = out.into_owned();
    assert!(out.ends_with(b"\r\n\r\n"));
    assert!(hits.is_empty());
    let (_out, hits) = resp.substitute(body.as_bytes());
    assert_eq!(hits.len(), 1);
    assert!(resp.must_close(), "compressed body hit must fail closed");
    // Request direction never fails closed on scan-only hits.
    let mut req = req_machine();
    let body = format!("blob-{FAKE}-blob");
    let head = format!(
      "POST /x HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
      body.len()
    );
    let _ = req.substitute(head.as_bytes());
    let (_out, hits) = req.substitute(body.as_bytes());
    assert_eq!(hits.len(), 1);
    assert!(!req.must_close());
  }

  #[test]
  fn chunked_trailers_redacted() {
    let mut resp = resp_machine();
    let input = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Tok: {VALUE}\r\n\r\n");
    let (out, hits) = resp.substitute(input.as_bytes());
    let out = out.into_owned();
    let out_str = String::from_utf8_lossy(&out);
    assert!(out_str.contains(&format!("X-Tok: {FAKE}")), "{out_str}");
    assert!(!out_str.contains(VALUE), "{out_str}");
    assert!(hits.iter().any(|hit| hit.location == Location::Body));
    assert!(!resp.must_close());
  }

  #[test]
  fn no_body_status_includes_205() {
    assert!(response_has_no_body(Some(205)));
  }
}
