//! Secret substitution state machines (HTTP/1, raw TCP, opaque scan).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use base64::Engine as _;
use httlib_hpack::{Decoder, Encoder};
use secrecy::ExposeSecret as _;

use crate::grants::{Grant, Scheme};

/// Max buffered header block before degrading to opaque scan-only.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Max buffered fixed-length or chunked body before scan-only fallback.
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Max header fields per head block for httparse scratch space.
const MAX_HEADERS: usize = 128;
/// HTTP/2 connection preface.
pub const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_MAX_BLOCK: usize = 64 * 1024;
const H2_MAX_FIELDS: usize = 1024;
const H2_MAX_STREAMS: usize = 1024;
const H2_OUTBOUND_PAYLOAD: usize = 16 * 1024;
const F_DATA: u8 = 0x0;
const F_HEADERS: u8 = 0x1;
const F_RST_STREAM: u8 = 0x3;
const F_PUSH_PROMISE: u8 = 0x5;
const F_CONTINUATION: u8 = 0x9;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// Chunk direction: guest→server requests or server→guest responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
  /// Guest→server: substitute decoy fakes with real values.
  Request,
  /// Server→guest: redact real values back to decoy fakes.
  Response,
}

/// Where a substitution hit was found (log context only, never values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
  /// Raw header bytes.
  Header,
  /// Inside an `Authorization: Basic` credential.
  BasicAuth,
  /// Message body / DATA payload.
  Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
  /// Grant label identifying the secret (never the value itself).
  pub label: String,
  /// Where the match was found.
  pub location: Location,
}

struct Pair {
  needle: Vec<u8>,
  replacement: Vec<u8>,
  label: String,
}

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
#[allow(
  clippy::struct_excessive_bools,
  reason = "framing state machine: each bool is one independent latch"
)]
pub struct SecretsMachine {
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
  pub fn new(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction) -> Self {
    Self::build(grants, scheme, host, port, dir, State::Head, false)
  }

  /// Raw TCP machine: only equal-length pairs (framing safety).
  pub fn new_raw(grants: &[Grant], host: &str, port: u16, dir: Direction) -> Self {
    Self::build(grants, Scheme::Tcp, host, port, dir, State::Raw, true)
  }

  /// Raw machine behind terminated TLS (`PlainMode::Raw`): the endpoint's
  /// identity is the `https://` grant, not `tcp://`.
  pub fn new_raw_tls(grants: &[Grant], host: &str, port: u16, dir: Direction) -> Self {
    Self::build(grants, Scheme::Https, host, port, dir, State::Raw, true)
  }

  /// Opaque machine: scan-only, forward unchanged (framing unknowable).
  #[cfg(test)]
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

/// Eligible needle→replacement pairs for a connection endpoint.
fn eligible_pairs(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction, equal_len_only: bool) -> Vec<Pair> {
  let mut pairs = Vec::new();
  for grant in grants {
    if !grant.matches(scheme, host, port) {
      continue;
    }
    let (needle, replacement) = match dir {
      Direction::Request => (grant.fake.as_bytes(), grant.value.expose_secret().as_bytes()),
      Direction::Response => (grant.value.expose_secret().as_bytes(), grant.fake.as_bytes()),
    };
    if needle.is_empty() || replacement.is_empty() {
      continue;
    }
    if equal_len_only && needle.len() != replacement.len() {
      continue;
    }
    pairs.push(Pair {
      needle: needle.to_vec(),
      replacement: replacement.to_vec(),
      label: grant.label.clone(),
    });
  }
  pairs
}

/// Cross-chunk overlap window: longest needle minus one.
fn max_tail_size(pairs: &[Pair]) -> usize {
  pairs.iter().map(|pair| pair.needle.len()).max().unwrap_or(1).saturating_sub(1)
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

/// True for response statuses that never carry a body (1xx, 204, 304).
fn response_has_no_body(status: Option<u16>) -> bool {
  let Some(code) = status else {
    return false;
  };
  (100..200).contains(&code) || code == 204 || code == 205 || code == 304
}

/// True when decoded H2 headers carry `:method: HEAD`.
fn is_head_method(headers: &[(Vec<u8>, Vec<u8>, u8)]) -> bool {
  headers
    .iter()
    .any(|(name, value, _)| name.eq_ignore_ascii_case(b":method") && value.eq_ignore_ascii_case(b"head"))
}

/// True when decoded H2 response headers carry a no-body `:status`.
fn response_status_no_body(headers: &[(Vec<u8>, Vec<u8>, u8)]) -> bool {
  let status = headers.iter().find_map(|(name, value, _)| {
    name
      .eq_ignore_ascii_case(b":status")
      .then(|| std::str::from_utf8(value).ok()?.trim().parse::<u16>().ok())?
  });
  response_has_no_body(status)
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

/// Substitute inside a decoded H2 authorization value (scheme + base64).
/// Returns the re-encoded value when a replacement happened.
fn substitute_basic_value(value: &str, needle: &str, replacement: &str) -> Option<String> {
  let (scheme, encoded) = value.split_once(char::is_whitespace)?;
  if !scheme.eq_ignore_ascii_case("basic") {
    return None;
  }
  let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
    Ok(bytes) => match String::from_utf8(bytes) {
      Ok(text) => text,
      Err(_) => return None,
    },
    Err(_) => return None,
  };
  if !decoded.contains(needle) {
    return None;
  }
  let replaced = decoded.replace(needle, replacement);
  Some(format!(
    "Basic {}",
    base64::engine::general_purpose::STANDARD.encode(replaced.as_bytes())
  ))
}

/// Replace all non-overlapping occurrences; `None` when nothing matched.
/// Allocates only on first match; copies runs, never byte-at-a-time.
fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
  if needle.is_empty() || haystack.len() < needle.len() {
    return None;
  }
  let mut out: Option<Vec<u8>> = None;
  let mut run_start = 0;
  let mut cursor = 0;
  while cursor + needle.len() <= haystack.len() {
    if haystack[cursor..].starts_with(needle) {
      let buf = out.get_or_insert_with(|| Vec::with_capacity(haystack.len()));
      buf.extend_from_slice(&haystack[run_start..cursor]);
      buf.extend_from_slice(replacement);
      cursor += needle.len();
      run_start = cursor;
    } else {
      cursor += 1;
    }
  }
  out.map(|mut buf| {
    buf.extend_from_slice(&haystack[run_start..]);
    buf
  })
}

fn replace_in(data: &[u8], pairs: &[Pair], location: Location) -> (Vec<u8>, Vec<Hit>) {
  // Lazy clone: zero pairs matching means zero allocations.
  let mut current = Cow::Borrowed(data);
  let mut hits = Vec::new();
  for pair in pairs {
    let hay: &[u8] = match &current {
      Cow::Borrowed(bytes) => bytes,
      Cow::Owned(buf) => buf,
    };
    if let Some(next) = replace_bytes(hay, &pair.needle, &pair.replacement) {
      current = Cow::Owned(next);
      hits.push(Hit {
        label: pair.label.clone(),
        location,
      });
    }
  }
  (current.into_owned(), hits)
}

/// True when `needle` matches at least once with the match ending past
/// `tail_len` (matches fully inside the old tail were already reported).
fn find_new_match(combined: &[u8], needle: &[u8], tail_len: usize) -> bool {
  if needle.is_empty() || combined.len() < needle.len() {
    return false;
  }
  combined
    .windows(needle.len())
    .enumerate()
    .any(|(i, w)| w == needle && i + needle.len() > tail_len)
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
      allow: vec!["https://api.github.com".parse::<crate::grants::UriGrant>().unwrap()],
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
      allow: vec!["https://api.github.com".parse::<crate::grants::UriGrant>().unwrap()],
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
      allow: vec!["tcp://10.0.0.8:5432".parse::<crate::grants::UriGrant>().unwrap()],
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
      allow: vec!["tcp://10.0.0.8:5432".parse::<crate::grants::UriGrant>().unwrap()],
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
      allow: vec!["tcp://10.0.0.8:5432".parse::<crate::grants::UriGrant>().unwrap()],
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
      allow: vec!["https://api:9443".parse::<crate::grants::UriGrant>().unwrap()],
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

// ---------------------------------------------------------------------------
// HTTP/2: HPACK header substitution, DATA scan-only
// ---------------------------------------------------------------------------

/// Anything that substitutes one chunk: HTTP/1, raw, opaque, or H2.
pub trait SubMachine {
  /// Process one chunk; empty input flushes held bytes at stream EOF.
  fn substitute<'b>(&mut self, chunk: &'b [u8]) -> (Cow<'b, [u8]>, Vec<Hit>);
  /// Drain pending HEAD-request count (request side only).
  fn take_head_requests(&mut self) -> usize {
    0
  }
  /// Suppress bodies for the next N responses (response side only).
  fn suppress_next_bodies(&mut self, _n: usize) {}
  /// Fail-closed latch: a scan-only path saw a needle it could not rewrite;
  /// the relay must drop the connection instead of leaking it.
  fn must_close(&self) -> bool {
    false
  }
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

/// Relay machine: HTTP/1-family or HTTP/2, chosen after protocol sniffing.
pub enum AnyMachine {
  Http1(SecretsMachine),
  H2(H2Machine),
}

impl SubMachine for AnyMachine {
  fn substitute<'b>(&mut self, chunk: &'b [u8]) -> (Cow<'b, [u8]>, Vec<Hit>) {
    match self {
      AnyMachine::Http1(machine) => machine.substitute(chunk),
      AnyMachine::H2(machine) => machine.substitute(chunk),
    }
  }
  fn take_head_requests(&mut self) -> usize {
    match self {
      AnyMachine::Http1(machine) => machine.take_head_requests(),
      AnyMachine::H2(machine) => machine.take_head_requests(),
    }
  }
  fn suppress_next_bodies(&mut self, n: usize) {
    match self {
      AnyMachine::Http1(machine) => machine.suppress_next_bodies(n),
      AnyMachine::H2(machine) => machine.suppress_next_bodies(n),
    }
  }
  fn must_close(&self) -> bool {
    match self {
      AnyMachine::Http1(machine) => machine.must_close(),
      AnyMachine::H2(machine) => machine.must_close(),
    }
  }
}

struct H2Block {
  stream_id: u32,
  end_stream: bool,
  fragments: Vec<u8>,
  raw: Vec<u8>,
}

/// Per-connection, per-direction HTTP/2 machine. HEADERS/CONTINUATION blocks
/// are HPACK-decoded, substituted, and re-encoded; DATA payloads are
/// substituted with the frame length rewritten (a per-stream overlap window
/// is held back so cross-frame split secrets substitute whole). Any framing
/// violation degrades to opaque scan-only forwarding.
pub struct H2Machine {
  pairs: Vec<Pair>,
  dir: Direction,
  decoder: Decoder<'static>,
  encoder: Encoder<'static>,
  buffer: Vec<u8>,
  preface_done: bool,
  block: Option<H2Block>,
  open_streams: HashSet<u32>,
  data_tails: HashMap<u32, Vec<u8>>,
  opaque: bool,
  scan_tail: Vec<u8>,
  tail_size: usize,
  /// Request side: HEAD methods seen, pending pickup by the relay.
  head_requests: usize,
  /// Response side: next N response HEADERS carry no DATA (HEAD replies).
  suppress_body: usize,
  /// Fail-closed latch: a scan-only path hit a needle it could not rewrite.
  must_close: bool,
}

impl H2Machine {
  /// `expect_preface` is true for the request direction only; responses
  /// start with frames.
  pub fn new(grants: &[Grant], scheme: Scheme, host: &str, port: u16, dir: Direction, expect_preface: bool) -> Self {
    let pairs = eligible_pairs(grants, scheme, host, port, dir, false);
    let tail_size = max_tail_size(&pairs);
    Self {
      pairs,
      dir,
      decoder: Decoder::default(),
      encoder: Encoder::default(),
      buffer: Vec::new(),
      preface_done: !expect_preface,
      block: None,
      open_streams: HashSet::new(),
      data_tails: HashMap::new(),
      opaque: false,
      scan_tail: Vec::new(),
      tail_size,
      head_requests: 0,
      suppress_body: 0,
      must_close: false,
    }
  }

  /// Process one chunk. Inherent implementation of the [`SubMachine`] protocol;
  /// the trait impl below forwards here so concrete and dynamic callers share
  /// one code path.
  pub fn substitute<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    if chunk.is_empty() {
      let mut out = std::mem::take(&mut self.buffer);
      if let Some(block) = self.block.take() {
        out.extend_from_slice(&block.raw);
      }
      // Flush per-stream DATA hold-backs: substitute and emit (stream order
      // across streams is already lost at EOF; dropping would lose bytes).
      let mut held_hits = Vec::new();
      for (stream_id, held) in std::mem::take(&mut self.data_tails) {
        if held.is_empty() {
          continue;
        }
        let (new_held, mut hh) = replace_in(&held, &self.pairs, Location::Body);
        held_hits.append(&mut hh);
        // A held window can exceed the 24-bit length only with a >16 MiB
        // needle; split rather than emit a lying length field.
        let mut offset = 0;
        while offset < new_held.len() {
          let take = (new_held.len() - offset).min(0xff_ffff);
          append_frame(&mut out, F_DATA, 0, stream_id, &new_held[offset..offset + take]);
          offset += take;
        }
      }
      return (Cow::Owned(out), held_hits);
    }
    if self.opaque {
      let hits = scan_with_tail(&self.pairs, &mut self.scan_tail, self.tail_size, chunk, Location::Body);
      if self.dir == Direction::Response && !hits.is_empty() {
        self.must_close = true;
      }
      return (Cow::Borrowed(chunk), hits);
    }
    self.buffer.extend_from_slice(chunk);
    let mut out = Vec::new();
    let mut hits = Vec::new();
    if !self.preface_done {
      if self.buffer.len() < H2_PREFACE.len() {
        return (Cow::Owned(Vec::new()), hits);
      }
      if !self.buffer.starts_with(H2_PREFACE) {
        self.go_opaque(&mut out, &mut hits);
        return finalize_borrow(chunk, out, hits);
      }
      out.extend_from_slice(H2_PREFACE);
      self.buffer.drain(..H2_PREFACE.len());
      self.preface_done = true;
    }
    // Take the buffer out of `self` so frame slices borrow the local vec
    // while `process_frame` mutates machine state; one compaction per
    // chunk instead of a memmove per frame.
    let mut buf = std::mem::take(&mut self.buffer);
    let mut cursor = 0;
    while buf.len() - cursor >= 9 {
      let len = ((buf[cursor] as usize) << 16) | ((buf[cursor + 1] as usize) << 8) | buf[cursor + 2] as usize;
      let full = 9 + len;
      if buf.len() - cursor < full {
        break;
      }
      let raw = &buf[cursor..cursor + full];
      let violation = match self.process_frame(raw, &mut hits) {
        Ok(emit) => {
          out.extend_from_slice(&emit);
          cursor += full;
          continue;
        }
        Err(emit) => emit,
      };
      // Violation: emit held + current bytes, go opaque, drain the rest.
      hits.extend(scan_with_tail(
        &self.pairs,
        &mut self.scan_tail,
        self.tail_size,
        &violation,
        Location::Body,
      ));
      out.extend_from_slice(&violation);
      self.buffer = buf.split_off(cursor + full);
      self.go_opaque(&mut out, &mut hits);
      return finalize_borrow(chunk, out, hits);
    }
    buf.drain(..cursor);
    self.buffer = buf;
    finalize_borrow(chunk, out, hits)
  }

  /// Process one complete frame. Ok = bytes to emit (borrowed when the
  /// frame passes through untouched, empty while holding a block); Err =
  /// bytes to emit before going opaque. `raw` borrows the caller's local
  /// frame buffer, never `self`.
  fn process_frame<'f>(&mut self, raw: &'f [u8], hits: &mut Vec<Hit>) -> Result<Cow<'f, [u8]>, Vec<u8>> {
    let kind = raw[3];
    let flags = raw[4];
    let stream_id = u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]) & 0x7fff_ffff;
    let payload = &raw[9..];
    if self.block.is_some() && kind != F_CONTINUATION {
      let mut emit = self.block.take().map(|block| block.raw).unwrap_or_default();
      emit.extend_from_slice(raw);
      return Err(emit);
    }
    match kind {
      F_HEADERS => self.headers_frame(stream_id, flags, payload, raw, hits).map(Cow::Owned),
      F_CONTINUATION => self.continuation_frame(stream_id, flags, payload, raw, hits).map(Cow::Owned),
      F_DATA => self.data_frame(stream_id, flags, payload, raw, hits).map(Cow::Owned),
      F_RST_STREAM => {
        if stream_id == 0 {
          return Err(raw.to_vec());
        }
        self.open_streams.remove(&stream_id);
        self.data_tails.remove(&stream_id);
        Ok(Cow::Borrowed(raw))
      }
      // PUSH_PROMISE carries an HPACK block that mutates the dynamic table;
      // forwarding without decoding would corrupt later HEADERS decoding.
      F_PUSH_PROMISE => Err(raw.to_vec()),
      _ => Ok(Cow::Borrowed(raw)),
    }
  }

  fn headers_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8], raw: &[u8], hits: &mut Vec<Hit>) -> Result<Vec<u8>, Vec<u8>> {
    if stream_id == 0 {
      return Err(raw.to_vec());
    }
    let fragment = headers_fragment(flags, payload).ok_or_else(|| raw.to_vec())?;
    if fragment.len() > H2_MAX_BLOCK {
      return Err(raw.to_vec());
    }
    let block = H2Block {
      stream_id,
      end_stream: flags & FLAG_END_STREAM != 0,
      fragments: fragment.to_vec(),
      raw: raw.to_vec(),
    };
    if flags & FLAG_END_HEADERS != 0 {
      self.finish_block(block, hits)
    } else {
      self.block = Some(block);
      Ok(Vec::new())
    }
  }

  fn continuation_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8], raw: &[u8], hits: &mut Vec<Hit>) -> Result<Vec<u8>, Vec<u8>> {
    let Some(mut block) = self.block.take() else {
      return Err(raw.to_vec());
    };
    if stream_id == 0 || stream_id != block.stream_id {
      block.raw.extend_from_slice(raw);
      return Err(block.raw);
    }
    block.fragments.extend_from_slice(payload);
    block.raw.extend_from_slice(raw);
    if block.fragments.len() > H2_MAX_BLOCK {
      return Err(block.raw);
    }
    if flags & FLAG_END_HEADERS != 0 {
      self.finish_block(block, hits)
    } else {
      self.block = Some(block);
      Ok(Vec::new())
    }
  }

  fn data_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8], raw: &[u8], hits: &mut Vec<Hit>) -> Result<Vec<u8>, Vec<u8>> {
    if stream_id == 0 || !self.open_streams.contains(&stream_id) {
      return Err(raw.to_vec());
    }
    let data = data_payload(flags, payload).ok_or_else(|| raw.to_vec())?;
    let end_stream = flags & FLAG_END_STREAM != 0;
    // Prepend the hold-back so cross-frame split secrets substitute whole;
    // hold the overlap window for the next frame (bounded by tail_size).
    // Padding is dropped and the length rewritten — always legal framing.
    let held_tail = self.data_tails.get_mut(&stream_id).map(std::mem::take).unwrap_or_default();
    let mut combined = held_tail;
    combined.extend_from_slice(data);
    let hold = if end_stream { 0 } else { self.tail_size.min(combined.len()) };
    let emit_len = combined.len() - hold;
    let (new_emit, mut data_hits) = replace_in(&combined[..emit_len], &self.pairs, Location::Body);
    hits.append(&mut data_hits);
    if end_stream {
      // Release the stream slot: otherwise long-lived H2 connections leak
      // one open_streams entry per DATA-terminated stream until the 1024
      // cap degrades the whole connection to opaque.
      self.data_tails.remove(&stream_id);
      self.open_streams.remove(&stream_id);
    } else if hold > 0 {
      self.data_tails.insert(stream_id, combined[emit_len..].to_vec());
    }
    let mut out_flags = flags & !(FLAG_PADDED | FLAG_END_STREAM);
    if end_stream {
      out_flags |= FLAG_END_STREAM;
    }
    if new_emit.len() > 0xff_ffff {
      // Substitution grew the payload past the 24-bit length field: the
      // frame cannot be legally re-framed, so degrade rather than lie.
      return Err(raw.to_vec());
    }
    let mut frame = Vec::with_capacity(9 + new_emit.len());
    append_frame(&mut frame, F_DATA, out_flags, stream_id, &new_emit);
    Ok(frame)
  }

  fn finish_block(&mut self, block: H2Block, hits: &mut Vec<Hit>) -> Result<Vec<u8>, Vec<u8>> {
    let mut frag = block.fragments;
    let mut headers: Vec<(Vec<u8>, Vec<u8>, u8)> = Vec::new();
    if self.decoder.decode(&mut frag, &mut headers).is_err() {
      return Err(block.raw);
    }
    if headers.len() > H2_MAX_FIELDS {
      return Err(block.raw);
    }
    substitute_h2_values(&mut headers, &self.pairs, hits);
    if self.dir == Direction::Request && is_head_method(&headers) {
      self.head_requests += 1;
    }
    // HEADERS without opening the stream, so stray DATA frames fail the
    // `open_streams` check and degrade to opaque instead of substituting
    let no_body = self.dir == Direction::Response && (self.suppress_body > 0 || response_status_no_body(&headers));
    // Trailer HEADERS (no `:status`) must not consume a pending HEAD
    // suppression — only real response heads decrement. Interim 1xx heads
    // (e.g. 103 Early Hints) keep the suppression for the final response.
    let status: Option<u16> = headers.iter().find_map(|(name, value, _)| {
      if !name.eq_ignore_ascii_case(b":status") {
        return None;
      }
      match std::str::from_utf8(value) {
        Ok(value) => {
          let parsed: Result<u16, _> = value.trim().parse();
          parsed.ok()
        }
        Err(_) => None,
      }
    });
    let has_status = status.is_some();
    let interim = status.is_some_and(|code| (100..200).contains(&code));
    if has_status && !interim && self.suppress_body > 0 && self.dir == Direction::Response {
      self.suppress_body -= 1;
    }
    let mut encoded = Vec::new();
    for (name, value, _) in &mut headers {
      if self
        .encoder
        .encode((std::mem::take(name), std::mem::take(value), Encoder::NEVER_INDEXED), &mut encoded)
        .is_err()
      {
        return Err(block.raw);
      }
    }
    if !no_body && !self.open_streams.contains(&block.stream_id) {
      if self.open_streams.len() >= H2_MAX_STREAMS {
        return Err(block.raw);
      }
      self.open_streams.insert(block.stream_id);
    }
    let mut out = Vec::new();
    append_header_frames(&mut out, block.stream_id, block.end_stream, &encoded);
    if block.end_stream {
      self.data_tails.remove(&block.stream_id);
      self.open_streams.remove(&block.stream_id);
    }
    Ok(out)
  }

  fn go_opaque(&mut self, out: &mut Vec<u8>, hits: &mut Vec<Hit>) {
    self.opaque = true;
    self.block = None;
    let rest = std::mem::take(&mut self.buffer);
    hits.extend(scan_with_tail(
      &self.pairs,
      &mut self.scan_tail,
      self.tail_size,
      &rest,
      Location::Body,
    ));
    out.extend_from_slice(&rest);
  }
}

impl SubMachine for H2Machine {
  fn substitute<'b>(&mut self, chunk: &'b [u8]) -> (Cow<'b, [u8]>, Vec<Hit>) {
    H2Machine::substitute(self, chunk)
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
/// old tail were already reported. Updates the tail.
fn scan_with_tail(pairs: &[Pair], tail: &mut Vec<u8>, tail_size: usize, data: &[u8], location: Location) -> Vec<Hit> {
  // Zero-copy: matches fully inside data scan in place; only matches
  // straddling the previous tail need a tiny combined window. One hit per
  // pair per chunk, matching the old single-scan semantics.
  let mut hits = Vec::new();
  if tail.is_empty() {
    for pair in pairs {
      if find_new_match(data, &pair.needle, 0) {
        hits.push(Hit {
          label: pair.label.clone(),
          location,
        });
      }
    }
  } else {
    let old_tail_len = tail.len();
    let bound = tail_size.min(data.len());
    let mut window = std::mem::take(tail);
    window.extend_from_slice(&data[..bound]);
    for pair in pairs {
      let inside = find_new_match(data, &pair.needle, 0);
      let crossing = find_crossing(&window, &pair.needle, old_tail_len);
      if inside || crossing {
        hits.push(Hit {
          label: pair.label.clone(),
          location,
        });
      }
    }
  }
  let keep = tail_size.min(data.len());
  *tail = data[data.len() - keep..].to_vec();
  hits
}

/// True when needle matches in window with the match starting before
/// `old_tail_len` (i.e. straddling the previous tail boundary).
fn find_crossing(window: &[u8], needle: &[u8], old_tail_len: usize) -> bool {
  if needle.is_empty() || window.len() < needle.len() {
    return false;
  }
  window
    .windows(needle.len())
    .enumerate()
    .any(|(i, w)| i < old_tail_len && w == needle)
}

fn finalize_borrow(chunk: &[u8], out: Vec<u8>, hits: Vec<Hit>) -> (Cow<'_, [u8]>, Vec<Hit>) {
  if out.as_slice() == chunk {
    (Cow::Borrowed(chunk), hits)
  } else {
    (Cow::Owned(out), hits)
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

/// Substitute all pairs in decoded header values. `:authority` is skipped
/// (routing safety); `authorization: Basic` is decoded first like HTTP/1.
fn substitute_h2_values(headers: &mut [(Vec<u8>, Vec<u8>, u8)], pairs: &[Pair], hits: &mut Vec<Hit>) {
  for pair in pairs {
    let mut header_hit = false;
    let mut basic_hit = false;
    let needle_str = std::str::from_utf8(&pair.needle).ok();
    let repl_str = std::str::from_utf8(&pair.replacement).ok();
    for (name, value, _) in headers.iter_mut() {
      if name.eq_ignore_ascii_case(b":authority") {
        continue;
      }
      if name.eq_ignore_ascii_case(b"authorization")
        && let (Some(needle), Some(repl)) = (needle_str, repl_str)
        && let Ok(val_str) = std::str::from_utf8(value)
        && let Some(new_val) = substitute_basic_value(val_str, needle, repl)
      {
        *value = new_val.into_bytes();
        basic_hit = true;
        continue;
      }
      if let Some(next) = replace_bytes(value, &pair.needle, &pair.replacement) {
        *value = next;
        header_hit = true;
      }
    }
    if basic_hit {
      hits.push(Hit {
        label: pair.label.clone(),
        location: Location::BasicAuth,
      });
    }
    if header_hit {
      hits.push(Hit {
        label: pair.label.clone(),
        location: Location::Header,
      });
    }
  }
}

fn headers_fragment(flags: u8, payload: &[u8]) -> Option<&[u8]> {
  let mut start = 0;
  let pad_len = if flags & FLAG_PADDED != 0 {
    start = 1;
    *payload.first()? as usize
  } else {
    0
  };
  if flags & FLAG_PRIORITY != 0 {
    start += 5;
  }
  if payload.len() < start + pad_len {
    return None;
  }
  Some(&payload[start..payload.len() - pad_len])
}

fn data_payload(flags: u8, payload: &[u8]) -> Option<&[u8]> {
  if flags & FLAG_PADDED == 0 {
    return Some(payload);
  }
  let pad_len = *payload.first()? as usize;
  if payload.len() < 1 + pad_len {
    return None;
  }
  Some(&payload[1..payload.len() - pad_len])
}

/// Emit a header block as HEADERS + CONTINUATION* capped at 16 KiB payloads.
fn append_header_frames(out: &mut Vec<u8>, stream_id: u32, end_stream: bool, block: &[u8]) {
  let mut first = true;
  let mut offset = 0;
  while first || offset < block.len() {
    let take = (block.len() - offset).min(H2_OUTBOUND_PAYLOAD);
    let payload = &block[offset..offset + take];
    offset += take;
    let kind = if first { F_HEADERS } else { F_CONTINUATION };
    let mut flags = 0;
    if offset == block.len() {
      flags |= FLAG_END_HEADERS;
    }
    if first && end_stream {
      flags |= FLAG_END_STREAM;
    }
    append_frame(out, kind, flags, stream_id, payload);
    first = false;
  }
}

/// Append one H2 frame header + payload. `payload` must fit the 24-bit
/// length field; callers cap at `H2_OUTBOUND_PAYLOAD` or reject on parse.
fn append_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
  let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
  out.extend_from_slice(&len.to_be_bytes()[1..]);
  out.push(kind);
  out.push(flags);
  out.extend_from_slice(&stream_id.to_be_bytes());
  out.extend_from_slice(payload);
}

#[cfg(test)]
mod h2_tests {
  use super::*;

  const FAKE: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const VALUE: &str = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  fn grants() -> Vec<Grant> {
    vec![Grant {
      label: "github".into(),
      fake: FAKE.into(),
      value: secrecy::SecretString::from(VALUE),
      allow: vec!["https://api.github.com".parse::<crate::grants::UriGrant>().unwrap()],
    }]
  }

  fn req_machine() -> H2Machine {
    H2Machine::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Request, true)
  }

  fn resp_machine() -> H2Machine {
    H2Machine::new(&grants(), Scheme::Https, "api.github.com", 443, Direction::Response, false)
  }

  fn encode_headers(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut encoder = Encoder::default();
    let mut out = Vec::new();
    for (name, value) in fields {
      encoder
        .encode(
          (name.as_bytes().to_vec(), value.as_bytes().to_vec(), Encoder::NEVER_INDEXED),
          &mut out,
        )
        .unwrap();
    }
    out
  }

  fn decode_headers(block: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut decoder = Decoder::default();
    let mut buf = block.to_vec();
    let mut headers = Vec::new();
    decoder.decode(&mut buf, &mut headers).unwrap();
    headers.into_iter().map(|(name, value, _)| (name, value)).collect()
  }

  fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    append_frame(&mut out, kind, flags, stream, payload);
    out
  }

  fn first_frame_payload(out: &[u8]) -> (u8, u8, u32, Vec<u8>) {
    let len = ((out[0] as usize) << 16) | ((out[1] as usize) << 8) | out[2] as usize;
    let kind = out[3];
    let flags = out[4];
    let stream = u32::from_be_bytes([out[5], out[6], out[7], out[8]]) & 0x7fff_ffff;
    (kind, flags, stream, out[9..9 + len].to_vec())
  }

  #[test]
  fn h2_request_headers_substituted() {
    let mut machine = req_machine();
    // Preface split across writes is held, not emitted.
    let (out1, _) = machine.substitute(&H2_PREFACE[..10]);
    assert!(out1.into_owned().is_empty());

    let block = encode_headers(&[
      (":method", "GET"),
      (":scheme", "https"),
      (":path", "/"),
      (":authority", "api.github.com"),
      ("authorization", &format!("Bearer {FAKE}")),
    ]);
    let mut input = H2_PREFACE[10..].to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block));
    let (out, hits) = machine.substitute(&input);
    let out = out.into_owned();
    assert!(out.starts_with(H2_PREFACE), "preface must pass through first");
    let (kind, flags, stream, payload) = first_frame_payload(&out[H2_PREFACE.len()..]);
    assert_eq!(kind, F_HEADERS);
    assert_eq!(stream, 1);
    assert_ne!(flags & FLAG_END_HEADERS, 0);
    assert_ne!(flags & FLAG_END_STREAM, 0);
    let headers = decode_headers(&payload);
    let auth = headers.iter().find(|(name, _)| name == b"authorization").unwrap();
    assert_eq!(auth.1, format!("Bearer {VALUE}").as_bytes());
    assert!(headers.iter().any(|(name, _)| name == b":authority"));
    assert!(hits.iter().any(|hit| hit.location == Location::Header));
  }

  #[test]
  fn h2_continuation_block_substituted() {
    let mut machine = req_machine();
    let block = encode_headers(&[(":method", "POST"), ("authorization", &format!("Bearer {FAKE}"))]);
    let mid = block.len() / 2;
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, 0, 1, &block[..mid]));
    input.extend_from_slice(&frame(F_CONTINUATION, FLAG_END_HEADERS, 1, &block[mid..]));
    let (out, _) = machine.substitute(&input);
    let out = out.into_owned();
    let (_, _, _, payload) = first_frame_payload(&out[H2_PREFACE.len()..]);
    let headers = decode_headers(&payload);
    let auth = headers.iter().find(|(name, _)| name == b"authorization").unwrap();
    assert_eq!(auth.1, format!("Bearer {VALUE}").as_bytes());
  }

  #[test]
  fn h2_data_substituted_with_hit() {
    let mut machine = req_machine();
    let block = encode_headers(&[(":method", "POST"), (":path", "/upload")]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS, 1, &block));
    let payload = format!("blob-{FAKE}-blob");
    input.extend_from_slice(&frame(F_DATA, FLAG_END_STREAM, 1, payload.as_bytes()));
    let (out, hits) = machine.substitute(&input);
    let out = out.into_owned();
    // Skip the re-encoded HEADERS frame; DATA carries the real value now.
    let mut rest = &out[H2_PREFACE.len()..];
    let hlen = ((rest[0] as usize) << 16) | ((rest[1] as usize) << 8) | rest[2] as usize;
    rest = &rest[9 + hlen..];
    let (kind, _, _, data) = first_frame_payload(rest);
    assert_eq!(kind, F_DATA);
    assert_eq!(data, format!("blob-{VALUE}-blob").as_bytes());
    assert_eq!(
      hits,
      vec![Hit {
        label: "github".into(),
        location: Location::Body
      }]
    );
  }

  #[test]
  fn h2_data_response_redacted() {
    let mut machine = resp_machine();
    let block = encode_headers(&[(":status", "200")]);
    let mut input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &block);
    let payload = format!("tok-{VALUE}-end");
    input.extend_from_slice(&frame(F_DATA, FLAG_END_STREAM, 1, payload.as_bytes()));
    let (out, hits) = machine.substitute(&input);
    let out = out.into_owned();
    let hlen = ((out[0] as usize) << 16) | ((out[1] as usize) << 8) | out[2] as usize;
    let (kind, _, _, data) = first_frame_payload(&out[9 + hlen..]);
    assert_eq!(kind, F_DATA);
    assert_eq!(data, format!("tok-{FAKE}-end").as_bytes());
    assert!(hits.iter().any(|hit| hit.location == Location::Body));
  }

  #[test]
  fn h2_response_redacts_values() {
    let mut machine = resp_machine();
    let block = encode_headers(&[(":status", "200"), ("x-echo", VALUE)]);
    let input = frame(F_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block);
    let (out, _) = machine.substitute(&input);
    let (_, _, _, payload) = first_frame_payload(&out);
    let headers = decode_headers(&payload);
    let echo = headers.iter().find(|(name, _)| name == b"x-echo").unwrap();
    assert_eq!(echo.1, FAKE.as_bytes());
  }

  #[test]
  fn h2_head_request_suppresses_response_data() {
    let mut req = req_machine();
    let block = encode_headers(&[(":method", "HEAD"), (":path", "/"), (":authority", "api.github.com")]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block));
    let (_, _) = req.substitute(&input);
    assert_eq!(req.take_head_requests(), 1);

    let mut resp = resp_machine();
    resp.suppress_next_bodies(1);
    let rblock = encode_headers(&[(":status", "200"), ("x-echo", VALUE)]);
    let input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &rblock);
    let (out, _) = resp.substitute(&input);
    let (_, _, _, payload) = first_frame_payload(&out);
    let headers = decode_headers(&payload);
    let echo = headers.iter().find(|(name, _)| name == b"x-echo").unwrap();
    assert_eq!(echo.1, FAKE.as_bytes());
    // Stream never opened: stray DATA is not substituted, just forwarded.
    let data = frame(F_DATA, FLAG_END_STREAM, 1, format!("tok-{VALUE}-end").as_bytes());
    let (out, _) = resp.substitute(&data);
    assert!(
      out.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()),
      "stray DATA must pass through"
    );
  }

  #[test]
  fn h2_garbage_goes_opaque_unchanged() {
    let mut machine = req_machine();
    let input = b"GARBAGE-NOT-A-PREFACE-AT-ALL-!!!!";
    assert!(input.len() >= H2_PREFACE.len());
    let (out, _) = machine.substitute(input);
    assert_eq!(out.as_ref(), input.as_slice());
    // Stays opaque: later chunks borrowed.
    let (out, _) = machine.substitute(b"more-bytes");
    assert!(matches!(out, Cow::Borrowed(_)));
  }

  #[test]
  fn h2_push_promise_forwarded_unchanged() {
    let mut machine = req_machine();
    let mut input = H2_PREFACE.to_vec();
    let promise = frame(0x5, FLAG_END_HEADERS, 1, b"promised-payload");
    input.extend_from_slice(&promise);
    let (out, hits) = machine.substitute(&input);
    assert_eq!(out.into_owned(), input);
    assert!(hits.is_empty());
  }

  #[test]
  fn h2_data_end_stream_releases_stream_id() {
    let mut machine = req_machine();
    let block = encode_headers(&[(":method", "POST"), (":path", "/upload")]);
    let mut input = H2_PREFACE.to_vec();
    input.extend_from_slice(&frame(F_HEADERS, FLAG_END_HEADERS, 1, &block));
    let (_, _) = machine.substitute(&input);
    assert!(machine.open_streams.contains(&1), "POST stream opens");
    let data = frame(F_DATA, FLAG_END_STREAM, 1, b"payload");
    let (_, _) = machine.substitute(&data);
    assert!(!machine.open_streams.contains(&1), "DATA END_STREAM must release the stream");
    assert!(machine.data_tails.is_empty());
  }

  #[test]
  fn h2_interim_103_keeps_head_suppression() {
    let mut resp = resp_machine();
    resp.suppress_next_bodies(1);
    let interim = encode_headers(&[(":status", "103")]);
    let input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &interim);
    let (_, _) = resp.substitute(&input);
    assert_eq!(resp.suppress_body, 1, "interim 1xx must not consume HEAD suppression");
    let final_head = encode_headers(&[(":status", "200")]);
    let input = frame(F_HEADERS, FLAG_END_HEADERS, 1, &final_head);
    let (_, _) = resp.substitute(&input);
    assert_eq!(resp.suppress_body, 0);
  }
}
