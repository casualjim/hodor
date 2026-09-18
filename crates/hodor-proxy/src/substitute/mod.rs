//! Secret substitution state machines: shared types, the dispatch trait,
//! and the scan helpers both machines use.
//!
//! `h1` holds the HTTP/1-family machine; `h2` holds the HPACK frame walker.

use std::borrow::Cow;

use secrecy::ExposeSecret as _;

use hodor_config::grants::{Grant, Scheme};

mod h1;
mod h2;

pub(crate) use h1::SecretsMachine;
pub(crate) use h2::{H2_PREFACE, H2Machine};

/// Chunk direction: guest→server requests or server→guest responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
  /// Guest→server: substitute decoy fakes with real values.
  Request,
  /// Server→guest: redact real values back to decoy fakes.
  Response,
}

/// What rides on the connection: picks the grant scheme, the initial
/// framing state, and whether only equal-length substitutions are safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MachineMode {
  /// Framed HTTP behind TLS (`https` grants).
  Https,
  /// Framed plain HTTP (`http` grants).
  Http,
  /// Raw TCP bytes (`tcp` grants, equal-length only).
  RawTcp,
  /// Raw bytes behind terminated TLS (`https` grants, equal-length only).
  RawTls,
  /// Scan-only passthrough, framing unknowable (test scaffolding).
  #[cfg(test)]
  Opaque,
}

impl MachineMode {
  /// Grant scheme the mode's pairs come from.
  fn scheme(self) -> Scheme {
    match self {
      Self::Https | Self::RawTls => Scheme::Https,
      Self::Http => Scheme::Http,
      Self::RawTcp => Scheme::Tcp,
      #[cfg(test)]
      Self::Opaque => Scheme::Https,
    }
  }

  /// True when framing is unknowable, so only equal-length substitutions
  /// preserve the byte stream.
  fn equal_len_only(self) -> bool {
    matches!(self, Self::RawTcp | Self::RawTls)
  }
}

/// Construction parameters for one substitution machine.
pub(crate) struct MachineParams<'a> {
  /// Grant source for the eligible pair set.
  pub(crate) grants: &'a [Grant],
  /// Connection endpoint host.
  pub(crate) host: &'a str,
  /// Connection endpoint port.
  pub(crate) port: u16,
  /// Connection leg.
  pub(crate) dir: Direction,
  /// What rides on the connection.
  pub(crate) mode: MachineMode,
  /// Stage-1 plugin hook; `None` keeps value-swap-only behavior.
  pub(crate) hook: Option<Box<dyn hodor_plugin::RewriteHook>>,
}

impl<'a> MachineParams<'a> {
  /// Fresh parameters; attach the plugin hook with [`MachineParams::hook`].
  pub(crate) fn new(grants: &'a [Grant], mode: MachineMode, host: &'a str, port: u16, dir: Direction) -> Self {
    Self {
      grants,
      host,
      port,
      dir,
      mode,
      hook: None,
    }
  }

  /// Attach the stage-1 plugin hook (builder).
  pub(crate) fn hook(mut self, hook: Option<Box<dyn hodor_plugin::RewriteHook>>) -> Self {
    self.hook = hook;
    self
  }
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
/// One substitution hit: label and where it was found (never the value).
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

/// Eligible needle→replacement pairs for a connection endpoint. The mode
/// supplies the grant scheme and the equal-length-only constraint.
fn eligible_pairs(grants: &[Grant], mode: MachineMode, host: &str, port: u16, dir: Direction) -> Vec<Pair> {
  let mut pairs = Vec::new();
  for grant in grants {
    if !grant.matches(mode.scheme(), host, port) {
      continue;
    }
    let (needle, replacement) = match dir {
      Direction::Request => (grant.fake.as_bytes(), grant.value.expose_secret().as_bytes()),
      Direction::Response => (grant.value.expose_secret().as_bytes(), grant.fake.as_bytes()),
    };
    if needle.is_empty() || replacement.is_empty() {
      continue;
    }
    if mode.equal_len_only() && needle.len() != replacement.len() {
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

/// True for response statuses that never carry a body (1xx, 204, 304).
fn response_has_no_body(status: Option<u16>) -> bool {
  let Some(code) = status else {
    return false;
  };
  (100..200).contains(&code) || code == 204 || code == 205 || code == 304
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
/// `tail_len`. Matches ending at or before `tail_len` lie wholly inside the
/// tail handed to this call and were already reported by the chunk that first
/// carried them.
fn find_new_match(combined: &[u8], needle: &[u8], tail_len: usize) -> bool {
  if needle.is_empty() || combined.len() < needle.len() {
    return false;
  }
  combined
    .windows(needle.len())
    .enumerate()
    .any(|(i, w)| w == needle && i + needle.len() > tail_len)
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

/// How many bytes of `data` may be emitted (and substituted) now without
/// cutting a needle: past the end of every complete match (so each is
/// substituted whole), and short of any trailing partial match (so it stays
/// held until more bytes arrive). A naive fixed or prefix-only window can
/// slice a needle that ends inside the hold-back — the prefix goes out raw
/// and the match never recombines.
fn needle_safe_emit_len(data: &[u8], pairs: &[Pair], tail_bound: usize) -> usize {
  let mut emit = data.len() - needle_prefix_suffix_len(data, pairs, tail_bound);
  for pair in pairs {
    let needle = &pair.needle;
    if needle.is_empty() || data.len() < needle.len() {
      continue;
    }
    for i in 0..=data.len() - needle.len() {
      if &data[i..i + needle.len()] == needle.as_slice() {
        emit = emit.max(i + needle.len());
      }
    }
  }
  emit
}

/// Anything that substitutes one chunk: HTTP/1, raw, opaque, or H2.
pub trait SubMachine {
  /// Process one chunk; empty input flushes held bytes at stream EOF.
  fn substitute<'a>(&mut self, chunk: &'a [u8]) -> impl Future<Output = (Cow<'a, [u8]>, Vec<Hit>)> + Send;
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

/// Relay machine: HTTP/1-family or HTTP/2, chosen after protocol sniffing.
pub(crate) enum AnyMachine {
  /// HTTP/1-family machine.
  Http1(SecretsMachine),
  /// HTTP/2 machine.
  H2(H2Machine),
}

impl SubMachine for AnyMachine {
  async fn substitute<'a>(&mut self, chunk: &'a [u8]) -> (Cow<'a, [u8]>, Vec<Hit>) {
    match self {
      AnyMachine::Http1(machine) => machine.substitute(chunk).await,
      AnyMachine::H2(machine) => machine.substitute(chunk).await,
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

/// Scan one chunk for hits, carrying `tail` across calls so a needle split
/// across a chunk boundary is still found. Matches resolving entirely inside
/// the retained tail were reported by the chunk that carried them. Updates
/// the tail.
fn scan_with_tail(pairs: &[Pair], tail: &mut Vec<u8>, tail_size: usize, data: &[u8], location: Location) -> Vec<Hit> {
  // Zero-copy: matches fully inside data scan in place; only matches
  // straddling the previous tail need a tiny combined window. One hit per
  // pair per chunk, so a chunk containing repeated needles reports one hit
  // rather than one per occurrence.
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
