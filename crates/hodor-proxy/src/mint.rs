//! Runtime token minting: freshly issued tokens never reach the guest as
//! real values.
//!
//! A flow-granted token endpoint's response is scanned for the flow's field
//! names; each real value found is paired with a freshly minted decoy and
//! recorded here. The decoy is what the guest holds. Later requests swap
//! the decoy back to the real value through the ordinary substitution path.

use std::collections::BTreeMap;
use std::sync::Arc;

use secrecy::SecretString;

/// One minted pair: the real freshly issued value and the decoy standing in
/// for it on the guest side. Keyed on the real value so rotation mints a new
/// pair per value without invalidating the old one.
#[derive(Debug, Clone)]
pub struct MintedPair {
  /// Grant label owning the flow (log identifier, never the value).
  pub label: String,
  /// The decoy the guest sees and re-sends.
  pub decoy: String,
}

/// Process-lifetime minted-pair store, shared across connections because
/// agents reuse tokens across connections.
// ponytail: process-memory only; restart orphans decoys the agent still
// holds and forces re-auth. Persist beside the CA if that ceiling bites.
#[derive(Debug, Default)]
pub struct MintStore {
  pairs: std::sync::Mutex<BTreeMap<String, MintedPair>>,
}

/// A handle to the store handed to each substitution machine.
#[derive(Debug, Clone)]
pub struct MintHandle {
  store: Arc<MintStore>,
}

impl MintStore {
  /// Mint a decoy for one real value and record the pair. Returns the
  /// existing decoy when the value was minted before, so repeated responses
  /// are idempotent.
  ///
  /// Minted decoys are not length-matched: they only ever ride HTTP legs
  /// (the mint path is reached from head processing, which raw machines
  /// never do), where length drift is rewritten by framing.
  ///
  /// # Errors
  ///
  /// Returns an error when the value is empty.
  pub fn mint(&self, label: &str, pattern: Option<&str>, field: &str, value: &str, expires_in: Option<u64>) -> eyre::Result<String> {
    eyre::ensure!(!value.is_empty(), "cannot mint a decoy for an empty value");
    let mut pairs = self.pairs.lock().expect("mint store poisoned");
    if let Some(pair) = pairs.get(value) {
      return Ok(pair.decoy.clone());
    }
    let decoy = hodor_config::config::fake_for(value, pattern);
    pairs.insert(
      value.to_string(),
      MintedPair {
        label: label.to_string(),
        decoy: decoy.clone(),
      },
    );
    tracing::debug!(label, field, expires_in = ?expires_in, "minted decoy for freshly issued token");
    Ok(decoy)
  }

  /// Every minted pair as (decoy, real, label), for request machines to
  /// union into their pair set at construction time.
  #[must_use]
  pub fn snapshot_pairs(&self) -> Vec<(String, SecretString, String)> {
    let pairs = self.pairs.lock().expect("mint store poisoned");
    pairs
      .iter()
      .map(|(real, pair)| (pair.decoy.clone(), SecretString::from(real.clone()), pair.label.clone()))
      .collect()
  }
}

impl MintHandle {
  /// A machine's view of the store. Label and decoy pattern come from the
  /// mint plan the machine derives from its grants.
  #[must_use]
  pub fn new(store: Arc<MintStore>) -> Self {
    Self { store }
  }

  /// Mint one field value; see [`MintStore::mint`].
  ///
  /// # Errors
  ///
  /// Returns an error when the value is empty.
  pub fn mint(&self, label: &str, pattern: Option<&str>, field: &str, value: &str, expires_in: Option<u64>) -> eyre::Result<String> {
    self.store.mint(label, pattern, field, value, expires_in)
  }

  /// Snapshot of every minted pair, (decoy, real, label), for request machines.
  #[must_use]
  pub fn pairs(&self) -> Vec<(String, SecretString, String)> {
    self.store.snapshot_pairs()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use secrecy::ExposeSecret as _;

  #[test]
  fn minted_decoy_is_seed_stable_and_pattern_shaped() {
    let store = MintStore::default();
    let one = store
      .mint("t", Some("tok_{hex:16}"), "access_token", "real-value-one", None)
      .unwrap();
    let again = store
      .mint("t", Some("tok_{hex:16}"), "access_token", "real-value-one", None)
      .unwrap();
    assert_eq!(one, again, "repeated mint is idempotent");
    assert!(one.starts_with("tok_"), "{one}");
    let other = store
      .mint("t", Some("tok_{hex:16}"), "access_token", "real-value-two", None)
      .unwrap();
    assert_ne!(one, other, "distinct values mint distinct decoys");
  }

  #[test]
  fn snapshot_pairs_map_decoy_back_to_real() {
    let store = MintStore::default();
    let decoy = store.mint("t", None, "refresh_token", "real-refresh", Some(3600)).unwrap();
    let pairs = store.snapshot_pairs();
    let Some((_, real, label)) = pairs.iter().find(|(d, _, _)| d == &decoy) else {
      panic!("pair recorded");
    };
    assert_eq!(real.expose_secret(), "real-refresh");
    assert_eq!(label, "t");
  }

  #[test]
  fn store_rejects_empty_values() {
    let store = MintStore::default();
    let err = store.mint("t", None, "access_token", "", None).unwrap_err();
    assert!(err.to_string().contains("empty value"), "{err:?}");
  }

  #[test]
  fn mint_records_the_label() {
    let store = MintStore::default();
    store.mint("my-rule", None, "access_token", "v", Some(900)).unwrap();
    let pairs = store.pairs.lock().unwrap();
    let pair = pairs.get("v").expect("pair recorded");
    assert_eq!(pair.label, "my-rule");
  }

  #[test]
  fn handle_mints_through_the_plan_arguments() {
    let store = Arc::new(MintStore::default());
    let handle = MintHandle::new(Arc::clone(&store));
    let decoy = handle.mint("rule", Some("d_{d:8}"), "access_token", "value", None).unwrap();
    assert!(decoy.starts_with("d_"), "{decoy}");
    assert!(decoy[2..].bytes().all(|b| b.is_ascii_digit()), "{decoy}");
    assert_eq!(handle.pairs().len(), 1);
  }
}
