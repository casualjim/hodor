//! Crate error type: every fallible API returns `Result<T, Error>`.

use std::path::PathBuf;

use fnox_core::FnoxError;

/// Every way fnox discovery and secret resolution can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// fnox discovery fails.
  #[error("fnox discovery failed: {source}")]
  Discovery {
    /// Underlying discovery failure.
    #[source]
    source: FnoxError,
  },
  /// Active profiles do not resolve.
  #[error("fnox profiles: {source}")]
  Profiles {
    /// Underlying profile failure.
    #[source]
    source: FnoxError,
  },
  /// Declared secrets cannot be listed.
  #[error("fnox: cannot list secrets: {source}")]
  ListSecrets {
    /// Underlying listing failure.
    #[source]
    source: FnoxError,
  },
  /// One config file does not load.
  #[error("fnox config {}: {source}", path.display())]
  ConfigFile {
    /// File that did not load.
    path: PathBuf,
    /// Underlying load failure.
    #[source]
    source: FnoxError,
  },
  /// One secret does not read.
  #[error("fnox secret `{key}`: {source}")]
  Secret {
    /// Secret key.
    key: String,
    /// Underlying read failure.
    #[source]
    source: FnoxError,
  },
  /// A declared key resolves to no value.
  #[error("fnox key `{key}` is declared but resolves to no value")]
  DeclaredNoValue {
    /// Secret key.
    key: String,
  },
  /// A declared key resolves to an empty value.
  #[error("fnox key `{key}` is declared but resolves to an empty value")]
  DeclaredEmpty {
    /// Secret key.
    key: String,
  },
  /// A rule resolves to no usable grant.
  #[error("rule `{label}` (env {env}): {detail}")]
  UnresolvedRule {
    /// Rule label.
    label: String,
    /// Rule env name.
    env: String,
    /// Why the rule drops.
    detail: String,
  },
  /// A registry error passes through from `hodor-config`.
  #[error(transparent)]
  Registry(#[from] hodor_config::Error),
}
