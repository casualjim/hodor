//! Crate error type: every fallible API returns `Result<T, Error>`.

use std::io::Error as IoError;
use std::path::PathBuf;

use hodor_config::Error as ConfigError;
use hodor_config::config::RewriteFormat;
use hodor_fnox::Error as FnoxError;
use serde_yaml::Error as YamlError;
use toml::ser::Error as TomlSerializeError;
use toml_edit::TomlError;

/// Every way stack generation and workspace commands can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// A `hodor-config` error passes through.
  #[error(transparent)]
  Config(Box<ConfigError>),
  /// A `hodor-fnox` error passes through.
  #[error(transparent)]
  Fnox(Box<FnoxError>),
  /// A `hodor-pki` error passes through.
  #[error(transparent)]
  Pki(#[from] hodor_pki::Error),
  /// An I/O failure with no extra context.
  #[error(transparent)]
  Io(#[from] IoError),
  /// `[workspace] home` is missing.
  #[error("[workspace] home is required {detail}")]
  HomeRequired {
    /// What needs the home directory.
    detail: String,
  },
  /// A `[workspace] include` entry does not exist.
  #[error("[workspace] include `{}` does not exist; docker would mount an empty directory in its place", entry.display())]
  IncludeMissing {
    /// Missing entry.
    entry: PathBuf,
  },
  /// The hodor config directory does not resolve.
  #[error("{detail}")]
  ConfigDir {
    /// What needs the directory.
    detail: String,
  },
  /// The guest identity CA does not load.
  #[error("guest identity CA `{}`: {source}", path.display())]
  GuestCa {
    /// CA file.
    path: PathBuf,
    /// Underlying load failure.
    #[source]
    source: hodor_pki::Error,
  },
  /// A file cannot be read.
  #[error("read {}: {source}", path.display())]
  ReadFile {
    /// File that could not be read.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A file cannot be written.
  #[error("write {}: {source}", path.display())]
  WriteFile {
    /// File that could not be written.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A stale generated file cannot be pruned.
  #[error("remove {}: {source}", path.display())]
  RemoveFile {
    /// File that could not be removed.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A directory cannot be created.
  #[error("create {}: {source}", path.display())]
  CreateDir {
    /// Directory that could not be created.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A grant fragment fails to serialize.
  #[error("serializing a grant fragment: {source}")]
  SerializeFragment {
    /// Underlying serialization failure.
    #[source]
    source: TomlSerializeError,
  },
  /// A decoy document fails to serialize.
  #[error("serializing a decoy document: {source}")]
  SerializeDecoy {
    /// Underlying serialization failure.
    #[source]
    source: YamlError,
  },
  /// A config value does not expand.
  #[error("failed to expand config value: {detail}")]
  ExpandValue {
    /// Expansion failure, Debug-rendered (xpanda reports no std error).
    detail: String,
  },
  /// An async lookup cannot block on a runtime.
  #[error("failed to run fnox lookup: {source}")]
  BlockOn {
    /// Underlying runtime failure.
    #[source]
    source: IoError,
  },
  /// A fnox secret resolves to no value.
  #[error("fnox secret `{name}` resolved to no value")]
  SecretNoValue {
    /// Secret name.
    name: String,
  },
  /// A passthrough name is also a rule env.
  #[error("[workspace] passthrough `{name}` is also a [rules.*] env: pick one path")]
  PassthroughOverlapRule {
    /// Offending name.
    name: String,
  },
  /// A passthrough name overlaps a selected decoy.
  #[error("[workspace] passthrough `{name}` overlaps a selected decoy: pick one path")]
  PassthroughOverlapDecoy {
    /// Offending name.
    name: String,
  },
  /// `[workspace] image` names an empty tag.
  #[error("[workspace] image is empty: name a tag or drop the key for the default")]
  EmptyImage,
  /// `[workspace.build]` names a dockerfile that does not exist.
  #[error("[workspace.build] dockerfile `{}` does not exist", path.display())]
  BuildDockerfileMissing {
    /// Missing dockerfile.
    path: PathBuf,
  },
  /// `[workspace.build]` names a context directory that does not exist.
  #[error("[workspace.build] context `{}` does not exist", path.display())]
  BuildContextMissing {
    /// Missing context directory.
    path: PathBuf,
  },
  /// `--build` without a `[workspace.build]` to build.
  #[error("--build names no [workspace.build]: add the section or drop the flag")]
  BuildNotConfigured,
  /// A file rewrite names an env with no known real value.
  #[error("file rewrite `{}` names `{name}` with no known real value", file.display())]
  RewriteNoValue {
    /// Rewrite source.
    file: PathBuf,
    /// Env name.
    name: String,
  },
  /// A file rewrite names an env with no decoy.
  #[error("file rewrite `{}` names `{name}` with no decoy", file.display())]
  RewriteNoDecoy {
    /// Rewrite source.
    file: PathBuf,
    /// Env name.
    name: String,
  },
  /// A file rewrite dest is not an absolute container path.
  #[error("file rewrite dest `{dest}` does not expand to an absolute container path")]
  RewriteDestNotAbsolute {
    /// Offending dest.
    dest: String,
  },
  /// An adapted rewrite names envs: the file is the source, drop `envs`.
  #[error("file rewrite `{}` states format `{format}`: the file is the source, drop `envs`", file.display())]
  RewriteWithEnvs {
    /// Rewrite source.
    file: PathBuf,
    /// The format that took the adapter path.
    format: RewriteFormat,
  },
  /// An adapted rewrite is not valid YAML.
  #[error("file rewrite `{}`: does not parse as YAML: {source}", file.display())]
  RewriteYaml {
    /// Rewrite source.
    file: PathBuf,
    /// Underlying parse failure.
    #[source]
    source: YamlError,
  },
  /// An adapted rewrite does not map onto a grant.
  #[error("file rewrite `{}`: invalid {format}: {detail}", file.display())]
  RewriteInvalid {
    /// Rewrite source.
    file: PathBuf,
    /// The format that took the adapter path.
    format: RewriteFormat,
    /// What fails to map.
    detail: String,
  },
  /// An ambient derivation source does not map onto grants or a decoy twin.
  #[error("derived source `{}`: {detail}", file.display())]
  SourceInvalid {
    /// The source file the derivation read.
    file: PathBuf,
    /// What fails to map.
    detail: String,
  },
  /// A mise file does not parse.
  #[error("parse mise.local.toml: {source}")]
  MiseParse {
    /// Underlying parse failure.
    #[source]
    source: TomlError,
  },
  /// A workspace cannot be resolved.
  #[error("resolve workspace {}: {source}", path.display())]
  ResolveWorkspace {
    /// Workspace that could not be resolved.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// The host refuses stack generation.
  #[error("hodor init supports Linux only: there is no capture backend for this host")]
  LinuxOnly,
  /// `--backend none` cannot generate a stack.
  #[error("`--backend none` is not valid for init: the generated stack needs a capture backend")]
  BackendNone,
  /// No compose layers exist.
  #[error("no compose layers for {}; run `hodor init` first or create one of the layer files", root.display())]
  NoComposeLayers {
    /// Workspace root.
    root: PathBuf,
  },
  /// docker compose does not spawn.
  #[error("spawn docker compose: {source}")]
  SpawnCompose {
    /// Underlying spawn failure.
    #[source]
    source: IoError,
  },
  /// docker compose exits non-zero.
  #[error("docker compose failed: {status}")]
  ComposeFailed {
    /// Exit status.
    status: String,
  },
  /// A file mode cannot be set.
  #[error("chmod {}: {source}", path.display())]
  ChmodFile {
    /// File whose mode could not be set.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A `[tools.*]` name is not a plain directory name.
  #[error("[tools.{name}] is not a plain directory name to mount")]
  ToolNameInvalid {
    /// Offending tool name.
    name: String,
  },
  /// A `[tools.*]` `config_dir` is not an absolute container path.
  #[error("[tools.{name}] config_dir `{template}` does not expand to an absolute container path")]
  ToolConfigNotAbsolute {
    /// Tool name.
    name: String,
    /// Offending template.
    template: String,
  },
}

impl From<ConfigError> for Error {
  fn from(source: ConfigError) -> Self {
    Self::Config(Box::new(source))
  }
}

impl From<FnoxError> for Error {
  fn from(source: FnoxError) -> Self {
    Self::Fnox(Box::new(source))
  }
}
