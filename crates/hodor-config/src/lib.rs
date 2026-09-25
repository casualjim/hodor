//! Hodor's shared vocabulary: the CLI surface, the config overlay, URI
//! grants, and the bundled host registry.
//!
//! Everything that talks to fnox lives in `hodor-fnox`; everything involving
//! certificates lives in `hodor-pki`.

pub mod cli;
pub mod config;
pub mod grants;
pub mod import;
pub mod plugins;
pub mod registry;
pub use config::{AppConfig, ProxyCfg, RuleCfg, fake_for, load};
pub use grants::{
  Credential, DatabaseScope, EndpointScope, Grant, HostPat, ResolvedConfig, Scheme, SslMode, SslNegotiation, decoy_for_rule, resolve,
  uri_match,
};
pub use plugins::{PluginCfg, PluginDirection, ResolvedPlugin, resolve_plugins};
pub use secrecy::ExposeSecret;
