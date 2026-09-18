//! PKI: the signing CA, per-domain leaf certificates, and SNI extraction.

pub mod ca;
pub mod sni;

pub use ca::{CertAuthority, CertCache, DomainCert, install_crypto_provider, load_or_generate, upstream_connector};
pub use sni::{MAX_HELLO, extract_sni};
