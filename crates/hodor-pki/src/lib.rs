//! PKI: the signing CA and per-domain leaf certificates for test stubs.

pub mod ca;

pub use ca::{CertAuthority, DomainCert, install_crypto_provider, load_or_generate};
