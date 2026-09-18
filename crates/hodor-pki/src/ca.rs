//! CA management + per-domain leaf certificate generation.

use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

/// Leaf validity for generated per-domain certificates.
const LEAF_VALIDITY_HOURS: u64 = 24;
/// A certificate authority for signing per-domain certificates.
pub struct CertAuthority {
  issuer: Issuer<'static, KeyPair>,
  cert_der: CertificateDer<'static>,
  /// PEM-encoded CA certificate (for client installation).
  cert_pem: String,
}

impl std::fmt::Debug for CertAuthority {
  /// Prints only what is safe to log: the private key is never rendered, and
  /// the certificate is summarized rather than dumped.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("CertAuthority")
      .field("cert_pem_bytes", &self.cert_pem.len())
      .field("cert_der_bytes", &self.cert_der.len())
      .finish_non_exhaustive()
  }
}

impl CertAuthority {
  /// Generate a new self-signed CA.
  ///
  /// # Errors
  ///
  /// Returns an error when key generation or self-signing fails.
  pub fn generate() -> eyre::Result<Self> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "hodor CA");
    dn.push(rcgen::DnType::OrganizationName, "hodor");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];

    let key_pair = KeyPair::generate().map_err(|err| eyre::eyre!("failed to generate CA key pair: {err}"))?;
    let cert = params
      .self_signed(&key_pair)
      .map_err(|err| eyre::eyre!("failed to self-sign CA certificate: {err}"))?;

    let cert_pem = cert.pem();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let issuer = Issuer::new(params, key_pair);

    Ok(Self {
      issuer,
      cert_der,
      cert_pem,
    })
  }

  /// Load a CA from PEM-encoded certificate and private key bytes.
  ///
  /// The original PEM bytes are preserved for `cert_pem()` so the identity
  /// served to clients matches the persisted file exactly.
  ///
  /// # Errors
  ///
  /// Returns an error when either PEM is not valid UTF-8, the key is not a
  /// parseable PKCS#8 key pair, or the certificate is not a parseable CA.
  pub fn load(cert_pem_bytes: &[u8], key_pem_bytes: &[u8]) -> eyre::Result<Self> {
    let cert_pem_str = std::str::from_utf8(cert_pem_bytes).map_err(|err| eyre::eyre!("invalid cert PEM: {err}"))?;
    let key_pem_str = std::str::from_utf8(key_pem_bytes).map_err(|err| eyre::eyre!("invalid key PEM: {err}"))?;

    let key_pair = KeyPair::from_pem(key_pem_str).map_err(|err| eyre::eyre!("failed to parse CA key: {err}"))?;
    let issuer = Issuer::from_ca_cert_pem(cert_pem_str, key_pair).map_err(|err| eyre::eyre!("failed to parse CA cert: {err}"))?;

    let original_der = {
      CertificateDer::from_pem_slice(cert_pem_str.as_bytes())
        .map(|cert| cert.to_vec())
        .map_err(|err| eyre::eyre!("failed to parse PEM: {err}"))?
    };

    Ok(Self {
      issuer,
      cert_der: CertificateDer::from(original_der),
      cert_pem: cert_pem_str.to_string(),
    })
  }

  /// Get the CA certificate as PEM bytes (for client installation).
  #[must_use]
  pub fn cert_pem(&self) -> Vec<u8> {
    self.cert_pem.as_bytes().to_vec()
  }

  /// Get the CA private key as PEM bytes (for persistence).
  #[must_use]
  pub fn key_pem(&self) -> Vec<u8> {
    self.issuer.key().serialize_pem().as_bytes().to_vec()
  }

  /// DER-encoded CA certificate.
  #[must_use]
  pub fn cert_der(&self) -> &CertificateDer<'static> {
    &self.cert_der
  }

  /// Generate a leaf certificate for `domain` signed by this CA.
  ///
  /// # Errors
  ///
  /// Returns an error when the domain is not a valid SAN or signing fails.
  pub fn generate_domain_cert(&self, domain: &str) -> eyre::Result<DomainCert> {
    generate_domain_cert(domain, self)
  }

  /// Boring CA pair for the rama MITM issuer: cert DER plus the PKCS8 key
  /// bytes this CA already holds, converted to boring types.
  ///
  /// # Errors
  ///
  /// Returns an error when the cert DER or the PKCS8 key bytes fail to parse
  /// as boring types.
  pub fn boring_pair(
    &self,
  ) -> eyre::Result<(
    rama::tls::boring::core::x509::X509,
    rama::tls::boring::core::pkey::PKey<rama::tls::boring::core::pkey::Private>,
  )> {
    let crt = rama::tls::boring::core::x509::X509::from_der(self.cert_der.as_ref())
      .map_err(|err| eyre::eyre!("CA cert DER is not a valid boring X509: {err}"))?;
    let key = rama::tls::boring::core::pkey::PKey::private_key_from_pkcs8(&self.issuer.key().serialize_der())
      .map_err(|err| eyre::eyre!("CA key is not a valid boring PKCS8 key: {err}"))?;
    Ok((crt, key))
  }
}

/// Load the CA from `path`, or generate + persist one (creating parent dirs).
/// File format is the cert PEM followed by the PKCS#8 key PEM, and both are
/// also written beside it as `<stem>.crt` and `<stem>.key`.
/// `create_new` elects a single winner across racing processes; losers load
/// the winner with backoff because the winner's `write_all` may not have
/// finished when `AlreadyExists` surfaces. A persistently unparseable file
/// (crash mid-write) stays a hard error: silently minting a fresh CA would
/// invalidate every installed client trust anchor.
///
/// # Errors
///
/// Returns an error when the existing file cannot be read or parsed, when the
/// parent directory cannot be created, or when no process wins the
/// generate-and-persist race.
pub fn load_or_generate(path: &Path) -> eyre::Result<CertAuthority> {
  let ca = if path.exists() {
    load_ca_file(path)?
  } else {
    generate_and_persist(path)?
  };
  sync_split_pems(path, &ca);
  Ok(ca)
}

/// Generate a CA and persist it, electing one winner across racing processes.
fn generate_and_persist(path: &Path) -> eyre::Result<CertAuthority> {
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent)?;
  }
  let ca = CertAuthority::generate()?;
  let mut contents = ca.cert_pem();
  contents.extend_from_slice(&ca.key_pem());
  match persist_ca_0600(path, &contents) {
    Ok(()) => Ok(ca),
    // Raced with another process creating it: load the winner.
    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => load_ca_file_with_retry(path),
    Err(err) => Err(err.into()),
  }
}

/// Keep `<stem>.crt` and `<stem>.key` beside the CA file, so a deployment can
/// hand the certificate to a workload without handing over the key. The
/// combined PEM stays the file hodor reads, and it stays authoritative: an
/// unchanged split file is left alone and a write failure is a warning rather
/// than a startup error, so a read-only mount still serves.
fn sync_split_pems(path: &Path, ca: &CertAuthority) {
  for (target, contents, mode) in [
    (path.with_extension("crt"), ca.cert_pem(), 0o644),
    (path.with_extension("key"), ca.key_pem(), 0o600),
  ] {
    if std::fs::read(&target).is_ok_and(|existing| existing == contents) {
      continue;
    }
    if let Err(err) = write_with_mode(&target, &contents, mode) {
      tracing::warn!(path = %target.display(), %err, "failed to write the split CA file");
    }
  }
}

/// Write `contents` to `target`, forcing `mode` so a umask cannot leave the
/// private key world readable.
fn write_with_mode(target: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
  let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(target)?;
  file.write_all(contents)?;
  file.sync_all()?;
  set_mode(target, mode)
}

#[cfg(unix)]
fn set_mode(target: &Path, mode: u32) -> std::io::Result<()> {
  use std::os::unix::fs::PermissionsExt as _;
  std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_target: &Path, _mode: u32) -> std::io::Result<()> {
  Ok(())
}

fn load_ca_file(path: &Path) -> eyre::Result<CertAuthority> {
  warn_on_loose_ca_perms(path);
  let text = std::fs::read_to_string(path)?;
  let key_start = text
    .find("-----BEGIN PRIVATE KEY-----")
    .ok_or_else(|| eyre::eyre!("{}: no private-key PEM block", path.display()))?;
  CertAuthority::load(&text.as_bytes()[..key_start], &text.as_bytes()[key_start..])
}

/// Warn when the CA file is group/other readable: the private key block
/// lives in the same file, so loose permissions are a full MITM hazard.
#[cfg(unix)]
fn warn_on_loose_ca_perms(path: &Path) {
  use std::os::unix::fs::PermissionsExt as _;
  let Ok(meta) = std::fs::metadata(path) else {
    return;
  };
  if meta.permissions().mode() & 0o077 != 0 {
    tracing::warn!(path = %path.display(), "CA file readable by group/other; expected 0600");
  }
}

#[cfg(not(unix))]
fn warn_on_loose_ca_perms(_path: &Path) {}

/// Load the winner's CA file, retrying while the winner is still writing.
/// Truncated reads (missing key block, PEM parse failure) retry for ~2s;
/// the last error surfaces when the file stays unparseable.
fn load_ca_file_with_retry(path: &Path) -> eyre::Result<CertAuthority> {
  let mut last = load_ca_file(path).err();
  for _ in 0..20 {
    std::thread::sleep(std::time::Duration::from_millis(100));
    match load_ca_file(path) {
      Ok(ca) => return Ok(ca),
      Err(err) => last = Some(err),
    }
  }
  Err(last.unwrap_or_else(|| eyre::eyre!("{}: CA file never became readable", path.display())))
}

#[cfg(unix)]
fn persist_ca_0600(path: &Path, contents: &[u8]) -> std::io::Result<()> {
  let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
  file.write_all(contents)?;
  file.sync_all()?;
  // Best-effort dir sync so the directory entry survives a crash.
  if let Some(parent) = path.parent()
    && let Ok(dir) = std::fs::File::open(parent)
  {
    let _ = dir.sync_all();
  }
  Ok(())
}

#[cfg(not(unix))]
fn persist_ca_0600(path: &Path, contents: &[u8]) -> std::io::Result<()> {
  let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
  file.write_all(contents)?;
  file.sync_all()
}

/// A generated certificate for a specific domain, with a cached
/// `ServerConfig` to avoid rebuilding it per connection.
pub struct DomainCert {
  /// Expiry time for the generated leaf certificate.
  pub expires_at: OffsetDateTime,
  /// Pre-built `ServerConfig` for this domain (avoids per-connection rebuild).
  pub server_config: Arc<rustls::ServerConfig>,
}

impl std::fmt::Debug for DomainCert {
  /// The pre-built `ServerConfig` holds the leaf private key and is not
  /// rendered; only the expiry is.
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("DomainCert")
      .field("expires_at", &self.expires_at)
      .finish_non_exhaustive()
  }
}

/// Generate a certificate for `domain` (SAN = SNI) signed by the given CA.
///
/// # Errors
///
/// Returns an error when `domain` is not a valid SAN, when leaf key
/// generation or signing fails, or when rustls rejects the resulting chain.
pub fn generate_domain_cert(domain: &str, ca: &CertAuthority) -> eyre::Result<DomainCert> {
  let now = OffsetDateTime::now_utc();
  let mut params = CertificateParams::new(vec![domain.to_string()]).map_err(|err| eyre::eyre!("bad SNI: {err}"))?;

  let mut dn = rcgen::DistinguishedName::new();
  dn.push(rcgen::DnType::CommonName, domain);
  params.distinguished_name = dn;
  params.is_ca = IsCa::ExplicitNoCa;
  params.use_authority_key_identifier_extension = true;
  params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature, rcgen::KeyUsagePurpose::KeyEncipherment];
  params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

  // Backdate not_before by 2 seconds for clock skew.
  params.not_before = now - Duration::seconds(2);
  params.not_after = now + Duration::hours(LEAF_VALIDITY_HOURS.cast_signed());
  let expires_at = params.not_after;

  let key_pair = rcgen::KeyPair::generate().map_err(|err| eyre::eyre!("keygen: {err}"))?;
  let cert_der = params.signed_by(&key_pair, &ca.issuer).map_err(|err| eyre::eyre!("sign: {err}"))?;

  let chain = vec![CertificateDer::from(cert_der.der().to_vec()), ca.cert_der.clone()];
  let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

  let server_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .map_err(|err| eyre::eyre!("server config: {err}"))?;

  Ok(DomainCert {
    expires_at,
    server_config: Arc::new(server_config),
  })
}

/// Install the aws-lc-rs crypto provider as the process default. Idempotent;
/// required before building any rustls config.
pub fn install_crypto_provider() {
  let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ca_roundtrips_through_file_byte_exact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub").join("ca.pem");
    let ca = load_or_generate(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    let reloaded = load_or_generate(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(reloaded.cert_der, ca.cert_der);
  }

  #[test]
  fn leaf_covers_ip_san() {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let cert = generate_domain_cert("127.0.0.1", &ca).unwrap();
    assert!(cert.expires_at > OffsetDateTime::now_utc());
  }

  #[test]
  fn split_pems_hold_one_half_each() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    let ca = load_or_generate(&path).unwrap();

    let crt = std::fs::read_to_string(dir.path().join("ca.crt")).unwrap();
    let key = std::fs::read_to_string(dir.path().join("ca.key")).unwrap();
    assert!(crt.contains("BEGIN CERTIFICATE"));
    assert!(!crt.contains("PRIVATE KEY"), "the certificate file carried the key");
    assert!(key.contains("PRIVATE KEY"));
    assert!(!key.contains("CERTIFICATE"), "the key file carried the certificate");

    // The combined file is still the certificate followed by the key.
    let pem = std::fs::read_to_string(&path).unwrap();
    assert!(pem.starts_with(&crt));
    assert!(pem.contains(&key));
    assert_eq!(crt, String::from_utf8(ca.cert_pem()).unwrap());
  }

  #[cfg(unix)]
  #[test]
  fn split_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    load_or_generate(&path).unwrap();
    let mode = std::fs::metadata(dir.path().join("ca.key")).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "key mode was {mode:o}");
  }

  #[test]
  fn a_deleted_split_file_is_rewritten_from_the_pem() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    load_or_generate(&path).unwrap();
    let before = std::fs::read(dir.path().join("ca.crt")).unwrap();
    std::fs::remove_file(dir.path().join("ca.crt")).unwrap();

    load_or_generate(&path).unwrap();
    assert_eq!(std::fs::read(dir.path().join("ca.crt")).unwrap(), before);
  }
}
