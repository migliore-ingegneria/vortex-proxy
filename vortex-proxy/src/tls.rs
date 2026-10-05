//! TLS termination and configuration logic for Vortex.
//!
//! This module handles loading certificates and private keys
//! into a `rustls::ServerConfig`, and providing an acceptor
//! for incoming secure connections, along with dynamic SNI certificate management.

use dashmap::DashMap;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Certificate and PrivateKey bundle for a domain.
#[derive(Debug)]
pub struct CertKeyBundle {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Clone for CertKeyBundle {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl CertKeyBundle {
    pub fn new(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Self {
        Self { certs, key }
    }
}

/// Dynamic SSL/TLS SNI Certificate Manager supporting hot-reloading and wildcard domains.
pub struct SniCertificateManager {
    domains: DashMap<String, CertKeyBundle>,
    default_bundle: RwLock<Option<CertKeyBundle>>,
}

impl Default for SniCertificateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SniCertificateManager {
    pub fn new() -> Self {
        Self {
            domains: DashMap::new(),
            default_bundle: RwLock::new(None),
        }
    }

    pub fn with_default(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Self {
        let manager = Self::new();
        manager.set_default(certs, key);
        manager
    }

    pub fn set_default(&self, certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) {
        let mut guard = self.default_bundle.write().unwrap();
        *guard = Some(CertKeyBundle::new(certs, key));
    }

    pub fn register_domain(
        &self,
        domain: impl Into<String>,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) {
        self.domains.insert(domain.into().to_lowercase(), CertKeyBundle::new(certs, key));
    }

    pub fn remove_domain(&self, domain: &str) -> bool {
        self.domains.remove(&domain.to_lowercase()).is_some()
    }

    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    pub fn reload_from_paths<P: AsRef<Path>>(
        &self,
        domain: impl Into<String>,
        cert_path: P,
        key_path: P,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        self.register_domain(domain, certs, key);
        Ok(())
    }

    /// Match exact domain name, wildcard `*.domain.com`, or fallback to default bundle.
    pub fn get_certificate(&self, server_name: &str) -> Option<CertKeyBundle> {
        let clean_name = server_name.to_lowercase();

        // 1. Exact domain match
        if let Some(bundle) = self.domains.get(&clean_name) {
            return Some(bundle.value().clone());
        }

        // 2. Wildcard domain match (e.g. api.example.com matches *.example.com)
        if let Some(dot_idx) = clean_name.find('.') {
            let wildcard = format!("*{}", &clean_name[dot_idx..]);
            if let Some(bundle) = self.domains.get(&wildcard) {
                return Some(bundle.value().clone());
            }
        }

        // 3. Fallback to default certificate bundle
        let guard = self.default_bundle.read().unwrap();
        guard.clone()
    }
}

/// Loads certificates from a PEM file.
pub fn load_certs<P: AsRef<Path>>(
    cert_path: P,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// Loads the first valid PKCS8 private key from a PEM file.
pub fn load_private_key<P: AsRef<Path>>(
    key_path: P,
) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map(|res| res.map(PrivateKeyDer::Pkcs8))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(keys.remove(0))
}

/// Loads a TLS `ServerConfig` from the given certificate and key paths (for HTTP/1.1 and H2).
pub fn load_tls_config<P: AsRef<Path>>(
    cert_path: P,
    key_path: P,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock dummy cert and key bytes for testing
    fn dummy_cert(id: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from(id.to_vec())
    }

    fn dummy_key(id: &[u8]) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(pki_types::PrivatePkcs8KeyDer::from(id.to_vec()))
    }

    #[test]
    fn test_sni_manager_exact_and_wildcard_matching() {
        let manager = SniCertificateManager::new();

        let cert1 = vec![dummy_cert(b"cert_example_com")];
        let key1 = dummy_key(b"key_example_com");
        manager.register_domain("example.com", cert1, key1);

        let cert_wild = vec![dummy_cert(b"cert_wildcard")];
        let key_wild = dummy_key(b"key_wildcard");
        manager.register_domain("*.test.org", cert_wild, key_wild);

        // Exact match
        let res1 = manager.get_certificate("example.com");
        assert!(res1.is_some());
        assert_eq!(res1.unwrap().certs[0].as_ref(), b"cert_example_com");

        // Case insensitivity
        let res_case = manager.get_certificate("EXAMPLE.COM");
        assert!(res_case.is_some());

        // Wildcard match
        let res2 = manager.get_certificate("sub.test.org");
        assert!(res2.is_some());
        assert_eq!(res2.unwrap().certs[0].as_ref(), b"cert_wildcard");

        // Unmatched domain with no default
        assert!(manager.get_certificate("unknown.net").is_none());
    }

    #[test]
    fn test_sni_manager_default_fallback() {
        let default_cert = vec![dummy_cert(b"default_cert")];
        let default_key = dummy_key(b"default_key");

        let manager = SniCertificateManager::with_default(default_cert, default_key);

        let res = manager.get_certificate("anydomain.com");
        assert!(res.is_some());
        assert_eq!(res.unwrap().certs[0].as_ref(), b"default_cert");
    }

    #[test]
    fn test_sni_manager_hot_reload_and_removal() {
        let manager = SniCertificateManager::new();

        let cert_v1 = vec![dummy_cert(b"v1")];
        let key_v1 = dummy_key(b"v1_key");
        manager.register_domain("app.domain.com", cert_v1, key_v1);

        assert_eq!(
            manager.get_certificate("app.domain.com").unwrap().certs[0].as_ref(),
            b"v1"
        );

        // Hot reload domain with new certificate v2
        let cert_v2 = vec![dummy_cert(b"v2")];
        let key_v2 = dummy_key(b"v2_key");
        manager.register_domain("app.domain.com", cert_v2, key_v2);

        assert_eq!(
            manager.get_certificate("app.domain.com").unwrap().certs[0].as_ref(),
            b"v2"
        );

        // Removal
        assert!(manager.remove_domain("app.domain.com"));
        assert!(manager.get_certificate("app.domain.com").is_none());
    }
}
