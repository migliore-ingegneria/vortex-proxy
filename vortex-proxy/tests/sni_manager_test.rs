#![allow(missing_docs)]

use std::sync::Arc;
use std::thread;
use vortex_proxy::tls::SniCertificateManager;

#[test]
fn test_concurrent_sni_certificate_hot_reloading() {
    let manager = Arc::new(SniCertificateManager::new());

    // Register initial domain
    let cert = pki_types::CertificateDer::from(vec![1, 2, 3]);
    let key = pki_types::PrivateKeyDer::Pkcs8(pki_types::PrivatePkcs8KeyDer::from(vec![4, 5, 6]));
    manager.register_domain("api.vortex.internal", vec![cert], key);

    assert_eq!(manager.domain_count(), 1);

    // Concurrent lookup and hot-reloading loop across multiple worker threads
    let mut handles = vec![];
    for t in 0..4 {
        let manager_clone: Arc<SniCertificateManager> = Arc::clone(&manager);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let domain_name = format!("service-{}-{}.cluster.local", t, i);
                let cert = pki_types::CertificateDer::from(vec![i as u8]);
                let key = pki_types::PrivateKeyDer::Pkcs8(pki_types::PrivatePkcs8KeyDer::from(vec![i as u8]));
                manager_clone.register_domain(&domain_name, vec![cert], key);

                let fetched = manager_clone.get_certificate(&domain_name);
                assert!(fetched.is_some());
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert!(manager.domain_count() >= 401);
}
