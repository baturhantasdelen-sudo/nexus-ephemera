//! Separate test executable: no TLS fixture has initialized process globals.
use nexus_ephemera::enterprise_runtime::HttpPayloadTransport;
use std::time::Duration;

#[test]
fn standalone_transport_installs_tls_provider_without_a_test_server() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    HttpPayloadTransport::new(Duration::from_secs(1)).unwrap();
    let provider = rustls::crypto::CryptoProvider::get_default()
        .unwrap()
        .clone();
    HttpPayloadTransport::new(Duration::from_secs(1)).unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &provider,
        rustls::crypto::CryptoProvider::get_default().unwrap()
    ));
}
