//! Uçtan uca: oturum → scout → mesh → event loop.

#![forbid(unsafe_code)]

use nexus_ephemera::{mesh, scout};

#[tokio::test(flavor = "current_thread")]
async fn full_offline_pipeline() {
    scout::initialize().await.expect("scout");
    mesh::initialize().await.expect("mesh");
    mesh::register_apoptosis_integration();

    let report = scout::run_discovery_cycle().await.expect("discovery");
    assert!(!report.sealed().ciphertext_b64.is_empty());
    assert!(report.vault_len() > 0);

    let envelope = mesh::ingest_scout_handoff(report.into_handoff()).expect("ingest");
    assert_eq!(envelope.topic, "scout/encrypted");
    assert!(envelope.local_file.is_some());

    mesh::run_event_loop().await.expect("event loop");
    assert!(mesh::receive_next().expect("recv").is_none());
}
