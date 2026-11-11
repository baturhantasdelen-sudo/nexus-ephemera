//! Apoptosis sonrası düz metin kalıntısı: ayrı süreçte üretim API'si.

#![forbid(unsafe_code)]

use mesh::EnvelopeBody;
use nexus_ephemera::{
    WipeStatus,
    apoptosis::{EphemeralBuffer, is_engaged, trigger_apoptosis},
    crypto, mesh, scout,
};
use scout::{EncryptedScoutHandoff, ScoutReportMeta, ScoutSnapshot};

#[tokio::test(flavor = "current_thread")]
async fn end_to_end_canary_leaves_no_plaintext_after_apoptosis() {
    const CANARY: &[u8] = b"NEXUS_FORENSIC_CANARY_99887766!!";

    crypto::init_session_from_entropy().expect("session");
    mesh::initialize().await.expect("mesh");
    mesh::register_apoptosis_integration();

    let snapshot = ScoutSnapshot {
        host_label: std::str::from_utf8(CANARY).expect("canary utf8").into(),
        open_ports_simulated: vec![],
        processes_simulated: vec![],
        env_keys_redacted: vec![],
        scanned_at_unix: 42,
    };
    let mut plain_src = EphemeralBuffer::from_serializable(&snapshot).expect("plain");
    assert!(plain_src.len() > CANARY.len());

    let sealed = crypto::seal_plaintext(&plain_src).expect("seal");
    let handoff = EncryptedScoutHandoff {
        sealed: sealed.clone(),
        meta: ScoutReportMeta {
            host_label: snapshot.host_label.clone(),
            scanned_at_unix: snapshot.scanned_at_unix,
            encrypted_bytes: sealed.ciphertext_b64.len(),
        },
    };
    let envelope = mesh::ingest_scout_handoff(handoff).expect("ingest");
    assert_eq!(envelope.topic, "scout/encrypted");

    let decode_cap = base64::decoded_len_estimate(envelope.sealed.ciphertext_b64.len());
    let mut plain_dst = EphemeralBuffer::with_capacity(decode_cap.max(512)).expect("dest");
    crypto::open_into(&envelope.sealed, &plain_dst).expect("open_into");
    let opened: EnvelopeBody = plain_dst.decode_json().expect("decoded");
    let decoded_snap = opened.scout_snapshot.as_ref().expect("scout payload");
    assert_eq!(decoded_snap.host_label, snapshot.host_label);

    assert_eq!(
        trigger_apoptosis().expect("trigger"),
        WipeStatus::Complete,
        "apoptosis must fully wipe registered state"
    );
    assert!(is_engaged());

    assert!(
        plain_src.fill(CANARY).is_err(),
        "wiped source buffer must reject writes fail-closed"
    );
    assert!(
        plain_dst.fill(CANARY).is_err(),
        "wiped destination buffer must reject writes fail-closed"
    );
    assert!(
        plain_src.decode_json::<ScoutSnapshot>().is_err(),
        "source must not decode after wipe"
    );
    assert!(
        plain_dst.decode_json::<EnvelopeBody>().is_err(),
        "destination must not decode after wipe"
    );

    assert!(
        mesh::receive_next().is_err(),
        "mesh queue access must fail after apoptosis"
    );
    assert!(
        mesh::publish_encrypted("forensic/block", serde_json::json!({})).is_err(),
        "mesh publish must fail after apoptosis"
    );
}
