//! Separate process: terminal lifecycle state must never need a test reset.
use nexus_ephemera::adapters::{github::GithubIssuePolicy, github_production::GithubTransport};
use nexus_ephemera::apoptosis::{WipeStatus, trigger_apoptosis};
use nexus_ephemera::broker::{AuthorizedCall, SecureTransport};
use nexus_ephemera::enterprise_runtime::HttpPayloadTransport;
use nexus_ephemera::operations::KeyRing;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[test]
fn apoptosis_irreversibly_rejects_keys_provider_credentials_and_reconstruction() {
    let mut ring = KeyRing::new(b"public-regression-fixture".to_vec()).unwrap();
    assert!(
        ring.sign_request(1, "key", "hash", "https://example.test/action")
            .is_ok()
    );
    let http = HttpPayloadTransport::new(Duration::from_millis(100)).unwrap();
    let policy =
        GithubIssuePolicy::load(include_bytes!("../policies/pilot_support_agent.json")).unwrap();
    let mut input = b"public-provider-fixture".to_vec();
    let mut provider = GithubTransport::new(http, policy.clone(), &mut input).unwrap();
    assert!(input.iter().all(|byte| *byte == 0));
    assert_eq!(trigger_apoptosis().unwrap(), WipeStatus::Complete);
    let payload = br#"{"tool":"support_agent","params":{"title":"fixture","body":"fixture"}}"#;
    let hash: String = Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let call = AuthorizedCall {
        target_endpoint: policy.endpoint(),
        payload_hash: &hash,
        binding_digest_hex: "fixture",
        call_nonce: 1,
        issued_at_unix_ms: 1,
        idempotency_key: "fixture",
        nexus_signature: "fixture",
    };
    assert!(provider.dispatch_payload(&call, payload).is_err());
    assert!(
        ring.sign_request(1, "key", "hash", "https://example.test/action")
            .is_err()
    );
    assert!(
        ring.rotate(b"replacement-fixture".to_vec(), 2, Duration::ZERO)
            .is_err()
    );
    assert!(KeyRing::new(b"new-fixture".to_vec()).is_err());
    let http = HttpPayloadTransport::new(Duration::from_millis(100)).unwrap();
    let mut next = b"new-provider-fixture".to_vec();
    assert!(GithubTransport::new(http, policy, &mut next).is_err());
    assert!(next.iter().all(|byte| *byte == 0));
}
