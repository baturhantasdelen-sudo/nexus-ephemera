//! Ajan ham anahtarı okumaz; yalnızca aracı fişiyle işlem yapar.

#![forbid(unsafe_code)]

use nexus_ephemera::broker::{
    AuthorizedCall, BrokerError, ExecuteWithPolicy, SecureTransactionAgent, SecureTransport,
    TransportReply,
};
use nexus_ephemera::context::LifecycleState;
use nexus_ephemera::exposure::{ExportBoundary, ExposureTags, NoPlaintextExport};

struct RecordingTransport {
    pub saw_canary: bool,
}

impl SecureTransport for RecordingTransport {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        let visible = format!(
            "{} {} {}",
            call.target_endpoint, call.payload_hash, call.binding_digest_hex
        );
        self.saw_canary = visible.contains("sk-broker-canary-42");
        assert!(!self.saw_canary, "transport must not receive the raw key");
        Ok(TransportReply { status: 204 })
    }
}

#[test]
fn agent_cannot_read_key_and_executes_only_through_broker() {
    let canary = "sk-broker-canary-42";
    let mut agent = SecureTransactionAgent::admit(
        canary.as_bytes(),
        ExposureTags::provider_bound("https://provider.example/charge", true, None).expect("tags"),
    )
    .expect("admit");

    assert!(!agent.allows_plaintext_export());
    const {
        assert!(!NoPlaintextExport::ALLOWS_PLAINTEXT_EXPORT);
    }
    let rendered = format!("{agent} {agent:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(canary));

    let clean = agent
        .sanitize_log("authorization: Bearer sk-broker-canary-42")
        .expect("sanitize");
    assert_eq!(clean, "authorization: Bearer [REDACTED]");

    let mut transport = RecordingTransport { saw_canary: false };
    let context_id = agent.context_id();
    let receipt = agent
        .execute(
            ExecuteWithPolicy {
                context_id,
                target_endpoint: "https://provider.example/charge".into(),
                payload_hash: "abc123".into(),
                idempotency_key: "broker-transaction".into(),
            },
            &mut transport,
        )
        .expect("execute");
    assert!(!transport.saw_canary);
    assert_eq!(receipt.transport_status, 204);
    assert!(!receipt.binding_digest_hex.contains(canary));
    assert_eq!(agent.lifecycle_state(), LifecycleState::Closed);
    let again = ExecuteWithPolicy {
        context_id,
        target_endpoint: "https://provider.example/charge".into(),
        payload_hash: "abc123".into(),
        idempotency_key: "broker-transaction-again".into(),
    };
    assert_eq!(
        agent
            .execute(again, &mut transport)
            .expect_err("second use"),
        BrokerError::SingleUseConsumed
    );
}
