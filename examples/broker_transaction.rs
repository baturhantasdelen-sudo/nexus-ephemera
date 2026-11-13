//! Agent calls the broker. The raw key is never printed or returned.

use nexus_ephemera::broker::{
    AuthorizedCall, BrokerError, ExecuteWithPolicy, SecureTransactionAgent, SecureTransport,
    TransportReply,
};
use nexus_ephemera::exposure::ExposureTags;

struct LocalProvider;

impl SecureTransport for LocalProvider {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        if call.binding_digest_hex.is_empty() || call.payload_hash.is_empty() {
            return Err(BrokerError::Transport("incomplete authorized call"));
        }
        Ok(TransportReply { status: 204 })
    }
}

fn main() {
    let tags = ExposureTags::provider_bound("https://provider.example/charge", true, None)
        .expect("provider binding");
    let mut agent = SecureTransactionAgent::admit(b"example-key-not-for-display", tags)
        .expect("admit key into locked context");

    println!("agent={agent}");
    println!("plaintext_export={}", agent.allows_plaintext_export());

    let context_id = agent.context_id();
    let receipt = agent
        .execute(
            ExecuteWithPolicy {
                context_id,
                target_endpoint: "https://provider.example/charge".into(),
                payload_hash: "sha256:example-payload".into(),
                idempotency_key: "example-broker-transaction".into(),
            },
            &mut LocalProvider,
        )
        .expect("brokered execute");

    println!(
        "transport_status={} lifecycle={:?} digest_len={}",
        receipt.transport_status,
        agent.lifecycle_state(),
        receipt.binding_digest_hex.len()
    );
}
