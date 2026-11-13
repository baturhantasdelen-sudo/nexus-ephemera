//! Reference flow. The agent sends `AuthorizedCall` only. The local HTTP
//! client zeroizes its request buffer. Panic and `CleanupIncomplete` stay visible.

#![forbid(unsafe_code)]

use nexus_ephemera::broker::{
    AuthorizedCall, BrokerError, ExecuteWithPolicy, SealReport, SecureTransactionAgent,
    SecureTransport, TransportReply,
};
use nexus_ephemera::context::LifecycleState;
use nexus_ephemera::exposure::ExposureTags;
use zeroize::Zeroize;

const ENDPOINT: &str = "https://provider.example/charge";
const KEY: &str = "reference-flow-key";

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn reference_flow_mock_and_realistic_never_export_the_key() {
    let _guard = serial();
    let mock = run_mock();
    assert_eq!(mock.transport_status, 204);
    assert_eq!(mock.seal_report, SealReport::Complete);
    assert!(!mock.binding_digest_hex.contains(KEY));

    let (retained, final_call) = run_realistic();
    assert_eq!(retained.seal_report, SealReport::Retained);
    assert_eq!(final_call.seal_report, SealReport::Complete);
    assert!(!retained.binding_digest_hex.contains(KEY));
    assert!(!final_call.binding_digest_hex.contains(KEY));
    assert_eq!(cleanup_view(SealReport::Partial), CleanupView::Incomplete);
    assert_eq!(cleanup_view(SealReport::Failed), CleanupView::Incomplete);
}

#[test]
fn transport_panic_seals_single_use_and_stays_visible() {
    let _guard = serial();
    let mut agent = admit(true);
    let cmd = command(&agent, "sha256:panic");
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = agent.execute(cmd, &mut PanicProvider);
    }));
    assert!(caught.is_err());
    assert_eq!(agent.lifecycle_state(), LifecycleState::Closed);
    let again = command(&agent, "sha256:panic");
    assert_eq!(
        agent.execute(again, &mut PanicProvider),
        Err(BrokerError::SingleUseConsumed)
    );
}

fn run_mock() -> nexus_ephemera::broker::TransactionReceipt {
    let mut agent = admit(true);
    let rendered = format!("{agent} {agent:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(KEY));
    let mut provider = MockProvider::default();
    let receipt = execute(&mut agent, &mut provider, "sha256:mock");
    assert_eq!(provider.calls, 1);
    assert!(provider.saw_nonce);
    assert!(provider.saw_timestamp);
    assert_eq!(agent.lifecycle_state(), LifecycleState::Closed);
    receipt
}

fn run_realistic() -> (
    nexus_ephemera::broker::TransactionReceipt,
    nexus_ephemera::broker::TransactionReceipt,
) {
    let mut agent = admit(false);
    let mut provider = RealisticProvider::default();
    let first = execute(&mut agent, &mut provider, "sha256:one");
    let second = execute(&mut agent, &mut provider, "sha256:two");
    assert_eq!(provider.nonces.len(), 2);
    assert_ne!(provider.nonces[0], provider.nonces[1]);
    assert_ne!(first.binding_digest_hex, second.binding_digest_hex);
    assert!(provider.wiped);
    assert!(provider.request_was_nonzero_before_wipe);
    assert_eq!(agent.lifecycle_state(), LifecycleState::Active);

    let mut once = admit(true);
    let final_call = execute(&mut once, &mut provider, "sha256:final");
    assert!(provider.wiped);
    assert_eq!(once.lifecycle_state(), LifecycleState::Closed);
    (first, final_call)
}

fn admit(single_use: bool) -> SecureTransactionAgent {
    SecureTransactionAgent::admit(
        KEY.as_bytes(),
        ExposureTags::provider_bound(ENDPOINT, single_use, None).expect("tags"),
    )
    .expect("admit")
}

fn command(agent: &SecureTransactionAgent, payload_hash: &str) -> ExecuteWithPolicy {
    ExecuteWithPolicy {
        context_id: agent.context_id(),
        target_endpoint: ENDPOINT.into(),
        payload_hash: payload_hash.into(),
        idempotency_key: format!("reference-flow-{payload_hash}"),
    }
}

fn execute(
    agent: &mut SecureTransactionAgent,
    transport: &mut impl SecureTransport,
    payload_hash: &str,
) -> nexus_ephemera::broker::TransactionReceipt {
    agent
        .execute(command(agent, payload_hash), transport)
        .expect("execute")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupView {
    Usable,
    Incomplete,
}

fn cleanup_view(report: SealReport) -> CleanupView {
    match report {
        SealReport::Retained | SealReport::Complete => CleanupView::Usable,
        SealReport::Partial | SealReport::Failed => CleanupView::Incomplete,
    }
}

fn reject_key(call: &AuthorizedCall<'_>) {
    let visible = format!(
        "{} {} {}",
        call.target_endpoint, call.payload_hash, call.binding_digest_hex
    );
    assert!(!visible.contains(KEY));
    assert_ne!(call.call_nonce, 0);
    assert_ne!(call.issued_at_unix_ms, 0);
    assert_eq!(call.binding_digest_hex.len(), 64);
}

#[derive(Default)]
struct MockProvider {
    calls: u32,
    saw_nonce: bool,
    saw_timestamp: bool,
}

impl SecureTransport for MockProvider {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        reject_key(call);
        self.calls = self.calls.saturating_add(1);
        self.saw_nonce = true;
        self.saw_timestamp = true;
        Ok(TransportReply { status: 204 })
    }
}

#[derive(Default)]
struct RealisticProvider {
    nonces: Vec<u64>,
    wiped: bool,
    request_was_nonzero_before_wipe: bool,
}

impl SecureTransport for RealisticProvider {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        reject_key(call);
        let mut body = format!(
            "POST {} HTTP/1.1\r\nx-nonce: {}\r\nx-issued-at: {}\r\nx-binding: {}\r\n\r\n{}",
            call.target_endpoint,
            call.call_nonce,
            call.issued_at_unix_ms,
            call.binding_digest_hex,
            call.payload_hash
        )
        .into_bytes();
        self.request_was_nonzero_before_wipe = body.iter().any(|byte| *byte != 0);
        assert!(
            body.windows(KEY.len())
                .all(|window| window != KEY.as_bytes())
        );
        body.zeroize();
        assert!(body.iter().all(|byte| *byte == 0));
        self.wiped = true;
        self.nonces.push(call.call_nonce);
        Ok(TransportReply { status: 200 })
    }
}

struct PanicProvider;

impl SecureTransport for PanicProvider {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        reject_key(call);
        panic!("provider failed during dispatch");
    }
}
