//! Reference integration. The agent never holds the raw key.
//!
//! `mock` is a deterministic local provider for CI. `realistic` builds an
//! HTTP request from `AuthorizedCall` (nonce, timestamp, binding digest) and
//! zeroizes that heap buffer before returning. Neither mode opens a socket.
//! `Partial` and `Failed` seals are cleanup failures; `execute` returns
//! `CleanupIncomplete` instead of a successful receipt.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use nexus_ephemera::broker::{
    AuthorizedCall, BrokerError, ExecuteWithPolicy, SealReport, SecureTransactionAgent,
    SecureTransport, TransportReply,
};
use nexus_ephemera::context::LifecycleState;
use nexus_ephemera::exposure::ExposureTags;
use zeroize::Zeroize;

const ENDPOINT: &str = "https://provider.example/charge";
const KEY: &[u8] = b"reference-key-not-printed";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        None => {
            run_mock();
            run_realistic();
            ExitCode::SUCCESS
        }
        Some("mock") => {
            run_mock();
            ExitCode::SUCCESS
        }
        Some("realistic") => {
            run_realistic();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("usage: reference_integration [mock|realistic] (unknown: {other})");
            ExitCode::from(2)
        }
    }
}

fn run_mock() {
    let mut agent = admit(true);
    let mut provider = MockProvider { calls: 0 };
    let receipt = execute(&mut agent, &mut provider, "sha256:mock-payload");
    assert_eq!(provider.calls, 1);
    assert_eq!(receipt.transport_status, 204);
    assert_eq!(receipt.seal_report, SealReport::Complete);
    assert_eq!(agent.lifecycle_state(), LifecycleState::Closed);
    println!(
        "mode=mock status={} seal={} lifecycle={:?}",
        receipt.transport_status,
        cleanup_view(receipt.seal_report),
        agent.lifecycle_state()
    );
}

fn run_realistic() {
    let mut retained = admit(false);
    let mut provider = RealisticProvider::default();
    let first = execute(&mut retained, &mut provider, "sha256:payload-one");
    let second = execute(&mut retained, &mut provider, "sha256:payload-two");
    assert_eq!(first.seal_report, SealReport::Retained);
    assert_eq!(second.seal_report, SealReport::Retained);
    assert_ne!(provider.nonces[0], provider.nonces[1]);
    assert_ne!(first.binding_digest_hex, second.binding_digest_hex);
    assert!(provider.wiped);
    assert_eq!(retained.lifecycle_state(), LifecycleState::Active);
    println!(
        "mode=realistic-retained status={} seal={} lifecycle={:?} nonce_count={}",
        second.transport_status,
        cleanup_view(second.seal_report),
        retained.lifecycle_state(),
        provider.nonces.len()
    );

    let mut once = admit(true);
    let receipt = execute(&mut once, &mut provider, "sha256:payload-final");
    assert_eq!(receipt.seal_report, SealReport::Complete);
    assert_eq!(once.lifecycle_state(), LifecycleState::Closed);
    assert!(provider.wiped);
    println!(
        "mode=realistic-single-use status={} seal={} lifecycle={:?}",
        receipt.transport_status,
        cleanup_view(receipt.seal_report),
        once.lifecycle_state()
    );
}

fn admit(single_use: bool) -> SecureTransactionAgent {
    let tags = ExposureTags::provider_bound(ENDPOINT, single_use, None).expect("tags");
    SecureTransactionAgent::admit(KEY, tags).expect("admit")
}

fn execute(
    agent: &mut SecureTransactionAgent,
    transport: &mut impl SecureTransport,
    payload_hash: &str,
) -> nexus_ephemera::broker::TransactionReceipt {
    agent
        .execute(
            ExecuteWithPolicy {
                context_id: agent.context_id(),
                target_endpoint: ENDPOINT.into(),
                payload_hash: payload_hash.into(),
                idempotency_key: format!("reference-{payload_hash}"),
            },
            transport,
        )
        .expect("brokered execute")
}

fn cleanup_view(report: SealReport) -> &'static str {
    match report {
        SealReport::Retained => "retained",
        SealReport::Complete => "complete",
        SealReport::Partial => "partial-cleanup-incomplete",
        SealReport::Failed => "failed-cleanup-incomplete",
    }
}

fn assert_call_has_no_key(call: &AuthorizedCall<'_>) {
    let visible = format!(
        "{} {} {} {} {} {}",
        call.target_endpoint,
        call.payload_hash,
        call.binding_digest_hex,
        call.call_nonce,
        call.issued_at_unix_ms,
        call.idempotency_key
    );
    assert!(!visible.contains("reference-key-not-printed"));
    assert_ne!(call.call_nonce, 0);
    assert_ne!(call.issued_at_unix_ms, 0);
    assert_eq!(call.binding_digest_hex.len(), 64);
}

struct MockProvider {
    calls: u32,
}

impl SecureTransport for MockProvider {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        assert_call_has_no_key(call);
        self.calls = self.calls.saturating_add(1);
        Ok(TransportReply { status: 204 })
    }
}

#[derive(Default)]
struct RealisticProvider {
    nonces: Vec<u64>,
    wiped: bool,
}

impl SecureTransport for RealisticProvider {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        assert_call_has_no_key(call);
        let mut body = format!(
            "POST {} HTTP/1.1\r\nx-nonce: {}\r\nx-issued-at: {}\r\nx-binding: {}\r\n\r\n{}",
            call.target_endpoint,
            call.call_nonce,
            call.issued_at_unix_ms,
            call.binding_digest_hex,
            call.payload_hash
        )
        .into_bytes();
        assert!(body.windows(KEY.len()).all(|window| window != KEY));
        assert!(body.iter().any(|byte| *byte != 0));
        body.zeroize();
        assert!(body.iter().all(|byte| *byte == 0));
        self.wiped = true;
        self.nonces.push(call.call_nonce);
        Ok(TransportReply { status: 200 })
    }
}
