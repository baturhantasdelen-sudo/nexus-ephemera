//! Enterprise chaos: tamper-evident audit, tenant denial, shared claims, saturation.
//!
//! The hash chain is not a MAC and not mTLS. A cached cluster receipt keeps the
//! first transport status. `duplicate_status` 409 is the provider conflict the
//! second node does not submit.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use nexus_ephemera::enterprise::{
    AuditEvent, AuditKind, AuditLedger, DUPLICATE_PROVIDER_STATUS, ReferenceCall,
    ReferenceClusterNode, ReferenceIdempotency, ServiceAccount, TenantDirectory, WORKER_CAP,
    WorkerGate, verify_export,
};
use nexus_ephemera::ipc::IpcError;

const SECRET: &[u8] = b"enterprise-tenant-secret";
const CHARGE: &str = "https://provider.example/charge";
const REFUND: &str = "https://provider.example/refund";
const NOW: u64 = 1_700_000_000_000;

#[test]
fn chaos_resilience_keeps_one_dispatch_and_a_verifiable_log() {
    let directory = directory();
    let token = directory
        .issue_token(SECRET, "billing", "charge", NOW + 60_000, NOW)
        .expect("token");
    let grant = directory
        .authorize(SECRET, &token, "billing", CHARGE, &[], NOW + 1_000)
        .expect("grant");
    assert_eq!(grant.service_account_id, "billing");

    let denied = directory.authorize(SECRET, &token, "billing", REFUND, &[], NOW + 1_000);
    assert!(matches!(denied, Err(IpcError::TargetDenied)));
    let spoofed = directory.authorize(SECRET, &token, "payments", CHARGE, &[], NOW + 1_000);
    assert!(matches!(spoofed, Err(IpcError::TargetDenied)));
    let forged = token.replacen("v1=", "v1=00", 1);
    assert!(matches!(
        directory.authorize(SECRET, &forged, "billing", CHARGE, &[], NOW + 1_000),
        Err(IpcError::TargetDenied | IpcError::Malformed)
    ));
    assert!(matches!(
        directory.authorize(
            SECRET,
            &token,
            "billing",
            "https://provider.example/charge?x=1",
            &[],
            NOW + 1_000,
        ),
        Err(IpcError::TargetDenied)
    ));
    assert!(!token.contains("enterprise-tenant-secret"));

    let store = Arc::new(ReferenceIdempotency::new(8).expect("store"));
    let hits = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(2));
    let call = call("billing", "idem-1");
    let mut threads = Vec::new();
    for _ in 0..2 {
        let store = Arc::clone(&store);
        let hits = Arc::clone(&hits);
        let barrier = Arc::clone(&barrier);
        let call = call.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            ReferenceClusterNode::new(store, hits).execute(&call)
        }));
    }
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().expect("join"))
        .collect();
    assert_eq!(hits.load(Ordering::SeqCst), 1, "{results:?}");
    let cached = ReferenceClusterNode::new(Arc::clone(&store), Arc::clone(&hits))
        .execute(&call)
        .expect("cached");
    assert_eq!(cached.duplicate_status, Some(DUPLICATE_PROVIDER_STATUS));
    assert_eq!(cached.transport_status, 204);
    assert_eq!(cached.seal_report, "retained");
    assert_eq!(cached.idempotency_key, "idem-1");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let conflict = call.clone();
    let mut conflict = conflict;
    conflict.payload_hash = "hash-other".into();
    assert!(matches!(
        ReferenceClusterNode::new(Arc::clone(&store), Arc::clone(&hits)).execute(&conflict),
        Err(IpcError::IdempotencyConflict)
    ));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let interrupted = call_named("billing", "idem-net");
    assert!(matches!(
        ReferenceClusterNode::new(Arc::clone(&store), Arc::clone(&hits))
            .execute_interrupted(&interrupted),
        Err(IpcError::Inconclusive)
    ));
    assert!(matches!(
        ReferenceClusterNode::new(Arc::clone(&store), Arc::clone(&hits)).execute(&interrupted),
        Err(IpcError::Inconclusive)
    ));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    store.quarantine_for_rotation();
    assert!(matches!(
        ReferenceClusterNode::new(Arc::clone(&store), Arc::clone(&hits))
            .execute(&call_named("billing", "idem-new")),
        Err(IpcError::Protocol("shared idempotency store is sealed"))
    ));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .redis_claim_command("billing", "idem-1")
            .expect("redis"),
        "SET nexus:idem:billing:idem-1 pending NX"
    );

    let gate = WorkerGate::new();
    let mut permits = Vec::new();
    for _ in 0..WORKER_CAP {
        permits.push(gate.try_acquire().expect("slot"));
    }
    assert!(matches!(gate.try_acquire(), Err(IpcError::RateLimited)));
    drop(permits.pop());
    let _released = gate.try_acquire().expect("slot after release");

    let mut ledger = AuditLedger::try_new().expect("audit admission");
    ledger
        .append(&AuditEvent {
            kind: AuditKind::Retained,
            service_account_id: grant.service_account_id,
            endpoint: cached.target_endpoint.clone(),
            payload_hash: cached.payload_hash.clone(),
            idempotency_key: cached.idempotency_key.clone(),
            seal_report: cached.seal_report.clone(),
            binding_digest_hex: cached.binding_digest_hex.clone(),
            transport_status: cached.transport_status,
        })
        .expect("retained");
    ledger
        .append(&AuditEvent {
            kind: AuditKind::TargetDenied,
            service_account_id: "billing".into(),
            endpoint: REFUND.into(),
            payload_hash: "hash-a".into(),
            idempotency_key: "idem-deny".into(),
            seal_report: String::new(),
            binding_digest_hex: String::new(),
            transport_status: 0,
        })
        .expect("denied");
    ledger
        .append(&AuditEvent {
            kind: AuditKind::IdempotencyConflict,
            service_account_id: "billing".into(),
            endpoint: CHARGE.into(),
            payload_hash: "hash-other".into(),
            idempotency_key: "idem-1".into(),
            seal_report: String::new(),
            binding_digest_hex: String::new(),
            transport_status: 0,
        })
        .expect("conflict");
    assert!(ledger.verify());
    let exported = ledger.export_json();
    assert!(verify_export(&exported, &ledger.checkpoint()));
    assert!(exported.contains("\"kind\":\"retained\""));
    assert!(exported.contains("\"kind\":\"target_denied\""));
    assert!(exported.contains("\"kind\":\"idempotency_conflict\""));
    assert!(!exported.contains("enterprise-tenant-secret"));
    let tampered = exported.replacen("retained", "receipt", 1);
    assert!(!verify_export(&tampered, &ledger.checkpoint()));
}

fn directory() -> TenantDirectory {
    TenantDirectory::try_new(vec![
        ServiceAccount {
            id: "billing".into(),
            roles: vec!["charge".into()],
            role_endpoints: Default::default(),
            role_params: Default::default(),
            attributes: Vec::new(),
            allowlist: vec![CHARGE.into()],
        },
        ServiceAccount {
            id: "payments".into(),
            roles: vec!["refund".into()],
            role_endpoints: Default::default(),
            role_params: Default::default(),
            attributes: Vec::new(),
            allowlist: vec![REFUND.into()],
        },
    ])
    .expect("directory")
}

fn call(account: &str, key: &str) -> ReferenceCall {
    call_named(account, key)
}

fn call_named(account: &str, key: &str) -> ReferenceCall {
    ReferenceCall {
        service_account_id: account.into(),
        endpoint: CHARGE.into(),
        payload_hash: "hash-a".into(),
        idempotency_key: key.into(),
        binding_digest_hex: "ab".repeat(32),
        seal_report: "retained".into(),
    }
}
