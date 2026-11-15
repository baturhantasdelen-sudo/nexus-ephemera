//! Negative security acceptance tests; no simulated external provider success.
use nexus_ephemera::enterprise::{
    AuditEvent, AuditKind, AuditLedger, ServiceAccount, TenantDirectory, WorkerGate, verify_export,
};
use nexus_ephemera::enterprise_runtime::{CheckpointSink, FileCheckpointSink};
use nexus_ephemera::enterprise_runtime::{RedisIdempotency, TenantAuthority, TenantCredential};
use nexus_ephemera::ipc::IpcError;
use std::collections::BTreeMap;
use std::sync::Arc;

const READ: &str = "https://provider.example/read";
const WRITE: &str = "https://provider.example/charge";
const KEY: &[u8] = b"public-enterprise-test-fixture";

fn account() -> ServiceAccount {
    ServiceAccount {
        id: "billing".into(),
        roles: vec!["read".into(), "charge".into()],
        attributes: vec![("region".into(), "eu".into())],
        allowlist: vec![READ.into(), WRITE.into()],
        role_endpoints: BTreeMap::from([
            ("read".into(), vec![READ.into()]),
            ("charge".into(), vec![WRITE.into()]),
        ]),
        role_params: BTreeMap::from([("charge".into(), vec!["amount".into()])]),
    }
}

#[test]
fn role_policy_expiry_and_same_length_mac_tampering_fail_closed() {
    let directory = TenantDirectory::try_new(vec![account()]).unwrap();
    let token = directory
        .issue_token(KEY, "billing", "read", 2000, 1000)
        .unwrap();
    let attributes = vec![("region".into(), "eu".into())];
    assert!(
        directory
            .authorize(KEY, &token, "billing", READ, &attributes, 1001)
            .is_ok()
    );
    assert!(matches!(
        directory.authorize(KEY, &token, "billing", WRITE, &attributes, 1001),
        Err(IpcError::TargetDenied)
    ));
    assert!(
        directory
            .authorize(KEY, &token, "billing", READ, &attributes, 2000)
            .is_err()
    );
    let mut forged = token.clone().into_bytes();
    let last = forged.last_mut().unwrap();
    *last = if *last == b'0' { b'1' } else { b'0' };
    let forged = String::from_utf8(forged).unwrap();
    assert_eq!(forged.len(), token.len());
    assert!(matches!(
        directory.authorize(KEY, &forged, "billing", READ, &attributes, 1001),
        Err(IpcError::TargetDenied)
    ));
    let mut changed = account();
    changed
        .role_endpoints
        .get_mut("read")
        .unwrap()
        .push(WRITE.into());
    let changed = TenantDirectory::try_new(vec![changed]).unwrap();
    assert!(
        changed
            .authorize(KEY, &token, "billing", READ, &attributes, 1001)
            .is_err()
    );
    let mut ambiguous = account();
    ambiguous.role_endpoints.clear();
    assert!(TenantDirectory::try_new(vec![ambiguous]).is_err());
}

#[test]
fn tenant_key_close_is_terminal_and_credentials_debug_is_redacted() {
    let authority =
        TenantAuthority::new(TenantDirectory::try_new(vec![account()]).unwrap(), KEY).unwrap();
    assert!(authority.issue_token("billing", "read", 2000, 1000).is_ok());
    authority.close().unwrap();
    assert!(
        authority
            .issue_token("billing", "read", 2000, 1000)
            .is_err()
    );
    let proof = TenantCredential {
        account: "billing".into(),
        token: "BEARER_CANARY".into(),
    };
    assert!(!format!("{proof:?}").contains("BEARER_CANARY"));
}

fn event() -> AuditEvent {
    AuditEvent {
        kind: AuditKind::Receipt,
        service_account_id: "billing".into(),
        endpoint: WRITE.into(),
        payload_hash: "LOW_ENTROPY_CANARY".into(),
        idempotency_key: "IDEMPOTENCY_CANARY".into(),
        seal_report: "retained".into(),
        binding_digest_hex: "ab".repeat(32),
        transport_status: 204,
    }
}

#[test]
fn audit_rejects_extension_duplicate_truncation_and_fully_rehashed_rewrite() {
    let mut ledger = AuditLedger::try_new().unwrap();
    ledger.append(&event()).unwrap();
    let export = ledger.export_json();
    let checkpoint = ledger.checkpoint();
    assert!(verify_export(&export, &checkpoint));
    assert!(!export.contains("LOW_ENTROPY_CANARY"));
    assert!(!export.contains("IDEMPOTENCY_CANARY"));
    let mut extra: serde_json::Value = serde_json::from_str(&export).unwrap();
    extra["records"][0]["event"]["unsigned_extra"] = serde_json::json!("hidden");
    assert!(!verify_export(&extra.to_string(), &checkpoint));
    let duplicate = export.replacen(
        "\"schema\":",
        "\"schema\":\"nexus-audit-v2\",\"schema\":",
        1,
    );
    assert!(!verify_export(&duplicate, &checkpoint));
    let mut rewrite = AuditLedger::try_new().unwrap();
    rewrite.append(&event()).unwrap();
    assert_ne!(rewrite.checkpoint(), checkpoint);
    assert!(!verify_export(&rewrite.export_json(), &checkpoint));
    assert!(verify_export(&rewrite.export_json(), &rewrite.checkpoint()));
    assert!(!verify_export(
        &AuditLedger::try_new().unwrap().export_json(),
        &checkpoint
    ));
    ledger.close().unwrap();
    assert!(ledger.append(&event()).is_err());
}

#[test]
fn audit_budget_is_bounded_and_rejects_before_growth() {
    let mut ledger = AuditLedger::try_new().unwrap();
    for _ in 0..1024 {
        ledger.append(&event()).unwrap();
    }
    let checkpoint = ledger.checkpoint();
    assert!(ledger.append(&event()).is_err());
    assert_eq!(ledger.checkpoint(), checkpoint);
}

#[test]
fn owned_worker_gate_survives_unwind_and_stays_bounded() {
    let gate = Arc::new(WorkerGate::new());
    let copy = Arc::clone(&gate);
    let unwind = std::panic::catch_unwind(move || {
        let _permit = copy.try_acquire_owned().unwrap();
        panic!("public fixture unwind");
    });
    assert!(unwind.is_err());
    let mut permits = (0..32)
        .map(|_| gate.try_acquire_owned().unwrap())
        .collect::<Vec<_>>();
    assert!(gate.try_acquire_owned().is_err());
    drop(permits.pop());
    let _replacement = gate.try_acquire_owned().unwrap();
}

#[test]
fn remote_plaintext_or_insecure_redis_is_not_an_enterprise_backend() {
    assert!(
        RedisIdempotency::new(
            "redis://203.0.113.1:6379",
            "test",
            8,
            std::time::Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        RedisIdempotency::new(
            "rediss://example.com:6379/#insecure",
            "test",
            8,
            std::time::Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        RedisIdempotency::new(
            "redis://127.0.0.1:6379",
            "bad:{namespace}",
            8,
            std::time::Duration::from_secs(1)
        )
        .is_err()
    );
}

#[test]
fn file_checkpoint_requires_monotonic_sequence_and_a_fresh_stream() {
    let directory = std::env::temp_dir().join(format!("nexus-audit-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("anchor.json");
    let sink = FileCheckpointSink::new(path.clone());
    let mut ledger = AuditLedger::try_new().unwrap();
    sink.store(&ledger.checkpoint(), &ledger.export_json())
        .unwrap();
    assert!(
        sink.store(&ledger.checkpoint(), &ledger.export_json())
            .is_err()
    );
    ledger.append(&event()).unwrap();
    sink.store(&ledger.checkpoint(), &ledger.export_json())
        .unwrap();
    assert!(verify_export(
        &std::fs::read_to_string(path.with_extension("audit.json")).unwrap(),
        &ledger.checkpoint()
    ));
    assert!(
        FileCheckpointSink::new(path.clone())
            .store(&ledger.checkpoint(), &ledger.export_json())
            .is_err()
    );
    std::fs::remove_file(path.with_extension("audit.json")).unwrap();
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
