//! Day-2 drills: key grace, worker shed, quarantine, sink and store failure.

use std::time::Duration;

use nexus_ephemera::crypto::sign_request_header;
use nexus_ephemera::enterprise::{
    AuditEvent, AuditKind, AuditLedger, ServiceAccount, TenantDirectory, WORKER_CAP, WorkerGate,
    verify_export,
};
use nexus_ephemera::ipc::IpcError;
use nexus_ephemera::operations::{
    KeyRing, TenantQuarantine, close_store_outage, dispatch_after_sink, shed_status, telemetry,
};

const NOW: u64 = 1_700_000_000_000;
const OLD: &[u8] = b"operations-broker-secret-v1";
const NEW: &[u8] = b"operations-broker-secret-v2";
const CHARGE: &str = "https://provider.example/charge";
const TOKEN: &str = "ghp_operations_token_value";
const BODY: &str = "The queue is stuck";

#[test]
fn operations_drills_rotate_shed_quarantine_and_keep_exports_closed() {
    let mut ring = KeyRing::new(OLD.to_vec()).expect("ring");
    let old_header = ring
        .sign_request(NOW, "idem-rotate", "sha256:payload", CHARGE)
        .expect("active key");
    ring.rotate(NEW.to_vec(), NOW, Duration::from_secs(10))
        .expect("rotate");
    let new_header = ring
        .sign_request(NOW, "idem-rotate", "sha256:payload", CHARGE)
        .expect("active key");
    assert!(
        ring.verify_request(
            &old_header,
            "idem-rotate",
            "sha256:payload",
            CHARGE,
            NOW + 1_000
        )
        .is_ok()
    );
    assert!(
        ring.verify_request(
            &new_header,
            "idem-rotate",
            "sha256:payload",
            CHARGE,
            NOW + 1_000
        )
        .is_ok()
    );
    assert!(matches!(
        ring.verify_request(
            &old_header,
            "idem-rotate",
            "sha256:payload",
            CHARGE,
            NOW + 10_001
        ),
        Err(IpcError::TargetDenied)
    ));
    let forged = sign_request_header(
        b"unauthorized-key",
        NOW,
        "idem-rotate",
        "sha256:payload",
        CHARGE,
    );
    let empty_key_forgery = sign_request_header(b"", NOW, "idem-rotate", "sha256:payload", CHARGE);
    assert!(
        ring.verify_request(
            &empty_key_forgery,
            "idem-rotate",
            "sha256:payload",
            CHARGE,
            NOW
        )
        .is_err(),
        "clock rollback cannot resurrect a wiped retired key as an empty key"
    );
    assert!(matches!(
        ring.verify_request(
            &forged,
            "idem-rotate",
            "sha256:payload",
            CHARGE,
            NOW + 1_000
        ),
        Err(IpcError::TargetDenied)
    ));
    let stale = ring
        .sign_request(NOW - 30_000, "idem-rotate", "sha256:payload", CHARGE)
        .expect("active key");
    assert!(matches!(
        ring.verify_request(&stale, "idem-rotate", "sha256:payload", CHARGE, NOW + 1_000),
        Err(IpcError::TargetDenied)
    ));
    let mut immediate = KeyRing::new(OLD.to_vec()).expect("immediate");
    let retired = immediate
        .sign_request(NOW, "idem-rotate", "sha256:payload", CHARGE)
        .expect("active key");
    immediate
        .rotate(NEW.to_vec(), NOW, Duration::ZERO)
        .expect("rotate without grace");
    assert!(matches!(
        immediate.verify_request(&retired, "idem-rotate", "sha256:payload", CHARGE, NOW),
        Err(IpcError::TargetDenied)
    ));
    assert!(!format!("{ring:?}").contains("operations-broker-secret"));

    let directory = directory();
    let mut tokens = KeyRing::new(OLD.to_vec()).expect("tenant ring");
    let old_token = tokens
        .issue_token(&directory, "billing", "charge", NOW + 60_000, NOW)
        .expect("old token");
    tokens
        .rotate(NEW.to_vec(), NOW, Duration::from_secs(10))
        .expect("rotate tenant key");
    assert!(
        tokens
            .authorize_token(&directory, &old_token, "billing", CHARGE, NOW + 1_000)
            .is_ok()
    );
    let fresh = tokens
        .issue_token(&directory, "billing", "charge", NOW + 60_000, NOW + 1_000)
        .expect("fresh token");
    assert!(
        tokens
            .authorize_token(&directory, &fresh, "billing", CHARGE, NOW + 1_000)
            .is_ok()
    );
    assert!(matches!(
        tokens.authorize_token(&directory, &old_token, "billing", CHARGE, NOW + 10_001),
        Err(IpcError::TargetDenied)
    ));
    assert!(matches!(
        tokens.authorize_token(&directory, &fresh, "billing", CHARGE, NOW + 120_000),
        Err(IpcError::TargetDenied)
    ));
    assert!(!old_token.contains("operations-broker-secret"));
    assert!(!fresh.contains("operations-broker-secret"));

    let gate = WorkerGate::new();
    let mut permits = Vec::new();
    for _ in 0..WORKER_CAP {
        permits.push(gate.try_acquire().expect("slot"));
    }
    let Err(shed) = gate.try_acquire() else {
        panic!("33rd worker was admitted");
    };
    assert_eq!(shed_status(&shed), Some(503));
    assert_eq!(format!("{shed}"), "ipc: principal rate limit");
    drop(permits.pop());
    assert!(gate.try_acquire().is_ok());
    drop(permits);

    let quarantine = TenantQuarantine::new(3, Duration::from_secs(30)).expect("quarantine");
    for _ in 0..2 {
        quarantine.record_denial("billing", NOW).expect("denial");
        quarantine.ensure("billing", NOW).expect("still admitted");
    }
    quarantine.record_denial("billing", NOW).expect("threshold");
    assert!(matches!(
        quarantine.ensure("billing", NOW + 1_000),
        Err(IpcError::TargetDenied)
    ));
    quarantine
        .ensure("billing", NOW + 30_000)
        .expect("block expired");

    let outage = close_store_outage(IpcError::IdempotencyUnavailable);
    assert!(matches!(outage, IpcError::Inconclusive));
    let rendered = format!("{outage}");
    assert_eq!(rendered, "ipc: provider outcome is inconclusive");
    assert!(!rendered.contains("redis://"));
    assert!(!rendered.contains(TOKEN));

    let mut hits = 0u64;
    let blocked = dispatch_after_sink(Err(IpcError::Protocol("audit sink is full")), &mut hits);
    assert!(blocked.is_err());
    assert_eq!(hits, 0);
    dispatch_after_sink(Ok(()), &mut hits).expect("sink accepted");
    assert_eq!(hits, 1);

    let mut ledger = AuditLedger::try_new().expect("ledger");
    ledger
        .append(&AuditEvent {
            kind: AuditKind::Retained,
            service_account_id: "billing".into(),
            endpoint: CHARGE.into(),
            payload_hash: "sha256:payload".into(),
            idempotency_key: "idem-rotate".into(),
            seal_report: "retained".into(),
            binding_digest_hex: "ab".repeat(32),
            transport_status: 204,
        })
        .expect("append");
    let bundle = telemetry(&ledger);
    assert!(verify_export(&bundle.export, &ledger.checkpoint()));
    assert_eq!(bundle.records, 1);
    assert!(bundle.export.contains(&bundle.merkle_root_hex));
    assert!(bundle.export.contains("\"kind\":\"retained\""));
    assert!(!bundle.export.contains("operations-broker-secret"));
    assert!(!bundle.export.contains(TOKEN));
    assert!(!bundle.export.contains(BODY));
    let tampered = bundle.export.replacen("retained", "receipt", 1);
    assert!(!verify_export(&tampered, &ledger.checkpoint()));
}

fn directory() -> TenantDirectory {
    TenantDirectory::try_new(vec![ServiceAccount {
        id: "billing".into(),
        roles: vec!["charge".into()],
        attributes: Vec::new(),
        allowlist: vec![CHARGE.into()],
        role_endpoints: Default::default(),
        role_params: Default::default(),
    }])
    .expect("directory")
}
