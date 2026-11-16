//! Field pilot: one service account, one issue route, one provider create per key.

use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use nexus_ephemera::adapters::github::{
    CreateResult, FindResult, GithubIssuePolicy, IssuePost, IssueProvider,
};
use nexus_ephemera::enterprise::{AuditLedger, ReferenceIdempotency};
use nexus_ephemera::enterprise_runtime::HttpPayloadTransport;
use nexus_ephemera::field::{FieldPilot, FieldRequest, SERVICE_ACCOUNT};
use nexus_ephemera::ipc::IpcError;

const NOW: u64 = 1_700_000_000_000;
const BROKER_SECRET: &[u8] = b"field-broker-hmac-secret";
const GITHUB_TOKEN: &[u8] = b"ghp_field_token_value";
const ISSUES: &str = "https://api.github.com/repos/pilot-org/support-queue/issues";

#[test]
fn support_account_is_isolated_and_reconciles_without_a_second_provider_write() {
    let pilot = pilot();
    assert!(!format!("{pilot:?}").contains("ghp_field_token_value"));
    assert!(!format!("{pilot:?}").contains("field-broker-hmac-secret"));
    let claim = ReferenceIdempotency::new(32)
        .expect("store")
        .redis_claim_command(SERVICE_ACCOUNT, "field-1")
        .expect("claim");
    assert_eq!(
        claim,
        "SET nexus:idem:support_agent_service_account:field-1 pending NX"
    );

    let mut ledger = AuditLedger::try_new().expect("ledger");
    let mut provider = Script::success();
    for (method, endpoint) in [
        (
            "POST",
            "https://api.github.com/repos/pilot-org/secret-admin-repo/issues",
        ),
        ("DELETE", ISSUES),
        ("PUT", ISSUES),
    ] {
        let denied = pilot.execute(
            &mut provider,
            ask(method, endpoint, "Printer jam", "field-denied"),
            &mut ledger,
        );
        assert!(
            matches!(denied, Err(IpcError::TargetDenied)),
            "{method} {endpoint}"
        );
    }
    assert_eq!(provider.creates, 0);

    let opened = pilot
        .execute(
            &mut provider,
            ask("POST", ISSUES, "Printer jam", "field-1"),
            &mut ledger,
        )
        .expect("open");
    assert_eq!(opened.transport_status, 201);
    assert_eq!(opened.duplicate_status, None);
    assert_eq!(opened.seal_report, "retained");
    assert_eq!(provider.creates, 1);
    let replay = pilot
        .execute(
            &mut provider,
            ask("POST", ISSUES, "Printer jam", "field-1"),
            &mut ledger,
        )
        .expect("replay");
    assert_eq!(replay.duplicate_status, Some(409));
    assert_eq!(replay.binding_digest_hex, opened.binding_digest_hex);
    assert_eq!(replay.payload_hash, opened.payload_hash);
    assert_eq!(provider.creates, 1);
    assert!(matches!(
        pilot.execute(
            &mut provider,
            ask("POST", ISSUES, "Other title", "field-1"),
            &mut ledger
        ),
        Err(IpcError::IdempotencyConflict)
    ));
    assert_eq!(provider.creates, 1);

    let mut timed = Script::timeout_after_store();
    let reconciled = pilot
        .execute(
            &mut timed,
            ask("POST", ISSUES, "Printer jam", "field-timeout"),
            &mut ledger,
        )
        .expect("timeout reconcile");
    assert_eq!(reconciled.duplicate_status, Some(409));
    assert_eq!(timed.creates, 1);

    let mut failed = Script::server_after_store();
    let server = pilot
        .execute(
            &mut failed,
            ask("POST", ISSUES, "Printer jam", "field-5xx"),
            &mut ledger,
        )
        .expect("5xx reconcile");
    assert_eq!(server.duplicate_status, Some(409));
    assert_eq!(failed.creates, 1);

    let mut missing = Script::timeout_then_create();
    let retried = pilot
        .execute(
            &mut missing,
            ask("POST", ISSUES, "Printer jam", "field-retry"),
            &mut ledger,
        )
        .expect("one retry");
    assert_eq!(retried.duplicate_status, None);
    assert_eq!(missing.creates, 2);

    let mut unknown = Script::timeout_unavailable();
    assert!(matches!(
        pilot.execute(
            &mut unknown,
            ask("POST", ISSUES, "Printer jam", "field-unknown"),
            &mut ledger
        ),
        Err(IpcError::Inconclusive)
    ));
    assert_eq!(unknown.creates, 1);
    assert!(matches!(
        pilot.execute(
            &mut unknown,
            ask("POST", ISSUES, "Printer jam", "field-unknown"),
            &mut ledger
        ),
        Err(IpcError::Inconclusive)
    ));
    assert_eq!(unknown.creates, 1);

    assert!(ledger.verify());
    let exported = ledger.export_json();
    let trusted = ledger.checkpoint();
    assert!(nexus_ephemera::enterprise::verify_export(
        &exported, &trusted
    ));
    for kind in [
        "target_denied",
        "idempotency_conflict",
        "retained",
        "audit_v2",
    ] {
        assert!(exported.contains(&format!("\"kind\":\"{kind}\"")), "{kind}");
    }
    assert!(!exported.contains("ghp_field_token_value"));
    assert!(!exported.contains("field-broker-hmac-secret"));
    assert!(!exported.contains("The queue is stuck"));
    let tampered = exported.replacen("\"kind\":\"audit_v2\"", "\"kind\":\"receipt\"", 1);
    assert_ne!(tampered, exported);
    assert!(!nexus_ephemera::enterprise::verify_export(
        &tampered, &trusted
    ));
}

#[test]
fn concurrent_same_key_hits_the_provider_once_and_replays_409() {
    let pilot = Arc::new(pilot());
    let shared = Arc::new(Mutex::new(Script::success()));
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let pilot = Arc::clone(&pilot);
        let shared = Arc::clone(&shared);
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            barrier.wait();
            let mut provider = SharedScript(shared);
            let mut ledger = AuditLedger::try_new().expect("ledger");
            pilot.execute(
                &mut provider,
                ask("POST", ISSUES, "Printer jam", "field-race"),
                &mut ledger,
            )
        }));
    }
    for thread in threads {
        let outcome = thread.join().expect("join");
        assert!(outcome.is_ok() || matches!(outcome, Err(IpcError::Inconclusive)));
    }
    assert_eq!(shared.lock().expect("script").creates, 1);
    let mut provider = SharedScript(Arc::clone(&shared));
    let mut ledger = AuditLedger::try_new().expect("ledger");
    let cached = pilot
        .execute(
            &mut provider,
            ask("POST", ISSUES, "Printer jam", "field-race"),
            &mut ledger,
        )
        .expect("cached");
    assert_eq!(cached.duplicate_status, Some(409));
    assert_eq!(shared.lock().expect("script").creates, 1);
}

fn ask<'a>(method: &'a str, endpoint: &'a str, title: &'a str, key: &'a str) -> FieldRequest<'a> {
    FieldRequest {
        method,
        endpoint,
        title,
        body: "The queue is stuck",
        idempotency_key: key,
        now_unix_ms: NOW,
    }
}

fn pilot() -> FieldPilot {
    let policy = GithubIssuePolicy::load(include_bytes!("../policies/pilot_support_agent.json"))
        .expect("policy");
    let http = HttpPayloadTransport::new(Duration::from_secs(2)).expect("http");
    FieldPilot::new(BROKER_SECRET.to_vec(), &http, policy, GITHUB_TOKEN.to_vec()).expect("pilot")
}

struct SharedScript(Arc<Mutex<Script>>);

impl IssueProvider for SharedScript {
    fn create(&mut self, request: &IssuePost<'_>) -> CreateResult {
        self.0.lock().expect("script").create(request)
    }
    fn find(&mut self, idempotency_key: &str) -> FindResult {
        self.0.lock().expect("script").find(idempotency_key)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Success,
    TimeoutStored,
    ServerStored,
    TimeoutThenCreate,
    TimeoutUnavailable,
}

struct Script {
    mode: Mode,
    creates: usize,
    stored: bool,
}

impl Script {
    fn success() -> Self {
        Self {
            mode: Mode::Success,
            creates: 0,
            stored: false,
        }
    }
    fn timeout_after_store() -> Self {
        Self {
            mode: Mode::TimeoutStored,
            creates: 0,
            stored: false,
        }
    }
    fn server_after_store() -> Self {
        Self {
            mode: Mode::ServerStored,
            creates: 0,
            stored: false,
        }
    }
    fn timeout_then_create() -> Self {
        Self {
            mode: Mode::TimeoutThenCreate,
            creates: 0,
            stored: false,
        }
    }
    fn timeout_unavailable() -> Self {
        Self {
            mode: Mode::TimeoutUnavailable,
            creates: 0,
            stored: false,
        }
    }
}

impl IssueProvider for Script {
    fn create(&mut self, request: &IssuePost<'_>) -> CreateResult {
        if request.authorization != b"Bearer ghp_field_token_value" {
            return CreateResult::Rejected(401);
        }
        self.creates += 1;
        match self.mode {
            Mode::Success => {
                self.stored = true;
                CreateResult::Created(201)
            }
            Mode::TimeoutStored | Mode::TimeoutUnavailable => {
                self.stored = self.mode == Mode::TimeoutStored;
                CreateResult::TimedOut
            }
            Mode::ServerStored => {
                self.stored = true;
                CreateResult::ServerError(503)
            }
            Mode::TimeoutThenCreate if self.creates == 1 => CreateResult::TimedOut,
            Mode::TimeoutThenCreate => {
                self.stored = true;
                CreateResult::Created(201)
            }
        }
    }

    fn find(&mut self, _idempotency_key: &str) -> FindResult {
        match self.mode {
            Mode::TimeoutUnavailable => FindResult::Unavailable,
            _ if self.stored => FindResult::Found(201),
            _ => FindResult::Missing,
        }
    }
}
