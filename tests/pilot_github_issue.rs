//! Support-agent pilot: one GitHub issue route, no token leakage, no second create.

use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nexus_ephemera::adapters::github::{
    CreateResult, FindResult, GithubIssuePolicy, GithubIssueTransport, IssuePost, IssueProvider,
};
use nexus_ephemera::crypto::{sign_request_header, verify_request_header};
use nexus_ephemera::enterprise::AuditLedger;
use nexus_ephemera::enterprise_runtime::HttpPayloadTransport;
use nexus_ephemera::ipc::IpcError;

const TOKEN: &[u8] = b"ghp_pilot_token_value";
const HMAC: &[u8] = b"broker-hmac-secret";

#[test]
fn support_agent_opens_one_issue_and_reconciles_without_a_second_create() {
    let policy = GithubIssuePolicy::load(include_bytes!("../policies/pilot_support_agent.json"))
        .expect("policy");
    assert_eq!(
        policy.endpoint(),
        "https://api.github.com/repos/pilot-org/support-queue/issues"
    );
    let http = HttpPayloadTransport::new(Duration::from_secs(2)).expect("http");
    let transport =
        GithubIssueTransport::from_http(&http, policy, TOKEN.to_vec()).expect("transport");
    assert_eq!(transport.timeout(), Duration::from_secs(2));
    let shown = format!("{transport:?}");
    assert!(!shown.contains("ghp_pilot_token_value"));

    let prepared = transport
        .prepare("Printer jam", "The queue is stuck", "issue-1")
        .expect("prepare");
    assert_eq!(prepared.method, "POST");
    assert_eq!(prepared.accept, "application/vnd.github+json");
    assert_eq!(prepared.api_version, "2022-11-28");
    assert!(
        prepared
            .body
            .windows(b"\"title\"".len())
            .any(|window| window == b"\"title\"")
    );
    assert!(
        std::str::from_utf8(&prepared.body)
            .unwrap()
            .contains("nexus-idempotency:issue-1")
    );
    let now = unix_ms();
    let header = sign_request_header(
        HMAC,
        now,
        "issue-1",
        &prepared.payload_hash,
        &prepared.endpoint,
    );
    verify_request_header(
        HMAC,
        &header,
        "issue-1",
        &prepared.payload_hash,
        &prepared.endpoint,
        now,
    )
    .expect("fresh hmac");
    assert!(
        verify_request_header(
            HMAC,
            &header,
            "issue-1",
            &prepared.payload_hash,
            &prepared.endpoint,
            now + 5_001,
        )
        .is_err()
    );
    assert!(!header.contains("ghp_pilot_token_value"));

    let mut ledger = AuditLedger::try_new().expect("ledger");
    let mut provider = Script::success();
    let first = transport
        .open_issue(
            &mut provider,
            "Printer jam",
            "The queue is stuck",
            "issue-1",
            &mut ledger,
        )
        .expect("open");
    assert_eq!(first.transport_status, 201);
    assert_eq!(first.seal_report, "retained");
    assert_eq!(first.duplicate_status, None);
    assert_eq!(provider.creates, 1);
    let second = transport
        .open_issue(
            &mut provider,
            "Printer jam",
            "The queue is stuck",
            "issue-1",
            &mut ledger,
        )
        .expect("replay");
    assert_eq!(second.duplicate_status, Some(409));
    assert_eq!(second.binding_digest_hex, first.binding_digest_hex);
    assert_eq!(second.payload_hash, first.payload_hash);
    assert_eq!(provider.creates, 1);
    assert!(ledger.verify());
    let exported = ledger.export_json();
    assert!(exported.contains("\"kind\":\"audit_v2\""));
    assert!(!exported.contains("ghp_pilot_token_value"));
    assert!(!exported.contains("broker-hmac-secret"));

    let mut extra = std::collections::BTreeMap::from([
        ("title".to_string(), "Printer jam".to_string()),
        ("body".to_string(), "The queue is stuck".to_string()),
        ("token".to_string(), "ghp_pilot_token_value".to_string()),
    ]);
    assert!(matches!(
        transport.open_fields(&mut provider, &extra, "issue-extra", &mut ledger),
        Err(IpcError::Malformed)
    ));
    extra.remove("token");
    assert_eq!(provider.creates, 1);

    for denied in [
        "https://api.github.com/orgs/pilot-org/transfers",
        "https://api.github.com/repos/pilot-org/support-queue/contents/README.md",
        "https://api.github.com/repos/pilot-org/support-queue/actions",
        "https://api.github.com/repos/pilot-org/support-queue/issues?x=1",
    ] {
        assert!(
            matches!(
                transport.reject_target(denied, &mut ledger),
                Err(IpcError::TargetDenied)
            ),
            "{denied}"
        );
    }
    assert_eq!(provider.creates, 1);

    let mut timed_out = Script::timeout_after_store();
    let reconciled = transport
        .open_issue(
            &mut timed_out,
            "Printer jam",
            "The queue is stuck",
            "issue-timeout",
            &mut ledger,
        )
        .expect("reconcile");
    assert_eq!(reconciled.duplicate_status, Some(409));
    assert_eq!(timed_out.creates, 1);

    let mut missing = Script::timeout_then_create();
    let retried = transport
        .open_issue(
            &mut missing,
            "Printer jam",
            "The queue is stuck",
            "issue-retry",
            &mut ledger,
        )
        .expect("retry");
    assert_eq!(retried.duplicate_status, None);
    assert_eq!(retried.transport_status, 201);
    assert_eq!(missing.creates, 2);
    let again = transport
        .open_issue(
            &mut missing,
            "Printer jam",
            "The queue is stuck",
            "issue-retry",
            &mut ledger,
        )
        .expect("cached after retry");
    assert_eq!(again.duplicate_status, Some(409));
    assert_eq!(missing.creates, 2);

    let transport = Arc::new(transport);
    let shared = Arc::new(Mutex::new(Script::success()));
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let transport = Arc::clone(&transport);
        let shared = Arc::clone(&shared);
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            barrier.wait();
            let mut provider = SharedScript(shared);
            let mut local = AuditLedger::try_new().expect("ledger");
            transport.open_issue(
                &mut provider,
                "Printer jam",
                "The queue is stuck",
                "issue-race",
                &mut local,
            )
        }));
    }
    for thread in threads {
        let outcome = thread.join().expect("join");
        assert!(outcome.is_ok() || matches!(outcome, Err(IpcError::Inconclusive)));
    }
    assert_eq!(shared.lock().expect("script").creates, 1);
    let mut provider = SharedScript(Arc::clone(&shared));
    let cached = transport
        .open_issue(
            &mut provider,
            "Printer jam",
            "The queue is stuck",
            "issue-race",
            &mut ledger,
        )
        .expect("race cache");
    assert_eq!(cached.duplicate_status, Some(409));
    assert_eq!(shared.lock().expect("script").creates, 1);
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

#[derive(Clone, Copy)]
enum ScriptMode {
    Success,
    TimeoutAfterStore,
    TimeoutThenCreate,
}

struct Script {
    mode: ScriptMode,
    creates: usize,
    stored: bool,
}

impl Script {
    fn success() -> Self {
        Self {
            mode: ScriptMode::Success,
            creates: 0,
            stored: false,
        }
    }
    fn timeout_after_store() -> Self {
        Self {
            mode: ScriptMode::TimeoutAfterStore,
            creates: 0,
            stored: false,
        }
    }
    fn timeout_then_create() -> Self {
        Self {
            mode: ScriptMode::TimeoutThenCreate,
            creates: 0,
            stored: false,
        }
    }
}

impl IssueProvider for Script {
    fn create(&mut self, request: &IssuePost<'_>) -> CreateResult {
        if request.authorization != b"Bearer ghp_pilot_token_value" {
            return CreateResult::Rejected(401);
        }
        self.creates += 1;
        match self.mode {
            ScriptMode::Success => {
                self.stored = true;
                CreateResult::Created(201)
            }
            ScriptMode::TimeoutAfterStore => {
                self.stored = true;
                CreateResult::TimedOut
            }
            ScriptMode::TimeoutThenCreate if self.creates == 1 => CreateResult::TimedOut,
            ScriptMode::TimeoutThenCreate => {
                self.stored = true;
                CreateResult::Created(201)
            }
        }
    }

    fn find(&mut self, _idempotency_key: &str) -> FindResult {
        if self.stored {
            FindResult::Found(201)
        } else {
            FindResult::Missing
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
