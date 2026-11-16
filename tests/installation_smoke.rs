//! Clean package install, health query, and the first support-agent issue.

use std::fs;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use nexus_ephemera::adapters::github::{
    CreateResult, FindResult, GithubIssueTransport, IssuePost, IssueProvider,
};
use nexus_ephemera::enterprise::AuditLedger;
use nexus_ephemera::enterprise_runtime::HttpPayloadTransport;
use nexus_ephemera::ipc::{
    BrokerDaemon, DaemonConfig, HealthReport, IpcError, LocalAcceptTransport, NexusClient,
};
use nexus_ephemera::packaging::{self, policy_tag};

#[test]
fn clean_install_serves_health_and_opens_one_issue() {
    let root = std::env::temp_dir().join(format!("nexus-pkg-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let package = root.join("package");
    let runtime_dir = root.join("run");
    fs::create_dir_all(&runtime_dir).expect("runtime dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700)).expect("0700");
    }
    let listen = listen_path(&runtime_dir);
    packaging::write_template(
        &package,
        &listen,
        include_bytes!("../policies/pilot_support_agent.json"),
    )
    .expect("template");
    loosen(&package);
    assert!(
        packaging::load(&package).is_err(),
        "loose package must fail closed"
    );
    packaging::seal(&package).expect("seal");
    let loaded = packaging::load(&package).expect("sealed package");
    assert_eq!(
        loaded.allow(),
        "https://api.github.com/repos/pilot-org/support-queue/issues"
    );
    let mut broken = fs::read(package.join("policy.hmac")).expect("hmac");
    broken[..2].copy_from_slice(b"00");
    fs::write(package.join("policy.hmac"), &broken).expect("tamper");
    assert!(
        packaging::load(&package).is_err(),
        "tampered hmac must fail closed"
    );
    packaging::seal(&package).expect("reseal");
    let loaded = packaging::load(&package).expect("resealed package");

    let degraded = nexus_ephemera::ipc::rollup_health(true, 32, true, true, "degraded");
    assert_eq!(degraded.status, "degraded");
    assert_eq!(degraded.worker_capacity, 32);
    let down = nexus_ephemera::ipc::rollup_health(true, 0, true, true, "unhealthy");
    assert_eq!(down.status, "unhealthy");

    let report = serve_health(&listen, loaded.watch());
    assert_eq!(report.status, "healthy");
    assert!(report.ipc_listening);
    assert!(report.policy_intact);
    assert!(report.hmac_ready);
    assert_eq!(report.idempotency, "local");
    assert_eq!(report.worker_occupied, 0);
    assert_eq!(report.worker_capacity, 32);
    assert!(!format!("{report:?}").contains("hmac.key"));

    let http = HttpPayloadTransport::new(Duration::from_secs(2)).expect("http");
    let transport = GithubIssueTransport::from_http(
        &http,
        policy_from(&package),
        b"ghp_install_token".to_vec(),
    )
    .expect("transport");
    let mut provider = Script { creates: 0 };
    let mut ledger = AuditLedger::try_new().expect("ledger");
    let receipt = transport
        .open_issue(
            &mut provider,
            "Printer jam",
            "The queue is stuck",
            "install-1",
            &mut ledger,
        )
        .expect("issue");
    assert_eq!(receipt.transport_status, 201);
    assert_eq!(provider.creates, 1);
    let replay = transport
        .open_issue(
            &mut provider,
            "Printer jam",
            "The queue is stuck",
            "install-1",
            &mut ledger,
        )
        .expect("replay");
    assert_eq!(replay.duplicate_status, Some(409));
    assert_eq!(provider.creates, 1);
    assert!(!ledger.export_json().contains("ghp_install_token"));
    let _ = fs::remove_dir_all(&root);
}

fn serve_health(
    listen: &str,
    source: std::sync::Arc<dyn nexus_ephemera::ipc::HealthSource>,
) -> HealthReport {
    let listen_for_server = listen.to_string();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("server runtime");
        let outcome = runtime.block_on(async move {
            let mut secret = b"install-smoke-broker-secret".to_vec();
            let mut daemon = BrokerDaemon::bind(
                DaemonConfig {
                    listen: listen_for_server,
                    allowlist: vec![
                        "https://api.github.com/repos/pilot-org/support-queue/issues".to_string(),
                    ],
                    max_payload_bytes: 4096,
                    timeout: Duration::from_secs(5),
                    idempotency_ttl: Duration::from_secs(60),
                    single_use: false,
                },
                &mut secret,
                LocalAcceptTransport,
            )
            .await
            .expect("bind");
            daemon.set_health_source(source);
            ready_tx.send(()).expect("ready");
            let served = daemon.serve_one().await;
            let seal = daemon.shutdown();
            (served, seal)
        });
        done_tx.send(outcome).expect("done");
    });
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("daemon did not bind");
    let client = NexusClient::new(listen, Duration::from_secs(5), 4096).expect("client");
    let client_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("client runtime");
    let report = client_runtime.block_on(client.health()).expect("health");
    let (served, seal) = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server");
    served.expect("served");
    seal.expect("seal");
    server.join().expect("join");
    report
}

fn policy_from(package: &std::path::Path) -> nexus_ephemera::adapters::github::GithubIssuePolicy {
    nexus_ephemera::adapters::github::GithubIssuePolicy::load(
        &fs::read(package.join("pilot_support_agent.json")).expect("policy"),
    )
    .expect("policy")
}

fn listen_path(runtime_dir: &std::path::Path) -> String {
    #[cfg(unix)]
    {
        runtime_dir.join("broker.sock").display().to_string()
    }
    #[cfg(windows)]
    {
        let _ = runtime_dir;
        format!(r"\\.\pipe\nexus-ephemera-pkg-{}", std::process::id())
    }
}

fn loosen(package: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["config.toml", ".env", "pilot_support_agent.json"] {
            fs::set_permissions(package.join(name), fs::Permissions::from_mode(0o644))
                .expect("loosen");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = package;
    }
}

struct Script {
    creates: usize,
}

impl IssueProvider for Script {
    fn create(&mut self, request: &IssuePost<'_>) -> CreateResult {
        assert!(request.authorization.starts_with(b"Bearer "));
        self.creates += 1;
        CreateResult::Created(201)
    }

    fn find(&mut self, _idempotency_key: &str) -> FindResult {
        FindResult::Missing
    }
}

#[test]
fn missing_package_field_fails_before_start() {
    let directory = std::env::temp_dir().join(format!("nexus-pkg-missing-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("dir");
    assert!(matches!(
        packaging::load(&directory),
        Err(IpcError::Protocol(_)) | Err(IpcError::Io(_))
    ));
    let key = [7u8; 32];
    let tag = policy_tag(&key, b"{}").expect("tag");
    assert_eq!(tag.len(), 32);
    let _ = fs::remove_dir_all(&directory);
}
