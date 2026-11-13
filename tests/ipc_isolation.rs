//! Daemon isolation: the client process never admits the key.

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use nexus_ephemera::broker::{
    AuthorizedCall, BrokerError, SealReport, SecureTransport, TransactionReceipt, TransportReply,
};
use nexus_ephemera::ipc::{
    BrokerDaemon, DaemonConfig, IpcError, LocalAcceptTransport, NexusClient, client_outcome,
    peer_is_authorized,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::process::Command;

static GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static LISTEN_SEQ: AtomicU64 = AtomicU64::new(0);
const SECRET: &[u8] = b"ipc-isolation-secret";
const ALLOWED: &str = "https://provider.example/charge";
const PREFIX: &str = "https://provider.example/charge/extra";

#[test]
fn peer_policy_and_cleanup_stay_closed() {
    assert!(peer_is_authorized(4, Some(9), 4).is_ok());
    assert!(matches!(
        peer_is_authorized(4, Some(9), 5),
        Err(IpcError::IdentityRejected)
    ));
    assert!(matches!(
        peer_is_authorized(4, None, 4),
        Err(IpcError::IdentityUnavailable)
    ));
    assert!(matches!(
        peer_is_authorized(4, Some(0), 4),
        Err(IpcError::IdentityUnavailable)
    ));
    let err = client_outcome(Err(BrokerError::CleanupIncomplete(sample(
        SealReport::Partial,
    ))))
    .unwrap_err();
    let shown = err.to_string();
    assert!(matches!(
        err,
        IpcError::CleanupIncomplete(ref receipt) if receipt.seal_report == SealReport::Partial
    ));
    assert!(!shown.contains("ab"));
    assert!(client_outcome(Ok(sample(SealReport::Failed))).is_err());
}

#[tokio::test]
async fn subprocess_allowlist_checks_the_parent_pid() {
    let listen = unique_listen();
    let mut child = Command::new(daemon_exe())
        .arg("--listen")
        .arg(&listen)
        .arg("--allow")
        .arg(ALLOWED)
        .arg("--max-payload")
        .arg("1024")
        .arg("--timeout-ms")
        .arg("2000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn daemon");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(SECRET).await.expect("write secret");
    }
    let mut stdout = tokio::io::BufReader::new(child.stdout.take().expect("stdout"));
    let mut ready = String::new();
    tokio::time::timeout(Duration::from_secs(20), stdout.read_line(&mut ready))
        .await
        .expect("daemon ready timeout")
        .expect("read ready");
    assert_eq!(ready.trim(), "ready", "daemon did not become ready");

    let client = NexusClient::new(&listen, Duration::from_secs(5), 1024).unwrap();
    let receipt = client
        .execute(ALLOWED, "payload-hash", "subprocess-allow")
        .await
        .expect("allowed call");
    assert_eq!(receipt.seal_report, SealReport::Retained);
    assert_eq!(receipt.transport_status, 204);
    assert_eq!(receipt.binding_digest_hex.len(), 64);
    assert!(!receipt.binding_digest_hex.contains("ipc-isolation-secret"));
    assert_secret_absent(&receipt);

    let denied = client
        .execute(PREFIX, "payload-hash", "subprocess-deny")
        .await
        .unwrap_err();
    assert!(
        matches!(denied, IpcError::TargetDenied),
        "prefix denial was {denied}"
    );
    assert!(!denied.to_string().contains("ipc-isolation-secret"));

    let _ = child.start_kill();
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("daemon did not exit")
        .expect("wait");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("ipc-isolation-secret"),
        "daemon stderr leaked the secret"
    );
    let needle = format!("peer_ok pid={}", std::process::id());
    assert!(
        stderr.contains(&needle),
        "daemon did not record the caller pid"
    );
    #[cfg(unix)]
    let _ = std::fs::remove_file(&listen);
}

#[tokio::test]
async fn daemon_binds_inside_the_runtime_and_prints_ready() {
    let listen = unique_listen();
    let mut child = Command::new(daemon_exe())
        .arg("--listen")
        .arg(&listen)
        .arg("--allow")
        .arg(ALLOWED)
        .arg("--timeout-ms")
        .arg("5000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn daemon");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(SECRET).await.expect("write secret");
    }
    let mut stdout = tokio::io::BufReader::new(child.stdout.take().expect("stdout"));
    let mut ready = String::new();
    tokio::time::timeout(Duration::from_secs(20), stdout.read_line(&mut ready))
        .await
        .expect("daemon ready timeout")
        .expect("read ready");
    assert_eq!(ready.trim(), "ready");
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "daemon exited after ready"
    );
    let client = NexusClient::new(&listen, Duration::from_secs(5), 1024).unwrap();
    let receipt = client
        .execute(ALLOWED, "payload-hash", "runtime-ready")
        .await
        .expect("call after ready");
    assert_eq!(receipt.seal_report, SealReport::Retained);
    assert_secret_absent(&receipt);
    let _ = child.start_kill();
    let _ = child.wait().await;
    #[cfg(unix)]
    let _ = std::fs::remove_file(&listen);
}

#[tokio::test]
async fn daemon_stdin_timeout_joins_before_ready() {
    let listen = unique_listen();
    let mut child = Command::new(daemon_exe())
        .arg("--listen")
        .arg(&listen)
        .arg("--allow")
        .arg(ALLOWED)
        .arg("--timeout-ms")
        .arg("200")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn daemon");
    let _stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");
    let finished = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
    let status = finished
        .expect("daemon stdin read stayed blocked")
        .expect("wait");
    assert!(!status.success(), "open stdin was accepted");
    let mut out = String::new();
    let _ = tokio::io::AsyncReadExt::read_to_string(&mut stdout, &mut out).await;
    assert!(!out.contains("ready"), "daemon printed ready without a key");
    drop(_stdin);
}

#[tokio::test]
async fn stalled_and_oversized_frames_are_rejected_before_use() {
    let _guard = GATE.lock().await;
    let listen = unique_listen();
    let mut secret = SECRET.to_vec();
    let mut daemon =
        BrokerDaemon::bind(test_config(&listen, 200), &mut secret, LocalAcceptTransport)
            .await
            .expect("bind");
    assert!(secret.iter().all(|byte| *byte == 0));

    let listen_hold = listen.clone();
    let held = tokio::spawn(async move {
        let mut stream = open_raw(&listen_hold).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = stream.shutdown().await;
    });
    let started = Instant::now();
    let err = daemon.serve_one().await.expect_err("stall");
    let elapsed = started.elapsed();
    assert!(matches!(err, IpcError::TimedOut));
    assert!(elapsed >= Duration::from_millis(150));
    assert!(elapsed < Duration::from_secs(2));
    held.abort();
    let _ = held.await;

    let listen_huge = listen.clone();
    let huge = tokio::spawn(async move {
        let mut stream = open_raw(&listen_huge).await;
        let _ = stream.write_all(&u32::MAX.to_le_bytes()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = stream.shutdown().await;
    });
    let err = daemon.serve_one().await.expect_err("oversize");
    assert!(
        matches!(err, IpcError::PayloadTooLarge { .. }),
        "oversize rejection was {err}"
    );
    huge.abort();

    let denied = tokio::spawn({
        let listen = listen.clone();
        async move {
            let client = NexusClient::new(listen, Duration::from_secs(3), 1024).unwrap();
            client.execute(PREFIX, "payload-hash", "stall-deny").await
        }
    });
    let err = daemon.serve_one().await.expect_err("prefix");
    assert!(matches!(err, IpcError::TargetDenied));
    assert!(matches!(denied.await.unwrap(), Err(IpcError::TargetDenied)));

    let allowed = tokio::spawn({
        let listen = listen.clone();
        async move {
            let client = NexusClient::new(listen, Duration::from_secs(3), 1024).unwrap();
            client.execute(ALLOWED, "payload-hash", "stall-allow").await
        }
    });
    let served = daemon.serve_one().await.expect("allowed");
    let nexus_ephemera::ipc::ServedCall::Call { peer_pid, receipt } = served else {
        panic!("expected a call result");
    };
    assert_eq!(peer_pid, std::process::id());
    assert_eq!(receipt.seal_report, SealReport::Retained);
    let receipt = allowed.await.unwrap().expect("client receipt");
    assert_secret_absent(&receipt);
}

#[tokio::test]
async fn duplicate_idempotency_key_does_not_dispatch_again() {
    let _guard = GATE.lock().await;
    let listen = unique_listen();
    let mut secret = SECRET.to_vec();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut daemon = BrokerDaemon::bind(
        test_config(&listen, 2_000),
        &mut secret,
        CountingTransport {
            calls: Arc::clone(&calls),
        },
    )
    .await
    .expect("bind");
    assert!(secret.iter().all(|byte| *byte == 0));

    let first_task = tokio::spawn({
        let listen = listen.clone();
        async move {
            NexusClient::new(listen, Duration::from_secs(3), 1024)
                .unwrap()
                .execute(ALLOWED, "hash-a", "idem-1")
                .await
        }
    });
    let first_served = daemon.serve_one().await.expect("first");
    let first = first_task.await.unwrap().expect("first receipt");
    let nexus_ephemera::ipc::ServedCall::Call { receipt, .. } = first_served else {
        panic!("expected a call");
    };
    assert_eq!(receipt.binding_digest_hex, first.binding_digest_hex);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let replay_task = tokio::spawn({
        let listen = listen.clone();
        async move {
            NexusClient::new(listen, Duration::from_secs(3), 1024)
                .unwrap()
                .execute(ALLOWED, "hash-a", "idem-1")
                .await
        }
    });
    let _ = daemon.serve_one().await.expect("replay");
    let replay = replay_task.await.unwrap().expect("replay receipt");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(replay.binding_digest_hex, first.binding_digest_hex);
    assert_eq!(replay.idempotency_key, "idem-1");
    assert!(!replay.binding_digest_hex.contains("ipc-isolation-secret"));

    let conflict_task = tokio::spawn({
        let listen = listen.clone();
        async move {
            NexusClient::new(listen, Duration::from_secs(3), 1024)
                .unwrap()
                .execute(ALLOWED, "hash-b", "idem-1")
                .await
        }
    });
    let conflict = daemon.serve_one().await.expect_err("conflict");
    assert!(matches!(conflict, IpcError::IdempotencyConflict));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let client_conflict = conflict_task.await.unwrap().expect_err("client conflict");
    assert!(matches!(client_conflict, IpcError::IdempotencyConflict));
    assert!(!client_conflict.to_string().contains("ipc-isolation-secret"));

    let metrics_task = tokio::spawn({
        let listen = listen.clone();
        async move {
            NexusClient::new(listen, Duration::from_secs(3), 1024)
                .unwrap()
                .metrics()
                .await
        }
    });
    let served = daemon.serve_one().await.expect("metrics");
    assert!(matches!(
        served,
        nexus_ephemera::ipc::ServedCall::Metrics { .. }
    ));
    let snapshot = metrics_task.await.unwrap().expect("snapshot");
    let text = snapshot.to_string();
    assert!(text.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || ch == '_' || ch == '=' || ch.is_ascii_whitespace()
    }));
    assert!(!text.contains("ipc-isolation-secret"));
    assert!(!text.contains(&first.binding_digest_hex));
    assert!(snapshot.cleanup_incomplete_rate <= 1000);
}

struct CountingTransport {
    calls: Arc<AtomicUsize>,
}

impl SecureTransport for CountingTransport {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        assert!(!call.binding_digest_hex.contains("ipc-isolation-secret"));
        assert_eq!(call.idempotency_key, "idem-1");
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(TransportReply { status: 204 })
    }
}

fn daemon_exe() -> std::path::PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_nexus_daemon") {
        return std::path::PathBuf::from(path);
    }
    let mut path = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push(if cfg!(windows) {
        "nexus-daemon.exe"
    } else {
        "nexus-daemon"
    });
    path
}

fn test_config(listen: &str, timeout_ms: u64) -> DaemonConfig {
    DaemonConfig {
        listen: listen.to_string(),
        allowlist: vec![ALLOWED.to_string()],
        max_payload_bytes: 1024,
        timeout: Duration::from_millis(timeout_ms),
        idempotency_ttl: Duration::from_secs(60),
        single_use: false,
    }
}

fn unique_listen() -> String {
    let n = LISTEN_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    #[cfg(unix)]
    {
        std::env::temp_dir()
            .join(format!("nexus-ephemera-{pid}-{n}.sock"))
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\nexus-ephemera-{pid}-{n}")
    }
}

fn sample(seal_report: SealReport) -> TransactionReceipt {
    TransactionReceipt {
        target_endpoint: ALLOWED.into(),
        payload_hash: "hash".into(),
        binding_digest_hex: "ab".into(),
        transport_status: 200,
        seal_report,
        idempotency_key: "sample-key".into(),
    }
}

fn assert_secret_absent(receipt: &TransactionReceipt) {
    assert!(!receipt.target_endpoint.contains("ipc-isolation-secret"));
    assert!(!receipt.payload_hash.contains("ipc-isolation-secret"));
    assert!(!receipt.binding_digest_hex.contains("ipc-isolation-secret"));
}

async fn open_raw(listen: &str) -> RawPipe {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match connect_raw(listen).await {
            Ok(stream) => return stream,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(err) => panic!("raw connect failed: {err}"),
        }
    }
}

#[cfg(unix)]
type RawPipe = tokio::net::UnixStream;

#[cfg(windows)]
type RawPipe = tokio::net::windows::named_pipe::NamedPipeClient;

async fn connect_raw(listen: &str) -> std::io::Result<RawPipe> {
    #[cfg(unix)]
    {
        tokio::net::UnixStream::connect(listen).await
    }
    #[cfg(windows)]
    {
        tokio::net::windows::named_pipe::ClientOptions::new().open(listen)
    }
}
