//! MCP-shaped tool call through the broker.
//!
//! The client sends the canonical payload hash. The daemon signs the upstream
//! request and returns a receipt. The binding digest is not a MAC and not mTLS.
//! A second identical key is the cached receipt and does not dispatch again.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nexus_ephemera::broker::{
    AuthorizedCall, BrokerError, SealReport, SecureTransport, TransportReply,
};
use nexus_ephemera::crypto::verify_request_header;
use nexus_ephemera::ipc::{BrokerDaemon, DaemonConfig, IpcError, NexusClient};
use sha2::{Digest, Sha256};

const ALLOWED: &str = "https://provider.example/charge";
const SECRET: &[u8] = b"ecosystem-mcp-secret";
const CANONICAL: &[u8] = br#"{"params":{"amount":"10","currency":"usd"},"tool":"charge"}"#;
const KEY: &str = "mcp-tool-1";

#[tokio::test]
async fn mcp_tool_call_receipt_is_retained_and_replay_does_not_dispatch() {
    let listen = unique_listen();
    let hash = sha256_hex(CANONICAL);
    let calls = Arc::new(AtomicUsize::new(0));
    let signature = Arc::new(Mutex::new(String::new()));
    let mut secret = SECRET.to_vec();
    let mut daemon = BrokerDaemon::bind(
        DaemonConfig {
            listen: listen.clone(),
            allowlist: vec![ALLOWED.to_string()],
            max_payload_bytes: 1024,
            timeout: Duration::from_secs(2),
            idempotency_ttl: Duration::from_secs(60),
            single_use: false,
        },
        &mut secret,
        CountingTransport {
            calls: Arc::clone(&calls),
            signature: Arc::clone(&signature),
        },
    )
    .await
    .expect("bind");
    assert!(secret.iter().all(|byte| *byte == 0));

    let first_task = client_execute(&listen, ALLOWED, hash.clone(), KEY);
    let served = serve_one(&mut daemon).await.expect("first serve");
    let nexus_ephemera::ipc::ServedCall::Call {
        receipt: served_receipt,
        ..
    } = served
    else {
        panic!("expected a call");
    };
    let receipt = first_task.await.expect("join").expect("receipt");
    assert_eq!(receipt.transport_status, 204);
    assert_eq!(receipt.seal_report, SealReport::Retained);
    assert_eq!(served_receipt.seal_report, SealReport::Retained);
    assert_eq!(receipt.payload_hash, hash);
    assert_eq!(receipt.target_endpoint, ALLOWED);
    assert_eq!(receipt.idempotency_key, KEY);
    assert_eq!(
        receipt.binding_digest_hex,
        served_receipt.binding_digest_hex
    );
    assert!(!receipt.binding_digest_hex.contains("ecosystem-mcp-secret"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let signed = signature.lock().expect("signature").clone();
    verify_request_header(SECRET, &signed, KEY, &hash, ALLOWED, unix_ms()).expect("hmac");
    assert_ne!(signed, receipt.binding_digest_hex);

    let replay_task = client_execute(&listen, ALLOWED, hash.clone(), KEY);
    let replay_served = serve_one(&mut daemon).await.expect("replay serve");
    let nexus_ephemera::ipc::ServedCall::Call {
        receipt: replay_served,
        ..
    } = replay_served
    else {
        panic!("expected a cached call");
    };
    let replay = replay_task.await.expect("join").expect("replay");
    assert_eq!(replay.binding_digest_hex, receipt.binding_digest_hex);
    assert_eq!(replay.seal_report, SealReport::Retained);
    assert_eq!(replay_served.seal_report, SealReport::Retained);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let conflict_task = client_execute(&listen, ALLOWED, "hash-tampered".to_string(), KEY);
    let conflict = serve_one(&mut daemon).await.expect_err("conflict");
    assert!(matches!(conflict, IpcError::IdempotencyConflict));
    let client_conflict = conflict_task
        .await
        .expect("join")
        .expect_err("client conflict");
    assert!(matches!(client_conflict, IpcError::IdempotencyConflict));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    for denied in [
        "https://evil.example/charge",
        "https://provider.example/charge?x=1",
        "https://provider.example/charge#frag",
    ] {
        let task = client_execute(&listen, denied, hash.clone(), "mcp-deny");
        let err = serve_one(&mut daemon).await.expect_err(denied);
        assert!(
            matches!(err, IpcError::TargetDenied),
            "{denied} produced {err}"
        );
        let client_err = task.await.expect("join").expect_err(denied);
        assert!(matches!(client_err, IpcError::TargetDenied));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

fn client_execute(
    listen: &str,
    endpoint: &str,
    payload_hash: String,
    idempotency_key: &str,
) -> tokio::task::JoinHandle<Result<nexus_ephemera::broker::TransactionReceipt, IpcError>> {
    let listen = listen.to_string();
    let endpoint = endpoint.to_string();
    let idempotency_key = idempotency_key.to_string();
    tokio::spawn(async move {
        NexusClient::new(listen, Duration::from_secs(3), 1024)
            .expect("client")
            .execute(&endpoint, &payload_hash, &idempotency_key)
            .await
    })
}

async fn serve_one<T>(
    daemon: &mut BrokerDaemon<T>,
) -> Result<nexus_ephemera::ipc::ServedCall, IpcError>
where
    T: SecureTransport + Send + 'static,
{
    tokio::time::timeout(Duration::from_secs(10), daemon.serve_one())
        .await
        .expect("serve timed out")
}

struct CountingTransport {
    calls: Arc<AtomicUsize>,
    signature: Arc<Mutex<String>>,
}

impl SecureTransport for CountingTransport {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        assert!(!call.binding_digest_hex.contains("ecosystem-mcp-secret"));
        assert!(!call.nexus_signature.contains("ecosystem-mcp-secret"));
        assert_ne!(call.nexus_signature, call.binding_digest_hex);
        assert!(!call.nexus_signature.is_empty());
        *self.signature.lock().expect("signature") = call.nexus_signature.to_string();
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(TransportReply { status: 204 })
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::digest(bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.as_slice() {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    digest.as_mut_slice().fill(0);
    out
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn unique_listen() -> String {
    let pid = std::process::id();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        #[cfg(target_os = "macos")]
        let dir = std::path::PathBuf::from("/tmp").join(format!("nexus-eco-{pid}"));
        #[cfg(not(target_os = "macos"))]
        let dir = std::env::temp_dir().join(format!("nexus-eco-{pid}"));
        let _ = std::fs::create_dir(&dir);
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        return dir.join("mcp.sock").to_string_lossy().into_owned();
    }
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\nexus-eco-{pid}")
    }
}
