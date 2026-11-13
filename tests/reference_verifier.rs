//! Loopback reference verifier for `X-Nexus-Signature`.
//!
//! The daemon signs with the broker secret. This listener checks that HMAC and
//! a five-second timestamp skew, then records the idempotency key. It binds
//! `127.0.0.1` only. The test transport dials that address only when the call
//! target is the one allowlisted endpoint. It is not an open proxy, and it is
//! not mTLS.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nexus_ephemera::broker::{
    AuthorizedCall, BrokerError, SealReport, SecureTransport, TransportReply,
};
use nexus_ephemera::crypto::{sign_request_header, verify_request_header};
use nexus_ephemera::ipc::{BrokerDaemon, DaemonConfig, IpcError, NexusClient};
use zeroize::{Zeroize, Zeroizing};

const ALLOWED: &str = "https://provider.example/charge";
const SECRET: &[u8] = b"reference-verifier-secret";

struct VerifierState {
    secret: Mutex<Zeroizing<Vec<u8>>>,
    seen: Mutex<HashSet<String>>,
    received: AtomicUsize,
    accepted: AtomicUsize,
    duplicates: AtomicUsize,
    rejected: AtomicUsize,
    stop: AtomicBool,
}

struct ReferenceVerifier {
    addr: SocketAddr,
    state: Arc<VerifierState>,
    thread: Option<JoinHandle<()>>,
}

struct Posted<'a> {
    endpoint: &'a str,
    payload_hash: &'a str,
    idempotency_key: &'a str,
    signature: Option<&'a str>,
}

struct HttpReply {
    status: u16,
    raw: Vec<u8>,
}

impl Drop for HttpReply {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl ReferenceVerifier {
    fn start(secret: &[u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind reference verifier");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("local addr");
        assert!(addr.ip().is_loopback());
        let state = Arc::new(VerifierState {
            secret: Mutex::new(Zeroizing::new(secret.to_vec())),
            seen: Mutex::new(HashSet::new()),
            received: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
            duplicates: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
        });
        let worker = Arc::clone(&state);
        let thread = thread::Builder::new()
            .name("nexus-reference-verifier".into())
            .spawn(move || serve(listener, worker))
            .expect("spawn verifier");
        Self {
            addr,
            state,
            thread: Some(thread),
        }
    }

    fn received(&self) -> usize {
        self.state.received.load(Ordering::SeqCst)
    }

    fn accepted(&self) -> usize {
        self.state.accepted.load(Ordering::SeqCst)
    }

    fn duplicates(&self) -> usize {
        self.state.duplicates.load(Ordering::SeqCst)
    }

    fn rejected(&self) -> usize {
        self.state.rejected.load(Ordering::SeqCst)
    }
}

impl Drop for ReferenceVerifier {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(listener: TcpListener, state: Arc<VerifierState>) {
    while !state.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if peer.ip().is_loopback() {
                    let _ = stream.set_nonblocking(false);
                    handle_connection(stream, &state);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    if let Ok(mut secret) = state.secret.lock() {
        *secret = Zeroizing::new(Vec::new());
    }
    if let Ok(mut seen) = state.seen.lock() {
        seen.clear();
    }
}

fn handle_connection(mut stream: TcpStream, state: &VerifierState) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut raw = read_headers(&mut stream);
    let status = decide(state, &raw);
    raw.zeroize();
    let reason = match status {
        204 => "No Content",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => "Unauthorized",
    };
    let mut response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(response.as_bytes());
    response.zeroize();
    let _ = stream.flush();
}

fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::with_capacity(512);
    let mut chunk = [0u8; 256];
    while raw.len() < 8 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                chunk[..n].zeroize();
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    chunk.zeroize();
    raw
}

fn decide(state: &VerifierState, raw: &[u8]) -> u16 {
    let status = match decision(state, raw) {
        Decision::Accept => 204,
        Decision::Duplicate => 409,
        Decision::Unavailable => 503,
        Decision::Reject => 401,
    };
    state.received.fetch_add(1, Ordering::SeqCst);
    match status {
        204 => {
            state.accepted.fetch_add(1, Ordering::SeqCst);
        }
        409 => {
            state.duplicates.fetch_add(1, Ordering::SeqCst);
        }
        _ => {
            state.rejected.fetch_add(1, Ordering::SeqCst);
        }
    }
    status
}

enum Decision {
    Accept,
    Duplicate,
    Unavailable,
    Reject,
}

fn decision(state: &VerifierState, raw: &[u8]) -> Decision {
    let Ok(text) = std::str::from_utf8(raw) else {
        return Decision::Reject;
    };
    let Some(block) = text.split("\r\n\r\n").next() else {
        return Decision::Reject;
    };
    if !block.starts_with("POST ") {
        return Decision::Reject;
    }
    let Ok(endpoint) = one_header(block, "x-nexus-endpoint") else {
        return Decision::Reject;
    };
    let Ok(payload_hash) = one_header(block, "x-nexus-payload-hash") else {
        return Decision::Reject;
    };
    let Ok(idempotency_key) = one_header(block, "x-nexus-idempotency-key") else {
        return Decision::Reject;
    };
    let Ok(signature) = one_header(block, "x-nexus-signature") else {
        return Decision::Reject;
    };
    let Ok(secret) = state.secret.lock() else {
        return Decision::Reject;
    };
    if verify_request_header(
        secret.as_slice(),
        signature,
        idempotency_key,
        payload_hash,
        endpoint,
        unix_ms(),
    )
    .is_err()
    {
        return Decision::Reject;
    }
    drop(secret);
    let Ok(mut seen) = state.seen.lock() else {
        return Decision::Reject;
    };
    if seen.contains(idempotency_key) {
        return Decision::Duplicate;
    }
    if seen.len() >= 32 {
        return Decision::Unavailable;
    }
    seen.insert(idempotency_key.to_string());
    Decision::Accept
}

fn one_header<'a>(block: &'a str, name: &str) -> Result<&'a str, ()> {
    let mut found = None;
    for line in block.split("\r\n").skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.eq_ignore_ascii_case(name) {
            if found.is_some() {
                return Err(());
            }
            let value = value.trim();
            if value.is_empty() || value.len() > 2048 {
                return Err(());
            }
            found = Some(value);
        }
    }
    found.ok_or(())
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn exchange(addr: SocketAddr, posted: Posted<'_>) -> Result<HttpReply, &'static str> {
    if !addr.ip().is_loopback() {
        return Err("reference dial is not loopback");
    }
    let mut request = encode_request(addr, posted)?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|_| "reference verifier unreachable")?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let write = stream.write_all(&request);
    request.zeroize();
    write.map_err(|_| "reference verifier write failed")?;
    let raw = read_headers(&mut stream);
    let status = status_code(&raw).ok_or("reference verifier status missing")?;
    Ok(HttpReply { status, raw })
}

fn encode_request(addr: SocketAddr, posted: Posted<'_>) -> Result<Vec<u8>, &'static str> {
    if !header_safe(posted.endpoint)
        || !header_safe(posted.payload_hash)
        || !header_safe(posted.idempotency_key)
    {
        return Err("reference field is not header-safe");
    }
    let signature = match posted.signature {
        Some(value) if signature_safe(value) => value,
        Some(_) => return Err("reference signature is not header-safe"),
        None => "",
    };
    let signature_line = if signature.is_empty() {
        String::new()
    } else {
        format!("X-Nexus-Signature: {signature}\r\n")
    };
    Ok(format!(
        "POST /v1/charge HTTP/1.1\r\nHost: {addr}\r\nX-Nexus-Endpoint: {}\r\nX-Nexus-Payload-Hash: {}\r\nX-Nexus-Idempotency-Key: {}\r\n{signature_line}Content-Length: 0\r\nConnection: close\r\n\r\n",
        posted.endpoint, posted.payload_hash, posted.idempotency_key
    )
    .into_bytes())
}

fn header_safe(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2048 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn signature_safe(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'=' | b','))
}

fn status_code(raw: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut parts = text.lines().next()?.split_whitespace();
    if parts.next()? != "HTTP/1.1" {
        return None;
    }
    parts.next()?.parse().ok()
}

struct SignedLoopbackTransport {
    addr: SocketAddr,
    allowed: &'static str,
}

impl SecureTransport for SignedLoopbackTransport {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        if !self.addr.ip().is_loopback() {
            return Err(BrokerError::Transport("reference dial is not loopback"));
        }
        if call.target_endpoint != self.allowed {
            return Err(BrokerError::Transport(
                "target is not the reference endpoint",
            ));
        }
        let reply = exchange(
            self.addr,
            Posted {
                endpoint: call.target_endpoint,
                payload_hash: call.payload_hash,
                idempotency_key: call.idempotency_key,
                signature: Some(call.nexus_signature),
            },
        )
        .map_err(|_| BrokerError::Transport("reference verifier rejected the call"))?;
        if reply
            .raw
            .windows(SECRET.len())
            .any(|window| window == SECRET)
        {
            return Err(BrokerError::Transport(
                "reference response echoed the secret",
            ));
        }
        if reply.status != 204 {
            return Err(BrokerError::Transport(
                "reference verifier rejected the call",
            ));
        }
        Ok(TransportReply { status: 204 })
    }
}

fn assert_no_secret(raw: &[u8]) {
    assert!(
        !raw.windows(SECRET.len()).any(|window| window == SECRET),
        "verifier response contained the broker secret"
    );
}

fn fresh_header(timestamp: u64, key: &str, payload_hash: &str, endpoint: &str) -> String {
    sign_request_header(SECRET, timestamp, key, payload_hash, endpoint)
}

#[test]
fn verifier_rejects_missing_forged_stale_and_duplicate_requests() {
    let verifier = ReferenceVerifier::start(SECRET);
    let now = unix_ms();
    let missing = exchange(
        verifier.addr,
        Posted {
            endpoint: ALLOWED,
            payload_hash: "hash-a",
            idempotency_key: "missing-key",
            signature: None,
        },
    )
    .expect("missing signature response");
    assert_eq!(missing.status, 401);
    assert_no_secret(&missing.raw);
    assert_eq!(verifier.rejected(), 1);
    assert_eq!(verifier.accepted(), 0);

    let mut forged = fresh_header(now, "forged-key", "hash-a", ALLOWED);
    let tail = forged.pop().expect("signature char");
    forged.push(if tail == 'a' { 'b' } else { 'a' });
    let forged = exchange(
        verifier.addr,
        Posted {
            endpoint: ALLOWED,
            payload_hash: "hash-a",
            idempotency_key: "forged-key",
            signature: Some(&forged),
        },
    )
    .expect("forged signature response");
    assert_eq!(forged.status, 401);
    assert_no_secret(&forged.raw);

    let stale = fresh_header(now.saturating_sub(6_000), "stale-key", "hash-a", ALLOWED);
    let stale = exchange(
        verifier.addr,
        Posted {
            endpoint: ALLOWED,
            payload_hash: "hash-a",
            idempotency_key: "stale-key",
            signature: Some(&stale),
        },
    )
    .expect("stale signature response");
    assert_eq!(stale.status, 401);
    assert_no_secret(&stale.raw);

    let swapped = fresh_header(now, "swap-key", "hash-a", ALLOWED);
    let swapped = exchange(
        verifier.addr,
        Posted {
            endpoint: "https://evil.example/charge",
            payload_hash: "hash-a",
            idempotency_key: "swap-key",
            signature: Some(&swapped),
        },
    )
    .expect("swapped endpoint response");
    assert_eq!(swapped.status, 401);
    assert_eq!(verifier.accepted(), 0);

    let fresh = fresh_header(now, "once-key", "hash-a", ALLOWED);
    let first = exchange(
        verifier.addr,
        Posted {
            endpoint: ALLOWED,
            payload_hash: "hash-a",
            idempotency_key: "once-key",
            signature: Some(&fresh),
        },
    )
    .expect("fresh signature response");
    assert_eq!(first.status, 204);
    assert_no_secret(&first.raw);
    assert_eq!(verifier.accepted(), 1);
    let second = exchange(
        verifier.addr,
        Posted {
            endpoint: ALLOWED,
            payload_hash: "hash-a",
            idempotency_key: "once-key",
            signature: Some(&fresh),
        },
    )
    .expect("duplicate signature response");
    assert_eq!(second.status, 409);
    assert_no_secret(&second.raw);
    assert_eq!(verifier.accepted(), 1);
    assert_eq!(verifier.duplicates(), 1);

    let mut foreign = SignedLoopbackTransport {
        addr: verifier.addr,
        allowed: ALLOWED,
    };
    let received = verifier.received();
    let err = foreign
        .dispatch(&AuthorizedCall {
            target_endpoint: "https://evil.example/charge",
            payload_hash: "hash-a",
            binding_digest_hex: "ab",
            call_nonce: 1,
            issued_at_unix_ms: now,
            idempotency_key: "foreign-key",
            nexus_signature: &fresh,
        })
        .expect_err("foreign target");
    assert!(matches!(
        err,
        BrokerError::Transport("target is not the reference endpoint")
    ));
    assert_eq!(verifier.received(), received);

    let mut public = SignedLoopbackTransport {
        addr: "8.8.8.8:80".parse().expect("addr"),
        allowed: ALLOWED,
    };
    let err = public
        .dispatch(&AuthorizedCall {
            target_endpoint: ALLOWED,
            payload_hash: "hash-a",
            binding_digest_hex: "ab",
            call_nonce: 1,
            issued_at_unix_ms: now,
            idempotency_key: "public-key",
            nexus_signature: &fresh,
        })
        .expect_err("public dial");
    assert!(matches!(
        err,
        BrokerError::Transport("reference dial is not loopback")
    ));
}

#[tokio::test]
async fn signed_execute_is_verified_once_and_replay_does_not_dispatch() {
    let verifier = ReferenceVerifier::start(SECRET);
    let listen = unique_listen();
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
        SignedLoopbackTransport {
            addr: verifier.addr,
            allowed: ALLOWED,
        },
    )
    .await
    .expect("bind");
    assert!(secret.iter().all(|byte| *byte == 0));

    let first = client_execute(&listen, "hash-ref", "ref-key-1");
    let served = serve_one(&mut daemon).await.expect("first serve");
    let receipt = first.await.expect("join").expect("first receipt");
    let nexus_ephemera::ipc::ServedCall::Call {
        receipt: served_receipt,
        ..
    } = served
    else {
        panic!("expected a call receipt");
    };
    assert_eq!(receipt.transport_status, 204);
    assert_eq!(receipt.seal_report, SealReport::Retained);
    assert_eq!(receipt.target_endpoint, ALLOWED);
    assert_eq!(receipt.payload_hash, "hash-ref");
    assert_eq!(receipt.idempotency_key, "ref-key-1");
    assert!(!receipt.binding_digest_hex.is_empty());
    assert_eq!(
        served_receipt.binding_digest_hex,
        receipt.binding_digest_hex
    );
    assert!(
        !receipt
            .binding_digest_hex
            .contains("reference-verifier-secret")
    );
    assert_eq!(verifier.accepted(), 1);
    assert_eq!(verifier.received(), 1);
    assert_eq!(verifier.duplicates(), 0);

    let replay = client_execute(&listen, "hash-ref", "ref-key-1");
    let _ = serve_one(&mut daemon).await.expect("replay serve");
    let replay = replay.await.expect("join").expect("replay receipt");
    assert_eq!(replay.transport_status, receipt.transport_status);
    assert_eq!(replay.seal_report, receipt.seal_report);
    assert_eq!(replay.binding_digest_hex, receipt.binding_digest_hex);
    assert_eq!(replay.idempotency_key, receipt.idempotency_key);
    assert_eq!(verifier.accepted(), 1);
    assert_eq!(verifier.received(), 1);
    assert_eq!(verifier.duplicates(), 0);
}

fn unique_listen() -> String {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\nexus-ref-{pid}-{n}")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        #[cfg(target_os = "macos")]
        let dir = std::path::PathBuf::from("/tmp").join(format!("nexus-ref-{pid}"));
        #[cfg(not(target_os = "macos"))]
        let dir = std::env::temp_dir().join(format!("nexus-ref-{pid}"));
        let _ = std::fs::create_dir(&dir);
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        dir.join(format!("n-{n}.sock"))
            .to_string_lossy()
            .into_owned()
    }
}

fn client_execute(
    listen: &str,
    payload_hash: &'static str,
    idempotency_key: &'static str,
) -> tokio::task::JoinHandle<Result<nexus_ephemera::broker::TransactionReceipt, IpcError>> {
    let listen = listen.to_string();
    tokio::spawn(async move {
        NexusClient::new(listen, Duration::from_secs(3), 1024)
            .expect("client")
            .execute(ALLOWED, payload_hash, idempotency_key)
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
