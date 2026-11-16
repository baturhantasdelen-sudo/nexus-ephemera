//! Phase 3 pilot: release daemon smoke, allowlist denial, and signed loopback.
//!
//! The subprocess is the `nexus-daemon` binary built with this test. The
//! loopback verifier is not an open proxy and it is not mTLS.

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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::process::Command;
use zeroize::{Zeroize, Zeroizing};

const ALLOWED: &str = "https://provider.example/charge";
const SECRET: &[u8] = b"pilot-daemon-secret";
const BODY: &[u8] = b"{\"op\":\"charge\"}";
const DENIED_TARGETS: [&str; 5] = [
    "https://evil.example/charge",
    "https://provider.example/charge?x=1",
    "https://provider.example/charge#frag",
    "https://provider.example/charge/../admin",
    "http://provider.example/charge",
];

#[tokio::test]
async fn release_daemon_binds_a_private_endpoint_and_denies_foreign_targets() {
    let listen = unique_listen();
    // Exactly one endpoint inspection, one successful call, and the denials.
    // The inspection must consume one connection on every platform.
    let expected_connections = DENIED_TARGETS.len() + 2;
    let mut child = Command::new(daemon_exe())
        .arg("--listen")
        .arg(&listen)
        .arg("--reference-mode")
        .arg("--allow")
        .arg(ALLOWED)
        .arg("--max-payload")
        .arg("1024")
        .arg("--timeout-ms")
        .arg("2000")
        .arg("--max-connections")
        .arg(expected_connections.to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn release daemon");
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
    assert_endpoint_is_private(&listen).await;

    let client = NexusClient::new(&listen, Duration::from_secs(5), 1024).expect("client");
    let receipt = client
        .execute(ALLOWED, "pilot-hash", "pilot-allow")
        .await
        .expect("allowlisted call");
    assert_eq!(receipt.transport_status, 204);
    assert_eq!(receipt.seal_report, SealReport::Retained);
    assert_eq!(receipt.target_endpoint, ALLOWED);
    assert!(!receipt.binding_digest_hex.contains("pilot-daemon-secret"));

    for denied in DENIED_TARGETS {
        let err = client
            .execute(denied, "pilot-hash", "pilot-deny")
            .await
            .expect_err(denied);
        assert!(
            matches!(err, IpcError::TargetDenied),
            "{denied} produced {err}"
        );
    }

    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("daemon exit")
        .expect("wait");
    assert!(output.status.success(), "daemon shutdown failed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("shutdown seal=complete"));
    assert!(!stderr.contains("pilot-daemon-secret"));
    assert!(
        stderr.contains(&format!("peer_ok pid={}", std::process::id())),
        "daemon did not record the caller pid: {stderr}"
    );
    #[cfg(unix)]
    let _ = std::fs::remove_file(&listen);
}

#[tokio::test]
async fn signed_loopback_checks_body_route_and_replays_without_a_second_dispatch() {
    let verifier = PilotVerifier::start(SECRET);
    let hash = sha256_hex(BODY);
    let now = unix_ms();

    let missing = verifier
        .exchange(ALLOWED, &hash, "missing-sig", None, BODY, "/charge")
        .expect("missing");
    assert_eq!(missing, 401);

    let stale = sign_request_header(
        SECRET,
        now.saturating_sub(30_000),
        "stale-key",
        &hash,
        ALLOWED,
    );
    assert_eq!(
        verifier
            .exchange(ALLOWED, &hash, "stale-key", Some(&stale), BODY, "/charge")
            .expect("stale"),
        401
    );
    let ahead = sign_request_header(
        SECRET,
        now.saturating_add(30_000),
        "ahead-key",
        &hash,
        ALLOWED,
    );
    assert_eq!(
        verifier
            .exchange(ALLOWED, &hash, "ahead-key", Some(&ahead), BODY, "/charge")
            .expect("ahead"),
        401
    );
    let inside = sign_request_header(SECRET, now, "inside-key", &hash, ALLOWED);
    assert!(verify_request_header(SECRET, &inside, "inside-key", &hash, ALLOWED, now).is_ok());
    assert!(
        verify_request_header(
            SECRET,
            &inside,
            "inside-key",
            &hash,
            ALLOWED,
            now.saturating_add(5_001),
        )
        .is_err()
    );

    let fresh = sign_request_header(SECRET, unix_ms(), "bad-body", &hash, ALLOWED);
    let bad_body = verifier
        .exchange(
            ALLOWED,
            &hash,
            "bad-body",
            Some(&fresh),
            b"other-body",
            "/charge",
        )
        .expect("bad body");
    assert_eq!(bad_body, 400);

    let path_header = sign_request_header(SECRET, unix_ms(), "bad-path", &hash, ALLOWED);
    for path in [
        "/charge?x=1",
        "/charge#frag",
        "/charge/../admin",
        "/v1/charge",
    ] {
        let status = verifier
            .exchange(ALLOWED, &hash, "bad-path", Some(&path_header), BODY, path)
            .expect(path);
        assert_eq!(status, 403, "{path}");
    }
    let malformed = verifier
        .exchange(
            ALLOWED,
            &hash,
            "bad-line",
            Some(&path_header),
            BODY,
            "not a request line",
        )
        .expect("malformed line");
    assert_eq!(malformed, 403);

    let once = sign_request_header(SECRET, unix_ms(), "once-key", &hash, ALLOWED);
    assert_eq!(
        verifier
            .exchange(ALLOWED, &hash, "once-key", Some(&once), BODY, "/charge")
            .expect("first"),
        204
    );
    assert_eq!(
        verifier
            .exchange(ALLOWED, &hash, "once-key", Some(&once), BODY, "/charge")
            .expect("duplicate"),
        409
    );
    assert_eq!(verifier.accepted(), 1);

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
        PilotTransport {
            addr: verifier.addr(),
            allowed: ALLOWED,
        },
    )
    .await
    .expect("bind");
    assert!(secret.iter().all(|byte| *byte == 0));
    let before = verifier.received();

    let first = client_execute(&listen, hash.clone(), "broker-key");
    let served = serve_one(&mut daemon).await.expect("first serve");
    let receipt = first.await.expect("join").expect("receipt");
    let nexus_ephemera::ipc::ServedCall::Call {
        receipt: served_receipt,
        ..
    } = served
    else {
        panic!("expected a call");
    };
    assert_eq!(receipt.transport_status, 204);
    assert_eq!(receipt.seal_report, SealReport::Retained);
    assert_eq!(receipt.payload_hash, hash);
    assert_eq!(
        receipt.binding_digest_hex,
        served_receipt.binding_digest_hex
    );
    assert!(!receipt.binding_digest_hex.contains("pilot-daemon-secret"));
    assert_eq!(verifier.received(), before + 1);

    let replay = client_execute(&listen, hash, "broker-key");
    let _ = serve_one(&mut daemon).await.expect("replay serve");
    let replay = replay.await.expect("join").expect("replay");
    assert_eq!(replay.binding_digest_hex, receipt.binding_digest_hex);
    assert_eq!(replay.idempotency_key, receipt.idempotency_key);
    assert_eq!(verifier.received(), before + 1);
    assert_eq!(verifier.accepted(), 2);
    assert_eq!(
        daemon.shutdown().expect("explicit cleanup"),
        SealReport::Complete
    );
}

#[tokio::test]
async fn interrupted_provider_cannot_report_successful_shutdown() {
    struct Slow(Arc<AtomicBool>);
    impl SecureTransport for Slow {
        fn dispatch(&mut self, _: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
            self.0.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(150));
            Ok(TransportReply { status: 204 })
        }
    }
    let entered = Arc::new(AtomicBool::new(false));
    let listen = unique_listen();
    let mut secret = SECRET.to_vec();
    let mut daemon = BrokerDaemon::bind(
        DaemonConfig {
            listen: listen.clone(),
            allowlist: vec![ALLOWED.into()],
            max_payload_bytes: 1024,
            timeout: Duration::from_secs(2),
            idempotency_ttl: Duration::from_secs(60),
            single_use: false,
        },
        &mut secret,
        Slow(Arc::clone(&entered)),
    )
    .await
    .expect("bind");
    let client = client_execute(&listen, "hash".into(), "interrupted");
    {
        let serving = daemon.serve_one();
        tokio::pin!(serving);
        tokio::select! {
            _ = &mut serving => panic!("provider returned too early"),
            () = tokio::time::sleep(Duration::from_secs(5)) => panic!("provider did not start"),
            () = async {
                while !entered.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            } => {}
        }
    }
    assert!(matches!(daemon.shutdown(), Err(IpcError::Inconclusive)));
    assert!(client.await.expect("client task").is_err());
    tokio::time::sleep(Duration::from_millis(200)).await;
}

async fn assert_endpoint_is_private(listen: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let meta = std::fs::metadata(listen).expect("socket metadata");
        assert!(meta.file_type().is_socket(), "listen path is not a socket");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // Windows inspects a connected pipe handle. Also exercise an actual
        // authenticated connection on Unix, rather than only stat(), so the
        // shutdown connection budget is identical on all platforms.
        NexusClient::new(listen, Duration::from_secs(5), 1024)
            .expect("inspection client")
            .metrics()
            .await
            .expect("authenticated Unix inspection");
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let client = loop {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(listen) {
                Ok(client) => break client,
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(err) => panic!("pilot pipe did not open: {err}"),
            }
        };
        let handle = client.as_raw_handle() as isize;
        let peer = nexus_ephemera_ipc_os::pipe_server_peer(handle).expect("pipe server identity");
        assert!(peer.same_user, "named pipe server is not the current user");
        assert_ne!(peer.pid, 0);
        nexus_ephemera_ipc_os::assert_pipe_dacl_is_current_user_only(handle)
            .expect("named pipe DACL is not current-user only");
    }
}

fn daemon_exe() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_nexus-daemon"))
}

fn unique_listen() -> String {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        #[cfg(target_os = "macos")]
        let dir = std::path::PathBuf::from("/tmp").join(format!("nexus-pilot-{pid}"));
        #[cfg(not(target_os = "macos"))]
        let dir = std::env::temp_dir().join(format!("nexus-pilot-{pid}"));
        let _ = std::fs::create_dir(&dir);
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        dir.join(format!("p-{n}.sock"))
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\nexus-pilot-{pid}-{n}")
    }
}

fn client_execute(
    listen: &str,
    payload_hash: String,
    idempotency_key: &str,
) -> tokio::task::JoinHandle<Result<nexus_ephemera::broker::TransactionReceipt, IpcError>> {
    let listen = listen.to_string();
    let idempotency_key = idempotency_key.to_string();
    tokio::spawn(async move {
        NexusClient::new(listen, Duration::from_secs(3), 1024)
            .expect("client")
            .execute(ALLOWED, &payload_hash, &idempotency_key)
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

struct PilotVerifier {
    addr: SocketAddr,
    state: Arc<PilotState>,
    thread: Option<JoinHandle<()>>,
}

struct PilotState {
    secret: Mutex<Zeroizing<Vec<u8>>>,
    seen: Mutex<std::collections::HashSet<String>>,
    received: AtomicUsize,
    accepted: AtomicUsize,
    stop: AtomicBool,
}

impl PilotVerifier {
    fn start(secret: &[u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind pilot verifier");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        assert!(addr.ip().is_loopback());
        let state = Arc::new(PilotState {
            secret: Mutex::new(Zeroizing::new(secret.to_vec())),
            seen: Mutex::new(std::collections::HashSet::new()),
            received: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
        });
        let worker = Arc::clone(&state);
        let thread = thread::Builder::new()
            .name("pilot-verifier".into())
            .spawn(move || serve(listener, worker))
            .expect("spawn verifier");
        Self {
            addr,
            state,
            thread: Some(thread),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn received(&self) -> usize {
        self.state.received.load(Ordering::SeqCst)
    }

    fn accepted(&self) -> usize {
        self.state.accepted.load(Ordering::SeqCst)
    }

    fn exchange(
        &self,
        endpoint: &str,
        payload_hash: &str,
        key: &str,
        signature: Option<&str>,
        body: &[u8],
        path: &str,
    ) -> Result<u16, &'static str> {
        if !self.addr.ip().is_loopback() {
            return Err("pilot dial is not loopback");
        }
        let mut request = encode(
            self.addr,
            endpoint,
            payload_hash,
            key,
            signature,
            body,
            path,
        )?;
        let mut stream = TcpStream::connect_timeout(&self.addr, Duration::from_secs(2))
            .map_err(|_| "pilot verifier unreachable")?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let write = stream.write_all(&request);
        request.zeroize();
        write.map_err(|_| "pilot verifier write failed")?;
        let raw = read_http(&mut stream);
        let status = status_code(&raw).ok_or("pilot status missing")?;
        assert!(
            !raw.windows(SECRET.len()).any(|window| window == SECRET),
            "verifier echoed the secret"
        );
        Ok(status)
    }
}

impl Drop for PilotVerifier {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(listener: TcpListener, state: Arc<PilotState>) {
    while !state.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) if peer.ip().is_loopback() => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                handle(stream, &state);
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
}

fn handle(mut stream: TcpStream, state: &PilotState) {
    let mut raw = read_http(&mut stream);
    let status = decide(state, &raw);
    raw.zeroize();
    let reason = match status {
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        409 => "Conflict",
        _ => "Unauthorized",
    };
    let mut response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(response.as_bytes());
    response.zeroize();
}

fn decide(state: &PilotState, raw: &[u8]) -> u16 {
    let status = match verdict(state, raw) {
        Verdict::Accept => 204,
        Verdict::Duplicate => 409,
        Verdict::BadRequest => 400,
        Verdict::Forbidden => 403,
        Verdict::Reject => 401,
    };
    state.received.fetch_add(1, Ordering::SeqCst);
    if status == 204 {
        state.accepted.fetch_add(1, Ordering::SeqCst);
    }
    status
}

enum Verdict {
    Accept,
    Duplicate,
    BadRequest,
    Forbidden,
    Reject,
}

fn verdict(state: &PilotState, raw: &[u8]) -> Verdict {
    let Some(pos) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Verdict::Reject;
    };
    let Ok(block) = std::str::from_utf8(&raw[..pos]) else {
        return Verdict::Reject;
    };
    let Some(path) = request_path(block) else {
        return Verdict::Forbidden;
    };
    let Ok(endpoint) = one_header(block, "x-nexus-endpoint") else {
        return Verdict::Reject;
    };
    let Ok(payload_hash) = one_header(block, "x-nexus-payload-hash") else {
        return Verdict::Reject;
    };
    let Ok(key) = one_header(block, "x-nexus-idempotency-key") else {
        return Verdict::Reject;
    };
    let Ok(signature) = one_header(block, "x-nexus-signature") else {
        return Verdict::Reject;
    };
    let Ok(secret) = state.secret.lock() else {
        return Verdict::Reject;
    };
    if verify_request_header(
        secret.as_slice(),
        signature,
        key,
        payload_hash,
        endpoint,
        unix_ms(),
    )
    .is_err()
    {
        return Verdict::Reject;
    }
    drop(secret);
    let Some(len) = content_length(&raw[..pos]) else {
        return Verdict::BadRequest;
    };
    let body = &raw[pos + 4..];
    if len > 64 * 1024 || body.len() != len || sha256_hex(body) != payload_hash {
        return Verdict::BadRequest;
    }
    if endpoint != ALLOWED || path != "/charge" || endpoint_path(endpoint) != Some("/charge") {
        return Verdict::Forbidden;
    }
    let Ok(mut seen) = state.seen.lock() else {
        return Verdict::Reject;
    };
    if !seen.insert(key.to_string()) {
        return Verdict::Duplicate;
    }
    Verdict::Accept
}

fn request_path(block: &str) -> Option<&str> {
    let mut parts = block.lines().next()?.split_whitespace();
    if parts.next()? != "POST" {
        return None;
    }
    let target = parts.next()?;
    if parts.next()? != "HTTP/1.1" || parts.next().is_some() || !path_safe(target) {
        return None;
    }
    Some(target)
}

fn endpoint_path(endpoint: &str) -> Option<&str> {
    let rest = endpoint.strip_prefix("https://")?;
    let slash = rest.find('/')?;
    let path = &rest[slash..];
    path_safe(path).then_some(path)
}

fn path_safe(path: &str) -> bool {
    path.starts_with('/')
        && (2..=2048).contains(&path.len())
        && !path.contains("//")
        && !path.contains(['?', '#', '%', '\\'])
        && !path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        && path.bytes().all(|byte| byte.is_ascii_graphic())
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

fn content_length(header: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(header).ok()?;
    let mut found = None;
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        found = Some(value.parse().ok()?);
    }
    found
}

fn encode(
    addr: SocketAddr,
    endpoint: &str,
    payload_hash: &str,
    key: &str,
    signature: Option<&str>,
    body: &[u8],
    path: &str,
) -> Result<Vec<u8>, &'static str> {
    if path.contains(['\r', '\n']) || endpoint.contains(['\r', '\n']) {
        return Err("pilot field is not header-safe");
    }
    let signature_line = match signature {
        Some(value) if !value.is_empty() => format!("X-Nexus-Signature: {value}\r\n"),
        _ => String::new(),
    };
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nX-Nexus-Endpoint: {endpoint}\r\nX-Nexus-Payload-Hash: {payload_hash}\r\nX-Nexus-Idempotency-Key: {key}\r\n{signature_line}Content-Length: {len}\r\nConnection: close\r\n\r\n",
        len = body.len(),
    )
    .into_bytes();
    request.extend_from_slice(body);
    Ok(request)
}

fn read_http(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 256];
    while raw.len() < 64 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                chunk[..n].zeroize();
                let Some(pos) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
                    continue;
                };
                match content_length(&raw[..pos]) {
                    Some(len) if raw.len() >= pos + 4 + len => break,
                    Some(_) => {}
                    None => break,
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    chunk.zeroize();
    raw
}

fn status_code(raw: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut parts = text.lines().next()?.split_whitespace();
    if parts.next()? != "HTTP/1.1" {
        return None;
    }
    parts.next()?.parse().ok()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::digest(bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.as_slice() {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    digest.zeroize();
    out
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

struct PilotTransport {
    addr: SocketAddr,
    allowed: &'static str,
}

impl SecureTransport for PilotTransport {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        if !self.addr.ip().is_loopback() || call.target_endpoint != self.allowed {
            return Err(BrokerError::Transport(
                "pilot target is not allowlisted loopback",
            ));
        }
        let status = dial(
            self.addr,
            call.target_endpoint,
            call.payload_hash,
            call.idempotency_key,
            call.nexus_signature,
        )
        .map_err(|_| BrokerError::Transport("pilot verifier rejected the call"))?;
        if status != 204 {
            return Err(BrokerError::Transport("pilot verifier rejected the call"));
        }
        Ok(TransportReply { status: 204 })
    }
}

fn dial(
    addr: SocketAddr,
    endpoint: &str,
    payload_hash: &str,
    key: &str,
    signature: &str,
) -> Result<u16, &'static str> {
    if !addr.ip().is_loopback() {
        return Err("pilot dial is not loopback");
    }
    let mut request = encode(
        addr,
        endpoint,
        payload_hash,
        key,
        Some(signature),
        BODY,
        "/charge",
    )?;
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|_| "unreachable")?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let write = stream.write_all(&request);
    request.zeroize();
    write.map_err(|_| "write failed")?;
    let raw = read_http(&mut stream);
    status_code(&raw).ok_or("status missing")
}
