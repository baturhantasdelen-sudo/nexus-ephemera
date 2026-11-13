//! Same-user IPC between `NexusClient` and the broker daemon.
//!
//! The client sends an endpoint and a payload hash. It never sends or receives
//! the raw key. The daemon admits the key into `SecureTransactionAgent` and
//! returns a receipt or `CleanupIncomplete`.
//!
//! Unix sockets are mode `0600`. Linux and macOS peers must present a matching
//! UID and a non-zero PID (`SO_PEERCRED` / `LOCAL_PEEREID`). The client checks
//! that same peer identity, and the socket mode, before it writes. A socket
//! file is removed only when this process still owns that inode. A `<path>.lock`
//! file is held for the daemon's lifetime and is not unlinked on exit. A live
//! listener is left in place.
//! Windows pipes reject remote clients. Before the first accept, the
//! pipe DACL is one allow ACE for the current user and that user is the owner.
//! Later instances keep that descriptor and are created before the previous
//! handle is closed. The client checks the server process SID before it
//! writes. This boundary is not mTLS and it does not stop a privileged
//! local administrator.

#![forbid(unsafe_code)]

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use crate::broker::{
    BrokerError, ExecuteWithPolicy, SealReport, SecureTransactionAgent, SecureTransport,
    TransactionReceipt, TransportReply,
};
use crate::exposure::ExposureTags;

pub const DEFAULT_UNIX_SOCK: &str = "/var/run/nexus-ephemera.sock";
pub const DEFAULT_WINDOWS_PIPE: &str = r"\\.\pipe\nexus-ephemera";
const HARD_PAYLOAD_CAP: usize = 64 * 1024;
const HARD_SECRET_CAP: usize = 4 * 1024;

#[derive(Debug)]
pub enum IpcError {
    Io(std::io::Error),
    IdentityRejected,
    IdentityUnavailable,
    PayloadTooLarge { limit: usize },
    TimedOut,
    TargetDenied,
    Malformed,
    CleanupIncomplete(TransactionReceipt),
    IdempotencyConflict,
    IdempotencyUnavailable,
    Broker(BrokerError),
    Protocol(&'static str),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "ipc io: {err}"),
            Self::IdentityRejected => write!(f, "ipc: caller identity rejected"),
            Self::IdentityUnavailable => write!(f, "ipc: caller identity unavailable"),
            Self::PayloadTooLarge { limit } => write!(f, "ipc: payload exceeds {limit} bytes"),
            Self::TimedOut => write!(f, "ipc: request timed out"),
            Self::TargetDenied => write!(f, "ipc: endpoint is not on the allowlist"),
            Self::Malformed => write!(f, "ipc: malformed frame"),
            Self::CleanupIncomplete(receipt) => write!(
                f,
                "ipc: cleanup {:?} after transport {}",
                receipt.seal_report, receipt.transport_status
            ),
            Self::IdempotencyConflict => {
                write!(f, "ipc: idempotency key was reused for a different call")
            }
            Self::IdempotencyUnavailable => write!(f, "ipc: idempotency cache is full"),
            Self::Broker(BrokerError::Memlock(msg)) => write!(f, "ipc: {msg}"),
            Self::Broker(_) => write!(f, "ipc: broker rejected the call"),
            Self::Protocol(msg) => write!(f, "ipc: {msg}"),
        }
    }
}

impl From<std::io::Error> for IpcError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

pub fn peer_is_authorized(
    peer_uid: u32,
    peer_pid: Option<u32>,
    daemon_uid: u32,
) -> Result<(), IpcError> {
    let Some(pid) = peer_pid else {
        return Err(IpcError::IdentityUnavailable);
    };
    if pid == 0 {
        return Err(IpcError::IdentityUnavailable);
    }
    if peer_uid != daemon_uid {
        return Err(IpcError::IdentityRejected);
    }
    Ok(())
}

pub fn client_outcome(
    result: Result<TransactionReceipt, BrokerError>,
) -> Result<TransactionReceipt, IpcError> {
    match result {
        Ok(receipt)
            if matches!(
                receipt.seal_report,
                SealReport::Partial | SealReport::Failed
            ) =>
        {
            Err(IpcError::CleanupIncomplete(receipt))
        }
        Ok(receipt) => Ok(receipt),
        Err(BrokerError::CleanupIncomplete(receipt)) => Err(IpcError::CleanupIncomplete(receipt)),
        Err(err) => Err(IpcError::Broker(err)),
    }
}

pub fn per_connection(err: &IpcError) -> bool {
    match err {
        IpcError::IdentityRejected
        | IpcError::IdentityUnavailable
        | IpcError::PayloadTooLarge { .. }
        | IpcError::TimedOut
        | IpcError::TargetDenied
        | IpcError::Malformed
        | IpcError::CleanupIncomplete(_)
        | IpcError::IdempotencyConflict
        | IpcError::IdempotencyUnavailable
        | IpcError::Broker(_) => true,
        IpcError::Io(err) => matches!(
            err.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::NotConnected
        ),
        IpcError::Protocol(_) => false,
    }
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub listen: String,
    pub allowlist: Vec<String>,
    pub max_payload_bytes: usize,
    pub timeout: Duration,
    pub idempotency_ttl: Duration,
    pub single_use: bool,
}

impl DaemonConfig {
    pub fn checked(mut self) -> Result<Self, IpcError> {
        if self.allowlist.is_empty() || self.allowlist.iter().any(|item| item.is_empty()) {
            return Err(IpcError::Protocol("allowlist is empty"));
        }
        if self.max_payload_bytes == 0 || self.max_payload_bytes > HARD_PAYLOAD_CAP {
            return Err(IpcError::Protocol("payload limit is outside 1..=65536"));
        }
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(120) {
            return Err(IpcError::Protocol("timeout is outside 1ms..=120s"));
        }
        if self.idempotency_ttl < Duration::from_millis(1)
            || self.idempotency_ttl > Duration::from_secs(24 * 60 * 60)
        {
            return Err(IpcError::Protocol("idempotency ttl is outside 1ms..=24h"));
        }
        self.allowlist.sort();
        self.allowlist.dedup();
        Ok(self)
    }
}

pub struct LocalAcceptTransport;

impl SecureTransport for LocalAcceptTransport {
    fn dispatch(
        &mut self,
        call: &crate::broker::AuthorizedCall<'_>,
    ) -> Result<TransportReply, BrokerError> {
        if call.call_nonce == 0
            || call.binding_digest_hex.is_empty()
            || call.payload_hash.is_empty()
            || call.idempotency_key.is_empty()
        {
            return Err(BrokerError::Transport("incomplete authorized call"));
        }
        Ok(TransportReply { status: 204 })
    }
}

#[derive(Debug)]
pub enum ServedCall {
    Call {
        peer_pid: u32,
        receipt: TransactionReceipt,
    },
    Metrics {
        peer_pid: u32,
    },
}

pub struct BrokerDaemon<T> {
    agent: SecureTransactionAgent,
    transport: T,
    allowlist: Vec<String>,
    max_payload_bytes: usize,
    timeout: Duration,
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    #[cfg(unix)]
    socket_path: std::path::PathBuf,
    #[cfg(unix)]
    socket_id: (u64, u64),
    #[cfg(unix)]
    listen_lock: nexus_ephemera_ipc_os::ListenLock,
    #[cfg(unix)]
    daemon_uid: u32,
    #[cfg(windows)]
    pipe_name: String,
    #[cfg(windows)]
    pending: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
    #[cfg(windows)]
    first_instance: bool,
    idempotency: crate::idempotency::IdempotencyCache,
}

impl<T: SecureTransport> BrokerDaemon<T> {
    /// Bind the listen socket or create the first named-pipe instance.
    ///
    /// Poll this on a Tokio runtime with IO enabled. `UnixListener::bind` panics
    /// without that context, and the Windows pipe create fails closed outside it.
    pub async fn bind(
        config: DaemonConfig,
        secret: &mut [u8],
        transport: T,
    ) -> Result<Self, IpcError> {
        tokio::task::yield_now().await;
        let config = config.checked()?;
        if secret.is_empty() || secret.len() > HARD_SECRET_CAP {
            secret.zeroize();
            return Err(IpcError::Protocol(
                "daemon secret length is outside 1..=4096",
            ));
        }
        let tags = ExposureTags::allowlist(config.allowlist.clone(), config.single_use, None)
            .map_err(|_| IpcError::Protocol("allowlist rejected"))?;
        let admitted = SecureTransactionAgent::admit(secret, tags);
        secret.zeroize();
        let agent = admitted.map_err(IpcError::Broker)?;
        listen(config, agent, transport)
    }

    pub async fn serve_one(&mut self) -> Result<ServedCall, IpcError> {
        let (mut stream, peer_pid) = self.accept().await?;
        let result = self.handle_stream(&mut stream).await;
        let _ = stream.shutdown().await;
        #[cfg(windows)]
        self.reserve_next_pipe(stream)?;
        match result? {
            FrameBody::Call(receipt) => Ok(ServedCall::Call { peer_pid, receipt }),
            FrameBody::Metrics => Ok(ServedCall::Metrics { peer_pid }),
        }
    }

    async fn handle_stream<S>(&mut self, stream: &mut S) -> Result<FrameBody, IpcError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut frame = read_frame(stream, self.max_payload_bytes, self.timeout).await?;
        let request = serde_json::from_slice::<WireRequest>(&frame);
        frame.zeroize();
        let request = match request {
            Ok(request) => request,
            Err(_) => {
                let outcome = Err(IpcError::Malformed);
                write_response(stream, &outcome, self.max_payload_bytes, self.timeout).await?;
                return outcome.map(FrameBody::Call);
            }
        };
        if request.op == WireOp::Metrics {
            let snapshot = crate::metrics::snapshot();
            let mut encoded = serde_json::to_vec(&MetricsFrame::from(snapshot))
                .map_err(|_| IpcError::Malformed)?;
            let written = write_frame(stream, &encoded, self.max_payload_bytes, self.timeout).await;
            encoded.zeroize();
            written?;
            return Ok(FrameBody::Metrics);
        }
        let outcome = dispatch_call(
            &request,
            &self.allowlist,
            &mut self.agent,
            &mut self.transport,
            &mut self.idempotency,
        );
        if let Err(err) =
            write_response(stream, &outcome, self.max_payload_bytes, self.timeout).await
        {
            return match outcome {
                Err(outcome) => Err(outcome),
                Ok(_) => Err(err),
            };
        }
        match outcome {
            Ok(receipt) => Ok(FrameBody::Call(receipt)),
            Err(err) => Err(err),
        }
    }

    #[cfg(unix)]
    async fn accept(&mut self) -> Result<(tokio::net::UnixStream, u32), IpcError> {
        let (stream, _) = self.listener.accept().await?;
        let cred = stream
            .peer_cred()
            .map_err(|_| note_auth_failure(IpcError::IdentityUnavailable))?;
        let peer_uid = u32::try_from(u64::from(cred.uid()))
            .map_err(|_| note_auth_failure(IpcError::IdentityUnavailable))?;
        let peer_pid = cred
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0);
        peer_is_authorized(peer_uid, peer_pid, self.daemon_uid).map_err(note_auth_failure)?;
        let peer_pid = peer_pid.ok_or(IpcError::IdentityUnavailable)?;
        Ok((stream, peer_pid))
    }

    #[cfg(windows)]
    fn open_pipe(&mut self) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, IpcError> {
        use std::os::windows::io::AsRawHandle;
        let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
        options.reject_remote_clients(true);
        if self.first_instance {
            options.first_pipe_instance(true);
            // Only the first instance can request WRITE_DAC. Later instances
            // are checked against the DACL this call installs.
            options.write_dac(true);
            options.write_owner(true);
        }
        let server = options.create(self.pipe_name.as_str())?;
        if self.first_instance {
            let handle = server.as_raw_handle() as isize;
            // Same owner, group, and single-user DACL shape as
            // `PipeSecurityAttributes::for_current_user` on create.
            nexus_ephemera_ipc_os::lock_pipe_to_current_user(handle)?;
            nexus_ephemera_ipc_os::assert_pipe_dacl_is_current_user_only(handle)
                .map_err(IpcError::from)?;
        }
        self.first_instance = false;
        Ok(server)
    }

    /// Create the next instance before `current` is dropped, so the pipe name
    /// is not free for another process to claim between requests.
    #[cfg(windows)]
    fn reserve_next_pipe(
        &mut self,
        current: tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> Result<(), IpcError> {
        match self.open_pipe() {
            Ok(next) => {
                drop(current);
                self.pending = Some(next);
                Ok(())
            }
            Err(err) => {
                // The connected instance still owns the name. Keep it if the
                // next create is denied, then fail closed.
                self.pending = Some(current);
                Err(err)
            }
        }
    }

    #[cfg(windows)]
    async fn accept(
        &mut self,
    ) -> Result<(tokio::net::windows::named_pipe::NamedPipeServer, u32), IpcError> {
        use std::os::windows::io::AsRawHandle;
        let server = match self.pending.take() {
            Some(server) => server,
            None => self.open_pipe()?,
        };
        if let Err(err) = server.connect().await {
            self.reserve_next_pipe(server)?;
            return Err(err.into());
        }
        let peer = match nexus_ephemera_ipc_os::pipe_peer(server.as_raw_handle() as isize) {
            Ok(peer) => peer,
            Err(_) => {
                self.reserve_next_pipe(server)?;
                return Err(note_auth_failure(IpcError::IdentityUnavailable));
            }
        };
        if peer.pid == 0 || !peer.same_user {
            let err = if peer.pid == 0 {
                IpcError::IdentityUnavailable
            } else {
                IpcError::IdentityRejected
            };
            self.reserve_next_pipe(server)?;
            return Err(note_auth_failure(err));
        }
        Ok((server, peer.pid))
    }
}

#[cfg(unix)]
fn listen<T>(
    config: DaemonConfig,
    agent: SecureTransactionAgent,
    transport: T,
) -> Result<BrokerDaemon<T>, IpcError> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::path::PathBuf::from(&config.listen);
    let mut listen_lock = match nexus_ephemera_ipc_os::ListenLock::acquire(&lock_path_for(&path)) {
        Ok(lock) => lock,
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock
            || err.kind() == std::io::ErrorKind::ResourceBusy
            || err.kind() == std::io::ErrorKind::AddrInUse
            || err.raw_os_error() == Some(11) // EAGAIN / EWOULDBLOCK
            || err.raw_os_error() == Some(16) // EBUSY
            || err.raw_os_error() == Some(98) // EADDRINUSE
            =>
        {
            return Err(IpcError::Protocol("listen socket is already in use"));
        }
        Err(err) => return Err(err.into()),
    };
    reclaim_unlocked_socket(&path)?;
    let listener = match tokio::net::UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(err)
            if err.kind() == std::io::ErrorKind::AddrInUse || err.raw_os_error() == Some(98) =>
        {
            return Err(IpcError::Protocol("listen socket is already in use"));
        }
        Err(err) => return Err(err.into()),
    };
    let socket_id = unix_file_id(&path)?;
    if let Err(err) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        remove_our_socket(&path, socket_id);
        return Err(err.into());
    }
    if unix_file_id(&path)? != socket_id {
        return Err(IpcError::Protocol("listen socket changed during bind"));
    }
    let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        remove_our_socket(&path, socket_id);
        return Err(IpcError::Protocol("socket mode is not 0600"));
    }
    listen_lock.record_pid()?;
    let daemon_uid = nexus_ephemera_ipc_os::current_uid()?;
    Ok(BrokerDaemon {
        agent,
        transport,
        allowlist: config.allowlist,
        max_payload_bytes: config.max_payload_bytes,
        timeout: config.timeout,
        listener,
        socket_path: path,
        socket_id,
        listen_lock,
        daemon_uid,
        idempotency: crate::idempotency::IdempotencyCache::new(
            config.idempotency_ttl,
            crate::idempotency::CACHE_CAP,
        ),
    })
}

#[cfg(unix)]
fn lock_path_for(path: &std::path::Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    std::path::PathBuf::from(name)
}

#[cfg(unix)]
fn unix_file_id(path: &std::path::Path) -> Result<(u64, u64), IpcError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(unix)]
fn remove_our_socket(path: &std::path::Path, id: (u64, u64)) {
    if unix_file_id(path).ok() == Some(id) {
        let _ = std::fs::remove_file(path);
    }
}

/// Unlink a socket only while this process holds the listen lock and nothing
/// is accepting on it. A live connect is left untouched.
#[cfg(unix)]
fn reclaim_unlocked_socket(path: &std::path::Path) -> Result<(), IpcError> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
        Ok(meta) if !meta.file_type().is_socket() => {
            Err(IpcError::Protocol("listen path is not a stale socket"))
        }
        Ok(_) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(stream) => {
                drop(stream);
                Err(IpcError::Protocol("listen socket is already in use"))
            }
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                match std::fs::metadata(path) {
                    Ok(meta) if meta.file_type().is_socket() => {
                        std::fs::remove_file(path)?;
                        Ok(())
                    }
                    Ok(_) => Err(IpcError::Protocol("listen path is not a stale socket")),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(err) => Err(err.into()),
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        },
    }
}

#[cfg(windows)]
fn listen<T: SecureTransport>(
    config: DaemonConfig,
    agent: SecureTransactionAgent,
    transport: T,
) -> Result<BrokerDaemon<T>, IpcError> {
    if !config.listen.starts_with(r"\\.\pipe\") {
        return Err(IpcError::Protocol(
            "windows listen path must be a named pipe",
        ));
    }
    let mut daemon = BrokerDaemon {
        agent,
        transport,
        allowlist: config.allowlist,
        max_payload_bytes: config.max_payload_bytes,
        timeout: config.timeout,
        pipe_name: config.listen,
        pending: None,
        first_instance: true,
        idempotency: crate::idempotency::IdempotencyCache::new(
            config.idempotency_ttl,
            crate::idempotency::CACHE_CAP,
        ),
    };
    let server = daemon.open_pipe()?;
    daemon.pending = Some(server);
    Ok(daemon)
}

impl<T> Drop for BrokerDaemon<T> {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            remove_our_socket(&self.socket_path, self.socket_id);
            // `listen_lock` drops after this and releases `flock` only; the
            // `<socket>.lock` path is never unlinked from Drop.
            let _lock = &self.listen_lock;
        }
    }
}

enum FrameBody {
    Call(TransactionReceipt),
    Metrics,
}

fn note_auth_failure(err: IpcError) -> IpcError {
    if matches!(
        err,
        IpcError::IdentityRejected | IpcError::IdentityUnavailable
    ) {
        crate::metrics::record_ipc_auth_failure();
    }
    err
}

fn dispatch_call<T: SecureTransport>(
    request: &WireRequest,
    allowlist: &[String],
    agent: &mut SecureTransactionAgent,
    transport: &mut T,
    cache: &mut crate::idempotency::IdempotencyCache,
) -> Result<TransactionReceipt, IpcError> {
    use crate::idempotency::{CachedBody, Lookup};
    if request.endpoint.is_empty()
        || request.payload_hash.is_empty()
        || !crate::idempotency::valid_key(&request.idempotency_key)
    {
        return Err(IpcError::Malformed);
    }
    if !allowlist.iter().any(|item| item == &request.endpoint) {
        return Err(IpcError::TargetDenied);
    }
    match cache.lookup(
        &request.idempotency_key,
        &request.endpoint,
        &request.payload_hash,
    ) {
        Lookup::Replay(outcome) => outcome,
        Lookup::Conflict => Err(IpcError::IdempotencyConflict),
        Lookup::Full => Err(IpcError::IdempotencyUnavailable),
        Lookup::Miss => {
            let started = std::time::Instant::now();
            let command = ExecuteWithPolicy {
                context_id: agent.context_id(),
                target_endpoint: request.endpoint.clone(),
                payload_hash: request.payload_hash.clone(),
                idempotency_key: request.idempotency_key.clone(),
            };
            let outcome = client_outcome(agent.execute(command, transport));
            if let Some(body) = CachedBody::from_outcome(&outcome) {
                let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                crate::metrics::record_dispatch_latency_us(micros);
                crate::metrics::record_terminal_outcome(matches!(
                    &outcome,
                    Err(IpcError::CleanupIncomplete(_))
                ));
                cache.commit(
                    &request.idempotency_key,
                    &request.endpoint,
                    &request.payload_hash,
                    body,
                );
            }
            outcome
        }
    }
}

async fn write_response<S>(
    stream: &mut S,
    outcome: &Result<TransactionReceipt, IpcError>,
    max_payload: usize,
    timeout: Duration,
) -> Result<(), IpcError>
where
    S: AsyncWrite + Unpin,
{
    let response = wire_from_outcome(outcome);
    let mut encoded = serde_json::to_vec(&response).map_err(|_| IpcError::Malformed)?;
    let written = write_frame(stream, &encoded, max_payload, timeout).await;
    encoded.zeroize();
    written
}

pub struct NexusClient {
    listen: String,
    timeout: Duration,
    max_payload_bytes: usize,
}

impl NexusClient {
    pub fn new(
        listen: impl Into<String>,
        timeout: Duration,
        max_payload_bytes: usize,
    ) -> Result<Self, IpcError> {
        if max_payload_bytes == 0 || max_payload_bytes > HARD_PAYLOAD_CAP {
            return Err(IpcError::Protocol("payload limit is outside 1..=65536"));
        }
        if timeout.is_zero() {
            return Err(IpcError::Protocol("timeout is outside 1ms..=120s"));
        }
        Ok(Self {
            listen: listen.into(),
            timeout,
            max_payload_bytes,
        })
    }

    pub async fn execute(
        &self,
        endpoint: &str,
        payload_hash: &str,
        idempotency_key: &str,
    ) -> Result<TransactionReceipt, IpcError> {
        if !crate::idempotency::valid_key(idempotency_key) {
            return Err(IpcError::Malformed);
        }
        let deadline = std::time::Instant::now() + self.timeout;
        let mut last = IpcError::TimedOut;
        while std::time::Instant::now() < deadline {
            match self.attempt(endpoint, payload_hash, idempotency_key).await {
                Ok(receipt) => return Ok(receipt),
                Err(err) if connection_retry(&err) => {
                    last = err;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(err) => return Err(err),
            }
        }
        Err(last)
    }

    pub async fn metrics(&self) -> Result<crate::metrics::MetricsSnapshot, IpcError> {
        let deadline = std::time::Instant::now() + self.timeout;
        let mut last = IpcError::TimedOut;
        while std::time::Instant::now() < deadline {
            match self.metrics_once().await {
                Ok(snapshot) => return Ok(snapshot),
                Err(err) if connection_retry(&err) => {
                    last = err;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(err) => return Err(err),
            }
        }
        Err(last)
    }

    async fn metrics_once(&self) -> Result<crate::metrics::MetricsSnapshot, IpcError> {
        let request = WireRequest {
            op: WireOp::Metrics,
            endpoint: String::new(),
            payload_hash: String::new(),
            idempotency_key: String::new(),
        };
        let mut body = serde_json::to_vec(&request).map_err(|_| IpcError::Malformed)?;
        let mut stream = connect_once(&self.listen).await?;
        let write = write_frame(&mut stream, &body, self.max_payload_bytes, self.timeout).await;
        body.zeroize();
        write?;
        let mut response = read_frame(&mut stream, self.max_payload_bytes, self.timeout).await?;
        let parsed: MetricsFrame =
            serde_json::from_slice(&response).map_err(|_| IpcError::Malformed)?;
        response.zeroize();
        let _ = stream.shutdown().await;
        parsed.into_snapshot()
    }

    async fn attempt(
        &self,
        endpoint: &str,
        payload_hash: &str,
        idempotency_key: &str,
    ) -> Result<TransactionReceipt, IpcError> {
        let request = WireRequest {
            op: WireOp::Call,
            endpoint: endpoint.to_string(),
            payload_hash: payload_hash.to_string(),
            idempotency_key: idempotency_key.to_string(),
        };
        let mut body = serde_json::to_vec(&request).map_err(|_| IpcError::Malformed)?;
        if body.len() > self.max_payload_bytes {
            body.zeroize();
            return Err(IpcError::PayloadTooLarge {
                limit: self.max_payload_bytes,
            });
        }
        let mut stream = connect_once(&self.listen).await?;
        let write = write_frame(&mut stream, &body, self.max_payload_bytes, self.timeout).await;
        body.zeroize();
        write?;
        let mut response = read_frame(&mut stream, self.max_payload_bytes, self.timeout).await?;
        let parsed: WireResponse =
            serde_json::from_slice(&response).map_err(|_| IpcError::Malformed)?;
        response.zeroize();
        let _ = stream.shutdown().await;
        parsed.into_result()
    }
}

fn connection_retry(err: &IpcError) -> bool {
    match err {
        IpcError::Io(err) => !matches!(err.kind(), std::io::ErrorKind::PermissionDenied),
        IpcError::TimedOut => true,
        _ => false,
    }
}

#[cfg(unix)]
type ClientStream = tokio::net::UnixStream;

#[cfg(windows)]
type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

async fn connect_once(listen: &str) -> Result<ClientStream, IpcError> {
    #[cfg(unix)]
    {
        let stream = tokio::net::UnixStream::connect(listen).await?;
        verify_unix_server(&stream, listen)?;
        Ok(stream)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let client = tokio::net::windows::named_pipe::ClientOptions::new().open(listen)?;
        let peer = nexus_ephemera_ipc_os::pipe_server_peer(client.as_raw_handle() as isize)
            .map_err(|_| IpcError::IdentityUnavailable)?;
        if peer.pid == 0 {
            return Err(IpcError::IdentityUnavailable);
        }
        if !peer.same_user {
            return Err(IpcError::IdentityRejected);
        }
        Ok(client)
    }
}

#[cfg(unix)]
fn verify_unix_server(stream: &tokio::net::UnixStream, path: &str) -> Result<(), IpcError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let cred = stream
        .peer_cred()
        .map_err(|_| IpcError::IdentityUnavailable)?;
    let peer_uid =
        u32::try_from(u64::from(cred.uid())).map_err(|_| IpcError::IdentityUnavailable)?;
    let peer_pid = cred
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0);
    let me = nexus_ephemera_ipc_os::current_uid()?;
    peer_is_authorized(peer_uid, peer_pid, me)?;
    let meta = std::fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 || meta.uid() != me {
        return Err(IpcError::IdentityRejected);
    }
    Ok(())
}

async fn read_frame<S>(
    stream: &mut S,
    max_payload: usize,
    timeout: Duration,
) -> Result<Vec<u8>, IpcError>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| IpcError::TimedOut)??;
    let len = usize::try_from(u32::from_le_bytes(len_buf)).unwrap_or(usize::MAX);
    if len == 0 || len > max_payload {
        return Err(IpcError::PayloadTooLarge { limit: max_payload });
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(timeout, stream.read_exact(&mut body))
        .await
        .map_err(|_| IpcError::TimedOut)??;
    Ok(body)
}

async fn write_frame<S>(
    stream: &mut S,
    body: &[u8],
    max_payload: usize,
    timeout: Duration,
) -> Result<(), IpcError>
where
    S: AsyncWrite + Unpin,
{
    if body.is_empty() || body.len() > max_payload {
        return Err(IpcError::PayloadTooLarge { limit: max_payload });
    }
    let len =
        u32::try_from(body.len()).map_err(|_| IpcError::PayloadTooLarge { limit: max_payload })?;
    let mut header = len.to_le_bytes();
    tokio::time::timeout(timeout, stream.write_all(&header))
        .await
        .map_err(|_| IpcError::TimedOut)??;
    header.zeroize();
    tokio::time::timeout(timeout, stream.write_all(body))
        .await
        .map_err(|_| IpcError::TimedOut)??;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum WireOp {
    #[default]
    Call,
    Metrics,
}

#[derive(Debug, Serialize, Deserialize)]
struct WireRequest {
    #[serde(default)]
    op: WireOp,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    payload_hash: String,
    #[serde(default)]
    idempotency_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MetricsFrame {
    kind: String,
    wipe_success_count: u64,
    quarantine_trigger_total: u64,
    cleanup_incomplete_rate: u64,
    ipc_auth_failure_total: u64,
    p95_dispatch_latency_us: u64,
}

impl From<crate::metrics::MetricsSnapshot> for MetricsFrame {
    fn from(snapshot: crate::metrics::MetricsSnapshot) -> Self {
        Self {
            kind: "metrics".to_string(),
            wipe_success_count: snapshot.wipe_success_count,
            quarantine_trigger_total: snapshot.quarantine_trigger_total,
            cleanup_incomplete_rate: snapshot.cleanup_incomplete_rate,
            ipc_auth_failure_total: snapshot.ipc_auth_failure_total,
            p95_dispatch_latency_us: snapshot.p95_dispatch_latency_us,
        }
    }
}

impl MetricsFrame {
    fn into_snapshot(self) -> Result<crate::metrics::MetricsSnapshot, IpcError> {
        if self.kind != "metrics" {
            return Err(IpcError::Malformed);
        }
        Ok(crate::metrics::MetricsSnapshot {
            wipe_success_count: self.wipe_success_count,
            quarantine_trigger_total: self.quarantine_trigger_total,
            cleanup_incomplete_rate: self.cleanup_incomplete_rate,
            ipc_auth_failure_total: self.ipc_auth_failure_total,
            p95_dispatch_latency_us: self.p95_dispatch_latency_us,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct WireResponse {
    kind: WireKind,
    code: String,
    transport_status: u16,
    seal_report: String,
    binding_digest_hex: String,
    target_endpoint: String,
    payload_hash: String,
    #[serde(default)]
    idempotency_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WireKind {
    Receipt,
    CleanupIncomplete,
    Rejected,
}

impl WireResponse {
    fn into_result(self) -> Result<TransactionReceipt, IpcError> {
        if self.kind == WireKind::Rejected {
            return Err(code_error(&self.code));
        }
        let Some(seal) = parse_seal(&self.seal_report) else {
            return Err(IpcError::Malformed);
        };
        let receipt = TransactionReceipt {
            target_endpoint: self.target_endpoint,
            payload_hash: self.payload_hash,
            binding_digest_hex: self.binding_digest_hex,
            transport_status: self.transport_status,
            seal_report: seal,
            idempotency_key: self.idempotency_key,
        };
        match (self.kind, seal) {
            // `Retained` is a successful multi-use call: the authority stayed
            // open, so there is no cleanup to complete. `Complete` is the only
            // successful seal. `Partial`, `Failed`, and an unknown name are not
            // receipts.
            (WireKind::Receipt, SealReport::Complete | SealReport::Retained) => Ok(receipt),
            (
                WireKind::Receipt | WireKind::CleanupIncomplete,
                SealReport::Partial | SealReport::Failed,
            ) => Err(IpcError::CleanupIncomplete(receipt)),
            (WireKind::CleanupIncomplete, SealReport::Complete | SealReport::Retained) => {
                Err(IpcError::Malformed)
            }
            (WireKind::Rejected, _) => Err(code_error("malformed")),
        }
    }
}

fn wire_from_outcome(outcome: &Result<TransactionReceipt, IpcError>) -> WireResponse {
    match outcome {
        Ok(receipt) => receipt_wire(WireKind::Receipt, "", receipt),
        Err(IpcError::CleanupIncomplete(receipt)) => {
            receipt_wire(WireKind::CleanupIncomplete, "cleanup_incomplete", receipt)
        }
        Err(err) => WireResponse {
            kind: WireKind::Rejected,
            code: code_name(err).to_string(),
            transport_status: 0,
            seal_report: String::new(),
            binding_digest_hex: String::new(),
            target_endpoint: String::new(),
            payload_hash: String::new(),
            idempotency_key: String::new(),
        },
    }
}

fn receipt_wire(kind: WireKind, code: &str, receipt: &TransactionReceipt) -> WireResponse {
    WireResponse {
        kind,
        code: code.to_string(),
        transport_status: receipt.transport_status,
        seal_report: seal_name(receipt.seal_report).to_string(),
        binding_digest_hex: receipt.binding_digest_hex.clone(),
        target_endpoint: receipt.target_endpoint.clone(),
        payload_hash: receipt.payload_hash.clone(),
        idempotency_key: receipt.idempotency_key.clone(),
    }
}

fn seal_name(report: SealReport) -> &'static str {
    match report {
        SealReport::Retained => "retained",
        SealReport::Complete => "complete",
        SealReport::Partial => "partial",
        SealReport::Failed => "failed",
    }
}

fn parse_seal(name: &str) -> Option<SealReport> {
    match name {
        "retained" => Some(SealReport::Retained),
        "complete" => Some(SealReport::Complete),
        "partial" => Some(SealReport::Partial),
        "failed" => Some(SealReport::Failed),
        _ => None,
    }
}

fn code_name(err: &IpcError) -> &'static str {
    match err {
        IpcError::TargetDenied => "target_denied",
        IpcError::PayloadTooLarge { .. } => "payload_too_large",
        IpcError::TimedOut => "timed_out",
        IpcError::IdentityRejected => "identity_rejected",
        IpcError::IdentityUnavailable => "identity_unavailable",
        IpcError::Malformed => "malformed",
        IpcError::CleanupIncomplete(_) => "cleanup_incomplete",
        IpcError::IdempotencyConflict => "idempotency_conflict",
        IpcError::IdempotencyUnavailable => "idempotency_unavailable",
        _ => "rejected",
    }
}

fn code_error(code: &str) -> IpcError {
    match code {
        "target_denied" => IpcError::TargetDenied,
        "payload_too_large" => IpcError::PayloadTooLarge { limit: 0 },
        "timed_out" => IpcError::TimedOut,
        "identity_rejected" => IpcError::IdentityRejected,
        "identity_unavailable" => IpcError::IdentityUnavailable,
        "malformed" => IpcError::Malformed,
        "cleanup_incomplete" => IpcError::Protocol("cleanup status missing receipt"),
        "idempotency_conflict" => IpcError::IdempotencyConflict,
        "idempotency_unavailable" => IpcError::IdempotencyUnavailable,
        _ => IpcError::Protocol("request rejected"),
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("nexus-ephemera ipc requires unix or windows");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_policy_rejects_missing_and_foreign_callers() {
        assert!(peer_is_authorized(7, Some(42), 7).is_ok());
        assert!(matches!(
            peer_is_authorized(7, Some(42), 8),
            Err(IpcError::IdentityRejected)
        ));
        assert!(matches!(
            peer_is_authorized(7, None, 7),
            Err(IpcError::IdentityUnavailable)
        ));
        assert!(matches!(
            peer_is_authorized(7, Some(0), 7),
            Err(IpcError::IdentityUnavailable)
        ));
    }

    #[test]
    fn cleanup_incomplete_is_not_a_receipt() {
        let receipt = sample(SealReport::Partial);
        let err = client_outcome(Err(BrokerError::CleanupIncomplete(receipt))).unwrap_err();
        assert!(matches!(
            err,
            IpcError::CleanupIncomplete(receipt) if receipt.seal_report == SealReport::Partial
        ));
        let err = client_outcome(Ok(sample(SealReport::Failed))).unwrap_err();
        assert!(matches!(
            err,
            IpcError::CleanupIncomplete(receipt) if receipt.seal_report == SealReport::Failed
        ));
    }

    #[test]
    fn unknown_or_failed_seal_is_not_a_receipt() {
        assert!(matches!(
            wire(WireKind::Receipt, "complete").into_result(),
            Ok(receipt) if receipt.seal_report == SealReport::Complete
        ));
        assert!(matches!(
            wire(WireKind::Receipt, "retained").into_result(),
            Ok(receipt) if receipt.seal_report == SealReport::Retained
        ));
        assert!(matches!(
            wire(WireKind::Receipt, "failed").into_result(),
            Err(IpcError::CleanupIncomplete(receipt))
                if receipt.seal_report == SealReport::Failed
        ));
        assert!(matches!(
            wire(WireKind::Receipt, "partial").into_result(),
            Err(IpcError::CleanupIncomplete(receipt))
                if receipt.seal_report == SealReport::Partial
        ));
        assert!(matches!(
            wire(WireKind::Receipt, "nope").into_result(),
            Err(IpcError::Malformed)
        ));
        assert!(matches!(
            wire(WireKind::CleanupIncomplete, "failed").into_result(),
            Err(IpcError::CleanupIncomplete(_))
        ));
        assert!(matches!(
            wire(WireKind::CleanupIncomplete, "complete").into_result(),
            Err(IpcError::Malformed)
        ));
    }

    fn wire(kind: WireKind, seal: &str) -> WireResponse {
        WireResponse {
            kind,
            code: String::new(),
            transport_status: 204,
            seal_report: seal.to_string(),
            binding_digest_hex: "ab".into(),
            target_endpoint: "https://provider.example/charge".into(),
            payload_hash: "hash".into(),
            idempotency_key: "sample-key".into(),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_socket_is_not_unlinked() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "nexus-ephemera-live-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"not-a-socket").expect("regular file");
        let mut secret = b"socket-guard-secret".to_vec();
        let err = match BrokerDaemon::bind(socket_config(&path), &mut secret, LocalAcceptTransport)
            .await
        {
            Ok(_) => panic!("regular file was accepted"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            IpcError::Protocol("listen path is not a stale socket")
        ));
        assert!(path.is_file());
        std::fs::remove_file(&path).expect("remove regular file");

        let listener = std::os::unix::net::UnixListener::bind(&path).expect("live listener");
        let mut secret = b"socket-guard-secret".to_vec();
        let err = match BrokerDaemon::bind(socket_config(&path), &mut secret, LocalAcceptTransport)
            .await
        {
            Ok(_) => panic!("live socket was replaced"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            IpcError::Protocol("listen socket is already in use")
        ));
        assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
        drop(listener);

        let mut secret = b"socket-guard-secret".to_vec();
        let daemon = BrokerDaemon::bind(socket_config(&path), &mut secret, LocalAcceptTransport)
            .await
            .expect("stale socket reclaimed");
        let mut secret = b"socket-guard-secret".to_vec();
        let err = match BrokerDaemon::bind(socket_config(&path), &mut secret, LocalAcceptTransport)
            .await
        {
            Ok(_) => panic!("second daemon took a locked socket"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            IpcError::Protocol("listen socket is already in use")
        ));
        let held = std::path::PathBuf::from(format!("{}.held", path.display()));
        std::fs::rename(&path, &held).expect("rename owned socket");
        let foreign = std::os::unix::net::UnixListener::bind(&path).expect("foreign socket");
        drop(daemon);
        assert!(
            std::os::unix::net::UnixStream::connect(&path).is_ok(),
            "drop removed a socket this daemon does not own"
        );
        drop(foreign);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&held);
        let _ = std::fs::remove_file(lock_path_for(&path));
    }

    #[cfg(unix)]
    fn socket_config(path: &std::path::Path) -> DaemonConfig {
        DaemonConfig {
            listen: path.to_string_lossy().into_owned(),
            allowlist: vec!["https://provider.example/charge".to_string()],
            max_payload_bytes: 1024,
            timeout: Duration::from_secs(1),
            idempotency_ttl: Duration::from_secs(60),
            single_use: false,
        }
    }

    fn sample(seal_report: SealReport) -> TransactionReceipt {
        TransactionReceipt {
            target_endpoint: "https://provider.example/charge".into(),
            payload_hash: "hash".into(),
            binding_digest_hex: "ab".into(),
            transport_status: 200,
            seal_report,
            idempotency_key: "sample-key".into(),
        }
    }
}
