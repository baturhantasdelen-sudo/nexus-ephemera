//! Broker daemon. The key is read from stdin and never from argv.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nexus_ephemera::broker::{AuthorizedCall, BrokerError, SecureTransport, TransportReply};
use nexus_ephemera::enterprise::{ServiceAccount, TenantDirectory};
use nexus_ephemera::enterprise_runtime::{
    FileCheckpointSink, HttpPayloadTransport, RedisIdempotency, TenantAuthority,
};
use nexus_ephemera::ipc::{BrokerDaemon, DaemonConfig, IpcError, LocalAcceptTransport};
use nexus_ephemera_memlock::MemLockError;
use zeroize::{Zeroize, Zeroizing};

struct LaunchArgs {
    config: DaemonConfig,
    max_connections: Option<u64>,
    enterprise_path: Option<std::path::PathBuf>,
    package_dir: Option<std::path::PathBuf>,
    listen_explicit: bool,
    reference_mode: bool,
    seal_package: bool,
    check_package: bool,
    init_package: bool,
    provision_store: bool,
    issue_token: Option<(String, String, u64)>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EnterpriseFile {
    accounts: Vec<ServiceAccount>,
    redis_url: String,
    namespace: String,
    capacity: usize,
    checkpoint_path: std::path::PathBuf,
    #[serde(default)]
    provider_ca_der: Option<std::path::PathBuf>,
    #[serde(default)]
    github_policy: Option<std::path::PathBuf>,
    #[serde(default)]
    github_token_file: Option<std::path::PathBuf>,
}

impl Drop for EnterpriseFile {
    fn drop(&mut self) {
        self.redis_url.zeroize();
    }
}

enum DaemonTransport {
    Local(LocalAcceptTransport),
    Http(HttpPayloadTransport),
    Github(nexus_ephemera::adapters::github_production::GithubTransport),
}
impl SecureTransport for DaemonTransport {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        match self {
            Self::Local(inner) => inner.dispatch(call),
            Self::Http(inner) => inner.dispatch(call),
            Self::Github(inner) => inner.dispatch(call),
        }
    }
    fn dispatch_payload(
        &mut self,
        call: &AuthorizedCall<'_>,
        payload: &[u8],
    ) -> Result<TransportReply, BrokerError> {
        match self {
            Self::Local(_) => Err(BrokerError::Transport(
                "enterprise provider is not configured",
            )),
            Self::Http(inner) => inner.dispatch_payload(call, payload),
            Self::Github(inner) => inner.dispatch_payload(call, payload),
        }
    }
}

const SECRET_MAX: usize = 4096;
const STDIN_PROBE: usize = SECRET_MAX + 1;
/// Upper bound to wait for the stdin reader to rendezvous before the secret timer starts.
const READER_HANDSHAKE_GRACE: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nexus-daemon: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), IpcError> {
    harden_before_secret()?;
    let args = parse_args(std::env::args().skip(1))?;
    if let Some(dir) = &args.package_dir {
        if args.init_package {
            nexus_ephemera::packaging::write_template(
                dir,
                &args.config.listen,
                include_bytes!("../policies/pilot_support_agent.json"),
            )?;
            nexus_ephemera::packaging::seal(dir)?;
            println!("package-created");
            return Ok(());
        }
        if args.seal_package {
            nexus_ephemera::packaging::seal(dir)?;
        }
        if args.check_package || args.seal_package {
            let _loaded = nexus_ephemera::packaging::load(dir)?;
            println!("package-ok");
            return Ok(());
        }
    } else if args.seal_package || args.check_package || args.init_package {
        return Err(IpcError::Protocol("package directory is required"));
    }
    let mut config = args.config;
    let package = args
        .package_dir
        .as_ref()
        .map(|dir| nexus_ephemera::packaging::load(dir))
        .transpose()?;
    if let Some(package) = &package {
        if args.listen_explicit && config.listen != package.listen() {
            return Err(IpcError::Protocol("listen does not match the package"));
        }
        if !config.allowlist.is_empty() {
            return Err(IpcError::Protocol(
                "package config already sets the allowlist",
            ));
        }
        config.listen = package.listen().to_string();
        config.allowlist = vec![package.allow().to_string()];
        config.timeout = package.timeout();
    }
    if args.enterprise_path.is_none() && !args.reference_mode {
        return Err(IpcError::Protocol(
            "enterprise configuration required; --reference-mode is simulation only",
        ));
    }
    if args.enterprise_path.is_some() && args.reference_mode {
        return Err(IpcError::Protocol(
            "reference and enterprise modes cannot be combined",
        ));
    }
    let cleanup_budget = config.timeout.saturating_add(Duration::from_secs(10));
    let max_connections = args.max_connections;
    let mut secret = read_secret(config.timeout)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    #[cfg(unix)]
    let (mut terminate, mut interrupt) = runtime.block_on(async {
        Ok::<_, std::io::Error>((
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
        ))
    })?;
    let mut daemon = if let Some(path) = args.enterprise_path {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        nexus_ephemera_ipc_os::assert_private_directory(parent)?;
        let bytes = Zeroizing::new(nexus_ephemera_ipc_os::read_private_file(&path, 65536)?);
        let mut enterprise: EnterpriseFile = serde_json::from_slice(&bytes)
            .map_err(|_| IpcError::Protocol("invalid enterprise configuration"))?;
        let directory = TenantDirectory::try_new(std::mem::take(&mut enterprise.accounts))?;
        if let Some((account, role, ttl)) = args.issue_token {
            let authority = TenantAuthority::new(directory, &secret)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| IpcError::Malformed)?;
            let now = u64::try_from(now.as_millis()).map_err(|_| IpcError::Malformed)?;
            let expires = now.checked_add(ttl).ok_or(IpcError::Malformed)?;
            let token = Zeroizing::new(authority.issue_token(&account, &role, expires, now)?);
            writeln!(std::io::stdout(), "{}", token.as_str())?;
            authority.close()?;
            return Ok(());
        }
        let store = Arc::new(RedisIdempotency::new(
            &enterprise.redis_url,
            &enterprise.namespace,
            enterprise.capacity,
            Duration::from_secs(2),
        )?);
        if args.provision_store {
            store.provision()?;
        }
        let sink = Arc::new(FileCheckpointSink::new(enterprise.checkpoint_path.clone()));
        let mut http = HttpPayloadTransport::new(config.timeout)?;
        if let Some(ca) = &enterprise.provider_ca_der {
            http = http.with_ca_der(&nexus_ephemera_ipc_os::read_private_file(ca, 65536)?)?;
        }
        let transport = match (&enterprise.github_policy, &enterprise.github_token_file) {
            (Some(policy_path), Some(token_path)) => {
                let policy = nexus_ephemera::adapters::github::GithubIssuePolicy::load(
                    &nexus_ephemera_ipc_os::read_private_file(policy_path, 65536)?,
                )?;
                let mut token =
                    Zeroizing::new(nexus_ephemera_ipc_os::read_private_file(token_path, 256)?);
                DaemonTransport::Github(
                    nexus_ephemera::adapters::github_production::GithubTransport::new(
                        http, policy, &mut token,
                    )?,
                )
            }
            (None, None) => DaemonTransport::Http(http),
            _ => {
                return Err(IpcError::Protocol(
                    "both GitHub policy and token file are required",
                ));
            }
        };
        runtime.block_on(BrokerDaemon::bind_enterprise(
            config,
            secret.as_mut_slice(),
            transport,
            directory,
            store,
            sink,
        ))?
    } else {
        if package.is_some() {
            return Err(IpcError::Protocol(
                "package execution requires enterprise configuration",
            ));
        }
        if args.provision_store || args.issue_token.is_some() {
            return Err(IpcError::Protocol("enterprise configuration is required"));
        }
        runtime.block_on(BrokerDaemon::bind(
            config,
            secret.as_mut_slice(),
            DaemonTransport::Local(LocalAcceptTransport),
        ))?
    };
    if let Some(package) = package {
        daemon.set_health_source(package.watch());
    }
    drop(secret);
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "ready").map_err(IpcError::from)?;
    stdout.flush().map_err(IpcError::from)?;
    drop(stdout);
    let served = runtime.block_on(async {
        let shutdown = async {
            #[cfg(unix)]
            {
                tokio::select! {
                    _ = interrupt.recv() => Ok::<(), std::io::Error>(()),
                    _ = terminate.recv() => Ok(()),
                }
            }
            #[cfg(not(unix))]
            tokio::signal::ctrl_c().await
        };
        tokio::pin!(shutdown);
        let mut connections = 0u64;
        loop {
            let outcome = tokio::select! {
                signal = &mut shutdown => {
                    signal.map_err(IpcError::from)?;
                    break Ok(());
                }
                result = daemon.serve_one() => result,
            };
            connections += 1;
            match outcome {
                Ok(nexus_ephemera::ipc::ServedCall::Call { peer_pid, .. })
                | Ok(nexus_ephemera::ipc::ServedCall::Metrics { peer_pid })
                | Ok(nexus_ephemera::ipc::ServedCall::Health { peer_pid }) => {
                    eprintln!("peer_ok pid={peer_pid}");
                }
                Err(err) if nexus_ephemera::ipc::per_connection(&err) => {}
                Err(err) => return Err(err),
            }
            if max_connections.is_some_and(|limit| connections >= limit) {
                break Ok(());
            }
        }
    });
    // Always inspect cleanup, including errors and signal cancellation. A
    // timed-out provider must not be reported as a successful shutdown.
    let cleanup = daemon.shutdown();
    // A native edge can have a deadline longer than trigger's default ten
    // seconds. On signal cancellation keep draining through that bounded I/O
    // instead of terminating the process while its permit/key is still live.
    let wipe = nexus_ephemera::apoptosis::trigger_apoptosis()
        .or_else(|_| nexus_ephemera::apoptosis::wait_apoptosis_complete(cleanup_budget));
    cleanup?;
    if !matches!(wipe, Ok(nexus_ephemera::apoptosis::WipeStatus::Complete)) {
        return Err(IpcError::Protocol("daemon global cleanup incomplete"));
    }
    eprintln!("shutdown seal=complete");
    served
}

fn harden_before_secret() -> Result<(), IpcError> {
    nexus_ephemera_memlock::harden_process_memory().map_err(|err| {
        IpcError::Protocol(match err {
            MemLockError::PrepareFailed => "memlock fail-closed: PrepareFailed",
            MemLockError::LockFailed => "memlock fail-closed: LockFailed",
            MemLockError::UnlockFailed => "memlock fail-closed: UnlockFailed",
            MemLockError::UnsupportedPlatform => "memlock fail-closed: UnsupportedPlatform",
            MemLockError::InvalidLength => "memlock fail-closed: InvalidLength",
            MemLockError::ArithmeticOverflow => "memlock fail-closed: ArithmeticOverflow",
            MemLockError::Wiped => "memlock fail-closed: Wiped",
            MemLockError::BufferWiped => "memlock fail-closed: BufferWiped",
            MemLockError::NotWritable => "memlock fail-closed: NotWritable",
            MemLockError::ProcessHardeningFailed => "memlock fail-closed: ProcessHardeningFailed",
        })
    })
}

fn read_secret(timeout: std::time::Duration) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let shutdown_reader = Arc::clone(&shutdown);
    let reader = std::thread::Builder::new()
        .name("stdin-key".into())
        .spawn(move || {
            #[cfg(windows)]
            {
                let _ = READER_THREAD_ID.set(nexus_ephemera_ipc_os::current_thread_id());
            }
            if ready_tx.send(()).is_err() {
                return;
            }
            let _ = result_tx.send(read_secret_capped(timeout, &shutdown_reader));
        })
        .map_err(IpcError::from)?;
    if let Err(err) = ready_rx.recv_timeout(READER_HANDSHAKE_GRACE) {
        drop(ready_rx);
        drop(result_rx);
        stop_reader_thread(reader, &shutdown)?;
        return Err(match err {
            std::sync::mpsc::RecvTimeoutError::Timeout => {
                IpcError::Protocol("daemon secret reader failed to start")
            }
            std::sync::mpsc::RecvTimeoutError::Disconnected => {
                IpcError::Protocol("daemon secret reader stopped")
            }
        });
    }
    let wait = if cfg!(windows) {
        timeout
    } else {
        timeout.saturating_add(std::time::Duration::from_millis(250))
    };
    let received = result_rx.recv_timeout(wait);
    let succeeded = matches!(received, Ok(Ok(_)));
    if succeeded {
        join_reader(reader)?;
        discard_late_stdin_results(&result_rx);
    } else {
        drop(result_rx);
        stop_reader_thread(reader, &shutdown)?;
    }
    match received {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(IpcError::Protocol(
            "daemon secret was not closed within the timeout",
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(IpcError::Protocol("daemon secret reader stopped"))
        }
    }
}

fn stop_reader_thread(
    reader: std::thread::JoinHandle<()>,
    shutdown: &AtomicBool,
) -> Result<(), IpcError> {
    shutdown.store(true, Ordering::SeqCst);
    for _ in 0..20 {
        cancel_reader();
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    join_reader(reader)
}

fn discard_late_stdin_results(
    rx: &std::sync::mpsc::Receiver<Result<Zeroizing<Vec<u8>>, IpcError>>,
) {
    while let Ok(result) = rx.try_recv() {
        drop(result);
    }
}

fn join_reader(reader: std::thread::JoinHandle<()>) -> Result<(), IpcError> {
    reader
        .join()
        .map_err(|_| IpcError::Protocol("daemon secret reader stopped"))
}

#[cfg(windows)]
fn cancel_reader() {
    let Some(id) = READER_THREAD_ID.get().copied() else {
        return;
    };
    let _ = nexus_ephemera_ipc_os::cancel_thread_id(id);
}

#[cfg(not(windows))]
fn cancel_reader() {}

#[cfg(windows)]
static READER_THREAD_ID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

fn read_secret_capped(
    timeout: std::time::Duration,
    shutdown: &AtomicBool,
) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    #[cfg(unix)]
    let read = read_secret_unix(timeout, shutdown);
    #[cfg(windows)]
    let read = {
        let _ = timeout;
        read_secret_windows(shutdown)
    };
    #[cfg(not(any(unix, windows)))]
    let read = {
        let _ = timeout;
        Err(IpcError::Protocol(
            "daemon secret length is outside 1..=4096",
        ))
    };
    let buffer = Zeroizing::new(read?);
    if buffer.is_empty() || buffer.len() > SECRET_MAX {
        return Err(IpcError::Protocol(
            "daemon secret length is outside 1..=4096",
        ));
    }
    Ok(buffer)
}

#[cfg(unix)]
fn read_secret_unix(
    timeout: std::time::Duration,
    shutdown: &AtomicBool,
) -> Result<Vec<u8>, IpcError> {
    nexus_ephemera_ipc_os::read_stdin_bounded_with_cancel(STDIN_PROBE, timeout, shutdown).map_err(
        |err| {
            if err.kind() == std::io::ErrorKind::TimedOut {
                IpcError::Protocol("daemon secret was not closed within the timeout")
            } else {
                IpcError::from(err)
            }
        },
    )
}

#[cfg(windows)]
fn read_secret_windows(shutdown: &AtomicBool) -> Result<Vec<u8>, IpcError> {
    let mut buffer = Zeroizing::new(vec![0u8; STDIN_PROBE]);
    let mut filled = 0usize;
    while filled < STDIN_PROBE {
        match nexus_ephemera_ipc_os::poll_stdin_read(&mut buffer[filled..], shutdown) {
            Ok(nexus_ephemera_ipc_os::StdinPoll::Read(n)) => filled += n,
            Ok(nexus_ephemera_ipc_os::StdinPoll::Eof) => break,
            Ok(nexus_ephemera_ipc_os::StdinPoll::Idle) => continue,
            Ok(nexus_ephemera_ipc_os::StdinPoll::Cancelled) => {
                return Err(IpcError::Protocol(
                    "daemon secret was not closed within the timeout",
                ));
            }
            Err(err) => return Err(err.into()),
        }
    }
    buffer.truncate(filled);
    let secret = buffer[..filled].to_vec();
    Ok(secret)
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<LaunchArgs, IpcError> {
    let mut listen = default_listen().to_string();
    let mut allowlist = Vec::new();
    let mut max_payload_bytes = 64 * 1024;
    let mut timeout_ms: u64 = 5_000;
    let mut idempotency_ttl_ms: u64 = 900_000;
    let mut single_use = false;
    let mut max_connections = None;
    let mut enterprise_path = None;
    let mut package_dir = None;
    let mut listen_explicit = false;
    let mut seal_package = false;
    let mut check_package = false;
    let mut init_package = false;
    let mut provision_store = false;
    let mut issue_token = None;
    let mut reference_mode = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--reference-mode" => reference_mode = true,
            "--enterprise-config" => {
                enterprise_path = Some(std::path::PathBuf::from(required(
                    &mut args,
                    "--enterprise-config",
                )?))
            }
            "--package" => {
                package_dir = Some(std::path::PathBuf::from(required(&mut args, "--package")?))
            }
            "--seal" => seal_package = true,
            "--check" => check_package = true,
            "--init-package" => init_package = true,
            "--provision-store" => provision_store = true,
            "--issue-tenant-token" => {
                let account = required(&mut args, "--issue-tenant-token")?;
                let role = required(&mut args, "--issue-tenant-token")?;
                let ttl = required(&mut args, "--issue-tenant-token")?
                    .parse::<u64>()
                    .map_err(|_| IpcError::Malformed)?;
                issue_token = Some((account, role, ttl));
            }
            "--max-connections" => {
                let count: u64 = required(&mut args, "--max-connections")?
                    .parse()
                    .map_err(|_| IpcError::Protocol("invalid connection limit"))?;
                if count == 0 {
                    return Err(IpcError::Protocol("connection limit must be positive"));
                }
                max_connections = Some(count);
            }
            "--listen" => {
                listen = required(&mut args, "--listen")?;
                listen_explicit = true;
            }
            "--allow" => allowlist.push(required(&mut args, "--allow")?),
            "--max-payload" => {
                max_payload_bytes = required(&mut args, "--max-payload")?
                    .parse()
                    .map_err(|_| IpcError::Protocol("max-payload is not a number"))?;
            }
            "--timeout-ms" => {
                timeout_ms = required(&mut args, "--timeout-ms")?
                    .parse()
                    .map_err(|_| IpcError::Protocol("timeout-ms is not a number"))?;
            }
            "--idempotency-ttl-ms" => {
                idempotency_ttl_ms = required(&mut args, "--idempotency-ttl-ms")?
                    .parse()
                    .map_err(|_| IpcError::Protocol("idempotency-ttl-ms is not a number"))?;
            }
            "--single-use" => single_use = true,
            "--help" => {
                println!(
                    "nexus-daemon --listen PATH --allow ENDPOINT [--allow ENDPOINT] [--max-payload N] [--timeout-ms N] [--idempotency-ttl-ms N] [--single-use] [--max-connections N] [--enterprise-config PATH | --reference-mode] [--provision-store] [--issue-tenant-token ACCOUNT ROLE TTL_MS] [--package DIR] [--init-package] [--seal] [--check]\nkey is read from stdin; Ctrl-C requests verified cleanup; enterprise mode requires a durable Redis namespace and bound payload requests; --package validates config.toml, .env, and the pilot policy before the broker starts"
                );
                std::process::exit(0);
            }
            _ => return Err(IpcError::Protocol("unknown argument")),
        }
    }
    Ok(LaunchArgs {
        config: DaemonConfig {
            listen,
            allowlist,
            max_payload_bytes,
            timeout: Duration::from_millis(timeout_ms),
            idempotency_ttl: Duration::from_millis(idempotency_ttl_ms),
            single_use,
        },
        max_connections,
        enterprise_path,
        package_dir,
        listen_explicit,
        reference_mode,
        seal_package,
        check_package,
        init_package,
        provision_store,
        issue_token,
    })
}

fn required(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, IpcError> {
    args.next()
        .filter(|value| !value.is_empty())
        .ok_or(IpcError::Protocol(match flag {
            "--listen" => "missing listen path",
            "--allow" => "missing allowlist endpoint",
            "--max-payload" => "missing max-payload",
            "--timeout-ms" => "missing timeout-ms",
            "--idempotency-ttl-ms" => "missing idempotency ttl",
            _ => "missing argument",
        }))
}

fn default_listen() -> &'static str {
    #[cfg(unix)]
    {
        nexus_ephemera::ipc::DEFAULT_UNIX_SOCK
    }
    #[cfg(windows)]
    {
        nexus_ephemera::ipc::DEFAULT_WINDOWS_PIPE
    }
}
