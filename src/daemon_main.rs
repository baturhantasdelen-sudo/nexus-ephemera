//! Broker daemon. The key is read from stdin and never from argv.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nexus_ephemera::ipc::{BrokerDaemon, DaemonConfig, IpcError, LocalAcceptTransport};
use nexus_ephemera_memlock::MemLockError;
use zeroize::Zeroizing;

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
    let config = parse_args(std::env::args().skip(1))?;
    let mut secret = read_secret(config.timeout)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut daemon = runtime.block_on(BrokerDaemon::bind(
        config,
        secret.as_mut_slice(),
        LocalAcceptTransport,
    ))?;
    drop(secret);
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "ready").map_err(IpcError::from)?;
    stdout.flush().map_err(IpcError::from)?;
    drop(stdout);
    runtime.block_on(async move {
        loop {
            match daemon.serve_one().await {
                Ok(nexus_ephemera::ipc::ServedCall::Call { peer_pid, .. })
                | Ok(nexus_ephemera::ipc::ServedCall::Metrics { peer_pid }) => {
                    eprintln!("peer_ok pid={peer_pid}");
                }
                Err(err) if nexus_ephemera::ipc::per_connection(&err) => {}
                Err(err) => return Err(err),
            }
        }
    })
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

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<DaemonConfig, IpcError> {
    let mut listen = default_listen().to_string();
    let mut allowlist = Vec::new();
    let mut max_payload_bytes = 64 * 1024;
    let mut timeout_ms: u64 = 5_000;
    let mut idempotency_ttl_ms: u64 = 900_000;
    let mut single_use = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = required(&mut args, "--listen")?,
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
                    "nexus-daemon --listen PATH --allow ENDPOINT [--allow ENDPOINT] [--max-payload N] [--timeout-ms N] [--idempotency-ttl-ms N] [--single-use]\nkey is read from stdin"
                );
                std::process::exit(0);
            }
            _ => return Err(IpcError::Protocol("unknown argument")),
        }
    }
    Ok(DaemonConfig {
        listen,
        allowlist,
        max_payload_bytes,
        timeout: Duration::from_millis(timeout_ms),
        idempotency_ttl: Duration::from_millis(idempotency_ttl_ms),
        single_use,
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
