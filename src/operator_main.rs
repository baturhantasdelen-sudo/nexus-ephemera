//! Offline operator boundary. No agent IPC, no claim mutation, no retry command.
#![forbid(unsafe_code)]
use nexus_ephemera::enterprise_runtime::{OperationState, RedisIdempotency};
use serde::Deserialize;
use std::{path::Path, process::ExitCode, time::Duration};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config<'a> {
    redis_url: &'a str,
    namespace: &'a str,
    capacity: usize,
}

fn run() -> Result<OperationState, ()> {
    nexus_ephemera_memlock::harden_process_memory().map_err(|_| ())?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 || args[0] != "inspect" {
        return Err(());
    }
    let path = Path::new(&args[1]);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    nexus_ephemera_ipc_os::assert_private_directory(parent).map_err(|_| ())?;
    let raw = Zeroizing::new(nexus_ephemera_ipc_os::read_private_file(path, 8192).map_err(|_| ())?);
    let config: Config<'_> = serde_json::from_slice(&raw).map_err(|_| ())?;
    let key_path = Path::new(&args[3]);
    let key_parent = key_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    nexus_ephemera_ipc_os::assert_private_directory(key_parent).map_err(|_| ())?;
    let key =
        Zeroizing::new(nexus_ephemera_ipc_os::read_private_file(key_path, 256).map_err(|_| ())?);
    let key = std::str::from_utf8(&key).map_err(|_| ())?;
    let store = RedisIdempotency::new(
        config.redis_url,
        config.namespace,
        config.capacity,
        Duration::from_secs(2),
    )
    .map_err(|_| ())?;
    store.inspect_operation(&args[2], key).map_err(|_| ())
}
fn main() -> ExitCode {
    let result = std::panic::catch_unwind(run).unwrap_or(Err(()));
    let wipe = nexus_ephemera::apoptosis::trigger_apoptosis();
    if !matches!(wipe, Ok(nexus_ephemera::apoptosis::WipeStatus::Complete)) {
        eprintln!("operator cleanup incomplete");
        return ExitCode::from(3);
    }
    let Ok(state) = result else {
        eprintln!(
            "operator inspection denied or unavailable; usage: nexus-operator inspect PRIVATE_CONFIG ACCOUNT PRIVATE_REQUEST_KEY_FILE"
        );
        return ExitCode::from(1);
    };
    use std::io::Write;
    let Ok(output) = serde_json::to_string(&state) else {
        return ExitCode::from(1);
    };
    if writeln!(std::io::stdout().lock(), "{output}").is_err() {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
