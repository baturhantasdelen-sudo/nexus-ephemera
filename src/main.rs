//! Nexus Ephemera — ana giriş noktası ve Tokio orkestrasyonu.

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use nexus_ephemera::apoptosis::{self, WipeStatus, trigger_apoptosis, wait_apoptosis_complete};
use nexus_ephemera::{mesh, scout};

struct ExitApoptosisGuard;

impl Drop for ExitApoptosisGuard {
    fn drop(&mut self) {
        if apoptosis::current_thread_holds_permit() {
            let _ = apoptosis::request_apoptosis();
            return;
        }
        let _ = apoptosis::request_apoptosis();
        let _ = wait_apoptosis_complete(Duration::from_secs(10));
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let _exit_guard = ExitApoptosisGuard;

    let agent_result = { run().await };

    let wipe_result = trigger_apoptosis();

    match (agent_result, wipe_result) {
        (Ok(()), Ok(WipeStatus::Complete)) => ExitCode::SUCCESS,
        (Ok(()), _) => ExitCode::from(2),
        (Err(_), Ok(WipeStatus::Complete)) => ExitCode::FAILURE,
        (Err(_), _) => ExitCode::from(3),
    }
}

async fn run() -> Result<(), String> {
    nexus_ephemera_memlock::harden_process_memory()
        .map_err(|e| format!("process memory harden: {e:?}"))?;
    scout::initialize().await?;
    mesh::initialize().await?;
    mesh::ensure_mesh_cleanup_registered();
    apoptosis::register_shutdown_hooks();

    let report = scout::run_discovery_cycle().await?;
    mesh::ingest_scout_handoff(report.into_handoff())?;
    mesh::run_event_loop().await?;

    Ok(())
}
