//! Locked allocation, in-place AEAD, and broker execute latency.
//!
//! Prints nearest-rank p95 and p99. These are local measurements, not a
//! certification. The sample loop does not print key material.

use std::hint::black_box;
use std::time::{Duration, Instant};

use nexus_ephemera::apoptosis::EphemeralBuffer;
use nexus_ephemera::broker::{
    AuthorizedCall, BrokerError, ExecuteWithPolicy, SecureTransactionAgent, SecureTransport,
    TransportReply,
};
use nexus_ephemera::crypto::{self, open_into, seal_plaintext};
use nexus_ephemera::exposure::ExposureTags;

const SAMPLES: usize = 64;
const WARMUP: usize = 8;

struct OkTransport;

impl SecureTransport for OkTransport {
    fn dispatch(&mut self, call: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        black_box(call.binding_digest_hex.len());
        Ok(TransportReply { status: 204 })
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("lifecycle bench: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let alloc = measure(SAMPLES, WARMUP, measure_locked_alloc)?;
    let aead = measure(SAMPLES, WARMUP, measure_seal_open)?;
    let agent = measure(SAMPLES, WARMUP, measure_agent_execute)?;
    println!("samples={SAMPLES}");
    report("locked_alloc", &alloc);
    report("seal_open", &aead);
    report("agent_execute", &agent);
    Ok(())
}

fn measure_locked_alloc() -> Result<(), String> {
    let buf = EphemeralBuffer::from_bytes(black_box(b"bench-locked-allocation-32b!!"))?;
    black_box(buf.len());
    Ok(())
}

fn measure_seal_open() -> Result<(), String> {
    let plain = EphemeralBuffer::from_bytes(black_box(b"bench-aead-plaintext-32-bytes!"))?;
    let sealed = seal_plaintext(&plain)?;
    let opened = EphemeralBuffer::with_capacity(128)?;
    open_into(&sealed, &opened)?;
    black_box(opened.len());
    Ok(())
}

fn measure_agent_execute() -> Result<(), String> {
    let tags = ExposureTags::provider_bound("https://provider.example/charge", false, None)
        .map_err(|err| format!("{err:?}"))?;
    let mut agent = SecureTransactionAgent::admit(b"bench-agent-key-material-32b!", tags)
        .map_err(|err| err.to_string())?;
    let context_id = agent.context_id();
    let mut transport = OkTransport;
    let receipt = agent
        .execute(
            ExecuteWithPolicy {
                context_id,
                target_endpoint: "https://provider.example/charge".into(),
                payload_hash: "bench-payload".into(),
                idempotency_key: "bench-execute".into(),
            },
            &mut transport,
        )
        .map_err(|err| err.to_string())?;
    black_box(receipt.transport_status);
    Ok(())
}

fn measure(
    samples: usize,
    warmup: usize,
    mut op: impl FnMut() -> Result<(), String>,
) -> Result<Vec<Duration>, String> {
    crypto::init_session_from_entropy()?;
    for _ in 0..warmup {
        op()?;
    }
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        op()?;
        times.push(started.elapsed());
    }
    Ok(times)
}

fn report(name: &str, samples: &[Duration]) {
    let mut ordered = samples.to_vec();
    ordered.sort();
    let p95 = percentile(&ordered, 95);
    let p99 = percentile(&ordered, 99);
    println!(
        "{name}_p95_us={} {name}_p99_us={}",
        p95.as_micros(),
        p99.as_micros()
    );
}

fn percentile(sorted: &[Duration], pct: usize) -> Duration {
    let index = (pct * sorted.len()).div_ceil(100).saturating_sub(1);
    sorted[index.min(sorted.len() - 1)]
}
