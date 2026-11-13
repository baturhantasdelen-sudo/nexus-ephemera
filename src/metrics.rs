//! Process counters for the daemon and the context lifecycle.
//!
//! A snapshot is five integers. It has no endpoint, payload, idempotency key,
//! binding digest, or secret bytes.

#![forbid(unsafe_code)]

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

const LATENCY_CAP: usize = 128;

static WIPE_SUCCESS: AtomicU64 = AtomicU64::new(0);
static QUARANTINE_TRIGGERS: AtomicU64 = AtomicU64::new(0);
static TERMINAL_OUTCOMES: AtomicU64 = AtomicU64::new(0);
static CLEANUP_INCOMPLETE: AtomicU64 = AtomicU64::new(0);
static IPC_AUTH_FAILURES: AtomicU64 = AtomicU64::new(0);
static LATENCIES: Mutex<LatencyRing> = Mutex::new(LatencyRing::empty());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub wipe_success_count: u64,
    pub quarantine_trigger_total: u64,
    /// Incomplete cleanups per one thousand terminal dispatches. Zero when no
    /// dispatch has finished. This is not a fraction in the range 0.0–1.0.
    pub cleanup_incomplete_rate: u64,
    pub ipc_auth_failure_total: u64,
    /// Nearest-rank p95 of the last 128 finished dispatches, in microseconds.
    /// Cache replays are not samples. Zero when no dispatch has finished.
    pub p95_dispatch_latency_us: u64,
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "wipe_success_count={} quarantine_trigger_total={} cleanup_incomplete_rate={} ipc_auth_failure_total={} p95_dispatch_latency_us={}",
            self.wipe_success_count,
            self.quarantine_trigger_total,
            self.cleanup_incomplete_rate,
            self.ipc_auth_failure_total,
            self.p95_dispatch_latency_us
        )
    }
}

pub fn snapshot() -> MetricsSnapshot {
    let terminal = TERMINAL_OUTCOMES.load(Ordering::Relaxed);
    let incomplete = CLEANUP_INCOMPLETE.load(Ordering::Relaxed);
    let rate = incomplete
        .saturating_mul(1000)
        .checked_div(terminal)
        .unwrap_or(0);
    MetricsSnapshot {
        wipe_success_count: WIPE_SUCCESS.load(Ordering::Relaxed),
        quarantine_trigger_total: QUARANTINE_TRIGGERS.load(Ordering::Relaxed),
        cleanup_incomplete_rate: rate,
        ipc_auth_failure_total: IPC_AUTH_FAILURES.load(Ordering::Relaxed),
        p95_dispatch_latency_us: latencies()
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .p95(),
    }
}

pub(crate) fn record_wipe_success() {
    WIPE_SUCCESS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_quarantine_trigger() {
    QUARANTINE_TRIGGERS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_terminal_outcome(cleanup_incomplete: bool) {
    TERMINAL_OUTCOMES.fetch_add(1, Ordering::Relaxed);
    if cleanup_incomplete {
        CLEANUP_INCOMPLETE.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_ipc_auth_failure() {
    IPC_AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_dispatch_latency_us(micros: u64) {
    latencies()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .push(micros);
}

fn latencies() -> &'static Mutex<LatencyRing> {
    &LATENCIES
}

struct LatencyRing {
    samples: [u64; LATENCY_CAP],
    len: usize,
    next: usize,
}

impl LatencyRing {
    const fn empty() -> Self {
        Self {
            samples: [0; LATENCY_CAP],
            len: 0,
            next: 0,
        }
    }

    fn push(&mut self, micros: u64) {
        self.samples[self.next] = micros;
        self.next = (self.next + 1) % LATENCY_CAP;
        if self.len < LATENCY_CAP {
            self.len += 1;
        }
    }

    fn p95(&self) -> u64 {
        if self.len == 0 {
            return 0;
        }
        let mut ordered = self.samples[..self.len].to_vec();
        ordered.sort_unstable();
        let rank = (95 * self.len).div_ceil(100);
        ordered[rank.saturating_sub(1)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_text_is_only_counter_names_and_integers() {
        let text = snapshot().to_string();
        assert!(text.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || ch == '_' || ch == '=' || ch.is_ascii_whitespace()
        }));
        assert!(!text.contains("binding"));
        assert!(!text.contains("payload"));
    }

    #[test]
    fn rate_and_p95_use_only_recorded_numbers() {
        record_terminal_outcome(false);
        record_terminal_outcome(true);
        record_dispatch_latency_us(10);
        record_dispatch_latency_us(20);
        let after = snapshot();
        assert!(after.cleanup_incomplete_rate <= 1000);
        assert!(after.p95_dispatch_latency_us > 0);
        let rendered = after.to_string();
        assert!(!rendered.contains("endpoint"));
        assert!(!rendered.contains("digest"));
    }
}
