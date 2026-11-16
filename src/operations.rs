//! Day-2 controls: key grace, worker shedding, and tenant quarantine.
//!
//! Request MAC bytes stay on the existing canonical input. This module only
//! chooses which secret is current. A previous secret verifies until its grace
//! instant and then becomes `TargetDenied`. Exports carry no signing secret.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::crypto::{sign_request_header, verify_request_header};
use crate::enterprise::{AuditLedger, TenantDirectory, TenantGrant};
use crate::ipc::IpcError;

pub const SHED_STATUS: u16 = 503;
const GRACE_MAX_MS: u64 = 24 * 60 * 60 * 1000;

pub struct KeyRing {
    current: Zeroizing<Vec<u8>>,
    previous: Option<PreviousKey>,
}

struct PreviousKey {
    secret: Zeroizing<Vec<u8>>,
    valid_until: u64,
}

impl KeyRing {
    pub fn new(secret: Vec<u8>) -> Result<Self, IpcError> {
        if secret.is_empty() || secret.len() > 4096 {
            return Err(IpcError::Malformed);
        }
        Ok(Self {
            current: Zeroizing::new(secret),
            previous: None,
        })
    }

    pub fn rotate(
        &mut self,
        next: Vec<u8>,
        now_unix_ms: u64,
        grace: Duration,
    ) -> Result<(), IpcError> {
        if next.is_empty() || next.len() > 4096 || next.as_slice() == self.current.as_slice() {
            return Err(IpcError::Malformed);
        }
        let grace_ms = u64::try_from(grace.as_millis()).map_err(|_| IpcError::Malformed)?;
        if grace_ms > GRACE_MAX_MS {
            return Err(IpcError::Malformed);
        }
        let retired = std::mem::replace(&mut self.current, Zeroizing::new(next));
        self.previous = if grace_ms == 0 {
            None
        } else {
            Some(PreviousKey {
                secret: retired,
                valid_until: now_unix_ms.saturating_add(grace_ms),
            })
        };
        Ok(())
    }

    pub fn sign_request(
        &self,
        timestamp_unix_ms: u64,
        idempotency_key: &str,
        payload_hash: &str,
        endpoint: &str,
    ) -> String {
        sign_request_header(
            &self.current,
            timestamp_unix_ms,
            idempotency_key,
            payload_hash,
            endpoint,
        )
    }

    pub fn verify_request(
        &self,
        header: &str,
        idempotency_key: &str,
        payload_hash: &str,
        endpoint: &str,
        now_unix_ms: u64,
    ) -> Result<(), IpcError> {
        if verify_request_header(
            &self.current,
            header,
            idempotency_key,
            payload_hash,
            endpoint,
            now_unix_ms,
        )
        .is_ok()
        {
            return Ok(());
        }
        if let Some(previous) = &self.previous
            && now_unix_ms < previous.valid_until
            && verify_request_header(
                &previous.secret,
                header,
                idempotency_key,
                payload_hash,
                endpoint,
                now_unix_ms,
            )
            .is_ok()
        {
            return Ok(());
        }
        Err(IpcError::TargetDenied)
    }

    pub fn issue_token(
        &self,
        directory: &TenantDirectory,
        service_account_id: &str,
        role: &str,
        expires_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<String, IpcError> {
        directory.issue_token(
            &self.current,
            service_account_id,
            role,
            expires_unix_ms,
            now_unix_ms,
        )
    }

    pub fn authorize_token(
        &self,
        directory: &TenantDirectory,
        token: &str,
        asserted_account: &str,
        endpoint: &str,
        now_unix_ms: u64,
    ) -> Result<TenantGrant, IpcError> {
        match directory.authorize(
            &self.current,
            token,
            asserted_account,
            endpoint,
            &[],
            now_unix_ms,
        ) {
            Ok(grant) => Ok(grant),
            Err(IpcError::TargetDenied) => {
                if let Some(previous) = &self.previous
                    && now_unix_ms < previous.valid_until
                {
                    return directory.authorize(
                        &previous.secret,
                        token,
                        asserted_account,
                        endpoint,
                        &[],
                        now_unix_ms,
                    );
                }
                Err(IpcError::TargetDenied)
            }
            Err(err) => Err(err),
        }
    }
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyRing")
            .field("previous", &self.previous.is_some())
            .finish_non_exhaustive()
    }
}

pub struct TenantQuarantine {
    threshold: u32,
    block_for_ms: u64,
    state: Mutex<BTreeMap<String, TenantState>>,
}

struct TenantState {
    denials: u32,
    blocked_until: Option<u64>,
}

impl TenantQuarantine {
    pub fn new(threshold: u32, block_for: Duration) -> Result<Self, IpcError> {
        let block_for_ms = u64::try_from(block_for.as_millis()).map_err(|_| IpcError::Malformed)?;
        if threshold == 0 || block_for_ms == 0 || block_for_ms > GRACE_MAX_MS {
            return Err(IpcError::Malformed);
        }
        Ok(Self {
            threshold,
            block_for_ms,
            state: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn ensure(&self, account: &str, now_unix_ms: u64) -> Result<(), IpcError> {
        if !account_ok(account) {
            return Err(IpcError::Malformed);
        }
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(slot) = state.get_mut(account) {
            if slot.blocked_until.is_some_and(|until| now_unix_ms < until) {
                return Err(IpcError::TargetDenied);
            }
            if slot.blocked_until.is_some() {
                slot.denials = 0;
                slot.blocked_until = None;
            }
        }
        Ok(())
    }

    pub fn record_denial(&self, account: &str, now_unix_ms: u64) -> Result<(), IpcError> {
        if !account_ok(account) {
            return Err(IpcError::Malformed);
        }
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let slot = state.entry(account.to_string()).or_insert(TenantState {
            denials: 0,
            blocked_until: None,
        });
        if slot.blocked_until.is_some_and(|until| now_unix_ms < until) {
            return Err(IpcError::TargetDenied);
        }
        if slot.blocked_until.is_some() {
            slot.denials = 0;
            slot.blocked_until = None;
        }
        slot.denials = slot.denials.saturating_add(1);
        if slot.denials >= self.threshold {
            slot.blocked_until = Some(now_unix_ms.saturating_add(self.block_for_ms));
        }
        Ok(())
    }
}

pub fn shed_status(err: &IpcError) -> Option<u16> {
    match err {
        IpcError::Protocol(message) if message.contains("capacity exhausted") => Some(SHED_STATUS),
        IpcError::RateLimited => Some(SHED_STATUS),
        _ => None,
    }
}

pub fn close_store_outage(err: IpcError) -> IpcError {
    match err {
        IpcError::IdempotencyUnavailable
        | IpcError::TimedOut
        | IpcError::Io(_)
        | IpcError::Inconclusive => IpcError::Inconclusive,
        other => other,
    }
}

pub struct TelemetryBundle {
    pub merkle_root_hex: String,
    pub head_hex: String,
    pub records: u64,
    pub export: String,
}

pub fn telemetry(ledger: &AuditLedger) -> TelemetryBundle {
    let checkpoint = ledger.checkpoint();
    TelemetryBundle {
        merkle_root_hex: hex(&checkpoint.merkle_root),
        head_hex: hex(&checkpoint.head),
        records: checkpoint.records,
        export: ledger.export_json(),
    }
}

pub fn dispatch_after_sink(stored: Result<(), IpcError>, hits: &mut u64) -> Result<(), IpcError> {
    stored?;
    *hits = hits.saturating_add(1);
    Ok(())
}

fn account_ok(account: &str) -> bool {
    (1..=32).contains(&account.len())
        && account.chars().all(|char| {
            char.is_ascii_lowercase() || char.is_ascii_digit() || char == '_' || char == '-'
        })
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}
