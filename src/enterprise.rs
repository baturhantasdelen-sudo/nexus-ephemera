//! Enterprise audit chain, tenant policy, and shared idempotency.
//!
//! The hash chain and Merkle root are tamper-evident for an exported log when
//! the root is kept outside that log. They are not a MAC, not mTLS, and not
//! durable by themselves. Tenant tokens are HMAC under a key derived from the
//! broker secret; this module does not return that secret. The shared store is
//! an atomic claim adapter. It is not a network service. Pending and
//! inconclusive entries do not expire and do not dispatch again.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use orion::hazardous::mac::hmac::sha256::{HmacSha256, SecretKey as HmacKey, Tag as HmacTag};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::idempotency::valid_key;
use crate::ipc::{IpcError, strict_service_target};

pub const WORKER_CAP: usize = 32;
pub const DUPLICATE_PROVIDER_STATUS: u16 = 409;
const SECRET_MAX: usize = 4096;
const TOKEN_TTL_MS: u64 = 24 * 60 * 60 * 1000;
const STORE_DOMAIN: &str = "nexus:idem:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKind {
    Receipt,
    TargetDenied,
    IdempotencyConflict,
    Retained,
}

impl AuditKind {
    fn label(self) -> &'static str {
        match self {
            Self::Receipt => "receipt",
            Self::TargetDenied => "target_denied",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::Retained => "retained",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "receipt" => Some(Self::Receipt),
            "target_denied" => Some(Self::TargetDenied),
            "idempotency_conflict" => Some(Self::IdempotencyConflict),
            "retained" => Some(Self::Retained),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub kind: AuditKind,
    pub service_account_id: String,
    pub endpoint: String,
    pub payload_hash: String,
    pub idempotency_key: String,
    pub seal_report: String,
    pub binding_digest_hex: String,
    pub transport_status: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Chained {
    sequence: u64,
    previous: [u8; 32],
    event: String,
    link: [u8; 32],
}

#[derive(Debug)]
pub struct AuditLedger {
    previous: [u8; 32],
    records: Vec<Chained>,
}

impl AuditLedger {
    pub fn new() -> Self {
        Self {
            previous: [0; 32],
            records: Vec::new(),
        }
    }

    pub fn append(&mut self, event: &AuditEvent) -> Result<[u8; 32], IpcError> {
        let encoded = canonical_event(event)?;
        let Some(sequence) = u64::try_from(self.records.len())
            .ok()
            .and_then(|len| len.checked_add(1))
        else {
            return Err(IpcError::Protocol("audit sequence exhausted"));
        };
        let link = chain_link(&self.previous, sequence, encoded.as_bytes());
        self.records.push(Chained {
            sequence,
            previous: self.previous,
            event: encoded,
            link,
        });
        self.previous = link;
        Ok(link)
    }

    pub fn verify(&self) -> bool {
        let mut previous = [0; 32];
        let mut links = Vec::with_capacity(self.records.len());
        for (index, record) in self.records.iter().enumerate() {
            let Some(sequence) = u64::try_from(index).ok().and_then(|i| i.checked_add(1)) else {
                return false;
            };
            if record.sequence != sequence
                || record.previous != previous
                || record.link != chain_link(&previous, sequence, record.event.as_bytes())
            {
                return false;
            }
            previous = record.link;
            links.push(record.link);
        }
        previous == self.previous && merkle_root(&links) == self.merkle_root()
    }

    pub fn merkle_root(&self) -> [u8; 32] {
        merkle_root(
            &self
                .records
                .iter()
                .map(|record| record.link)
                .collect::<Vec<_>>(),
        )
    }

    pub fn head(&self) -> [u8; 32] {
        self.previous
    }

    pub fn export_json(&self) -> String {
        let mut out = String::from("{\"head\":\"");
        out.push_str(&hex_encode(&self.previous));
        out.push_str("\",\"merkle_root\":\"");
        out.push_str(&hex_encode(&self.merkle_root()));
        out.push_str("\",\"records\":[");
        for (index, record) in self.records.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str("{\"event\":");
            out.push_str(&record.event);
            out.push_str(",\"link\":\"");
            out.push_str(&hex_encode(&record.link));
            out.push_str("\",\"previous\":\"");
            out.push_str(&hex_encode(&record.previous));
            out.push_str("\",\"sequence\":");
            out.push_str(&record.sequence.to_string());
            out.push('}');
        }
        out.push_str("]}");
        out
    }
}

impl Default for AuditLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub id: String,
    pub roles: Vec<String>,
    pub attributes: Vec<(String, String)>,
    pub allowlist: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TenantDirectory {
    accounts: BTreeMap<String, AccountPolicy>,
}

#[derive(Debug, Clone)]
struct AccountPolicy {
    roles: Vec<String>,
    attributes: Vec<(String, String)>,
    allowlist: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantGrant {
    pub service_account_id: String,
    pub role: String,
    pub endpoint: String,
}

impl TenantDirectory {
    pub fn try_new(accounts: Vec<ServiceAccount>) -> Result<Self, IpcError> {
        let mut map = BTreeMap::new();
        for account in accounts {
            if !ident(&account.id) || map.contains_key(&account.id) {
                return Err(IpcError::Malformed);
            }
            let mut roles = account.roles;
            roles.sort();
            roles.dedup();
            if roles.is_empty() || roles.iter().any(|role| !ident(role)) {
                return Err(IpcError::Malformed);
            }
            let mut attributes = account.attributes;
            attributes.sort();
            if attributes.iter().any(|(key, value)| {
                !ident(key) || value.is_empty() || !printable_ascii(value) || key == "secret"
            }) {
                return Err(IpcError::Malformed);
            }
            for pair in attributes.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(IpcError::Malformed);
                }
            }
            if account.allowlist.is_empty() {
                return Err(IpcError::Malformed);
            }
            for endpoint in &account.allowlist {
                strict_service_target(endpoint)?;
            }
            map.insert(
                account.id,
                AccountPolicy {
                    roles,
                    attributes,
                    allowlist: account.allowlist,
                },
            );
        }
        if map.is_empty() {
            return Err(IpcError::Malformed);
        }
        Ok(Self { accounts: map })
    }

    pub fn issue_token(
        &self,
        secret: &[u8],
        service_account_id: &str,
        role: &str,
        expires_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<String, IpcError> {
        let account = self
            .accounts
            .get(service_account_id)
            .ok_or(IpcError::TargetDenied)?;
        if !account.roles.iter().any(|item| item == role) {
            return Err(IpcError::TargetDenied);
        }
        if expires_unix_ms <= now_unix_ms
            || expires_unix_ms.saturating_sub(now_unix_ms) > TOKEN_TTL_MS
        {
            return Err(IpcError::Malformed);
        }
        let mac = tenant_mac(secret, service_account_id, role, expires_unix_ms)?;
        let header = format!(
            "sa={service_account_id},role={role},exp={expires_unix_ms},v1={}",
            hex_encode(mac.unprotected_as_ref())
        );
        drop(mac);
        Ok(header)
    }

    pub fn authorize(
        &self,
        secret: &[u8],
        token: &str,
        asserted_account: &str,
        endpoint: &str,
        presented_attributes: &[(String, String)],
        now_unix_ms: u64,
    ) -> Result<TenantGrant, IpcError> {
        strict_service_target(endpoint)?;
        let (account_id, role, expires) = parse_token(token)?;
        if account_id != asserted_account {
            return Err(IpcError::TargetDenied);
        }
        let expected = tenant_mac(secret, &account_id, &role, expires)?;
        let presented = decode_mac(token)?;
        let mac_ok = bool::from(presented.ct_eq(expected.unprotected_as_ref()));
        drop(expected);
        if !mac_ok || now_unix_ms >= expires {
            return Err(IpcError::TargetDenied);
        }
        let Some(account) = self.accounts.get(&account_id) else {
            return Err(IpcError::TargetDenied);
        };
        if !account.roles.iter().any(|item| item == &role) {
            return Err(IpcError::TargetDenied);
        }
        let mut presented_sorted = presented_attributes.to_vec();
        presented_sorted.sort();
        if presented_sorted != account.attributes
            || !account.allowlist.iter().any(|item| item == endpoint)
        {
            return Err(IpcError::TargetDenied);
        }
        Ok(TenantGrant {
            service_account_id: account_id,
            role,
            endpoint: endpoint.to_string(),
        })
    }
}

#[derive(Debug)]
pub struct SharedIdempotency {
    cap: usize,
    fence: AtomicU64,
    state: Mutex<StoreState>,
}

#[derive(Debug)]
struct StoreState {
    sealed: bool,
    slots: BTreeMap<String, Slot>,
}

#[derive(Debug)]
enum Slot {
    Pending {
        endpoint: String,
        payload_hash: String,
        fence: u64,
    },
    Done {
        endpoint: String,
        payload_hash: String,
        receipt: SharedReceipt,
    },
    Inconclusive {
        endpoint: String,
        payload_hash: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedReceipt {
    pub target_endpoint: String,
    pub payload_hash: String,
    pub binding_digest_hex: String,
    pub transport_status: u16,
    pub seal_report: String,
    pub idempotency_key: String,
    pub duplicate_status: Option<u16>,
    pub service_account_id: String,
}

enum Claim {
    Leader(u64),
    Cached(SharedReceipt),
    Conflict,
    Inconclusive,
    Sealed,
    Full,
}

impl SharedIdempotency {
    pub fn new(cap: usize) -> Result<Self, IpcError> {
        if cap == 0 {
            return Err(IpcError::Malformed);
        }
        Ok(Self {
            cap,
            fence: AtomicU64::new(1),
            state: Mutex::new(StoreState {
                sealed: false,
                slots: BTreeMap::new(),
            }),
        })
    }

    pub fn quarantine_for_rotation(&self) {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .sealed = true;
    }

    pub fn redis_claim_command(
        &self,
        service_account_id: &str,
        idempotency_key: &str,
    ) -> Result<String, IpcError> {
        if !ident(service_account_id) || !valid_key(idempotency_key) {
            return Err(IpcError::Malformed);
        }
        Ok(format!(
            "SET {STORE_DOMAIN}{service_account_id}:{idempotency_key} pending NX"
        ))
    }

    fn claim(
        &self,
        service_account_id: &str,
        idempotency_key: &str,
        endpoint: &str,
        payload_hash: &str,
    ) -> Claim {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if state.sealed {
            return Claim::Sealed;
        }
        let map_key = store_key(service_account_id, idempotency_key);
        if let Some(slot) = state.slots.get(&map_key) {
            return match slot {
                Slot::Done {
                    endpoint: stored_endpoint,
                    payload_hash: stored_hash,
                    receipt,
                } if stored_endpoint == endpoint && stored_hash == payload_hash => {
                    let mut cached = receipt.clone();
                    cached.duplicate_status = Some(DUPLICATE_PROVIDER_STATUS);
                    Claim::Cached(cached)
                }
                Slot::Pending {
                    endpoint: stored_endpoint,
                    payload_hash: stored_hash,
                    ..
                }
                | Slot::Inconclusive {
                    endpoint: stored_endpoint,
                    payload_hash: stored_hash,
                } if stored_endpoint == endpoint && stored_hash == payload_hash => {
                    Claim::Inconclusive
                }
                _ => Claim::Conflict,
            };
        }
        if state.slots.len() >= self.cap {
            return Claim::Full;
        }
        let Ok(fence) = self
            .fence
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
        else {
            return Claim::Full;
        };
        state.slots.insert(
            map_key,
            Slot::Pending {
                endpoint: endpoint.to_string(),
                payload_hash: payload_hash.to_string(),
                fence,
            },
        );
        Claim::Leader(fence)
    }

    fn commit_done(&self, call: &ClusterCall, fence: u64, transport_status: u16) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let map_key = store_key(&call.service_account_id, &call.idempotency_key);
        let pending = matches!(
            state.slots.get(&map_key),
            Some(Slot::Pending {
                endpoint,
                payload_hash,
                fence: stored,
            }) if *stored == fence
                && endpoint == &call.endpoint
                && payload_hash == &call.payload_hash
        );
        if !pending {
            return false;
        }
        state.slots.insert(
            map_key,
            Slot::Done {
                endpoint: call.endpoint.clone(),
                payload_hash: call.payload_hash.clone(),
                receipt: shared_receipt(call, transport_status, None),
            },
        );
        true
    }

    fn commit_inconclusive(&self, call: &ClusterCall, fence: u64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let map_key = store_key(&call.service_account_id, &call.idempotency_key);
        let pending = matches!(
            state.slots.get(&map_key),
            Some(Slot::Pending {
                endpoint,
                payload_hash,
                fence: stored,
            }) if *stored == fence
                && endpoint == &call.endpoint
                && payload_hash == &call.payload_hash
        );
        if !pending {
            return false;
        }
        state.slots.insert(
            map_key,
            Slot::Inconclusive {
                endpoint: call.endpoint.clone(),
                payload_hash: call.payload_hash.clone(),
            },
        );
        true
    }
}

#[derive(Debug, Clone)]
pub struct ClusterCall {
    pub service_account_id: String,
    pub endpoint: String,
    pub payload_hash: String,
    pub idempotency_key: String,
    pub binding_digest_hex: String,
    pub seal_report: String,
}

pub struct ClusterNode {
    store: Arc<SharedIdempotency>,
    provider_hits: Arc<AtomicUsize>,
}

impl ClusterNode {
    pub fn new(store: Arc<SharedIdempotency>, provider_hits: Arc<AtomicUsize>) -> Self {
        Self {
            store,
            provider_hits,
        }
    }

    pub fn execute(&self, call: &ClusterCall) -> Result<SharedReceipt, IpcError> {
        self.finish(call, false)
    }

    pub fn execute_interrupted(&self, call: &ClusterCall) -> Result<SharedReceipt, IpcError> {
        self.finish(call, true)
    }

    fn finish(&self, call: &ClusterCall, interrupt: bool) -> Result<SharedReceipt, IpcError> {
        validate_call(call)?;
        match self.store.claim(
            &call.service_account_id,
            &call.idempotency_key,
            &call.endpoint,
            &call.payload_hash,
        ) {
            Claim::Leader(fence) => {
                if interrupt {
                    if !self.store.commit_inconclusive(call, fence) {
                        return Err(IpcError::Inconclusive);
                    }
                    return Err(IpcError::Inconclusive);
                }
                if !self.store.commit_done(call, fence, 204) {
                    return Err(IpcError::Inconclusive);
                }
                self.provider_hits.fetch_add(1, Ordering::SeqCst);
                Ok(shared_receipt(call, 204, None))
            }
            Claim::Cached(receipt) => Ok(receipt),
            Claim::Conflict => Err(IpcError::IdempotencyConflict),
            Claim::Inconclusive => Err(IpcError::Inconclusive),
            Claim::Sealed => Err(IpcError::Protocol("shared idempotency store is sealed")),
            Claim::Full => Err(IpcError::IdempotencyUnavailable),
        }
    }
}

pub struct WorkerGate {
    inflight: AtomicUsize,
}

pub struct WorkerPermit<'a> {
    gate: &'a WorkerGate,
}

impl WorkerGate {
    pub fn new() -> Self {
        Self {
            inflight: AtomicUsize::new(0),
        }
    }

    pub fn try_acquire(&self) -> Result<WorkerPermit<'_>, IpcError> {
        loop {
            let current = self.inflight.load(Ordering::SeqCst);
            if current >= WORKER_CAP {
                return Err(IpcError::Protocol(
                    "ipc io: pending operation capacity exhausted",
                ));
            }
            if self
                .inflight
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(WorkerPermit { gate: self });
            }
        }
    }
}

impl Default for WorkerGate {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WorkerPermit<'_> {
    fn drop(&mut self) {
        self.gate.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

fn shared_receipt(
    call: &ClusterCall,
    transport_status: u16,
    duplicate_status: Option<u16>,
) -> SharedReceipt {
    SharedReceipt {
        target_endpoint: call.endpoint.clone(),
        payload_hash: call.payload_hash.clone(),
        binding_digest_hex: call.binding_digest_hex.clone(),
        transport_status,
        seal_report: call.seal_report.clone(),
        idempotency_key: call.idempotency_key.clone(),
        duplicate_status,
        service_account_id: call.service_account_id.clone(),
    }
}

fn validate_call(call: &ClusterCall) -> Result<(), IpcError> {
    if !ident(&call.service_account_id) || !valid_key(&call.idempotency_key) {
        return Err(IpcError::Malformed);
    }
    strict_service_target(&call.endpoint)?;
    if !graphic(&call.payload_hash) || call.payload_hash.len() > 128 {
        return Err(IpcError::Malformed);
    }
    if call.seal_report != "retained" && call.seal_report != "complete" {
        return Err(IpcError::Malformed);
    }
    if call.binding_digest_hex.len() != 64
        || !call
            .binding_digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(IpcError::Malformed);
    }
    Ok(())
}

fn store_key(account: &str, idempotency_key: &str) -> String {
    format!("{account}\u{1f}{idempotency_key}")
}

fn canonical_event(event: &AuditEvent) -> Result<String, IpcError> {
    if !ident(&event.service_account_id)
        || !printable_ascii(&event.endpoint)
        || !printable_ascii(&event.payload_hash)
        || !printable_ascii(&event.idempotency_key)
        || !printable_ascii(&event.seal_report)
        || !printable_ascii(&event.binding_digest_hex)
    {
        return Err(IpcError::Malformed);
    }
    Ok(format!(
        "{{\"binding_digest_hex\":{},\"endpoint\":{},\"idempotency_key\":{},\"kind\":{},\"payload_hash\":{},\"seal_report\":{},\"service_account_id\":{},\"transport_status\":{}}}",
        json_string(&event.binding_digest_hex),
        json_string(&event.endpoint),
        json_string(&event.idempotency_key),
        json_string(event.kind.label()),
        json_string(&event.payload_hash),
        json_string(&event.seal_report),
        json_string(&event.service_account_id),
        event.transport_status
    ))
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for char in value.chars() {
        match char {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn chain_link(previous: &[u8; 32], sequence: u64, event: &[u8]) -> [u8; 32] {
    let event_hash = Sha256::digest(event);
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-enterprise-audit-v1");
    hasher.update(previous);
    hasher.update(sequence.to_le_bytes());
    hasher.update(event_hash);
    hasher.finalize().into()
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return Sha256::digest(b"nexus-merkle-empty-v1").into();
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut index = 0;
        while index < level.len() {
            let left = level[index];
            let right = if index + 1 < level.len() {
                level[index + 1]
            } else {
                level[index]
            };
            next.push(merkle_pair(left, right));
            index += 2;
        }
        level = next;
    }
    level[0]
}

fn merkle_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-merkle-pair-v1");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn verify_export(exported: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(exported) else {
        return false;
    };
    let Some(records) = value.get("records").and_then(|item| item.as_array()) else {
        return false;
    };
    let mut previous = [0; 32];
    let mut links = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let Some(sequence) = record.get("sequence").and_then(|item| item.as_u64()) else {
            return false;
        };
        let Some(expected) = u64::try_from(index)
            .ok()
            .and_then(|item| item.checked_add(1))
        else {
            return false;
        };
        if sequence != expected {
            return false;
        }
        let Some(stored_previous) = record
            .get("previous")
            .and_then(|item| item.as_str())
            .and_then(decode_hex_array)
        else {
            return false;
        };
        let Some(stored_link) = record
            .get("link")
            .and_then(|item| item.as_str())
            .and_then(decode_hex_array)
        else {
            return false;
        };
        let Some(event) = record.get("event").and_then(event_from_json) else {
            return false;
        };
        let Ok(encoded) = canonical_event(&event) else {
            return false;
        };
        if stored_previous != previous
            || stored_link != chain_link(&previous, sequence, encoded.as_bytes())
        {
            return false;
        }
        previous = stored_link;
        links.push(stored_link);
    }
    let Some(head) = value
        .get("head")
        .and_then(|item| item.as_str())
        .and_then(decode_hex_array)
    else {
        return false;
    };
    let Some(root) = value
        .get("merkle_root")
        .and_then(|item| item.as_str())
        .and_then(decode_hex_array)
    else {
        return false;
    };
    head == previous && root == merkle_root(&links)
}

fn event_from_json(value: &serde_json::Value) -> Option<AuditEvent> {
    let kind = AuditKind::parse(value.get("kind")?.as_str()?)?;
    let transport = u16::try_from(value.get("transport_status")?.as_u64()?).ok()?;
    Some(AuditEvent {
        kind,
        service_account_id: value.get("service_account_id")?.as_str()?.to_string(),
        endpoint: value.get("endpoint")?.as_str()?.to_string(),
        payload_hash: value.get("payload_hash")?.as_str()?.to_string(),
        idempotency_key: value.get("idempotency_key")?.as_str()?.to_string(),
        seal_report: value.get("seal_report")?.as_str()?.to_string(),
        binding_digest_hex: value.get("binding_digest_hex")?.as_str()?.to_string(),
        transport_status: transport,
    })
}

fn decode_hex_array(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    let bytes = hex.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let hi = hex_value(bytes[index * 2])?;
        let lo = hex_value(bytes[index * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn tenant_mac(
    secret: &[u8],
    service_account_id: &str,
    role: &str,
    expires_unix_ms: u64,
) -> Result<HmacTag, IpcError> {
    if secret.is_empty() || secret.len() > SECRET_MAX {
        return Err(IpcError::Malformed);
    }
    let signing_key = derive_tenant_key(secret)?;
    let mut mac = keyed_mac(signing_key.unprotected_as_ref())?;
    drop(signing_key);
    mac.update(b"tenant-v1").map_err(|_| IpcError::Malformed)?;
    mac.update(&expires_unix_ms.to_le_bytes())
        .map_err(|_| IpcError::Malformed)?;
    for field in [service_account_id.as_bytes(), role.as_bytes()] {
        mac.update(&(field.len() as u64).to_le_bytes())
            .map_err(|_| IpcError::Malformed)?;
        mac.update(field).map_err(|_| IpcError::Malformed)?;
    }
    mac.finalize().map_err(|_| IpcError::Malformed)
}

fn derive_tenant_key(secret: &[u8]) -> Result<HmacTag, IpcError> {
    let mut extract = keyed_mac(b"nexus-ephemera-hmac-v1")?;
    extract.update(secret).map_err(|_| IpcError::Malformed)?;
    let prk = extract.finalize().map_err(|_| IpcError::Malformed)?;
    let mut expand = keyed_mac(prk.unprotected_as_ref())?;
    drop(prk);
    expand
        .update(b"nexus-ephemera-tenant-token-v1")
        .map_err(|_| IpcError::Malformed)?;
    expand.update(&[0x01]).map_err(|_| IpcError::Malformed)?;
    expand.finalize().map_err(|_| IpcError::Malformed)
}

fn keyed_mac(key: &[u8]) -> Result<HmacSha256, IpcError> {
    let guarded = HmacKey::try_from(key).map_err(|_| IpcError::Malformed)?;
    Ok(HmacSha256::new(&guarded))
}

fn parse_token(token: &str) -> Result<(String, String, u64), IpcError> {
    let mut account = None;
    let mut role = None;
    let mut expires = None;
    let mut mac = None;
    for part in token.split(',') {
        if let Some(value) = part.strip_prefix("sa=") {
            if account.is_some() || !ident(value) {
                return Err(IpcError::Malformed);
            }
            account = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("role=") {
            if role.is_some() || !ident(value) {
                return Err(IpcError::Malformed);
            }
            role = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("exp=") {
            if expires.is_some() {
                return Err(IpcError::Malformed);
            }
            expires = Some(value.parse::<u64>().map_err(|_| IpcError::Malformed)?);
        } else if let Some(value) = part.strip_prefix("v1=") {
            if mac.is_some()
                || value.len() != 64
                || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(IpcError::Malformed);
            }
            mac = Some(value);
        } else {
            return Err(IpcError::Malformed);
        }
    }
    if account.is_none() || role.is_none() || expires.is_none() || mac.is_none() {
        return Err(IpcError::Malformed);
    }
    Ok((
        account.expect("account checked"),
        role.expect("role checked"),
        expires.expect("expiry checked"),
    ))
}

fn decode_mac(token: &str) -> Result<Vec<u8>, IpcError> {
    let hex = token
        .split(',')
        .find_map(|part| part.strip_prefix("v1="))
        .ok_or(IpcError::Malformed)?;
    if hex.len() != 64 {
        return Err(IpcError::Malformed);
    }
    let mut out = Vec::with_capacity(32);
    let bytes = hex.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_value(bytes[index]).ok_or(IpcError::Malformed)?;
        let lo = hex_value(bytes[index + 1]).ok_or(IpcError::Malformed)?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn ident(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    (1..=32).contains(&value.len())
        && chars.all(|char| {
            char.is_ascii_lowercase() || char.is_ascii_digit() || char == '_' || char == '-'
        })
}

fn printable_ascii(value: &str) -> bool {
    value
        .chars()
        .all(|char| char.is_ascii_graphic() || char == ' ')
}

fn graphic(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_merkle_root_is_stable() {
        let root = merkle_root(&[]);
        let digest: [u8; 32] = Sha256::digest(b"nexus-merkle-empty-v1").into();
        assert_eq!(hex_encode(&root), hex_encode(&digest));
        assert!(AuditLedger::new().verify());
    }

    #[test]
    fn mutated_event_breaks_the_chain_and_the_export() {
        let mut ledger = AuditLedger::new();
        ledger
            .append(&AuditEvent {
                kind: AuditKind::Retained,
                service_account_id: "billing".into(),
                endpoint: "https://provider.example/charge".into(),
                payload_hash: "hash-a".into(),
                idempotency_key: "key-1".into(),
                seal_report: "retained".into(),
                binding_digest_hex: "ab".repeat(32),
                transport_status: 204,
            })
            .expect("append");
        assert!(ledger.verify());
        let exported = ledger.export_json();
        assert!(verify_export(&exported));
        ledger.records[0].event.push('x');
        assert!(!ledger.verify());
        let mut tampered = exported;
        tampered = tampered.replacen("hash-a", "hash-b", 1);
        assert!(!verify_export(&tampered));
    }
}
