//! Enforced enterprise admission and durable Redis claims. No simulated receipts.
#![forbid(unsafe_code)]

use crate::apoptosis::EphemeralBuffer;
use crate::broker::{
    AuthorizedCall, BrokerError, SealReport, SecureTransport, TransactionReceipt, TransportReply,
};
use crate::enterprise::{
    AuditCheckpoint, AuditEvent, AuditKind, AuditLedger, OwnedWorkerPermit, TenantDirectory,
    WorkerGate,
};
use crate::ipc::{IpcError, strict_service_target};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantCredential {
    pub account: String,
    pub token: String,
}

impl std::fmt::Debug for TenantCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TenantCredential([REDACTED])")
    }
}

impl Drop for TenantCredential {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

pub struct TenantAuthority {
    directory: TenantDirectory,
    key: EphemeralBuffer,
}

impl TenantAuthority {
    pub fn new(directory: TenantDirectory, key: &[u8]) -> Result<Self, IpcError> {
        nexus_ephemera_memlock::harden_process_memory()
            .map_err(|_| IpcError::Protocol("process hardening failed"))?;
        if key.is_empty() || key.len() > 4096 {
            return Err(IpcError::Malformed);
        }
        Ok(Self {
            directory,
            key: EphemeralBuffer::from_bytes(key)
                .map_err(|_| IpcError::Protocol("tenant key admission failed"))?,
        })
    }

    pub fn issue_token(
        &self,
        account: &str,
        role: &str,
        expires: u64,
        now: u64,
    ) -> Result<String, IpcError> {
        self.key
            .with_sensitive_bytes(|key| {
                Ok(self.directory.issue_token(key, account, role, expires, now))
            })
            .map_err(|_| IpcError::TargetDenied)?
    }

    fn verify(
        &self,
        proof: &TenantCredential,
        endpoint: &str,
        payload: &[u8],
    ) -> Result<(), IpcError> {
        let attributes = self
            .directory
            .account_attributes(&proof.account)
            .ok_or(IpcError::TargetDenied)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IpcError::TargetDenied)?;
        let now = u64::try_from(now.as_millis()).map_err(|_| IpcError::TargetDenied)?;
        let role = self
            .key
            .with_sensitive_bytes(|key| {
                Ok(self
                    .directory
                    .authorize(key, &proof.token, &proof.account, endpoint, attributes, now)
                    .map(|grant| grant.role))
            })
            .map_err(|_| IpcError::TargetDenied)??;
        let permitted = self
            .directory
            .allowed_params(&proof.account, &role)
            .ok_or(IpcError::TargetDenied)?;
        let body: BoundPayload =
            serde_json::from_slice(payload).map_err(|_| IpcError::Malformed)?;
        if !matches!(&body.tool, Parameter::Text(value) if value.as_str() == role)
            || body.params.0.keys().any(|key| !permitted.contains(key))
        {
            return Err(IpcError::TargetDenied);
        }
        Ok(())
    }

    pub fn close(&self) -> Result<(), IpcError> {
        self.key.try_wipe().map_err(|_| {
            crate::apoptosis::record_aux_unlock_failure();
            IpcError::Protocol("tenant key cleanup incomplete")
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundPayload {
    tool: Parameter,
    params: BoundParams,
}

enum Parameter {
    Text(Zeroizing<String>),
    Integer,
}
impl<'de> Deserialize<'de> for Parameter {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ParameterVisitor;
        impl<'de> serde::de::Visitor<'de> for ParameterVisitor {
            type Value = Parameter;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded string or integer")
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Parameter, E> {
                let value = Zeroizing::new(value);
                if value.len() > 256 || value.chars().any(|c| c.is_control()) {
                    return Err(E::custom("invalid parameter"));
                }
                Ok(Parameter::Text(value))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Parameter, E> {
                self.visit_string(value.to_string())
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Parameter, E> {
                if value.unsigned_abs() > 1_000_000_000_000 {
                    return Err(E::custom("invalid parameter"));
                }
                Ok(Parameter::Integer)
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Parameter, E> {
                if value > 1_000_000_000_000 {
                    return Err(E::custom("invalid parameter"));
                }
                Ok(Parameter::Integer)
            }
        }
        deserializer.deserialize_any(ParameterVisitor)
    }
}

struct BoundParams(std::collections::BTreeMap<String, Parameter>);
impl<'de> Deserialize<'de> for BoundParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ParamsVisitor;
        impl<'de> serde::de::Visitor<'de> for ParamsVisitor {
            type Value = BoundParams;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded unique parameters")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<BoundParams, M::Error> {
                use serde::de::Error;
                let mut values = BoundParams(std::collections::BTreeMap::new());
                while let Some(mut key) = map.next_key::<String>()? {
                    if values.0.len() >= 16
                        || key.len() > 32
                        || values.0.contains_key(&key)
                        || crate::enterprise::credential_name(&key)
                    {
                        key.zeroize();
                        return Err(M::Error::custom("invalid parameter fields"));
                    }
                    values.0.insert(key, map.next_value()?);
                }
                Ok(values)
            }
        }
        deserializer.deserialize_map(ParamsVisitor)
    }
}
impl Drop for BoundParams {
    fn drop(&mut self) {
        for (mut key, _) in std::mem::take(&mut self.0) {
            key.zeroize();
        }
    }
}

impl Drop for TenantAuthority {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// The backend is a trust dependency. Provision explicitly, never on reconnect.
/// Plaintext TCP is restricted to literal loopback; remote backends require TLS.
pub struct RedisIdempotency {
    client: redis::Client,
    key: String,
    capacity: usize,
    timeout: Duration,
}

const SCHEMA: &str = "nexus-enterprise-store-v1";
const CLAIM: &str = r#"
if redis.call('HGET',KEYS[1],'_schema') ~= ARGV[1] then return {'missing'} end
if redis.call('HGET',KEYS[1],'_sealed') ~= '0' then return {'sealed'} end
local raw=redis.call('HGET',KEYS[1],ARGV[2])
if raw then
  local e=cjson.decode(raw)
  if e.fp ~= ARGV[3] then return {'conflict'} end
  if e.state == 'done' then return {'cached', e.receipt} end
  return {'inconclusive'}
end
local cap=tonumber(redis.call('HGET',KEYS[1],'_capacity'))
if not cap or cap ~= tonumber(ARGV[4]) then return {'missing'} end
if redis.call('HLEN',KEYS[1])-4 >= cap then return {'full'} end
redis.call('HINCRBY',KEYS[1],'_fence',1)
local fence=redis.call('HGET',KEYS[1],'_fence')
redis.call('HSET',KEYS[1],ARGV[2],cjson.encode({state='pending',fp=ARGV[3],fence=fence}))
return {'leader',fence}
"#;
const FINISH: &str = r#"
if redis.call('HGET',KEYS[1],'_schema') ~= ARGV[1] then return 0 end
local raw=redis.call('HGET',KEYS[1],ARGV[2])
if not raw then return 0 end
local e=cjson.decode(raw)
if e.state ~= 'pending' or e.fp ~= ARGV[3] or e.fence ~= ARGV[4] then return 0 end
e.state=ARGV[5]
if ARGV[5] == 'done' then e.receipt=ARGV[6] end
redis.call('HSET',KEYS[1],ARGV[2],cjson.encode(e))
return 1
"#;

impl RedisIdempotency {
    pub fn new(
        url: &str,
        namespace: &str,
        capacity: usize,
        timeout: Duration,
    ) -> Result<Self, IpcError> {
        if !(1..=4096).contains(&capacity)
            || timeout.is_zero()
            || timeout > Duration::from_secs(10)
            || namespace.is_empty()
            || namespace.len() > 64
            || !namespace
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(IpcError::Malformed);
        }
        let client = redis::Client::open(url)
            .map_err(|_| IpcError::Protocol("invalid Redis configuration"))?;
        match client.get_connection_info().addr() {
            redis::ConnectionAddr::Tcp(host, _)
                if host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback()) => {}
            redis::ConnectionAddr::TcpTls {
                insecure: false, ..
            } => {}
            redis::ConnectionAddr::Unix(_) => {}
            _ => return Err(IpcError::Protocol("remote Redis requires verified TLS")),
        }
        Ok(Self {
            client,
            key: format!("nexus:enterprise:{{{namespace}}}"),
            capacity,
            timeout,
        })
    }

    fn connection(&self) -> Result<redis::Connection, IpcError> {
        let mut connection = self
            .client
            .get_connection_with_timeout(self.timeout)
            .map_err(|_| IpcError::IdempotencyUnavailable)?;
        connection
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| IpcError::IdempotencyUnavailable)?;
        connection
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| IpcError::IdempotencyUnavailable)?;
        // Refuse an ephemeral/default Redis server for production claims.
        let info: String = redis::cmd("INFO")
            .arg("persistence")
            .query(&mut connection)
            .map_err(|_| IpcError::IdempotencyUnavailable)?;
        let sync: Vec<String> = redis::cmd("CONFIG")
            .arg("GET")
            .arg("appendfsync")
            .query(&mut connection)
            .map_err(|_| IpcError::IdempotencyUnavailable)?;
        let eviction: Vec<String> = redis::cmd("CONFIG")
            .arg("GET")
            .arg("maxmemory-policy")
            .query(&mut connection)
            .map_err(|_| IpcError::IdempotencyUnavailable)?;
        if !info.lines().any(|line| line.trim_end() == "aof_enabled:1")
            || sync.get(1).map(String::as_str) != Some("always")
            || eviction.get(1).map(String::as_str) != Some("noeviction")
        {
            return Err(IpcError::Protocol(
                "Redis requires AOF always and noeviction",
            ));
        }
        Ok(connection)
    }

    /// Operator-only bootstrap. A lost namespace is never recreated by claim.
    pub fn provision(&self) -> Result<(), IpcError> {
        let script = r#"if redis.call('EXISTS',KEYS[1]) == 1 then return 0 end
redis.call('HSET',KEYS[1],'_schema',ARGV[1],'_sealed','0','_fence','0','_capacity',ARGV[2]); return 1"#;
        let mut connection = self.connection()?;
        let result: i64 = redis::cmd("EVAL")
            .arg(script)
            .arg(1)
            .arg(&self.key)
            .arg(SCHEMA)
            .arg(self.capacity)
            .query(&mut connection)
            .map_err(|_| IpcError::IdempotencyUnavailable)?;
        if result != 1 {
            return Err(IpcError::Protocol("Redis namespace already exists"));
        }
        Ok(())
    }

    pub fn health(&self) -> Result<(), IpcError> {
        let mut connection = self.connection()?;
        let values: Vec<Option<String>> = redis::cmd("HMGET")
            .arg(&self.key)
            .arg("_schema")
            .arg("_sealed")
            .arg("_capacity")
            .query(&mut connection)
            .map_err(|_| IpcError::IdempotencyUnavailable)?;
        if values.len() != 3
            || values[0].as_deref() != Some(SCHEMA)
            || values[1].as_deref() != Some("0")
            || values[2].as_deref() != Some(self.capacity.to_string().as_str())
        {
            return Err(IpcError::IdempotencyUnavailable);
        }
        Ok(())
    }

    pub fn quarantine_for_rotation(&self) -> Result<(), IpcError> {
        let mut connection = self.connection()?;
        let result: i64 = redis::cmd("EVAL").arg("if redis.call('HGET',KEYS[1],'_schema') ~= ARGV[1] then return 0 end; redis.call('HSET',KEYS[1],'_sealed','1'); return 1")
            .arg(1).arg(&self.key).arg(SCHEMA).query(&mut connection).map_err(|_| IpcError::IdempotencyUnavailable)?;
        if result != 1 {
            return Err(IpcError::IdempotencyUnavailable);
        }
        Ok(())
    }

    fn claim(&self, call: &VerifiedCall) -> Result<Claim, IpcError> {
        let mut connection = self.connection()?;
        let result: Vec<String> = redis::cmd("EVAL")
            .arg(CLAIM)
            .arg(1)
            .arg(&self.key)
            .arg(SCHEMA)
            .arg(&call.store_id)
            .arg(&call.fingerprint)
            .arg(self.capacity)
            .query(&mut connection)
            .map_err(|_| IpcError::IdempotencyUnavailable)?;
        match result.first().map(String::as_str) {
            Some("leader") => Ok(Claim::Leader(
                result.get(1).ok_or(IpcError::Malformed)?.clone(),
            )),
            Some("cached") => {
                let receipt = result
                    .get(1)
                    .filter(|value| value.len() <= 8192)
                    .ok_or(IpcError::Malformed)?;
                let receipt: TransactionReceipt =
                    serde_json::from_str(receipt).map_err(|_| IpcError::Malformed)?;
                validate_receipt(call, &receipt)?;
                Ok(Claim::Cached(receipt))
            }
            Some("conflict") => Err(IpcError::IdempotencyConflict),
            Some("inconclusive") => Err(IpcError::Inconclusive),
            Some("full") => Err(IpcError::IdempotencyUnavailable),
            Some("sealed") => Err(IpcError::Protocol("Redis namespace is quarantined")),
            _ => Err(IpcError::IdempotencyUnavailable),
        }
    }

    fn finish(
        &self,
        call: &VerifiedCall,
        fence: &str,
        receipt: Option<&TransactionReceipt>,
    ) -> Result<(), IpcError> {
        let mut connection = self.connection()?;
        let state = if receipt.is_some() {
            "done"
        } else {
            "inconclusive"
        };
        let encoded = receipt
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| IpcError::Malformed)?
            .unwrap_or_default();
        let result: i64 = redis::cmd("EVAL")
            .arg(FINISH)
            .arg(1)
            .arg(&self.key)
            .arg(SCHEMA)
            .arg(&call.store_id)
            .arg(&call.fingerprint)
            .arg(fence)
            .arg(state)
            .arg(encoded)
            .query(&mut connection)
            .map_err(|_| IpcError::Inconclusive)?;
        if result != 1 {
            return Err(IpcError::Inconclusive);
        }
        Ok(())
    }
}

enum Claim {
    Leader(String),
    Cached(TransactionReceipt),
}

pub trait CheckpointSink: Send + Sync {
    fn store(&self, checkpoint: &AuditCheckpoint, exported: &str) -> Result<(), IpcError>;
}

/// A caller must place this path in its separately trusted anchor store.
pub struct FileCheckpointSink {
    path: std::path::PathBuf,
    last: Mutex<Option<u64>>,
}
impl FileCheckpointSink {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            last: Mutex::new(None),
        }
    }
}
impl CheckpointSink for FileCheckpointSink {
    fn store(&self, checkpoint: &AuditCheckpoint, exported: &str) -> Result<(), IpcError> {
        use std::io::Write;
        let mut last = self.last.try_lock().map_err(|_| IpcError::RateLimited)?;
        if last.is_none() && self.path.exists() {
            return Err(IpcError::Protocol(
                "checkpoint stream already exists; choose a new stream path",
            ));
        }
        if last.is_some_and(|previous| previous.checked_add(1) != Some(checkpoint.records)) {
            return Err(IpcError::Protocol("checkpoint sequence is not monotonic"));
        }
        let temporary = self
            .path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        let content = serde_json::json!({"head":hex(&checkpoint.head),"merkle_root":hex(&checkpoint.merkle_root),"records":checkpoint.records});
        file.write_all(content.to_string().as_bytes())?;
        file.sync_all()?;
        drop(file);
        let export_path = self.path.with_extension("audit.json");
        let export_temporary = self
            .path
            .with_extension(format!("{}.audit.tmp", uuid::Uuid::new_v4()));
        let mut export_options = std::fs::OpenOptions::new();
        export_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            export_options.mode(0o600);
        }
        let mut export = export_options.open(&export_temporary)?;
        export.write_all(exported.as_bytes())?;
        export.sync_all()?;
        drop(export);
        std::fs::rename(export_temporary, export_path)?;
        std::fs::rename(&temporary, &self.path)?;
        #[cfg(unix)]
        {
            let parent = self.path.parent().ok_or(IpcError::Malformed)?;
            std::fs::File::open(parent)?.sync_all()?;
        }
        *last = Some(checkpoint.records);
        Ok(())
    }
}

pub struct EnterpriseAdmission {
    closed: std::sync::atomic::AtomicBool,
    authority: TenantAuthority,
    store: Arc<RedisIdempotency>,
    gate: Arc<WorkerGate>,
    audit: Mutex<AuditLedger>,
    sink: Arc<dyn CheckpointSink>,
}

impl EnterpriseAdmission {
    pub fn new(
        authority: TenantAuthority,
        store: Arc<RedisIdempotency>,
        sink: Arc<dyn CheckpointSink>,
    ) -> Result<Self, IpcError> {
        store.health()?;
        let audit = AuditLedger::try_new()?;
        sink.store(&audit.checkpoint(), &audit.export_json())?;
        Ok(Self {
            closed: std::sync::atomic::AtomicBool::new(false),
            authority,
            store,
            sink,
            gate: Arc::new(WorkerGate::new()),
            audit: Mutex::new(audit),
        })
    }

    pub fn export_audit(&self) -> Result<String, IpcError> {
        Ok(self
            .audit
            .try_lock()
            .map_err(|_| IpcError::RateLimited)?
            .export_json())
    }

    pub fn close(&self) -> Result<(), IpcError> {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        let authority = self.authority.close();
        let audit = self
            .audit
            .try_lock()
            .map_err(|_| IpcError::RateLimited)?
            .close();
        authority?;
        audit
    }

    fn note(
        &self,
        kind: AuditKind,
        account: &str,
        endpoint: &str,
        hash: &str,
        key: &str,
        receipt: Option<&TransactionReceipt>,
    ) -> Result<(), IpcError> {
        let mut audit = self.audit.try_lock().map_err(|_| IpcError::RateLimited)?;
        audit.append(&AuditEvent {
            kind,
            service_account_id: account.to_string(),
            endpoint: endpoint.to_string(),
            payload_hash: hash.to_string(),
            idempotency_key: key.to_string(),
            seal_report: receipt.map_or(String::new(), |r| format!("{:?}", r.seal_report)),
            binding_digest_hex: receipt.map_or(String::new(), |r| r.binding_digest_hex.clone()),
            transport_status: receipt.map_or(0, |r| r.transport_status),
        })?;
        let result = self.sink.store(&audit.checkpoint(), &audit.export_json());
        if result.is_err() {
            self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        result
    }

    pub(crate) fn begin(
        self: &Arc<Self>,
        proof: &TenantCredential,
        endpoint: &str,
        payload: &[u8],
        hash: &str,
        key: &str,
    ) -> Result<Admission, IpcError> {
        let permit = self.gate.try_acquire_owned()?;
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(IpcError::TargetDenied);
        }
        if payload.is_empty()
            || payload.len() > 65536
            || hash != hex(&Sha256::digest(payload))
            || !crate::idempotency::valid_key(key)
        {
            return Err(IpcError::Malformed);
        }
        if let Err(error) = self.authority.verify(proof, endpoint, payload) {
            self.note(
                AuditKind::TargetDenied,
                "rejected",
                endpoint,
                hash,
                key,
                None,
            )?;
            return Err(error);
        }
        let store_id = digest_parts(&[&proof.account, key]);
        let fingerprint = digest_parts(&[endpoint, hash]);
        let call = VerifiedCall {
            account: proof.account.clone(),
            endpoint: endpoint.to_string(),
            hash: hash.to_string(),
            original_key: key.to_string(),
            store_id,
            fingerprint,
            payload: Zeroizing::new(payload.to_vec()),
        };
        // Anchor the authorization record before any external side effect.
        self.note(AuditKind::Receipt, &call.account, endpoint, hash, key, None)?;
        let claim = self.store.claim(&call);
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(IpcError::Inconclusive);
        }
        match claim {
            Ok(Claim::Leader(fence)) => Ok(Admission::Execute(EnterpriseOperation {
                admission: Arc::clone(self),
                call,
                fence,
                _permit: permit,
            })),
            Ok(Claim::Cached(mut receipt)) => {
                receipt.idempotency_key = key.to_string();
                if matches!(
                    receipt.seal_report,
                    SealReport::Partial | SealReport::Failed
                ) {
                    return Err(IpcError::CleanupIncomplete(receipt));
                }
                Ok(Admission::Cached(receipt))
            }
            Err(IpcError::IdempotencyConflict) => {
                self.note(
                    AuditKind::IdempotencyConflict,
                    &call.account,
                    endpoint,
                    hash,
                    key,
                    None,
                )?;
                Err(IpcError::IdempotencyConflict)
            }
            Err(error) => Err(error),
        }
    }
}

struct VerifiedCall {
    account: String,
    endpoint: String,
    hash: String,
    original_key: String,
    store_id: String,
    fingerprint: String,
    payload: Zeroizing<Vec<u8>>,
}

pub(crate) enum Admission {
    Execute(EnterpriseOperation),
    Cached(TransactionReceipt),
}

/// Not publicly constructible. Dropping an interrupted operation leaves a
/// durable Pending entry, which is never automatically retried or expired.
pub(crate) struct EnterpriseOperation {
    admission: Arc<EnterpriseAdmission>,
    call: VerifiedCall,
    fence: String,
    _permit: OwnedWorkerPermit,
}

impl EnterpriseOperation {
    pub(crate) fn provider_key(&self) -> &str {
        &self.call.store_id
    }
    pub(crate) fn payload(&self) -> &[u8] {
        &self.call.payload
    }

    pub(crate) fn finish(
        self,
        result: Result<TransactionReceipt, IpcError>,
    ) -> Result<TransactionReceipt, IpcError> {
        let (mut receipt, incomplete) = match result {
            Ok(receipt) => (receipt, false),
            Err(IpcError::CleanupIncomplete(receipt)) => (receipt, true),
            Err(error) => {
                self.admission.store.finish(&self.call, &self.fence, None)?;
                return Err(error);
            }
        };
        validate_receipt(&self.call, &receipt)?;
        let audit_result = self.admission.note(
            AuditKind::Retained,
            &self.call.account,
            &self.call.endpoint,
            &self.call.hash,
            &self.call.original_key,
            Some(&receipt),
        );
        if audit_result.is_err() {
            self.admission
                .closed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            receipt.seal_report = SealReport::Partial;
        }
        self.admission
            .store
            .finish(&self.call, &self.fence, Some(&receipt))?;
        receipt.idempotency_key = self.call.original_key.clone();
        if audit_result.is_err()
            || incomplete
            || matches!(
                receipt.seal_report,
                SealReport::Partial | SealReport::Failed
            )
        {
            return Err(IpcError::CleanupIncomplete(receipt));
        }
        Ok(receipt)
    }
}

#[cfg(test)]
#[path = "enterprise_runtime_tests.rs"]
mod tests;

fn validate_receipt(call: &VerifiedCall, receipt: &TransactionReceipt) -> Result<(), IpcError> {
    if receipt.target_endpoint != call.endpoint
        || receipt.payload_hash != call.hash
        || receipt.idempotency_key != call.store_id
        || receipt.binding_digest_hex.len() != 64
        || !receipt
            .binding_digest_hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(IpcError::Inconclusive);
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest_parts(parts: &[&str]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"nexus-enterprise-binding-v1");
    for part in parts {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part.as_bytes());
    }
    hex(&hash.finalize())
}

/// Actual TLS HTTP execution. Redirects/proxies are disabled; only the server
/// authorized endpoint and exact payload bytes are forwarded. Providers must
/// honor the signed idempotency key; Redis alone cannot guarantee exactly-once.
pub struct HttpPayloadTransport {
    timeout: Duration,
    root: Option<reqwest::Certificate>,
}
impl HttpPayloadTransport {
    pub fn new(timeout: Duration) -> Result<Self, IpcError> {
        // reqwest's rustls-no-provider never installs a provider implicitly.
        // A test TLS server can mask this in-process; standalone daemons must
        // initialize it themselves. Preserve an application-installed provider.
        // An install race is acceptable only if a provider is now available.
        if rustls::crypto::CryptoProvider::get_default().is_none()
            && rustls::crypto::ring::default_provider()
                .install_default()
                .is_err()
            && rustls::crypto::CryptoProvider::get_default().is_none()
        {
            return Err(IpcError::Protocol("TLS crypto provider unavailable"));
        }
        if timeout.is_zero() || timeout > Duration::from_secs(120) {
            return Err(IpcError::Malformed);
        }
        Ok(Self {
            timeout,
            root: None,
        })
    }

    /// Operator-provisioned trust anchor; certificate/hostname verification is
    /// never disabled. Used for private provider PKI as well as test TLS.
    pub fn with_ca_der(mut self, der: &[u8]) -> Result<Self, IpcError> {
        self.root = Some(reqwest::Certificate::from_der(der).map_err(|_| IpcError::Malformed)?);
        Ok(self)
    }
}
impl SecureTransport for HttpPayloadTransport {
    fn dispatch(&mut self, _: &AuthorizedCall<'_>) -> Result<TransportReply, BrokerError> {
        Err(BrokerError::Transport(
            "HTTP provider requires bound payload",
        ))
    }
    fn dispatch_payload(
        &mut self,
        call: &AuthorizedCall<'_>,
        payload: &[u8],
    ) -> Result<TransportReply, BrokerError> {
        strict_service_target(call.target_endpoint)
            .map_err(|_| BrokerError::Transport("provider target denied"))?;
        if call.payload_hash != hex(&Sha256::digest(payload)) {
            return Err(BrokerError::Transport("provider payload mismatch"));
        }
        let mut builder = reqwest::blocking::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.timeout);
        if let Some(root) = &self.root {
            builder = builder.tls_certs_only([root.clone()]);
        }
        let client = builder
            .build()
            .map_err(|_| BrokerError::Transport("provider client unavailable"))?;
        let response = client
            .post(call.target_endpoint)
            .header("Content-Type", "application/json")
            .header("X-Nexus-Signature", call.nexus_signature)
            .header("X-Nexus-Payload-Hash", call.payload_hash)
            .header("X-Nexus-Endpoint", call.target_endpoint)
            .header("X-Nexus-Idempotency-Key", call.idempotency_key)
            .header("Idempotency-Key", call.idempotency_key)
            .body(payload.to_vec())
            .send()
            .map_err(|_| BrokerError::Inconclusive)?;
        Ok(TransportReply {
            status: response.status().as_u16(),
        })
    }
}
