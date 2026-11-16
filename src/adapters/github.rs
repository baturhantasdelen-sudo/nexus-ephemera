//! GitHub Issues adapter for the support-agent pilot.
//!
//! `HttpPayloadTransport` supplies the timeout. This type adds the issue
//! schema, the bearer header, and reconciliation. The token is not returned.

use serde::Deserialize;

use crate::idempotency::valid_key;
use crate::ipc::{IpcError, strict_service_target};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    role: String,
    service_account_id: String,
    provider: String,
    method: String,
    owner: String,
    repo: String,
    endpoint: String,
    allowed_fields: Vec<String>,
    denied_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubIssuePolicy {
    service_account_id: String,
    owner: String,
    repo: String,
    endpoint: String,
}

impl GithubIssuePolicy {
    pub fn load(bytes: &[u8]) -> Result<Self, IpcError> {
        let file: PolicyFile = serde_json::from_slice(bytes).map_err(|_| IpcError::Malformed)?;
        if file.role != "support_agent"
            || file.service_account_id != "support"
            || file.provider != "github_issues"
            || file.method != "POST"
        {
            return Err(IpcError::Malformed);
        }
        if !github_name(&file.owner) || !github_name(&file.repo) {
            return Err(IpcError::Malformed);
        }
        let endpoint = format!(
            "https://api.github.com/repos/{}/{}/issues",
            file.owner, file.repo
        );
        if file.endpoint != endpoint {
            return Err(IpcError::Malformed);
        }
        strict_service_target(&endpoint)?;
        let mut fields = file.allowed_fields;
        fields.sort();
        if fields != ["body", "title"] {
            return Err(IpcError::Malformed);
        }
        let mut denied = file.denied_capabilities;
        denied.sort();
        if denied != ["delete", "infrastructure", "transfer"] {
            return Err(IpcError::Malformed);
        }
        Ok(Self {
            service_account_id: file.service_account_id,
            owner: file.owner,
            repo: file.repo,
            endpoint,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn service_account_id(&self) -> &str {
        &self.service_account_id
    }

    pub fn authorize_target(&self, endpoint: &str) -> Result<(), IpcError> {
        if endpoint == self.endpoint {
            return Ok(());
        }
        let _ = strict_service_target(endpoint);
        Err(IpcError::TargetDenied)
    }

    pub fn reconciliation_url(&self, idempotency_key: &str) -> Result<String, IpcError> {
        if !valid_key(idempotency_key) {
            return Err(IpcError::Malformed);
        }
        let marker = marker(idempotency_key);
        Ok(format!(
            "https://api.github.com/search/issues?q=repo:{}/{}+{}",
            self.owner,
            self.repo,
            percent_encode(&marker)
        ))
    }
}

// This in-memory scripted adapter is deliberately absent from production builds.
// It cannot provide restart/HA idempotency. Use github_production through IPC.
#[cfg(feature = "reference-pilots")]
mod reference {
    use super::*;
    use crate::enterprise::{AuditEvent, AuditKind, AuditLedger, DUPLICATE_PROVIDER_STATUS};
    use crate::enterprise_runtime::HttpPayloadTransport;
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, sync::Mutex, time::Duration};
    use zeroize::Zeroizing;
    const ACCEPT: &str = "application/vnd.github+json";
    const API_VERSION: &str = "2022-11-28";
    const TITLE_MAX: usize = 256;
    const BODY_MAX: usize = 8192;
    #[derive(Clone, PartialEq, Eq)]
    pub struct PreparedIssue {
        pub method: &'static str,
        pub endpoint: String,
        pub accept: &'static str,
        pub api_version: &'static str,
        pub body: Vec<u8>,
        pub payload_hash: String,
        pub idempotency_key: String,
    }

    impl std::fmt::Debug for PreparedIssue {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("PreparedIssue([REDACTED])")
        }
    }

    impl Drop for PreparedIssue {
        fn drop(&mut self) {
            zeroize::Zeroize::zeroize(&mut self.body);
        }
    }

    pub struct IssuePost<'a> {
        pub endpoint: &'a str,
        pub body: &'a [u8],
        pub idempotency_key: &'a str,
        pub authorization: &'a [u8],
        pub payload_hash: &'a str,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CreateResult {
        Created(u16),
        ServerError(u16),
        TimedOut,
        Rejected(u16),
        Duplicate,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FindResult {
        Found(u16),
        Missing,
        Unavailable,
    }

    pub trait IssueProvider {
        fn create(&mut self, request: &IssuePost<'_>) -> CreateResult;
        fn find(&mut self, idempotency_key: &str) -> FindResult;
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IssueReceipt {
        pub target_endpoint: String,
        pub payload_hash: String,
        pub binding_digest_hex: String,
        pub transport_status: u16,
        pub seal_report: &'static str,
        pub idempotency_key: String,
        pub duplicate_status: Option<u16>,
    }

    enum Slot {
        Pending,
        Done(IssueReceipt),
        Inconclusive,
    }

    pub struct GithubIssueTransport {
        timeout: Duration,
        policy: GithubIssuePolicy,
        token: crate::apoptosis::EphemeralBuffer,
        slots: Mutex<BTreeMap<String, Slot>>,
    }

    impl GithubIssueTransport {
        pub fn from_http(
            http: &HttpPayloadTransport,
            policy: GithubIssuePolicy,
            token: Vec<u8>,
        ) -> Result<Self, IpcError> {
            let token = Zeroizing::new(token);
            if token.is_empty()
                || token.len() > 256
                || token.windows(7).any(|window| window == b"Bearer ")
                || !token.iter().all(|byte| byte.is_ascii_graphic())
            {
                return Err(IpcError::Malformed);
            }
            Ok(Self {
                timeout: http.timeout(),
                policy,
                token: crate::apoptosis::EphemeralBuffer::from_bytes(&token)
                    .map_err(|_| IpcError::TargetDenied)?,
                slots: Mutex::new(BTreeMap::new()),
            })
        }

        pub fn timeout(&self) -> Duration {
            self.timeout
        }

        pub fn open_fields<P: IssueProvider>(
            &self,
            provider: &mut P,
            fields: &BTreeMap<String, String>,
            idempotency_key: &str,
            ledger: &mut AuditLedger,
        ) -> Result<IssueReceipt, IpcError> {
            let mut keys: Vec<&str> = fields.keys().map(String::as_str).collect();
            keys.sort_unstable();
            if keys != ["body", "title"] {
                return Err(IpcError::Malformed);
            }
            self.open_issue(
                provider,
                fields.get("title").ok_or(IpcError::Malformed)?,
                fields.get("body").ok_or(IpcError::Malformed)?,
                idempotency_key,
                ledger,
            )
        }

        pub fn prepare(
            &self,
            title: &str,
            body: &str,
            idempotency_key: &str,
        ) -> Result<PreparedIssue, IpcError> {
            let _permit = crate::apoptosis::acquire_permit().map_err(|_| IpcError::TargetDenied)?;
            if !valid_key(idempotency_key)
                || !field_ok(title, TITLE_MAX, false)
                || !field_ok(body, BODY_MAX, true)
            {
                return Err(IpcError::Malformed);
            }
            let marked = Zeroizing::new(format!("{body}\n\n{}", marker(idempotency_key)));
            let encoded_body = Zeroizing::new(json_string(&marked));
            let encoded_title = Zeroizing::new(json_string(title));
            let encoded = Zeroizing::new(format!(
                "{{\"body\":{},\"title\":{}}}",
                encoded_body.as_str(),
                encoded_title.as_str()
            ));
            let body_bytes = encoded.as_bytes().to_vec();
            Ok(PreparedIssue {
                method: "POST",
                endpoint: self.policy.endpoint.clone(),
                accept: ACCEPT,
                api_version: API_VERSION,
                payload_hash: hex(&Sha256::digest(&body_bytes)),
                body: body_bytes,
                idempotency_key: idempotency_key.to_string(),
            })
        }

        pub fn open_issue<P: IssueProvider>(
            &self,
            provider: &mut P,
            title: &str,
            body: &str,
            idempotency_key: &str,
            ledger: &mut AuditLedger,
        ) -> Result<IssueReceipt, IpcError> {
            let prepared = self.prepare(title, body, idempotency_key)?;
            self.policy.authorize_target(&prepared.endpoint)?;
            if !self.claim(idempotency_key)? {
                return self.cached(idempotency_key, &prepared);
            }
            // Reserve audit capacity before a side effect. A failed reservation
            // leaves a permanent uncertain claim; retries cannot dispatch again.
            ledger.append(&audit_event(
                AuditKind::Receipt,
                &self.policy,
                &prepared.endpoint,
                &prepared.payload_hash,
                idempotency_key,
                "",
                0,
            ))?;
            let outcome = self.create_and_reconcile(provider, &prepared);
            self.finish(idempotency_key, outcome, ledger)
        }

        pub fn reject_target(
            &self,
            endpoint: &str,
            ledger: &mut AuditLedger,
        ) -> Result<(), IpcError> {
            let denied = self.policy.authorize_target(endpoint);
            if denied.is_err() {
                ledger.append(&audit_event(
                    AuditKind::TargetDenied,
                    &self.policy,
                    endpoint,
                    "denied",
                    "denied-route",
                    "",
                    0,
                ))?;
            }
            denied
        }

        fn create_and_reconcile<P: IssueProvider>(
            &self,
            provider: &mut P,
            prepared: &PreparedIssue,
        ) -> Result<IssueReceipt, IpcError> {
            match self.create(provider, prepared) {
                CreateResult::Created(status) if (200..300).contains(&status) => {
                    Ok(receipt(prepared, status, None))
                }
                CreateResult::Duplicate => self.found_or_inconclusive(provider, prepared),
                CreateResult::ServerError(status) if (500..600).contains(&status) => {
                    self.reconcile(provider, prepared)
                }
                CreateResult::TimedOut => self.reconcile(provider, prepared),
                CreateResult::Rejected(_)
                | CreateResult::Created(_)
                | CreateResult::ServerError(_) => Err(IpcError::Malformed),
            }
        }

        fn reconcile<P: IssueProvider>(
            &self,
            provider: &mut P,
            prepared: &PreparedIssue,
        ) -> Result<IssueReceipt, IpcError> {
            match provider.find(&prepared.idempotency_key) {
                FindResult::Found(status) => {
                    Ok(receipt(prepared, status, Some(DUPLICATE_PROVIDER_STATUS)))
                }
                // Search absence is not proof that the first POST was rejected.
                FindResult::Missing | FindResult::Unavailable => Err(IpcError::Inconclusive),
            }
        }

        fn found_or_inconclusive<P: IssueProvider>(
            &self,
            provider: &mut P,
            prepared: &PreparedIssue,
        ) -> Result<IssueReceipt, IpcError> {
            match provider.find(&prepared.idempotency_key) {
                FindResult::Found(status) => {
                    Ok(receipt(prepared, status, Some(DUPLICATE_PROVIDER_STATUS)))
                }
                FindResult::Missing | FindResult::Unavailable => Err(IpcError::Inconclusive),
            }
        }

        fn create<P: IssueProvider>(
            &self,
            provider: &mut P,
            prepared: &PreparedIssue,
        ) -> CreateResult {
            let authorization = match self.token.with_sensitive_bytes(|token| {
                let mut authorization = Zeroizing::new(Vec::with_capacity(7 + token.len()));
                authorization.extend_from_slice(b"Bearer ");
                authorization.extend_from_slice(token);
                Ok(authorization)
            }) {
                Ok(value) => value,
                Err(_) => return CreateResult::Rejected(403),
            };
            provider.create(&IssuePost {
                endpoint: &prepared.endpoint,
                body: &prepared.body,
                idempotency_key: &prepared.idempotency_key,
                authorization: &authorization,
                payload_hash: &prepared.payload_hash,
            })
        }

        fn claim(&self, key: &str) -> Result<bool, IpcError> {
            let mut slots = self.slots.lock().unwrap_or_else(|err| err.into_inner());
            match slots.get(key) {
                Some(Slot::Done(_)) => Ok(false),
                Some(Slot::Pending | Slot::Inconclusive) => Err(IpcError::Inconclusive),
                None => {
                    if slots.len() >= 1024 {
                        return Err(IpcError::IdempotencyUnavailable);
                    }
                    slots.insert(key.to_string(), Slot::Pending);
                    Ok(true)
                }
            }
        }

        fn cached(&self, key: &str, prepared: &PreparedIssue) -> Result<IssueReceipt, IpcError> {
            let slots = self.slots.lock().unwrap_or_else(|err| err.into_inner());
            match slots.get(key) {
                Some(Slot::Done(receipt)) => {
                    if receipt.payload_hash != prepared.payload_hash
                        || receipt.target_endpoint != prepared.endpoint
                    {
                        return Err(IpcError::IdempotencyConflict);
                    }
                    let mut cached = receipt.clone();
                    cached.duplicate_status = Some(DUPLICATE_PROVIDER_STATUS);
                    Ok(cached)
                }
                _ => Err(IpcError::Inconclusive),
            }
        }

        fn finish(
            &self,
            key: &str,
            outcome: Result<IssueReceipt, IpcError>,
            ledger: &mut AuditLedger,
        ) -> Result<IssueReceipt, IpcError> {
            let mut slots = self.slots.lock().unwrap_or_else(|err| err.into_inner());
            match outcome {
                Ok(receipt) => {
                    let audited = ledger.append(&audit_event(
                        AuditKind::AuditV2,
                        &self.policy,
                        &receipt.target_endpoint,
                        &receipt.payload_hash,
                        &receipt.idempotency_key,
                        &receipt.binding_digest_hex,
                        receipt.transport_status,
                    ));
                    if let Err(error) = audited {
                        slots.insert(key.to_string(), Slot::Inconclusive);
                        return Err(error);
                    }
                    if let Err(error) = ledger.append(&audit_event(
                        AuditKind::Retained,
                        &self.policy,
                        &receipt.target_endpoint,
                        &receipt.payload_hash,
                        &receipt.idempotency_key,
                        &receipt.binding_digest_hex,
                        receipt.transport_status,
                    )) {
                        slots.insert(key.to_string(), Slot::Inconclusive);
                        return Err(error);
                    }
                    slots.insert(key.to_string(), Slot::Done(receipt.clone()));
                    Ok(receipt)
                }
                Err(IpcError::Malformed) => {
                    // A provider callback may have accepted before returning an
                    // invalid response. Never make its claim reusable.
                    slots.insert(key.to_string(), Slot::Inconclusive);
                    Err(IpcError::Malformed)
                }
                Err(err) => {
                    slots.insert(key.to_string(), Slot::Inconclusive);
                    Err(err)
                }
            }
        }
    }

    impl std::fmt::Debug for GithubIssueTransport {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("GithubIssueTransport")
                .field("endpoint", &self.policy.endpoint)
                .field("timeout", &self.timeout)
                .finish()
        }
    }

    fn receipt(
        prepared: &PreparedIssue,
        status: u16,
        duplicate_status: Option<u16>,
    ) -> IssueReceipt {
        IssueReceipt {
            target_endpoint: prepared.endpoint.clone(),
            payload_hash: prepared.payload_hash.clone(),
            binding_digest_hex: binding_digest(
                &prepared.endpoint,
                &prepared.payload_hash,
                &prepared.idempotency_key,
            ),
            transport_status: status,
            seal_report: "retained",
            idempotency_key: prepared.idempotency_key.clone(),
            duplicate_status,
        }
    }

    fn binding_digest(endpoint: &str, payload_hash: &str, idempotency_key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"nexus-enterprise-binding-v1");
        for part in [endpoint, payload_hash, idempotency_key] {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        hex(&hasher.finalize())
    }

    fn audit_event(
        kind: AuditKind,
        policy: &GithubIssuePolicy,
        endpoint: &str,
        payload_hash: &str,
        idempotency_key: &str,
        binding_digest_hex: &str,
        transport_status: u16,
    ) -> AuditEvent {
        AuditEvent {
            kind,
            service_account_id: policy.service_account_id.clone(),
            endpoint: endpoint.to_string(),
            payload_hash: payload_hash.to_string(),
            idempotency_key: idempotency_key.to_string(),
            seal_report: if kind == AuditKind::AuditV2 {
                "retained".to_string()
            } else {
                String::new()
            },
            binding_digest_hex: binding_digest_hex.to_string(),
            transport_status,
        }
    }
}
#[cfg(feature = "reference-pilots")]
pub use reference::*;

fn marker(idempotency_key: &str) -> String {
    format!("<!-- nexus-idempotency:{idempotency_key} -->")
}

#[cfg(feature = "reference-pilots")]
fn field_ok(value: &str, max: usize, allow_multiline: bool) -> bool {
    if value.is_empty() || value.len() > max {
        return false;
    }
    value.chars().all(|char| {
        char == '\n' && allow_multiline
            || char == '\t' && allow_multiline
            || char.is_ascii_graphic()
            || char == ' '
    })
}

fn github_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        && !value.contains("//")
}

#[cfg(feature = "reference-pilots")]
fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for char in value.chars() {
        match char {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(feature = "reference-pilots")]
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}
