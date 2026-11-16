//! Field pilot for the support-agent service account.
//!
//! The broker mints and checks the tenant HMAC. The GitHub token stays in the
//! issue transport. A denied method or repository never reaches the provider.

#![forbid(unsafe_code)]

use std::time::Duration;

use zeroize::Zeroizing;

use crate::adapters::github::{
    GithubIssuePolicy, GithubIssueTransport, IssueProvider, IssueReceipt,
};
use crate::enterprise::{AuditEvent, AuditKind, AuditLedger, ServiceAccount, TenantDirectory};
use crate::enterprise_runtime::HttpPayloadTransport;
use crate::ipc::IpcError;

pub const SERVICE_ACCOUNT: &str = "support_agent_service_account";
pub const ROLE: &str = "support_agent";
const TOKEN_WINDOW_MS: u64 = 60_000;

pub struct FieldPilot {
    directory: TenantDirectory,
    secret: Zeroizing<Vec<u8>>,
    transport: GithubIssueTransport,
}

pub struct FieldRequest<'a> {
    pub method: &'a str,
    pub endpoint: &'a str,
    pub title: &'a str,
    pub body: &'a str,
    pub idempotency_key: &'a str,
    pub now_unix_ms: u64,
}

struct Note<'a> {
    kind: AuditKind,
    endpoint: &'a str,
    payload_hash: &'a str,
    idempotency_key: &'a str,
    binding_digest_hex: &'a str,
    transport_status: u16,
}

impl FieldPilot {
    pub fn new(
        secret: Vec<u8>,
        http: &HttpPayloadTransport,
        policy: GithubIssuePolicy,
        provider_token: Vec<u8>,
    ) -> Result<Self, IpcError> {
        if secret.is_empty() || secret.len() > 4096 {
            return Err(IpcError::Malformed);
        }
        let endpoint = policy.endpoint().to_string();
        let directory = TenantDirectory::try_new(vec![ServiceAccount {
            id: SERVICE_ACCOUNT.to_string(),
            roles: vec![ROLE.to_string()],
            attributes: Vec::new(),
            allowlist: vec![endpoint.clone()],
            role_endpoints: std::collections::BTreeMap::from([(ROLE.to_string(), vec![endpoint])]),
            role_params: std::collections::BTreeMap::from([(
                ROLE.to_string(),
                vec!["body".to_string(), "title".to_string()],
            )]),
        }])?;
        Ok(Self {
            directory,
            secret: Zeroizing::new(secret),
            transport: GithubIssueTransport::from_http(http, policy, provider_token)?,
        })
    }

    pub fn timeout(&self) -> Duration {
        self.transport.timeout()
    }

    pub fn execute<P: IssueProvider>(
        &self,
        provider: &mut P,
        request: FieldRequest<'_>,
        ledger: &mut AuditLedger,
    ) -> Result<IssueReceipt, IpcError> {
        if let Err(err) = self.authorize(request.endpoint, request.now_unix_ms) {
            if matches!(err, IpcError::TargetDenied) {
                let _ = self.note(ledger, denied(&request));
            }
            return Err(err);
        }
        if request.method != "POST" {
            let _ = self.note(ledger, denied(&request));
            return Err(IpcError::TargetDenied);
        }
        match self.transport.open_issue(
            provider,
            request.title,
            request.body,
            request.idempotency_key,
            ledger,
        ) {
            Ok(receipt) => {
                if receipt.duplicate_status.is_none() {
                    self.note(
                        ledger,
                        Note {
                            kind: AuditKind::Retained,
                            endpoint: &receipt.target_endpoint,
                            payload_hash: &receipt.payload_hash,
                            idempotency_key: &receipt.idempotency_key,
                            binding_digest_hex: &receipt.binding_digest_hex,
                            transport_status: receipt.transport_status,
                        },
                    )?;
                }
                Ok(receipt)
            }
            Err(IpcError::IdempotencyConflict) => {
                let _ = self.note(
                    ledger,
                    Note {
                        kind: AuditKind::IdempotencyConflict,
                        endpoint: request.endpoint,
                        payload_hash: "conflict",
                        idempotency_key: request.idempotency_key,
                        binding_digest_hex: "",
                        transport_status: 0,
                    },
                );
                Err(IpcError::IdempotencyConflict)
            }
            Err(err) => Err(err),
        }
    }

    fn authorize(&self, endpoint: &str, now_unix_ms: u64) -> Result<(), IpcError> {
        let expires = now_unix_ms
            .checked_add(TOKEN_WINDOW_MS)
            .ok_or(IpcError::Malformed)?;
        let token = self.directory.issue_token(
            &self.secret,
            SERVICE_ACCOUNT,
            ROLE,
            expires,
            now_unix_ms,
        )?;
        self.directory.authorize(
            &self.secret,
            &token,
            SERVICE_ACCOUNT,
            endpoint,
            &[],
            now_unix_ms,
        )?;
        Ok(())
    }

    fn note(&self, ledger: &mut AuditLedger, note: Note<'_>) -> Result<(), IpcError> {
        ledger.append(&AuditEvent {
            kind: note.kind,
            service_account_id: SERVICE_ACCOUNT.to_string(),
            endpoint: note.endpoint.to_string(),
            payload_hash: note.payload_hash.to_string(),
            idempotency_key: note.idempotency_key.to_string(),
            seal_report: if note.kind == AuditKind::Retained {
                "retained".to_string()
            } else {
                String::new()
            },
            binding_digest_hex: note.binding_digest_hex.to_string(),
            transport_status: note.transport_status,
        })?;
        Ok(())
    }
}

fn denied<'a>(request: &'a FieldRequest<'_>) -> Note<'a> {
    Note {
        kind: AuditKind::TargetDenied,
        endpoint: request.endpoint,
        payload_hash: "denied",
        idempotency_key: request.idempotency_key,
        binding_digest_hex: "",
        transport_status: 0,
    }
}

impl std::fmt::Debug for FieldPilot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FieldPilot")
            .field("service_account", &SERVICE_ACCOUNT)
            .field("role", &ROLE)
            .finish_non_exhaustive()
    }
}
